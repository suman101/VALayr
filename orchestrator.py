"""
End-to-End Orchestrator — Wires the full exploit subnet pipeline.

Pipeline:
  1. Generate task corpus (task-generator)
  2. Accept miner exploit submission
  3. Validate exploit (validator/engine)
  4. Fingerprint + deduplicate (validator/fingerprint)
  5. Score severity (validator/scoring)
  6. Feed results to incentive adapter (subnet-adapter)
  7. Produce epoch weights

This is the glue that makes the subnet tick.
"""

import hashlib
import json
import os
import sys
import time
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Resolve project root for imports
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.utils.logging import get_logger
from validator import metrics as _metrics

logger = get_logger(__name__)

from task_generator.generate import CorpusGenerator, TaskPackage
from task_generator.mainnet import MainnetContractSource
from validator.engine.validate import (
    ValidationEngine,
    ExploitSubmission,
    ValidationResult,
    ExecutionTrace,
)
from validator.fingerprint.dedup import FingerprintEngine, FingerprintComponents
from validator.scoring.severity import SeverityScorer, SeverityBreakdown
from subnet_adapter.incentive import (
    SubnetIncentiveAdapter,
    ValidatorVote,
    EpochResult,
)
from validator.anticollusion.consensus import AntiCollusionEngine
from validator.engine.adversarial import (
    AdversarialEngine,
    InvariantSubmission,
    ChallengeSubmission,
    ChallengeReport,
    ChallengeResult,
)


# ── Input Validation ──────────────────────────────────────────────────────────

MAX_TASK_ID_LEN = 256
MAX_MINER_ADDRESS_LEN = 256
MAX_EXPLOIT_SOURCE_BYTES = 64_000  # 64 KB — mitigates DoS via huge payloads


def _validate_str(name: str, value: str, max_len: int) -> Optional[str]:
    """Return an error string if *value* is invalid, else None."""
    if not isinstance(value, str) or not value.strip():
        return f"{name} must be a non-empty string"
    if len(value) > max_len:
        return f"{name} exceeds maximum length ({max_len})"
    return None


# ── Constants ────────────────────────────────────────────────────────────────

DATA_DIR = PROJECT_ROOT / "data"
CORPUS_DIR = PROJECT_ROOT / "contracts" / "corpus"
REPORTS_DIR = DATA_DIR / "reports"
FINGERPRINT_DB = DATA_DIR / "fingerprints.json"


# ── Orchestrator ─────────────────────────────────────────────────────────────

@dataclass
class SubmissionResult:
    """Full result returned to a miner after submission processing."""
    task_id: str
    miner_address: str
    validation_result: str = ""   # VALID or REJECT_*
    fingerprint: str = ""
    is_duplicate: bool = False
    reward_multiplier: float = 0.0
    severity_score: float = 0.0
    severity_detail: str = ""
    validation_time_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Orchestrator:
    """
    Wires task generation → validation → fingerprinting → scoring → incentives.

    Modes:
      - local:  Run everything in-process (dev / testing)
      - docker: Validation in isolated Docker container (network-disabled sandbox)
    """

    def __init__(
        self,
        mode: str = "local",
        validator_id: str = "validator-0",
        anvil_port: int = 18545,
        corpus_dir: Optional[Path] = None,
        data_dir: Optional[Path] = None,
        rpc_url: str = "http://127.0.0.1:8545",
        registry_address: str = "",
        scoring_address: str = "",
    ):
        self.mode = mode
        self.validator_id = validator_id
        self.anvil_port = anvil_port
        self.corpus_dir = corpus_dir or CORPUS_DIR
        self.data_dir = data_dir or DATA_DIR
        self.reports_dir = self.data_dir / "reports"

        # Initialize components
        self.corpus_gen = CorpusGenerator(output_dir=self.corpus_dir)
        self.mainnet_source = MainnetContractSource(output_dir=self.corpus_dir)
        self.validator = ValidationEngine(
            validator_id=validator_id,
            anvil_port=anvil_port,
        )
        self.fingerprinter = FingerprintEngine(
            db_path=self.data_dir / "fingerprints.json"
        )
        self.scorer = SeverityScorer()
        self.incentive = SubnetIncentiveAdapter()

        # Stage 3: Adversarial Engine
        self.adversarial = AdversarialEngine(
            mode=mode,
            registry_address=registry_address,
            scoring_address=scoring_address,
            rpc_url=rpc_url,
            data_dir=self.data_dir / "adversarial",
        )

        # Ensure directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Anti-Collusion Engine for multi-validator consensus
        self.anticollusion = AntiCollusionEngine(
            data_dir=self.data_dir / "anticollusion",
        )

        # Epoch overlap guard
        self._last_closed_epoch: int = -1
        self._epoch_lock = threading.Lock()

    # ── Task Corpus ───────────────────────────────────────────────────────

    def generate_corpus(self, count_per_class: int = 2, seed: int = 42,
                         max_difficulty: int = 1) -> list[TaskPackage]:
        """Generate the task corpus miners will compete on."""
        logger.info("Generating task corpus (seed=%d, max_difficulty=%d)", seed, max_difficulty)
        packages = self.corpus_gen.generate_batch(
            count_per_class=count_per_class, seed=seed,
            max_difficulty=max_difficulty,
        )
        paths = self.corpus_gen.save_batch(packages)
        manifest = self.corpus_gen.generate_manifest(packages)
        (self.corpus_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True)
        )
        logger.info("Generated %d tasks across %d classes", len(packages), len(set(p.vulnerability_class for p in packages)))
        return packages

    def fetch_mainnet_tasks(
        self,
        addresses: list[str],
        chain_id: int = 1,
        difficulty: int = 3,
    ) -> list[TaskPackage]:
        """Fetch verified mainnet contracts and add them to the corpus.

        Merges fetched packages into the existing manifest so synthetic and
        mainnet tasks coexist in the same corpus directory.
        """
        logger.info("Fetching %d mainnet contract(s) from chain %d", len(addresses), chain_id)
        packages = self.mainnet_source.fetch_and_save(
            addresses=addresses, chain_id=chain_id, difficulty=difficulty,
        )

        # Merge into existing manifest
        manifest_path = self.corpus_dir / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
        else:
            manifest = {"version": 1, "total_tasks": 0, "tasks": []}

        existing_ids = {t["task_id"] for t in manifest.get("tasks", [])}
        for pkg in packages:
            if pkg.task_id not in existing_ids:
                manifest["tasks"].append({
                    "task_id": pkg.task_id,
                    "vulnerability_class": pkg.vulnerability_class,
                    "difficulty": pkg.difficulty,
                    "source_hash": hashlib.sha256(pkg.source_code.encode()).hexdigest(),
                })
        manifest["total_tasks"] = len(manifest["tasks"])

        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
        logger.info("Added %d mainnet task(s) to corpus", len(packages))
        return packages

    def list_tasks(self) -> list[dict]:
        """List all available tasks from the corpus manifest."""
        manifest_path = self.corpus_dir / "manifest.json"
        if not manifest_path.exists():
            return []
        manifest = json.loads(manifest_path.read_text())
        return manifest.get("tasks", [])

    def load_task(self, task_id: str) -> Optional[dict]:
        """Load a specific task by ID (or unambiguous prefix).

        Prefix matching is supported for convenience (e.g. ``0xabc`` matches
        ``0xabc123...``), but the prefix **must** be unambiguous.  If multiple
        tasks match the same prefix, ``None`` is returned and a warning is
        logged so the caller can surface the error.
        """
        candidates: list[dict] = []

        for d in self.corpus_dir.iterdir():
            if not d.is_dir():
                continue
            task_json_path = d / "task.json"
            if not task_json_path.exists():
                continue

            task = json.loads(task_json_path.read_text())
            full_id = task.get("task_id", "")

            # Exact match — return immediately (no ambiguity possible)
            if full_id == task_id or d.name == task_id:
                task["_source_dir"] = str(d)
                return task

            # Prefix match
            if full_id.startswith(task_id) or d.name.startswith(task_id):
                task["_source_dir"] = str(d)
                candidates.append(task)

        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            logger.warning(
                "Ambiguous task prefix '%s' matches %d tasks — specify more characters",
                task_id[:16], len(candidates),
            )
            return None  # Ambiguous
        return None  # Not found

    # ── Full Pipeline ─────────────────────────────────────────────────────

    def process_submission(
        self,
        task_id: str,
        exploit_source: str,
        miner_address: str,
        entry_functions: list[str] | None = None,
    ) -> SubmissionResult:
        """
        Full pipeline: validate → fingerprint → score → record.

        This is the core function miners interact with.
        """
        result = SubmissionResult(
            task_id=task_id,
            miner_address=miner_address,
        )

        # ── Input validation ──
        for name, val, limit in [
            ("task_id", task_id, MAX_TASK_ID_LEN),
            ("miner_address", miner_address, MAX_MINER_ADDRESS_LEN),
        ]:
            err = _validate_str(name, val, limit)
            if err:
                result.validation_result = "REJECT_INVALID_FORMAT"
                result.error = err
                return result
        if not isinstance(exploit_source, str) or not exploit_source.strip():
            result.validation_result = "REJECT_INVALID_FORMAT"
            result.error = "exploit_source must be a non-empty string"
            return result
        if len(exploit_source.encode()) > MAX_EXPLOIT_SOURCE_BYTES:
            result.validation_result = "REJECT_INVALID_FORMAT"
            result.error = f"exploit_source exceeds {MAX_EXPLOIT_SOURCE_BYTES} bytes"
            return result

        start = time.monotonic()

        # Step 1: Load task
        task = self.load_task(task_id)
        if task is None:
            result.validation_result = "REJECT_INVALID_FORMAT"
            result.error = f"Task {task_id[:16]}... not found"
            return result

        # Step 2: Build submission (with multi-tx entry_functions if provided)
        submission = ExploitSubmission(
            task_id=task_id,
            exploit_source=exploit_source,
            entry_functions=entry_functions or [],
        )

        # Step 3: Validate
        logger.info("Validating exploit for task %s...", task_id[:16])
        if self.mode == "docker":
            report = self._validate_in_docker(task, submission)
        else:
            report = self.validator.validate(task, submission)
        result.validation_result = report.result.value
        result.validation_time_ms = report.validation_time_ms

        if report.result != ValidationResult.VALID:
            result.error = report.error_message
            self._save_report(result)
            return result

        # Step 4: Score severity
        if report.execution_trace:
            breakdown = self.scorer.score_detailed(report.execution_trace)
            result.severity_score = breakdown.final_severity
            result.severity_detail = breakdown.detail

        # Step 5: Fingerprint + dedup
        if report.fingerprint:
            dedup = self.fingerprinter.check_duplicate(
                task_id=task_id,
                fingerprint=report.fingerprint,
                miner_address=miner_address,
            )
            result.fingerprint = report.fingerprint
            result.is_duplicate = dedup.is_duplicate
            result.reward_multiplier = dedup.reward_multiplier
        else:
            result.reward_multiplier = 1.0

        # Step 6: Record vote in incentive adapter
        vote = ValidatorVote(
            validator_hotkey=self.validator_id,
            task_id=task_id,
            submission_hash=hashlib.sha256(exploit_source.encode()).hexdigest(),
            result=report.result.value,
            fingerprint=result.fingerprint,
            severity_score=result.severity_score,
            timestamp=time.time(),
            miner_hotkey=miner_address,
        )
        self.incentive.record_vote(vote)

        # Step 7: Feed vote to anti-collusion engine for cross-validator consensus
        self.anticollusion.register_validator(self.validator_id, stake=1.0)
        consensus_vote = {
            "validator_hotkey": vote.validator_hotkey,
            "result": vote.result,
            "fingerprint": vote.fingerprint,
            "severity_score": vote.severity_score,
        }
        self.anticollusion.compute_consensus(
            task_id=task_id,
            submission_hash=vote.submission_hash,
            votes=[consensus_vote],
        )

        result.validation_time_ms = int((time.monotonic() - start) * 1000)
        self._save_report(result)

        # Record metrics
        _metrics.inc("validations_total")
        _metrics.observe("validation_latency_ms", result.validation_time_ms)
        if result.validation_result == "VALID":
            _metrics.inc("validations_valid")
        if result.is_duplicate:
            _metrics.inc("duplicates_total")
        if result.severity_score > 0:
            _metrics.observe("severity_score", result.severity_score)

        return result

    # ── Stage 3: Adversarial Mode ─────────────────────────────────────────

    def submit_invariant(
        self,
        miner_address: str,
        target_contract_hash: str,
        description: str,
        solidity_condition: str,
        compiled_check: bytes = b"",
    ) -> int:
        """
        Class A miner submits an invariant.

        Returns the invariant ID assigned by the registry.
        """
        for name, val, limit in [
            ("miner_address", miner_address, MAX_MINER_ADDRESS_LEN),
            ("target_contract_hash", target_contract_hash, MAX_TASK_ID_LEN),
            ("description", description, 2048),
            ("solidity_condition", solidity_condition, MAX_EXPLOIT_SOURCE_BYTES),
        ]:
            err = _validate_str(name, val, limit)
            if err:
                raise ValueError(err)

        submission = InvariantSubmission(
            miner_address=miner_address,
            target_contract_hash=target_contract_hash,
            description=description,
            solidity_condition=solidity_condition,
            compiled_check=compiled_check,
        )
        inv_id = self.adversarial.submit_invariant(submission)
        _metrics.inc("invariants_submitted")
        return inv_id

    def submit_challenge(
        self,
        miner_address: str,
        invariant_id: int,
        exploit_source: str,
        target_task_id: str,
    ) -> ChallengeReport:
        """
        Class B miner challenges an invariant with an exploit.

        Returns a ChallengeReport with the outcome.
        """
        for name, val, limit in [
            ("miner_address", miner_address, MAX_MINER_ADDRESS_LEN),
            ("target_task_id", target_task_id, MAX_TASK_ID_LEN),
        ]:
            err = _validate_str(name, val, limit)
            if err:
                raise ValueError(err)
        if not isinstance(exploit_source, str) or not exploit_source.strip():
            raise ValueError("exploit_source must be a non-empty string")
        if len(exploit_source.encode()) > MAX_EXPLOIT_SOURCE_BYTES:
            raise ValueError(f"exploit_source exceeds {MAX_EXPLOIT_SOURCE_BYTES} bytes")
        if not isinstance(invariant_id, int) or invariant_id < 0:
            raise ValueError("invariant_id must be a non-negative integer")

        challenge = ChallengeSubmission(
            miner_address=miner_address,
            invariant_id=invariant_id,
            exploit_source=exploit_source,
            target_task_id=target_task_id,
        )
        report = self.adversarial.process_challenge(challenge)
        _metrics.inc("challenges_total")
        if report.result == ChallengeResult.INVARIANT_BROKEN:
            _metrics.inc("invariants_broken")
        elif report.result == ChallengeResult.INVARIANT_HELD:
            _metrics.inc("invariants_held")
        return report

    def get_adversarial_weights(self) -> dict[str, float]:
        """Compute weight vector from Stage 3 adversarial scores."""
        return self.adversarial.compute_adversarial_weights()

    # ── Docker Sandbox Validation ─────────────────────────────────────────

    # Docker image used for network-isolated exploit execution
    DOCKER_SANDBOX_IMAGE = "ghcr.io/exploit-subnet/validator:v0.1.0"
    DOCKER_SANDBOX_TIMEOUT = 180  # seconds

    def _validate_in_docker(self, task_json: dict, submission: ExploitSubmission):
        """Run validation inside a network-disabled Docker container.

        The container has no internet access (``--network=none``) ensuring
        deterministic, tamper-proof execution.  The task and exploit are
        written to a temp dir which is bind-mounted read-only.
        """
        import subprocess
        import tempfile

        from validator.engine.validate import ValidationReport, ValidationResult

        report = ValidationReport(
            task_id=submission.task_id,
            result=ValidationResult.REJECT_INVALID_FORMAT,
            validator_id=self.validator_id,
        )
        start = time.monotonic()

        try:
            with tempfile.TemporaryDirectory(prefix="exploit-docker-") as tmpdir:
                tmpdir = Path(tmpdir)
                # Write task + exploit to temp dir
                (tmpdir / "task.json").write_text(json.dumps(task_json, indent=2))
                (tmpdir / "exploit.sol").write_text(submission.exploit_source)

                cmd = [
                    "docker", "run", "--rm",
                    "--network=none",
                    "--cpus=2",
                    "--memory=4g",
                    "--read-only",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
                    "-v", f"{tmpdir}:/workspace:ro",
                    "-e", "PYTHONHASHSEED=0",
                    "-e", "ANVIL_BLOCK_TIMESTAMP=1700000000",
                    "-e", "ANVIL_BLOCK_NUMBER=18000000",
                    "-e", "ANVIL_GAS_LIMIT=30000000",
                    "-e", "ANVIL_CHAIN_ID=31337",
                    self.DOCKER_SANDBOX_IMAGE,
                    "python3", "-m", "validator.engine.validate",
                    "--task", "/workspace/task.json",
                    "--exploit", "/workspace/exploit.sol",
                    "--output", "/tmp/result.json",
                ]

                result_proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.DOCKER_SANDBOX_TIMEOUT,
                )

                # Read result from the dedicated output file (written inside container)
                result_json_path = tmpdir / "result.json"
                result_data = None

                if result_json_path.exists():
                    try:
                        result_data = json.loads(result_json_path.read_text())
                    except (json.JSONDecodeError, OSError) as e:
                        logger.error("Docker result.json parse error: %s", e)

                # Fall back to parsing stdout last line if output file not found
                if result_data is None:
                    output_lines = result_proc.stdout.strip().splitlines()
                    if output_lines:
                        try:
                            result_data = json.loads(output_lines[-1])
                        except (json.JSONDecodeError, ValueError, TypeError) as e:
                            report.error_message = f"Docker sandbox output parse error: {e}"
                            logger.error("Docker sandbox parse error: %s\nstdout: %s",
                                         e, result_proc.stdout[:500])

                if result_data:
                    try:
                        report.result = ValidationResult(
                            result_data.get("result", "REJECT_INVALID_FORMAT")
                        )
                        report.error_message = result_data.get("error_message", "")
                        report.fingerprint = result_data.get("fingerprint", "")
                        report.severity_score = result_data.get("severity_score", 0.0)
                        if result_data.get("execution_trace"):
                            from validator.engine.validate import ExecutionTrace
                            report.execution_trace = ExecutionTrace(**result_data["execution_trace"])
                    except (ValueError, TypeError) as e:
                        report.error_message = f"Docker result parse error: {e}"
                elif not report.error_message:
                    report.error_message = "Docker sandbox produced no output"
                    if result_proc.stderr:
                        logger.error("Docker sandbox stderr: %s", result_proc.stderr[:500])

        except subprocess.TimeoutExpired:
            report.result = ValidationResult.REJECT_TIMEOUT
            report.error_message = f"Docker sandbox exceeded {self.DOCKER_SANDBOX_TIMEOUT}s"
        except FileNotFoundError:
            report.error_message = "Docker not found — install Docker or switch to local mode"
            logger.error("Docker not available for sandbox validation")
        except (OSError, subprocess.SubprocessError) as e:
            report.error_message = f"Docker sandbox error: {type(e).__name__}: {e}"
            logger.error("Docker sandbox error: %s", e, exc_info=True)

        report.validation_time_ms = int((time.monotonic() - start) * 1000)
        return report

    # ── Epoch Management ──────────────────────────────────────────────────

    def close_epoch(self, epoch_number: int, start_block: int, end_block: int) -> EpochResult:
        """
        Close current epoch and compute weights.

        Called periodically (e.g., every ~1 hour on Bittensor).
        Uses a lock to prevent concurrent epoch processing.
        """
        if not self._epoch_lock.acquire(blocking=False):
            logger.warning(
                "Epoch %d blocked — another epoch is still being processed",
                epoch_number,
            )
            return EpochResult(
                epoch_number=epoch_number,
                start_block=start_block,
                end_block=end_block,
                total_submissions=0,
                total_valid=0,
                weights={},
            )
        try:
            return self._close_epoch_inner(epoch_number, start_block, end_block)
        finally:
            self._epoch_lock.release()

    def _close_epoch_inner(self, epoch_number: int, start_block: int, end_block: int) -> EpochResult:
        """Internal epoch close logic, called under lock."""
        if epoch_number <= self._last_closed_epoch:
            logger.warning(
                "Epoch %d already closed (last=%d) — skipping",
                epoch_number, self._last_closed_epoch,
            )
            return EpochResult(
                epoch_number=epoch_number,
                start_block=start_block,
                end_block=end_block,
                total_submissions=0,
                total_valid=0,
                weights={},
            )
        self._last_closed_epoch = epoch_number
        logger.info("Closing epoch %d (blocks %d-%d)", epoch_number, start_block, end_block)
        epoch = self.incentive.compute_epoch_weights(epoch_number, start_block, end_block)

        # Merge adversarial weights (Stage 3) into epoch result
        adv_weights = self.adversarial.compute_adversarial_weights()
        if adv_weights:
            # Blend: 70% standard exploit scoring + 30% adversarial scoring
            EXPLOIT_WEIGHT = 0.7
            ADVERSARIAL_WEIGHT = 0.3
            all_miners = set(epoch.weights.keys()) | set(adv_weights.keys())
            blended: dict[str, float] = {}
            for miner in all_miners:
                std = epoch.weights.get(miner, 0.0) * EXPLOIT_WEIGHT
                adv = adv_weights.get(miner, 0.0) * ADVERSARIAL_WEIGHT
                blended[miner] = std + adv
            # Re-normalise
            total = sum(blended.values())
            if total > 0:
                epoch.weights = {k: v / total for k, v in blended.items()}
            logger.info("Blended adversarial weights for %d miners", len(adv_weights))

        # Prune stale fingerprint records (retain 30 days by default)
        pruned = self.fingerprinter.prune()
        if pruned:
            logger.info("Pruned %d stale fingerprint records", pruned)

        # Save epoch result
        epoch_path = self.data_dir / "epochs" / f"epoch_{epoch_number}.json"
        epoch_path.parent.mkdir(parents=True, exist_ok=True)
        epoch_data = self.incentive.export_epoch(epoch)
        # Include adversarial scores in export
        epoch_data["adversarial_scores"] = self.adversarial.get_all_scores()
        epoch_path.write_text(json.dumps(epoch_data, indent=2, sort_keys=True))

        logger.info("Epoch %d: %d/%d valid", epoch_number, epoch.total_valid, epoch.total_submissions)

        if epoch.weights:
            logger.info("Weights: %s", json.dumps({k[:8]: round(v, 4) for k, v in epoch.weights.items()}))
        return epoch

    # ── Internal ──────────────────────────────────────────────────────────

    def _save_report(self, result: SubmissionResult):
        """Persist submission result to disk."""
        report_path = self.reports_dir / f"{result.task_id[:16]}_{result.miner_address[:8]}_{time.time_ns()}.json"
        report_path.write_text(json.dumps(result.to_dict(), indent=2))

    def reset(self) -> None:
        """Reset all state. For testing only."""
        self.fingerprinter.reset_db()
        self.incentive = SubnetIncentiveAdapter()
        self.anticollusion = AntiCollusionEngine(
            data_dir=self.data_dir / "anticollusion",
        )
        self.adversarial.reset()
        # Clean reports
        if self.reports_dir.exists():
            for f in self.reports_dir.glob("*.json"):
                f.unlink()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Exploit Subnet Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate task corpus
  python orchestrator.py generate --count 2

  # Process a miner submission
  python orchestrator.py submit --task 0xabc123 --exploit exploit.sol --miner 0xDEAD

  # Close an epoch and compute weights
  python orchestrator.py epoch --number 1 --start 100 --end 460
        """,
    )
    subparsers = parser.add_subparsers(dest="command")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate task corpus")
    gen_parser.add_argument("--count", type=int, default=2, help="Mutations per class")
    gen_parser.add_argument("--seed", type=int, default=42, help="RNG seed")
    gen_parser.add_argument("--difficulty", type=int, default=1, choices=[1, 2, 3],
                            help="Max difficulty level (1-3)")

    # submit
    sub_parser = subparsers.add_parser("submit", help="Process a miner submission")
    sub_parser.add_argument("--task", type=str, required=True, help="Task ID or prefix")
    sub_parser.add_argument("--exploit", type=str, required=True, help="Exploit .sol path")
    sub_parser.add_argument("--miner", type=str, default="0xDEAD", help="Miner address")

    # epoch
    ep_parser = subparsers.add_parser("epoch", help="Close epoch and compute weights")
    ep_parser.add_argument("--number", type=int, required=True)
    ep_parser.add_argument("--start", type=int, required=True)
    ep_parser.add_argument("--end", type=int, required=True)

    # list
    subparsers.add_parser("list", help="List available tasks")

    # Stage 3: invariant
    inv_parser = subparsers.add_parser("invariant", help="Submit an invariant (Class A)")
    inv_parser.add_argument("--miner", type=str, default="0xCLASS_A", help="Class A miner address")
    inv_parser.add_argument("--target", type=str, required=True, help="Target contract hash")
    inv_parser.add_argument("--desc", type=str, required=True, help="Invariant description")
    inv_parser.add_argument("--condition", type=str, required=True, help="Solidity condition")

    # Stage 3: challenge
    chal_parser = subparsers.add_parser("challenge", help="Challenge an invariant (Class B)")
    chal_parser.add_argument("--miner", type=str, default="0xCLASS_B", help="Class B miner address")
    chal_parser.add_argument("--invariant-id", type=int, required=True, help="Invariant ID to challenge")
    chal_parser.add_argument("--exploit", type=str, required=True, help="Exploit .sol path")
    chal_parser.add_argument("--task", type=str, required=True, help="Target task ID")

    args = parser.parse_args()
    orch = Orchestrator()

    if args.command == "generate":
        orch.generate_corpus(count_per_class=args.count, seed=args.seed,
                              max_difficulty=args.difficulty)

    elif args.command == "submit":
        exploit_source = Path(args.exploit).read_text()
        result = orch.process_submission(args.task, exploit_source, args.miner)
        print(f"\n{'='*60}")
        print(f"Result:     {result.validation_result}")
        print(f"Severity:   {result.severity_score:.4f}")
        print(f"Fingerprint:{result.fingerprint[:20]}..." if result.fingerprint else "")
        print(f"Duplicate:  {result.is_duplicate}")
        print(f"Reward:     {result.reward_multiplier:.2f}x")
        print(f"Time:       {result.validation_time_ms}ms")
        if result.error:
            print(f"Error:      {result.error}")

    elif args.command == "epoch":
        orch.close_epoch(args.number, args.start, args.end)

    elif args.command == "list":
        tasks = orch.list_tasks()
        if not tasks:
            print("[!] No tasks found. Run 'generate' first.")
        else:
            print(f"{'Task ID':20s} {'Class':20s} {'Difficulty':>10s}")
            print("-" * 52)
            for t in tasks:
                print(f"{t['task_id'][:18]:20s} {t['vulnerability_class']:20s} {t['difficulty']:>10d}")

    elif args.command == "invariant":
        inv_id = orch.submit_invariant(
            miner_address=args.miner,
            target_contract_hash=args.target,
            description=args.desc,
            solidity_condition=args.condition,
        )
        print(f"[+] Invariant submitted: ID={inv_id}")

    elif args.command == "challenge":
        exploit_source = Path(args.exploit).read_text()
        report = orch.submit_challenge(
            miner_address=args.miner,
            invariant_id=args.invariant_id,
            exploit_source=exploit_source,
            target_task_id=args.task,
        )
        print(f"\n{'='*60}")
        print(f"Challenge result: {report.result.value}")
        print(f"Class A miner:    {report.class_a_miner}")
        print(f"Class B miner:    {report.class_b_miner}")
        print(f"Invariant held:   {report.invariant_held}")
        print(f"Time:             {report.validation_time_ms}ms")
        if report.error_message:
            print(f"Error:            {report.error_message}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
