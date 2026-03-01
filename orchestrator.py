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
from validator.commit_reveal import (
    CommitRevealClient,
    CommitRevealSimulator,
    CommitRecord,
    RevealResult,
)
from validator.anticollusion.consensus import AntiCollusionEngine


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
    commit_hash: str = ""         # Commit-reveal: hash submitted on-chain
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
        commit_reveal_address: str = "",
        rpc_url: str = "http://127.0.0.1:8545",
    ):
        self.mode = mode
        self.validator_id = validator_id
        self.anvil_port = anvil_port
        self.corpus_dir = corpus_dir or CORPUS_DIR
        self.data_dir = data_dir or DATA_DIR
        self.reports_dir = self.data_dir / "reports"

        # Initialize components
        self.corpus_gen = CorpusGenerator(output_dir=self.corpus_dir)
        self.validator = ValidationEngine(
            validator_id=validator_id,
            anvil_port=anvil_port,
        )
        self.fingerprinter = FingerprintEngine(
            db_path=self.data_dir / "fingerprints.json"
        )
        self.scorer = SeverityScorer()
        self.incentive = SubnetIncentiveAdapter()

        # Ensure directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Commit-Reveal: live client or in-memory simulator
        if commit_reveal_address:
            self.commit_reveal = CommitRevealClient(
                contract_address=commit_reveal_address,
                rpc_url=rpc_url,
                data_dir=self.data_dir / "commit-reveal",
            )
        else:
            self.commit_reveal = CommitRevealSimulator()
        self.commit_reveal_live = bool(commit_reveal_address)

        # Anti-Collusion Engine for multi-validator consensus
        self.anticollusion = AntiCollusionEngine(
            data_dir=self.data_dir / "anticollusion",
        )

        # Epoch overlap guard
        self._last_closed_epoch: int = -1

    # ── Task Corpus ───────────────────────────────────────────────────────

    def generate_corpus(self, count_per_class: int = 2, seed: int = 42) -> list[TaskPackage]:
        """Generate the task corpus miners will compete on."""
        logger.info("Generating task corpus (seed=%d)", seed)
        packages = self.corpus_gen.generate_batch(
            count_per_class=count_per_class, seed=seed
        )
        paths = self.corpus_gen.save_batch(packages)
        manifest = self.corpus_gen.generate_manifest(packages)
        (self.corpus_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True)
        )
        logger.info("Generated %d tasks across %d classes", len(packages), len(set(p.vulnerability_class for p in packages)))
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

    # ── Commit-Reveal Flow ───────────────────────────────────────────────

    def commit_exploit(
        self,
        task_id: str,
        exploit_source: str,
        miner_address: str,
    ) -> CommitRecord:
        """
        Phase 1: Commit an exploit hash on-chain (or in simulator).

        The miner calls this FIRST, then waits for the reveal window to open.
        Returns a CommitRecord with nonce — MUST be saved locally for reveal.
        """
        if self.commit_reveal_live:
            record = self.commit_reveal.prepare_commit(task_id, exploit_source)
            record = self.commit_reveal.submit_commit(record)
        else:
            # Simulator mode — auto-open the task if not already open
            if task_id not in self.commit_reveal.tasks:
                self.commit_reveal.open_task(task_id)
            record = self.commit_reveal.commit(
                task_id=task_id,
                miner=miner_address,
                exploit_source=exploit_source,
            )
        return record

    def reveal_and_process(
        self,
        task_id: str,
        exploit_source: str,
        miner_address: str,
        commit_record: Optional[CommitRecord] = None,
    ) -> SubmissionResult:
        """
        Phase 2: Reveal the exploit and run the full validation pipeline.

        This is called AFTER the commit window closes and reveal window opens.
        If commit_record is provided, it's used for reveal; otherwise loaded from disk.
        """
        result = SubmissionResult(
            task_id=task_id,
            miner_address=miner_address,
            validation_result="",
        )

        # Reveal on-chain
        if self.commit_reveal_live:
            reveal_result = self.commit_reveal.reveal(task_id)
            if not reveal_result.success:
                result.validation_result = "REJECT_REVEAL_FAILED"
                result.error = reveal_result.error
                return result
            result.commit_hash = commit_record.commit_hash if commit_record else ""
        elif commit_record:
            reveal_result = self.commit_reveal.reveal(
                task_id=task_id,
                miner=miner_address,
                record=commit_record,
            )
            if not reveal_result.success:
                result.validation_result = "REJECT_REVEAL_FAILED"
                result.error = reveal_result.error
                return result
            result.commit_hash = commit_record.commit_hash

        # Now run the standard validation pipeline
        pipeline_result = self.process_submission(task_id, exploit_source, miner_address)
        # Propagate commit_hash from the reveal phase into the pipeline result
        if result.commit_hash:
            pipeline_result.commit_hash = result.commit_hash
        return pipeline_result

    # ── Full Pipeline ─────────────────────────────────────────────────────

    def process_submission(
        self,
        task_id: str,
        exploit_source: str,
        miner_address: str,
    ) -> SubmissionResult:
        """
        Full pipeline: validate → fingerprint → score → record.

        This is the core function miners interact with.
        """
        result = SubmissionResult(
            task_id=task_id,
            miner_address=miner_address,
        )
        start = time.monotonic()

        # Step 1: Load task
        task = self.load_task(task_id)
        if task is None:
            result.validation_result = "REJECT_INVALID_FORMAT"
            result.error = f"Task {task_id[:16]}... not found"
            return result

        # Step 2: Build submission
        submission = ExploitSubmission(
            task_id=task_id,
            exploit_source=exploit_source,
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

                # Try to parse result from stdout (last line is JSON)
                output_lines = result_proc.stdout.strip().splitlines()
                if output_lines:
                    try:
                        result_data = json.loads(output_lines[-1])
                        report.result = ValidationResult(
                            result_data.get("result", "REJECT_INVALID_FORMAT")
                        )
                        report.error_message = result_data.get("error_message", "")
                        report.fingerprint = result_data.get("fingerprint", "")
                        report.severity_score = result_data.get("severity_score", 0.0)
                        if result_data.get("execution_trace"):
                            from validator.engine.validate import ExecutionTrace
                            report.execution_trace = ExecutionTrace(**result_data["execution_trace"])
                    except (json.JSONDecodeError, ValueError, TypeError) as e:
                        report.error_message = f"Docker sandbox output parse error: {e}"
                        logger.error("Docker sandbox parse error: %s\nstdout: %s",
                                     e, result_proc.stdout[:500])
                else:
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
        """
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

        # Prune stale fingerprint records (retain 30 days by default)
        pruned = self.fingerprinter.prune()
        if pruned:
            logger.info("Pruned %d stale fingerprint records", pruned)

        # Save epoch result
        epoch_path = self.data_dir / "epochs" / f"epoch_{epoch_number}.json"
        epoch_path.parent.mkdir(parents=True, exist_ok=True)
        epoch_data = self.incentive.export_epoch(epoch)
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

    def reset(self):
        """Reset all state. For testing only."""
        self.fingerprinter.reset_db()
        self.incentive = SubnetIncentiveAdapter()
        self.anticollusion = AntiCollusionEngine(
            data_dir=self.data_dir / "anticollusion",
        )
        # Clean reports
        if self.reports_dir.exists():
            for f in self.reports_dir.glob("*.json"):
                f.unlink()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
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

    args = parser.parse_args()
    orch = Orchestrator()

    if args.command == "generate":
        orch.generate_corpus(count_per_class=args.count, seed=args.seed)

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

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
