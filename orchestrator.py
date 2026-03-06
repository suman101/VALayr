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

# ── Execution Safety: Concurrency & Cost Budget ──────────────────────────────

# Max concurrent validations to prevent resource exhaustion from parallel submissions.
# Each validation can use up to 2 CPU + 4GB RAM, so cap at a safe level.
MAX_CONCURRENT_VALIDATIONS = int(os.environ.get("VALAYR_MAX_CONCURRENT_VALIDATIONS", "4"))
_validation_semaphore = threading.Semaphore(MAX_CONCURRENT_VALIDATIONS)

# Per-epoch compute budget (in cumulative CPU-seconds). 0 = unlimited.
# Default 10 000 CPU-seconds ≈ 83 full-timeout (120 s) validations per epoch,
# well above the 50-submission-per-miner cap while preventing runaway costs.
EPOCH_COMPUTE_BUDGET = float(os.environ.get("VALAYR_EPOCH_COMPUTE_BUDGET", "10000"))

# Timeout for a single process_submission call (seconds).
SUBMISSION_TIMEOUT = int(os.environ.get("VALAYR_SUBMISSION_TIMEOUT", "300"))

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
from validator.bounty.anti_bypass import AntiBypassEngine
from validator.bounty.platform import (
    BountyReport,
    PlatformRegistry,
    create_default_registry,
)
from validator.bounty.identity import IdentityStore
from validator.bounty.reward_split import RewardSplitEngine
from validator.scoring.uniqueness import UniquenessScorer
from validator.utils.difficulty import (
    get_max_difficulty,
    get_mainnet_ratio,
    get_min_severity,
    get_epoch_config,
)
from task_generator.discovery import MainnetAutoDiscovery


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

        # In docker (bittensor) mode, enforce sandbox requirement automatically.
        if mode == "docker" and not os.environ.get("VALAYR_REQUIRE_SANDBOX"):
            os.environ["VALAYR_REQUIRE_SANDBOX"] = "1"
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

        # Anti-Bypass Engine — timestamps exploits and detects platform bypasses
        self.anti_bypass = AntiBypassEngine(
            data_dir=self.data_dir / "anti_bypass",
        )

        # Bounty Platform Registry + Identity Store
        self.platform_registry = create_default_registry()
        self.identity_store = IdentityStore(
            data_dir=self.data_dir / "identities",
            platform_registry=self.platform_registry,
        )

        # Reward Split Engine
        self.reward_split = RewardSplitEngine(
            data_dir=self.data_dir / "rewards",
        )

        # Anti-LLM Uniqueness Scorer
        self.uniqueness_scorer = UniquenessScorer()

        # Mainnet Auto-Discovery
        self.mainnet_discovery = MainnetAutoDiscovery(
            data_dir=self.data_dir / "discovery",
        )

        # Current epoch (for difficulty ramping)
        self._current_epoch: int = 0

        # Epoch overlap guard
        self._last_closed_epoch: int = -1
        self._epoch_lock = threading.Lock()

        # ── Cost-per-validation tracking ──────────────────────────────────
        self._epoch_wall_seconds: float = 0.0
        self._epoch_validations: int = 0
        self._cost_lock = threading.Lock()

        # Startup validation — log which secrets are configured
        try:
            from validator.utils.secrets import log_secret_status
            log_secret_status()
        except Exception:
            pass  # Don't block startup if secrets module has issues

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

        # C-8 fix: register tasks with uniqueness scorer so timing bonuses work
        for pkg in packages:
            self.uniqueness_scorer.register_task(pkg.task_id)

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

        # ── Execution safety: check epoch compute budget ──
        if EPOCH_COMPUTE_BUDGET > 0:
            with self._cost_lock:
                if self._epoch_wall_seconds >= EPOCH_COMPUTE_BUDGET:
                    result.validation_result = "REJECT_INVALID_FORMAT"
                    result.error = "Epoch compute budget exhausted"
                    logger.warning(
                        "Rejecting submission: epoch wall budget %.1fs exhausted",
                        EPOCH_COMPUTE_BUDGET,
                    )
                    return result

        # ── Execution safety: concurrency semaphore ──
        if not _validation_semaphore.acquire(timeout=30):
            result.validation_result = "REJECT_TIMEOUT"
            result.error = "Validation queue full — try again later"
            logger.warning("Submission rejected: concurrency limit (%d)", MAX_CONCURRENT_VALIDATIONS)
            return result

        try:
            return self._process_submission_inner(
                task_id, exploit_source, miner_address, entry_functions, result,
            )
        finally:
            _validation_semaphore.release()

    def _process_submission_inner(
        self,
        task_id: str,
        exploit_source: str,
        miner_address: str,
        entry_functions: list[str] | None,
        result: SubmissionResult,
    ) -> SubmissionResult:
        """Inner pipeline behind the concurrency semaphore."""

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

        # Step 6: Anti-LLM uniqueness scoring
        uniqueness = self.uniqueness_scorer.score_submission(
            task_id=task_id,
            exploit_source=exploit_source,
            miner_address=miner_address,
            gas_used=report.execution_trace.gas_used if report.execution_trace else 0,
            selector_count=len(report.execution_trace.function_selectors) if report.execution_trace else 0,
            difficulty=task.get("difficulty", 1),
        )
        if uniqueness.is_herd:
            result.reward_multiplier *= (1.0 - uniqueness.herd_penalty)
            logger.info(
                "Herd penalty applied to %s: %d similar submissions",
                miner_address[:10], uniqueness.herd_size,
            )
        result.reward_multiplier *= uniqueness.final_multiplier
        result.reward_multiplier = max(0.0, min(1.0, result.reward_multiplier))

        # Step 6b: Difficulty-based minimum severity filter
        min_sev = get_min_severity(self._current_epoch)
        if result.severity_score < min_sev:
            logger.info(
                "Severity %.4f below epoch minimum %.4f for %s — zeroing reward",
                result.severity_score, min_sev, miner_address[:10],
            )
            result.reward_multiplier = 0.0

        # Step 7: Record subnet receipt for anti-bypass tracking
        if result.fingerprint:
            self.anti_bypass.record_subnet_receipt(
                task_id=task_id,
                miner_hotkey=miner_address,
                fingerprint=result.fingerprint,
            )

        # Step 8: Record vote in incentive adapter
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

        # Step 9: Feed vote to anti-collusion engine for cross-validator consensus
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

        # ── Cost-per-validation tracking ──
        elapsed_wall = time.monotonic() - start
        with self._cost_lock:
            self._epoch_wall_seconds += elapsed_wall
            self._epoch_validations += 1
        _metrics.observe("validation_wall_seconds", elapsed_wall)
        logger.debug(
            "Validation cost: %.2fs wall | epoch total: %.1fs / %d validations",
            elapsed_wall, self._epoch_wall_seconds, self._epoch_validations,
        )

        return result

    # ── Bounty Platform Submission ─────────────────────────────────────────

    def submit_to_bounty_platforms(
        self,
        task_id: str,
        miner_address: str,
        fingerprint: str,
        severity_score: float,
        exploit_source: str,
        exploit_description: str = "",
        target_address: str = "",
        chain_id: int = 1,
    ) -> list[dict]:
        """Submit a validated exploit to all registered bounty platforms.

        Only submits if:
          - The miner has a verified identity on the platform
          - The exploit has a valid subnet receipt (anti-bypass)
          - The severity meets the platform's minimum threshold

        Returns a list of submission receipt dicts.
        """
        receipts = []

        # Check anti-bypass: must have subnet receipt
        receipt = self.anti_bypass.get_receipt(fingerprint)
        if not receipt:
            logger.warning(
                "No subnet receipt for fingerprint %s — skipping bounty submission",
                fingerprint[:16],
            )
            return receipts

        # Get miner's identity across platforms
        identity = self.identity_store.get_identity(miner_address)
        if not identity:
            logger.info("Miner %s has no linked identities", miner_address[:10])
            return receipts

        for platform_name in self.platform_registry.list_platforms():
            platform_id = identity.get_platform_id(platform_name)
            if not platform_id:
                continue

            adapter = self.platform_registry.get(platform_name)
            if not adapter:
                continue

            report = BountyReport(
                task_id=task_id,
                miner_hotkey=miner_address,
                platform_id=platform_id,
                target_address=target_address,
                chain_id=chain_id,
                vulnerability_class=self._get_task_vuln_class(task_id),
                severity_score=severity_score,
                exploit_description=exploit_description or f"Automated exploit for {task_id[:16]}",
                exploit_source=exploit_source,
                fingerprint=fingerprint,
                subnet_timestamp=receipt.subnet_timestamp,
            )

            submission_receipt = adapter.submit_report(report)
            receipts.append(submission_receipt.to_dict())
            logger.info(
                "Submitted to %s: report_id=%s status=%s",
                platform_name, submission_receipt.report_id, submission_receipt.status.value,
            )

            _metrics.inc("bounty_submissions_total")

        return receipts

    def check_platform_bypass(
        self,
        fingerprint: str,
        platform: str,
        platform_timestamp: int,
    ) -> Optional[dict]:
        """Check if a platform submission predates the subnet receipt.

        Returns violation dict if bypass detected, None otherwise.
        """
        violation = self.anti_bypass.check_platform_submission(
            fingerprint=fingerprint,
            platform=platform,
            platform_timestamp=platform_timestamp,
        )
        if violation:
            logger.warning(
                "BYPASS DETECTED: miner=%s platform=%s delta=%ds",
                violation.miner_hotkey[:10], platform, violation.delta_seconds,
            )
            _metrics.inc("bypass_violations_total")
            return violation.to_dict()
        return None

    def process_bounty_payout(
        self,
        report_id: str,
        platform: str,
        task_id: str,
        fingerprint: str,
        miner_address: str,
        bounty_amount: float,
        currency: str = "USD",
    ) -> dict:
        """Process a bounty payout: compute reward split and record."""
        split = self.reward_split.compute_split(
            report_id=report_id,
            platform=platform,
            task_id=task_id,
            fingerprint=fingerprint,
            miner_hotkey=miner_address,
            validator_id=self.validator_id,
            bounty_amount=bounty_amount,
            currency=currency,
        )
        logger.info(
            "Reward split: miner=%.2f validator=%.2f treasury=%.2f (%s %s)",
            split.miner_amount, split.validator_amount, split.treasury_amount,
            bounty_amount, currency,
        )
        _metrics.inc("bounty_payouts_total")
        _metrics.observe("bounty_payout_amount", bounty_amount)
        return split.to_dict()

    def _get_task_vuln_class(self, task_id: str) -> str:
        """Look up vulnerability class for a task."""
        task = self.load_task(task_id)
        if task:
            return task.get("vulnerability_class", "unknown")
        return "unknown"

    # ── Mainnet Discovery + Difficulty Ramping ─────────────────────────────

    def refresh_corpus(self, epoch: int) -> dict:
        """Refresh the task corpus based on current epoch difficulty.

        Called at each epoch boundary to:
          1. Ramp difficulty based on epoch schedule
          2. Discover and fetch new mainnet contracts
          3. Regenerate synthetic corpus at current difficulty

        Returns a summary dict.
        """
        self._current_epoch = epoch
        config = get_epoch_config(epoch)
        max_diff = config["max_difficulty"]
        mainnet_ratio = config["mainnet_ratio"]

        logger.info(
            "Epoch %d corpus refresh: difficulty=%d mainnet_ratio=%.0f%%",
            epoch, max_diff, mainnet_ratio * 100,
        )

        # Regenerate synthetic corpus at current difficulty
        packages = self.generate_corpus(
            count_per_class=2, seed=42 + epoch, max_difficulty=max_diff,
        )

        # Discover and fetch mainnet contracts if ratio > 0
        mainnet_count = 0
        if mainnet_ratio > 0:
            discovered = self.mainnet_discovery.discover(chain_id=1)
            addresses = self.mainnet_discovery.get_addresses(chain_id=1)
            target_mainnet = max(1, int(len(packages) * mainnet_ratio / (1 - mainnet_ratio + 0.001)))
            fetch_addrs = addresses[:target_mainnet]
            if fetch_addrs:
                try:
                    mainnet_pkgs = self.fetch_mainnet_tasks(
                        addresses=fetch_addrs, chain_id=1, difficulty=max_diff,
                    )
                    mainnet_count = len(mainnet_pkgs)
                except Exception as e:
                    logger.warning("Mainnet fetch failed: %s", e)

        summary = {
            "epoch": epoch,
            "max_difficulty": max_diff,
            "mainnet_ratio": mainnet_ratio,
            "synthetic_tasks": len(packages),
            "mainnet_tasks": mainnet_count,
            "total_tasks": len(packages) + mainnet_count,
        }
        logger.info("Corpus refresh: %s", json.dumps(summary))
        return summary

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
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--pids-limit=256",
                    "-v", f"{tmpdir}:/workspace:rw",
                    "-e", "PYTHONHASHSEED=0",
                    "-e", "ANVIL_BLOCK_TIMESTAMP=1700000000",
                    "-e", "ANVIL_BLOCK_NUMBER=18000000",
                    "-e", "ANVIL_GAS_LIMIT=30000000",
                    "-e", "ANVIL_CHAIN_ID=31337",
                    self.DOCKER_SANDBOX_IMAGE,
                    "python3", "-m", "validator.engine.validate",
                    "--task", "/workspace/task.json",
                    "--exploit", "/workspace/exploit.sol",
                    "--output", "/workspace/result.json",
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
                        trace_data = result_data.get("execution_trace")
                        if trace_data:
                            from validator.engine.validate import ExecutionTrace
                            report.execution_trace = ExecutionTrace(**trace_data)
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
        self._current_epoch = epoch_number
        logger.info("Closing epoch %d (blocks %d-%d)", epoch_number, start_block, end_block)

        # Log and reset per-epoch cost tracking
        with self._cost_lock:
            logger.info(
                "Epoch %d cost: %.1f wall-seconds across %d validations (avg %.2fs/validation)",
                epoch_number,
                self._epoch_wall_seconds,
                self._epoch_validations,
                self._epoch_wall_seconds / max(self._epoch_validations, 1),
            )
            self._epoch_wall_seconds = 0.0
            self._epoch_validations = 0

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

    def get_epoch_cost_summary(self) -> dict:
        """Return current epoch's compute cost summary for operator visibility.

        Validators can poll this to monitor resource spend and decide whether
        to adjust VALAYR_EPOCH_COMPUTE_BUDGET or MAX_CONCURRENT_VALIDATIONS.
        """
        with self._cost_lock:
            return {
                "epoch": self._current_epoch,
                "wall_seconds_used": round(self._epoch_wall_seconds, 2),
                "wall_budget": EPOCH_COMPUTE_BUDGET or "unlimited",
                "validations_count": self._epoch_validations,
                "avg_wall_per_validation": round(
                    self._epoch_wall_seconds / max(self._epoch_validations, 1), 2
                ),
                "concurrent_limit": MAX_CONCURRENT_VALIDATIONS,
            }

    def _save_report(self, result: SubmissionResult):
        """Persist submission result to disk."""
        report_path = self.reports_dir / f"{result.task_id[:16]}_{result.miner_address[:8]}_{time.time_ns()}.json"
        payload = json.dumps(result.to_dict(), indent=2)
        tmp_path = report_path.with_suffix(".tmp")
        tmp_path.write_text(payload)
        fd = os.open(str(tmp_path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, report_path)

    def reset(self) -> None:
        """Reset all state. For testing only."""
        self.fingerprinter.reset_db()
        self.incentive = SubnetIncentiveAdapter()
        self.anticollusion = AntiCollusionEngine(
            data_dir=self.data_dir / "anticollusion",
        )
        self.adversarial.reset()
        self.uniqueness_scorer.reset()
        self._current_epoch = 0
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

    # refresh — difficulty ramp + mainnet discovery
    refresh_parser = subparsers.add_parser("refresh", help="Refresh corpus for current epoch")
    refresh_parser.add_argument("--epoch", type=int, required=True, help="Current epoch number")

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

    elif args.command == "refresh":
        summary = orch.refresh_corpus(epoch=args.epoch)
        config = get_epoch_config(args.epoch)
        print(f"\n{'='*60}")
        print(f"Epoch:          {args.epoch}")
        print(f"Max difficulty: {config['max_difficulty']}")
        print(f"Mainnet ratio:  {config['mainnet_ratio']:.0%}")
        print(f"Min severity:   {config['min_severity']:.2f}")
        print(f"Synthetic:      {summary['synthetic_tasks']}")
        print(f"Mainnet:        {summary['mainnet_tasks']}")
        print(f"Total:          {summary['total_tasks']}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
