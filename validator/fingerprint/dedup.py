"""
Fingerprint & Deduplication Engine.

Deduplication is by STATE IMPACT, not vulnerability class.
That's the only objective criterion.

Fingerprint = keccak(
    function_selectors,
    sorted_storage_slot_diffs,
    balance_delta,
    call_graph_hash
)

Rules (deterministic, published before launch):
  - First valid submission for a fingerprint: FULL_REWARD (100%)
  - Subsequent valid submissions with same fingerprint: DUPLICATE_REWARD (10%)
  - Zero reward for invalid submissions

Ambiguity creates governance wars. This engine has none.
"""

import hashlib
import threading
try:
    import fcntl
except ImportError:
    fcntl = None  # Windows fallback — file locking disabled
import json
import os
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── Constants ────────────────────────────────────────────────────────────────

FULL_REWARD_MULTIPLIER = 1.0
DUPLICATE_REWARD_MULTIPLIER = 0.10
ZERO_REWARD_MULTIPLIER = 0.0

# Storage path for fingerprint DB (production: use a proper DB)
FINGERPRINT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "fingerprints.json"


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class FingerprintComponents:
    """Raw components used to compute the fingerprint."""
    function_selectors: list[str] = field(default_factory=list)
    storage_slot_diffs: list[dict] = field(default_factory=list)  # [{slot, before, after}]
    balance_delta: int = 0
    ownership_changed: bool = False
    proxy_admin_mutated: bool = False
    call_graph_hash: str = ""

    def canonical_string(self) -> str:
        """Produce deterministic canonical string for hashing."""
        parts = []

        # 1. Function selectors (sorted)
        parts.append("selectors:" + ",".join(sorted(self.function_selectors)))

        # 2. Storage diffs (sorted by slot index)
        sorted_diffs = sorted(self.storage_slot_diffs, key=lambda d: d.get("slot", ""))
        diff_strs = []
        for d in sorted_diffs:
            diff_strs.append(f"{d['slot']}:{d.get('before','0x0')}->{d.get('after','0x0')}")
        parts.append("storage:" + "|".join(diff_strs))

        # 3. Balance delta
        parts.append(f"balance_delta:{self.balance_delta}")

        # 4. Ownership change flag
        parts.append(f"ownership_changed:{int(self.ownership_changed)}")

        # 5. Proxy admin mutation flag
        parts.append(f"proxy_admin_mutated:{int(self.proxy_admin_mutated)}")

        # 6. Call graph hash
        parts.append(f"call_graph:{self.call_graph_hash}")

        return "::".join(parts)


@dataclass
class FingerprintRecord:
    """Stored record of a fingerprint."""
    fingerprint: str
    task_id: str
    miner_address: str
    first_seen_at: float  # Unix timestamp
    components: dict = field(default_factory=dict)
    submission_count: int = 1


@dataclass
class DedupResult:
    """Result of deduplication check."""
    fingerprint: str
    is_duplicate: bool
    reward_multiplier: float
    first_submission_miner: str = ""
    first_submission_time: float = 0.0
    submission_number: int = 1


# ── Well-Known Storage Slots ─────────────────────────────────────────────────

# ERC-1967 Implementation slot
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# ERC-1967 Admin slot
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# OpenZeppelin Ownable owner slot (typically slot 0 in simple contracts)
OWNER_SLOTS = {"0x0", "0x00"}


# ── Fingerprint Engine ───────────────────────────────────────────────────────

class FingerprintEngine:
    """
    Computes canonical fingerprints and manages deduplication state.
    """

    def __init__(self, db_path: Path = FINGERPRINT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._db: dict[str, dict[str, FingerprintRecord]] = {}  # task_id -> fingerprint -> record
        self._load_db()

    # ── Public API ────────────────────────────────────────────────────────

    def compute_fingerprint(self, components: FingerprintComponents) -> str:
        """Compute canonical fingerprint hash from components."""
        from validator.utils.hashing import keccak256
        canonical = components.canonical_string()
        return keccak256(canonical.encode())

    def extract_components(self, execution_trace: dict) -> FingerprintComponents:
        """Extract fingerprint components from an execution trace dict."""
        fc = FingerprintComponents()

        # Function selectors
        fc.function_selectors = execution_trace.get("function_selectors", [])

        # Storage diffs
        raw_diffs = execution_trace.get("storage_diffs", [])
        for diff in raw_diffs:
            fc.storage_slot_diffs.append({
                "slot": diff.get("slot", "0x0"),
                "before": diff.get("before", "0x" + "0" * 64),
                "after": diff.get("after", "0x" + "0" * 64),
            })

        # Balance delta
        fc.balance_delta = execution_trace.get("balance_delta", 0)

        # Ownership change detection
        for diff in raw_diffs:
            slot = diff.get("slot", "")
            if slot in OWNER_SLOTS or slot == EIP1967_ADMIN_SLOT:
                fc.ownership_changed = True

        # Proxy admin mutation
        for diff in raw_diffs:
            if diff.get("slot", "") == EIP1967_ADMIN_SLOT:
                fc.proxy_admin_mutated = True
            if diff.get("slot", "") == EIP1967_IMPL_SLOT:
                fc.proxy_admin_mutated = True

        # Call graph hash
        call_trace = execution_trace.get("call_trace", [])
        if call_trace:
            graph_str = json.dumps(call_trace, sort_keys=True, separators=(",", ":"))
            from validator.utils.hashing import keccak256
            fc.call_graph_hash = keccak256(graph_str.encode())[2:34]  # 16 hex chars
        else:
            from validator.utils.hashing import keccak256
            fc.call_graph_hash = keccak256(
                "->".join(fc.function_selectors).encode()
            )[2:34]  # 16 hex chars

        return fc

    def check_duplicate(self, task_id: str, fingerprint: str,
                        miner_address: str) -> DedupResult:
        """
        Check if a fingerprint already exists for this task.

        Returns DedupResult with reward multiplier.
        Rules are deterministic and published:
          - First: 100% reward
          - Subsequent: 10% reward
        """
        with self._lock:
            task_db = self._db.get(task_id, {})

            if fingerprint in task_db:
                record = task_db[fingerprint]
                record.submission_count += 1
                self._save_db()

                return DedupResult(
                    fingerprint=fingerprint,
                    is_duplicate=True,
                    reward_multiplier=DUPLICATE_REWARD_MULTIPLIER,
                    first_submission_miner=record.miner_address,
                    first_submission_time=record.first_seen_at,
                    submission_number=record.submission_count,
                )

            # First submission
            record = FingerprintRecord(
                fingerprint=fingerprint,
                task_id=task_id,
                miner_address=miner_address,
                first_seen_at=time.time(),
            )

            if task_id not in self._db:
                self._db[task_id] = {}
            self._db[task_id][fingerprint] = record
            self._save_db()

            return DedupResult(
                fingerprint=fingerprint,
                is_duplicate=False,
                reward_multiplier=FULL_REWARD_MULTIPLIER,
                first_submission_miner=miner_address,
                first_submission_time=record.first_seen_at,
                submission_number=1,
        )

    def get_task_fingerprints(self, task_id: str) -> list[str]:
        """List all unique fingerprints for a task."""
        with self._lock:
            return list(self._db.get(task_id, {}).keys())

    def get_fingerprint_count(self, task_id: str) -> int:
        """Count unique fingerprints for a task."""
        with self._lock:
            return len(self._db.get(task_id, {}))

    # ── Persistence (concurrency-safe) ──────────────────────────────────

    def _load_db(self):
        """Load fingerprint database from disk with shared (read) lock."""
        if not self.db_path.exists():
            return
        lock_path = self.db_path.with_suffix(".lock")
        try:
            with open(lock_path, "w") as lf:
                if fcntl:
                    fcntl.flock(lf, fcntl.LOCK_SH)
                try:
                    with open(self.db_path, "r") as f:
                        raw = json.load(f)
                finally:
                    if fcntl:
                        fcntl.flock(lf, fcntl.LOCK_UN)
            for task_id, fps in raw.items():
                self._db[task_id] = {}
                for fp, rec in fps.items():
                    self._db[task_id][fp] = FingerprintRecord(**rec)
        except (json.JSONDecodeError, TypeError, OSError):
            self._db = {}

    def _save_db(self):
        """Persist fingerprint database with atomic write + exclusive lock.

        Writes to a temporary file in the same directory, then renames.
        This prevents partial-write corruption if the process crashes mid-write.
        ``fcntl.LOCK_EX`` serialises concurrent validators on the same machine.
        """
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.db_path.with_suffix(".lock")

        serialized = {}
        for task_id, fps in self._db.items():
            serialized[task_id] = {}
            for fp, rec in fps.items():
                serialized[task_id][fp] = asdict(rec)

        data = json.dumps(serialized, indent=2, sort_keys=True)

        # Exclusive lock → write to temp → atomic rename
        with open(lock_path, "w") as lf:
            if fcntl:
                fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                fd, tmp_path = tempfile.mkstemp(
                    dir=str(self.db_path.parent),
                    suffix=".tmp",
                )
                try:
                    with os.fdopen(fd, "w") as tmp:
                        tmp.write(data)
                    # Atomic rename (POSIX guarantees atomicity on same filesystem)
                    os.replace(tmp_path, str(self.db_path))
                except BaseException:
                    # Clean up temp file on any error
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise
            finally:
                if fcntl:
                    fcntl.flock(lf, fcntl.LOCK_UN)
        # Remove lock file after successful write
        try:
            os.unlink(str(lock_path))
        except OSError:
            pass

    def reset_db(self):
        """Clear all stored fingerprints. For testing only."""
        with self._lock:
            self._db = {}
            if self.db_path.exists():
                self.db_path.unlink()

    def prune(self, max_age_seconds: float = 30 * 24 * 3600) -> int:
        """Remove fingerprint records older than *max_age_seconds*.

        Returns the number of pruned records.  Default retention is 30 days.
        This prevents the JSON DB from growing unboundedly.
        """
        with self._lock:
            cutoff = time.time() - max_age_seconds
            pruned = 0
            empty_tasks: list[str] = []

            for task_id, fps in self._db.items():
                stale_keys = [
                    fp for fp, rec in fps.items()
                    if rec.first_seen_at < cutoff
                ]
                for fp in stale_keys:
                    del fps[fp]
                    pruned += 1
                if not fps:
                    empty_tasks.append(task_id)

            for task_id in empty_tasks:
                del self._db[task_id]

            if pruned:
                self._save_db()

            return pruned
