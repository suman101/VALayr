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

from validator.utils.logging import get_logger

logger = get_logger(__name__)


# ── Constants ────────────────────────────────────────────────────────────────

FULL_REWARD_MULTIPLIER = 1.0
DUPLICATE_REWARD_MULTIPLIER = 0.10
ZERO_REWARD_MULTIPLIER = 0.0

# Maximum number of tasks to keep in the fingerprint database.  Oldest tasks
# (by earliest fingerprint timestamp) are evicted when this limit is exceeded.
# Prevents unbounded memory growth (DoS vector) while retaining enough history
# for deduplication of recent work.
MAX_FINGERPRINT_TASKS = 5_000

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
    # Multi-tx: ordered list of test function names
    test_function_order: list[str] = field(default_factory=list)
    # Multi-tx: per-function selector groups (preserving execution order)
    per_function_selectors: dict[str, list[str]] = field(default_factory=dict)

    def canonical_string(self) -> str:
        """Produce deterministic canonical string for hashing.

        For multi-tx exploits, the fingerprint encodes the *sequence* of
        per-function selector sets so that two exploits calling the same
        functions in a different order produce different fingerprints.
        """
        parts = []

        # 1. Function selectors — sequence-aware for multi-tx
        if self.per_function_selectors and self.test_function_order:
            # Hash per-function selector sets in execution order
            seq_parts = []
            for fn_name in self.test_function_order:
                fn_sels = sorted(set(self.per_function_selectors.get(fn_name, [])))
                seq_parts.append(f"{fn_name}={','.join(fn_sels)}")
            parts.append("selector_sequence:" + "|".join(seq_parts))
        elif self.per_function_selectors:
            # F-1 fix: per_function_selectors present but test_function_order
            # is empty. Use sorted function names to produce a deterministic
            # (though order-unaware) fingerprint instead of falling through
            # to the flat selector hash that loses multi-TX information.
            seq_parts = []
            for fn_name in sorted(self.per_function_selectors.keys()):
                fn_sels = sorted(set(self.per_function_selectors.get(fn_name, [])))
                seq_parts.append(f"{fn_name}={','.join(fn_sels)}")
            parts.append("selector_sequence_unordered:" + "|".join(seq_parts))
        else:
            # Single-tx fallback: sorted flat selectors
            parts.append("selectors:" + ",".join(sorted(self.function_selectors)))

        # 2. Storage diffs (sorted by slot index numerically)
        sorted_diffs = sorted(
            self.storage_slot_diffs,
            key=lambda d: int(d.get("slot", "0x0"), 16) if d.get("slot", "0x0").startswith("0x") else 0,
        )
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


def _normalize_slot(slot: str) -> str:
    """Normalize a hex storage slot to canonical lowercase form.

    '0x0000...01' → '0x1', '0X0a' → '0xa', non-hex values pass through.
    """
    if not isinstance(slot, str) or not slot.startswith(("0x", "0X")):
        return slot
    try:
        return hex(int(slot, 16))
    except (ValueError, OverflowError):
        return slot


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

        # Multi-tx: per-function selector groups and execution order
        fc.per_function_selectors = execution_trace.get("per_function_selectors", {})
        fc.test_function_order = execution_trace.get("test_function_order", [])

        # Storage diffs — normalize slot values to canonical hex form
        raw_diffs = execution_trace.get("storage_diffs", [])
        for diff in raw_diffs:
            raw_slot = diff.get("slot", "0x0")
            norm_slot = _normalize_slot(raw_slot)
            fc.storage_slot_diffs.append({
                "slot": norm_slot,
                "before": diff.get("before", "0x" + "0" * 64),
                "after": diff.get("after", "0x" + "0" * 64),
            })

        # Balance delta
        fc.balance_delta = execution_trace.get("balance_delta", 0)

        # Ownership change detection (use normalized slots)
        for diff in raw_diffs:
            slot = _normalize_slot(diff.get("slot", ""))
            if slot in OWNER_SLOTS or slot == EIP1967_ADMIN_SLOT:
                fc.ownership_changed = True

        # Proxy admin mutation (use normalized slots)
        for diff in raw_diffs:
            slot = _normalize_slot(diff.get("slot", ""))
            if slot == EIP1967_ADMIN_SLOT:
                fc.proxy_admin_mutated = True
            if slot == EIP1967_IMPL_SLOT:
                fc.proxy_admin_mutated = True

        # Call graph hash — sequence-aware for multi-tx
        call_trace = execution_trace.get("call_trace", [])
        if call_trace:
            graph_str = json.dumps(call_trace, sort_keys=True, separators=(",", ":"))
            from validator.utils.hashing import keccak256
            fc.call_graph_hash = keccak256(graph_str.encode())[2:34]
        elif fc.per_function_selectors and fc.test_function_order:
            # Multi-tx: hash the ordered per-function selector chains
            from validator.utils.hashing import keccak256
            chain_parts = []
            for fn_name in fc.test_function_order:
                fn_sels = fc.per_function_selectors.get(fn_name, [])
                chain_parts.append(f"{fn_name}:{'->'.join(fn_sels)}")
            fc.call_graph_hash = keccak256(
                "|".join(chain_parts).encode()
            )[2:34]
        elif fc.function_selectors:
            # F-2 fix: incorporate storage diff slots into the fallback hash
            # to reduce collisions when call_trace is missing.
            from validator.utils.hashing import keccak256
            diff_slots = [d.get("slot", "") for d in fc.storage_slot_diffs]
            fallback_data = "->".join(fc.function_selectors) + "||" + ",".join(diff_slots)
            fc.call_graph_hash = keccak256(fallback_data.encode())[2:34]
        else:
            from validator.utils.hashing import keccak256
            fc.call_graph_hash = keccak256(b"empty")[2:34]

        return fc

    def check_duplicate(self, task_id: str, fingerprint: str,
                        miner_address: str,
                        uniqueness_score: float | None = None) -> DedupResult:
        """
        Check if a fingerprint already exists for this task.

        Returns DedupResult with reward multiplier.
        Rules are deterministic and published:
          - First: 100% reward
          - Subsequent: 10% reward

        If *uniqueness_score* is provided and the fingerprint is a duplicate
        yet the uniqueness score is high (>0.7), a warning is logged since
        this indicates a contradiction between dedup and the uniqueness scorer
        (F-3 fix).
        """
        with self._lock:
            task_db = self._db.get(task_id, {})

            if fingerprint in task_db:
                record = task_db[fingerprint]
                record.submission_count += 1
                self._save_db_unlocked()

                # F-3 fix: flag contradiction between dedup and uniqueness
                if uniqueness_score is not None and uniqueness_score > 0.7:
                    logger.warning(
                        "Dedup/uniqueness contradiction: fingerprint %s is duplicate "
                        "but uniqueness_score=%.2f (task=%s, miner=%s)",
                        fingerprint[:16], uniqueness_score, task_id, miner_address,
                    )

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
            self._save_db_unlocked()

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
        """Load fingerprint database from disk with shared (read) lock.

        .. warning:: F-4: The JSON file DB is adequate for early-stage
           operation but will not scale to thousands of tasks/fingerprints.
           Plan migration to SQLite or a KV store before mainnet launch.
        """
        if not self.db_path.exists():
            return
        lock_path = self.db_path.with_suffix(".lock")
        try:
            # SEC-3.3: hold the file lock for the entire read so a concurrent
            # writer cannot modify the file between our read and a subsequent
            # write (TOCTOU race prevention).
            with open(lock_path, "w") as lf:
                if fcntl:
                    fcntl.flock(lf, fcntl.LOCK_SH)
                try:
                    with open(self.db_path, "r") as f:
                        raw = json.load(f)
                finally:
                    if fcntl:
                        fcntl.flock(lf, fcntl.LOCK_UN)
            if not isinstance(raw, dict):
                self._db = {}
                return
            for task_id, fps in raw.items():
                self._db[task_id] = {}
                for fp, rec in fps.items():
                    self._db[task_id][fp] = FingerprintRecord(**rec)
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            logger.warning("Failed to load fingerprint DB from %s: %s — starting empty", self.db_path, exc)
            self._db = {}

        # SEC-3.2: verify data directory permissions on startup.
        # Ensure the parent directory is not world-readable, since the
        # fingerprint DB may contain competitive intelligence.
        db_parent = self.db_path.parent
        try:
            import stat
            st = db_parent.stat()
            if st.st_mode & (stat.S_IROTH | stat.S_IWOTH):
                logger.warning(
                    "Fingerprint DB directory %s is world-accessible "
                    "(mode %o) — consider restricting to 0700",
                    db_parent, stat.S_IMODE(st.st_mode),
                )
        except OSError:
            pass

    def _save_db(self):
        """Persist fingerprint database (acquires _lock first)."""
        with self._lock:
            self._save_db_unlocked()

    def _save_db_unlocked(self):
        """Persist fingerprint database with atomic write + exclusive lock.

        Writes to a temporary file in the same directory, then renames.
        This prevents partial-write corruption if the process crashes mid-write.
        ``fcntl.LOCK_EX`` serialises concurrent validators on the same machine.

        IMPORTANT: Caller must already hold ``self._lock`` or guarantee
        single-threaded access.
        """
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.db_path.with_suffix(".lock")

        # Evict oldest tasks when DB exceeds capacity to prevent unbounded
        # memory growth.  "Oldest" = earliest first_seen_at across all
        # fingerprints in a task.
        if len(self._db) > MAX_FINGERPRINT_TASKS:
            task_ages = {
                tid: min(
                    (r.first_seen_at for r in fps.values()),
                    default=0,
                )
                for tid, fps in self._db.items()
            }
            sorted_tasks = sorted(task_ages, key=task_ages.get)  # type: ignore[arg-type]
            evict_count = len(self._db) - MAX_FINGERPRINT_TASKS
            for tid in sorted_tasks[:evict_count]:
                del self._db[tid]

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
                        tmp.flush()
                        os.fsync(tmp.fileno())
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
                self._save_db_unlocked()

            return pruned
