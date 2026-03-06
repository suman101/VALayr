"""
Anti-LLM Uniqueness Scoring — Penalise templated, one-shot exploit patterns.

Strategies:
  1. **Structural similarity** — Compare AST-level structure of submissions
     across miners.  If N miners produce near-identical exploit structure
     for the same task, apply a "herd penalty".
  2. **Timing analysis** — Exploits submitted within seconds of task
     publication likely used automated LLM pipelines.  Apply a cooldown
     bonus: later submissions that are unique get a small boost.
  3. **Complexity floor** — Require minimum exploit complexity (gas usage,
     number of distinct function calls) that scales with difficulty level.

These don't block LLM usage (that's futile) — they make *unique* solutions
more valuable than copy-paste LLM output.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Optional


# ── Constants ────────────────────────────────────────────────────────────────

# Herd penalty: if >N miners submit structurally identical exploits, penalise
HERD_THRESHOLD = 3       # Number of similar submissions before penalty kicks in
HERD_PENALTY = 0.50      # 50% penalty for herd submissions
HERD_SIMILARITY = 0.85   # Jaccard similarity threshold for "same structure"

# Timing: submissions within this window of task publication get no bonus
SPEED_COOLDOWN_SECONDS = 120  # 2 minutes
TIMING_BONUS_MAX = 0.10       # Up to 10% bonus for non-rushed unique submissions

# Complexity floor per difficulty level
MIN_GAS_BY_DIFFICULTY = {
    1: 30_000,
    2: 80_000,
    3: 150_000,
}
MIN_SELECTORS_BY_DIFFICULTY = {
    1: 1,
    2: 2,
    3: 3,
}


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class StructuralProfile:
    """Normalised structural representation of an exploit."""
    function_count: int = 0
    selector_count: int = 0
    has_loop: bool = False
    has_assembly: bool = False
    call_count: int = 0
    state_write_count: int = 0
    structural_hash: str = ""     # Hash of normalised structure


@dataclass
class UniquenessResult:
    """Result of uniqueness analysis for a submission."""
    structural_hash: str
    is_herd: bool = False
    herd_size: int = 0
    herd_penalty: float = 0.0
    timing_bonus: float = 0.0
    complexity_pass: bool = True
    complexity_detail: str = ""
    final_multiplier: float = 1.0  # Applied to reward


# ── Uniqueness Scorer ────────────────────────────────────────────────────────

class UniquenessScorer:
    """Tracks and scores submission uniqueness per task."""

    def __init__(self):
        # task_id → list of (structural_hash, miner, timestamp)
        self._submissions: dict[str, list[tuple[str, str, float]]] = {}
        # task_id → publication timestamp
        self._task_timestamps: dict[str, float] = {}

    def register_task(self, task_id: str, published_at: Optional[float] = None) -> None:
        """Record when a task was published (for timing analysis)."""
        self._task_timestamps[task_id] = published_at or time.time()

    def score_submission(
        self,
        task_id: str,
        exploit_source: str,
        miner_address: str,
        gas_used: int = 0,
        selector_count: int = 0,
        difficulty: int = 1,
    ) -> UniquenessResult:
        """Score a submission's uniqueness.

        Call this AFTER validation succeeds but BEFORE final reward computation.
        """
        profile = self._compute_profile(exploit_source)
        result = UniquenessResult(structural_hash=profile.structural_hash)

        # Register this submission
        now = time.time()
        if task_id not in self._submissions:
            self._submissions[task_id] = []
        self._submissions[task_id].append(
            (profile.structural_hash, miner_address, now)
        )

        # 1. Herd detection
        same_structure = [
            s for s in self._submissions[task_id]
            if s[0] == profile.structural_hash and s[1] != miner_address
        ]
        result.herd_size = len(same_structure) + 1  # Including this submission

        if result.herd_size > HERD_THRESHOLD:
            result.is_herd = True
            result.herd_penalty = HERD_PENALTY

        # 2. Timing analysis
        pub_time = self._task_timestamps.get(task_id, 0)
        if pub_time > 0:
            elapsed = now - pub_time
            if elapsed > SPEED_COOLDOWN_SECONDS and not result.is_herd:
                # Bonus for non-rushed, unique submissions (up to TIMING_BONUS_MAX)
                bonus_factor = min(elapsed / 600.0, 1.0)  # Full bonus at 10 min
                result.timing_bonus = TIMING_BONUS_MAX * bonus_factor

        # 3. Complexity floor
        min_gas = MIN_GAS_BY_DIFFICULTY.get(difficulty, 30_000)
        min_sels = MIN_SELECTORS_BY_DIFFICULTY.get(difficulty, 1)

        if gas_used > 0 and gas_used < min_gas:
            result.complexity_pass = False
            result.complexity_detail = (
                f"gas_used={gas_used} < min={min_gas} for difficulty={difficulty}"
            )
        if selector_count > 0 and selector_count < min_sels:
            result.complexity_pass = False
            result.complexity_detail = (
                f"selectors={selector_count} < min={min_sels} for difficulty={difficulty}"
            )

        # Compute final multiplier
        multiplier = 1.0
        if result.is_herd:
            multiplier -= result.herd_penalty
        multiplier += result.timing_bonus
        if not result.complexity_pass:
            # S-8 fix: reject below-complexity exploits entirely instead of
            # giving them 50% reward. Trivial exploits should not earn.
            multiplier = 0.0
        result.final_multiplier = max(0.0, min(1.5, multiplier))

        return result

    @staticmethod
    def _compute_profile(source: str) -> StructuralProfile:
        """Compute normalised structural profile of exploit source.

        Strips variable names, literals, and comments — keeps only
        the structural skeleton (function count, control flow, call patterns).
        """
        profile = StructuralProfile()

        # Strip comments
        source_clean = re.sub(r'//[^\n]*', '', source)
        source_clean = re.sub(r'/\*.*?\*/', '', source_clean, flags=re.DOTALL)

        # Count functions
        functions = re.findall(r'function\s+\w+\s*\(', source_clean)
        profile.function_count = len(functions)

        # Count external calls (.call, .transfer, .send)
        calls = re.findall(r'\.(call|transfer|send|delegatecall)\s*[\({]', source_clean)
        profile.call_count = len(calls)

        # Count state writes (=, +=, -=, but not == or !=)
        writes = re.findall(r'[^!=<>]\s*[+\-*]?=\s*[^=]', source_clean)
        profile.state_write_count = len(writes)

        # Detect loops
        profile.has_loop = bool(re.search(r'\b(for|while)\s*\(', source_clean))

        # Detect assembly
        profile.has_assembly = bool(re.search(r'\bassembly\s*\{', source_clean))

        # Count unique selectors (function calls with 4-byte signatures)
        selectors = re.findall(r'\b\w+\s*\(', source_clean)
        profile.selector_count = len(set(selectors))

        # Structural hash: normalise away variable names but KEEP function
        # names and Solidity keywords. S-5 fix: the prior approach of
        # replacing ALL identifiers with 'ID' collapsed semantically
        # different exploits (reentrancy vs overflow) into the same hash.
        normalised = re.sub(r'\b0x[0-9a-fA-F]+\b', 'HEX', source_clean)
        normalised = re.sub(r'\b\d+\b', 'NUM', normalised)
        # Preserve function names, Solidity keywords, and type names
        keywords = {
            'function', 'contract', 'import', 'pragma', 'if', 'else', 'for',
            'while', 'return', 'require', 'assert', 'revert', 'emit', 'event',
            'mapping', 'struct', 'modifier', 'constructor', 'public', 'private',
            'internal', 'external', 'view', 'pure', 'payable', 'memory',
            'storage', 'calldata', 'address', 'uint256', 'int256', 'bool',
            'bytes', 'bytes32', 'string', 'call', 'transfer', 'send',
            'delegatecall', 'assembly', 'sstore', 'sload', 'selfdestruct',
        }
        def _replace_id(m):
            word = m.group(0)
            if word in keywords or word.startswith('test_'):
                return word
            return 'ID'
        normalised = re.sub(r'\b[a-zA-Z_]\w*\b', _replace_id, normalised)
        normalised = re.sub(r'\s+', ' ', normalised).strip()

        profile.structural_hash = hashlib.sha256(normalised.encode()).hexdigest()[:16]

        return profile

    def reset(self) -> None:
        """Clear all state. For testing."""
        self._submissions.clear()
        self._task_timestamps.clear()
