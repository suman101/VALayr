"""
Validator Anti-Collusion Engine.

This is where most subnets rot.

Mechanics:
  - Random validator assignment per task
  - Minimum quorum N (e.g., 5)
  - Majority agreement required
  - Minority dissent flagged and tracked

If a validator:
  - Approves invalid exploit → divergence recorded
  - Rejects valid exploit → divergence recorded

If divergence > threshold → slash stake.

ALL execution traces must be public and replayable locally.
Transparency is anti-cartel armor.
If validation logs are private, collusion becomes undetectable.
"""

import hashlib
import json
import math
import random
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── Constants ────────────────────────────────────────────────────────────────

MIN_QUORUM = 5
CONSENSUS_THRESHOLD = 0.66       # 66% agreement for consensus
DIVERGENCE_SLASH_THRESHOLD = 0.20  # Slash if >20% divergence rate
DIVERGENCE_WINDOW = 100           # Measure over last N validations
SLASH_AMOUNT_BPS = 500            # 5% of stake per slash event
SLASH_COOLDOWN_SECONDS = 24 * 3600  # 24h cooldown before slash can be lifted
MAX_VALIDATORS_PER_TASK = 11      # Odd number for tiebreaking

# ── Data Structures ──────────────────────────────────────────────────────────


@dataclass
class ValidatorState:
    """Tracked state of a single validator."""
    hotkey: str
    stake: float = 0.0
    total_validations: int = 0
    agreements: int = 0
    divergences: int = 0
    recent_results: list[bool] = field(default_factory=list)  # True=agreed, False=diverged
    last_active: float = 0.0
    slashed: bool = False
    slash_count: int = 0
    slashed_at: float = 0.0  # Timestamp when last slashed

    @property
    def divergence_rate(self) -> float:
        """Rolling divergence rate over recent window."""
        window = self.recent_results[-DIVERGENCE_WINDOW:]
        if not window:
            return 0.0
        return 1.0 - (sum(window) / len(window))

    @property
    def reliability_score(self) -> float:
        """Reliability score [0, 1]. Used for validator selection weighting."""
        if self.total_validations == 0:
            return 0.5  # Neutral for new validators
        base = self.agreements / self.total_validations
        # Penalize recent divergence more heavily
        recent_rate = 1.0 - self.divergence_rate
        return 0.6 * base + 0.4 * recent_rate


@dataclass
class ConsensusResult:
    """Result of consensus computation for a single task submission."""
    task_id: str
    submission_hash: str
    consensus_result: str = ""      # "VALID" or "REJECT_*"
    consensus_fingerprint: str = ""
    consensus_severity: float = 0.0
    agreement_ratio: float = 0.0
    quorum_size: int = 0
    agreeing_validators: list[str] = field(default_factory=list)
    diverging_validators: list[str] = field(default_factory=list)
    votes: list[dict] = field(default_factory=list)


@dataclass
class SlashEvent:
    """Recorded slash event for audit trail."""
    validator_hotkey: str
    reason: str
    divergence_rate: float
    slash_amount_bps: int
    timestamp: float
    evidence_hashes: list[str] = field(default_factory=list)


# ── Anti-Collusion Engine ────────────────────────────────────────────────────

class AntiCollusionEngine:
    """
    Manages validator assignment, consensus, divergence tracking, and slashing.

    Core principle: All execution traces are public and replayable.
    Any third party can re-run validation and verify consensus.
    """

    def __init__(self, seed: int = 42, data_dir: Optional[Path] = None):
        self.rng = random.Random(seed)
        self.data_dir = data_dir or Path(__file__).parent.parent.parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.validators: dict[str, ValidatorState] = {}
        self.consensus_history: list[ConsensusResult] = []
        self.slash_events: list[SlashEvent] = []

        self._load_state()

    # ── Validator Management ──────────────────────────────────────────────

    def register_validator(self, hotkey: str, stake: float = 0.0):
        """Register a new validator or update stake."""
        if hotkey not in self.validators:
            self.validators[hotkey] = ValidatorState(hotkey=hotkey, stake=stake)
        else:
            self.validators[hotkey].stake = stake

    def get_active_validators(self) -> list[str]:
        """Get list of active (non-slashed) validator hotkeys."""
        return [
            v.hotkey for v in self.validators.values()
            if not v.slashed and v.stake > 0
        ]

    # ── Random Assignment ─────────────────────────────────────────────────

    def assign_validators(self, task_id: str) -> list[str]:
        """
        Randomly assign validators to a task.

        Uses task_id as additional entropy to make assignment deterministic
        but unpredictable. Weighted by reliability score.
        """
        active = self.get_active_validators()
        if len(active) < MIN_QUORUM:
            raise ValueError(f"Insufficient active validators: {len(active)} < {MIN_QUORUM}")

        # Seed RNG with task_id for deterministic but unpredictable assignment
        task_seed = int(hashlib.sha256(task_id.encode()).hexdigest()[:16], 16)
        task_rng = random.Random(task_seed)

        # Weighted selection by reliability
        weights = [self.validators[h].reliability_score for h in active]
        total_weight = sum(weights)
        if total_weight <= 0:
            weights = [1.0] * len(active)
            total_weight = len(active)

        # Normalize
        probs = [w / total_weight for w in weights]

        # Select without replacement
        n_select = min(MAX_VALIDATORS_PER_TASK, len(active))
        selected = []
        remaining = list(zip(active, probs))

        for _ in range(n_select):
            if not remaining:
                break
            hotkeys, probs_remaining = zip(*remaining)
            total = sum(probs_remaining)
            norm_probs = [p / total for p in probs_remaining]

            # Weighted random selection
            r = task_rng.random()
            cumsum = 0
            chosen_idx = 0
            for i, p in enumerate(norm_probs):
                cumsum += p
                if r <= cumsum:
                    chosen_idx = i
                    break

            selected.append(hotkeys[chosen_idx])
            remaining = [(h, p) for h, p in remaining if h != hotkeys[chosen_idx]]

        return selected

    # ── Consensus Computation ─────────────────────────────────────────────

    def compute_consensus(self, task_id: str, submission_hash: str,
                          votes: list[dict]) -> ConsensusResult:
        """
        Compute consensus from validator votes.

        Each vote: {validator_hotkey, result, fingerprint, severity_score}

        Returns ConsensusResult and updates validator divergence tracking.
        """
        result = ConsensusResult(
            task_id=task_id,
            submission_hash=submission_hash,
            quorum_size=len(votes),
        )

        if len(votes) < MIN_QUORUM:
            result.consensus_result = "NO_QUORUM"
            return result

        # Tally results
        result_tally: dict[str, list[str]] = {}  # result → [validator_hotkeys]
        fingerprint_tally: dict[str, list[str]] = {}
        severity_values: list[float] = []

        for vote in votes:
            hotkey = vote["validator_hotkey"]
            vote_result = vote["result"]
            fp = vote.get("fingerprint", "")
            sev = vote.get("severity_score", 0.0)

            result_tally.setdefault(vote_result, []).append(hotkey)
            if fp:
                fingerprint_tally.setdefault(fp, []).append(hotkey)
            if sev > 0:
                severity_values.append(sev)

            result.votes.append(vote)

        # Find majority
        total_votes = len(votes)
        majority_result = None
        majority_validators = []

        for res, validators in result_tally.items():
            ratio = len(validators) / total_votes
            if ratio >= CONSENSUS_THRESHOLD:
                majority_result = res
                majority_validators = validators
                result.agreement_ratio = ratio
                break

        if majority_result is None:
            # No consensus — find plurality
            majority_result = max(result_tally, key=lambda r: len(result_tally[r]))
            majority_validators = result_tally[majority_result]
            result.agreement_ratio = len(majority_validators) / total_votes

        result.consensus_result = majority_result
        result.agreeing_validators = majority_validators

        # Identify diverging validators
        all_voters = {v["validator_hotkey"] for v in votes}
        result.diverging_validators = list(all_voters - set(majority_validators))

        # Consensus fingerprint (from agreeing validators)
        if fingerprint_tally:
            result.consensus_fingerprint = max(
                fingerprint_tally, key=lambda fp: len(fingerprint_tally[fp])
            )

        # Consensus severity (median of agreeing validators)
        if severity_values:
            severity_values.sort()
            mid = len(severity_values) // 2
            result.consensus_severity = severity_values[mid]

        # ── Update Validator State ────────────────────────────────────────
        for hotkey in result.agreeing_validators:
            if hotkey in self.validators:
                v = self.validators[hotkey]
                v.total_validations += 1
                v.agreements += 1
                v.recent_results.append(True)
                v.recent_results = v.recent_results[-DIVERGENCE_WINDOW:]
                v.last_active = time.time()

        for hotkey in result.diverging_validators:
            if hotkey in self.validators:
                v = self.validators[hotkey]
                v.total_validations += 1
                v.divergences += 1
                v.recent_results.append(False)
                v.recent_results = v.recent_results[-DIVERGENCE_WINDOW:]
                v.last_active = time.time()

        # ── Check Slash Conditions ────────────────────────────────────────
        self._check_slashing()

        self.consensus_history.append(result)
        # Prune history to prevent unbounded memory growth
        _MAX_HISTORY = 10_000
        if len(self.consensus_history) > _MAX_HISTORY:
            self.consensus_history = self.consensus_history[-_MAX_HISTORY:]
        self._save_state()

        return result

    # ── Slashing ──────────────────────────────────────────────────────────

    def _check_slashing(self):
        """Check all validators for slash conditions and cooldown recovery."""
        now = time.time()
        for hotkey, v in self.validators.items():
            # Recovery: lift slash after cooldown if divergence has improved
            if v.slashed and v.slashed_at > 0:
                if (now - v.slashed_at) >= SLASH_COOLDOWN_SECONDS:
                    if v.divergence_rate <= DIVERGENCE_SLASH_THRESHOLD:
                        v.slashed = False
                        v.slashed_at = 0.0
                        v.recent_results = []  # Reset window
                        continue

            if v.slashed:
                continue
            if v.total_validations < MIN_QUORUM:
                continue  # Not enough data

            if v.divergence_rate > DIVERGENCE_SLASH_THRESHOLD:
                self._slash_validator(hotkey, v)

    def _slash_validator(self, hotkey: str, v: ValidatorState):
        """Execute slash on a validator."""
        v.slashed = True
        v.slash_count += 1
        v.slashed_at = time.time()

        event = SlashEvent(
            validator_hotkey=hotkey,
            reason=f"Divergence rate {v.divergence_rate:.2%} exceeds threshold {DIVERGENCE_SLASH_THRESHOLD:.2%}",
            divergence_rate=v.divergence_rate,
            slash_amount_bps=SLASH_AMOUNT_BPS,
            timestamp=time.time(),
            evidence_hashes=[
                hashlib.sha256(json.dumps(asdict(c), sort_keys=True).encode()).hexdigest()[:16]
                for c in self.consensus_history[-DIVERGENCE_WINDOW:]
                if hotkey in c.diverging_validators
            ],
        )
        self.slash_events.append(event)

    def get_slash_events(self) -> list[dict]:
        """Get all slash events for audit trail."""
        return [asdict(e) for e in self.slash_events]

    # ── Transparency / Replayability ──────────────────────────────────────

    def export_consensus_log(self) -> list[dict]:
        """
        Export full consensus history for public verification.

        This is the anti-cartel armor. Anyone can:
        1. Download the consensus log
        2. Re-run each validation locally
        3. Verify that consensus was reached honestly
        """
        return [
            {
                "task_id": c.task_id,
                "submission_hash": c.submission_hash,
                "consensus_result": c.consensus_result,
                "consensus_fingerprint": c.consensus_fingerprint,
                "agreement_ratio": c.agreement_ratio,
                "quorum_size": c.quorum_size,
                "agreeing_validators": c.agreeing_validators,
                "diverging_validators": c.diverging_validators,
                "votes": c.votes,
            }
            for c in self.consensus_history
        ]

    def export_validator_stats(self) -> dict:
        """Export validator reliability stats."""
        return {
            hotkey: {
                "total_validations": v.total_validations,
                "agreements": v.agreements,
                "divergences": v.divergences,
                "divergence_rate": round(v.divergence_rate, 4),
                "reliability_score": round(v.reliability_score, 4),
                "slashed": v.slashed,
                "slash_count": v.slash_count,
            }
            for hotkey, v in self.validators.items()
        }

    # ── Persistence ───────────────────────────────────────────────────────

    def _save_state(self):
        """Persist state to disk."""
        state = {
            "validators": {k: asdict(v) for k, v in self.validators.items()},
            "slash_events": [asdict(e) for e in self.slash_events],
            "consensus_history": [asdict(c) for c in self.consensus_history],
        }
        (self.data_dir / "anticollusion_state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True)
        )

    def _load_state(self):
        """Load state from disk."""
        state_path = self.data_dir / "anticollusion_state.json"
        if not state_path.exists():
            return

        try:
            state = json.loads(state_path.read_text())
            for hotkey, vdata in state.get("validators", {}).items():
                self.validators[hotkey] = ValidatorState(**vdata)
            for edata in state.get("slash_events", []):
                self.slash_events.append(SlashEvent(**edata))
            for cdata in state.get("consensus_history", []):
                self.consensus_history.append(ConsensusResult(**cdata))
        except (json.JSONDecodeError, TypeError):
            pass


# ── CLI / Docker Entry Point ─────────────────────────────────────────────────

def main() -> None:
    """
    Entry point for ``python -m validator.anticollusion.consensus``.

    Starts the anti-collusion engine as a long-running service alongside
    the metrics / health HTTP server so the docker-compose healthcheck
    and monitoring can reach it.
    """
    import argparse
    import sys as _sys

    _project_root = Path(__file__).resolve().parent.parent.parent
    _sys.path.insert(0, str(_project_root))

    from validator.metrics import MetricsServer

    parser = argparse.ArgumentParser(description="Anti-Collusion Consensus Relay")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Health/metrics HTTP bind address")
    parser.add_argument("--port", type=int, default=9946, help="Health/metrics HTTP port")
    parser.add_argument("--data-dir", type=str, default=None, help="Data directory")
    args = parser.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else Path(__file__).parent.parent.parent / "data" / "anticollusion"
    engine = AntiCollusionEngine(data_dir=data_dir)

    srv = MetricsServer(host=args.host, port=args.port)
    srv.start()
    print(f"Consensus relay running (health/metrics on :{args.port})")
    print(f"Data dir: {data_dir}")
    print(f"Active validators: {len(engine.get_active_validators())}")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        srv.stop()
        print("Consensus relay stopped.")


if __name__ == "__main__":
    main()

