"""
Subnet Incentive Adapter — Bridges validation results to Bittensor TAO rewards.

This is the interface between the exploit validation engine and Bittensor's
on-chain incentive mechanism. It translates:
  - Validation reports → miner scores
  - Fingerprint dedup results → reward multipliers
  - Severity scores → weight contributions
  - Commit-reveal priority → temporal ordering

The adapter is the ONLY component that touches Bittensor primitives.
Everything else is chain-agnostic.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── Constants ────────────────────────────────────────────────────────────────

# Reward distribution parameters (v1 — FIXED)
BASE_REWARD_PER_TASK = 1.0           # Normalized TAO units
DUPLICATE_PENALTY = 0.90             # 90% penalty for duplicate fingerprints
INVALID_SUBMISSION_PENALTY = 0.0     # Zero reward
COMMIT_REVEAL_BONUS = 0.05           # 5% bonus for earliest commit

# Validator consensus parameters
MIN_VALIDATOR_QUORUM = 5
CONSENSUS_THRESHOLD = 0.66           # 66% agreement required

# Anti-spam parameters
MIN_SUBMISSIONS_FOR_WEIGHT = 1       # Must submit at least 1 valid exploit
MAX_SUBMISSIONS_PER_EPOCH = 50       # Per miner per epoch
EPOCH_DURATION_BLOCKS = 360          # ~1 hour on Bittensor


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class MinerScore:
    """Score for a single miner in an epoch."""
    miner_hotkey: str
    valid_exploits: int = 0
    invalid_submissions: int = 0
    unique_fingerprints: int = 0
    duplicate_fingerprints: int = 0
    total_severity: float = 0.0
    earliest_commits: int = 0
    raw_score: float = 0.0
    normalized_score: float = 0.0    # [0, 1] after normalization across all miners


@dataclass
class EpochResult:
    """Complete scoring for one epoch."""
    epoch_number: int
    start_block: int
    end_block: int
    miner_scores: dict[str, MinerScore] = field(default_factory=dict)
    total_submissions: int = 0
    total_valid: int = 0
    weights: dict[str, float] = field(default_factory=dict)  # hotkey → weight [0, 1]


@dataclass
class ValidatorVote:
    """A single validator's vote on a submission."""
    validator_hotkey: str
    task_id: str
    submission_hash: str
    result: str              # "VALID" or "REJECT_*"
    fingerprint: str = ""
    severity_score: float = 0.0
    timestamp: float = 0.0
    miner_hotkey: str = ""   # Explicit miner hotkey (from Bittensor synapse)


# ── Subnet Incentive Adapter ─────────────────────────────────────────────────

class SubnetIncentiveAdapter:
    """
    Translates validation results into Bittensor-compatible weights.

    Flow per epoch:
    1. Collect all validation reports from validators
    2. Achieve consensus on each submission
    3. Compute miner scores
    4. Normalize to weight vector
    5. Submit weights to Bittensor chain

    This adapter does NOT import bittensor directly — it produces
    weight vectors that the Bittensor neuron wrapper consumes.
    """

    def __init__(self, netuid: int = 1):
        self.netuid = netuid
        self._current_epoch = 0
        self._votes: list[ValidatorVote] = []
        self._epoch_results: list[EpochResult] = []

    # ── Public API ────────────────────────────────────────────────────────

    def record_vote(self, vote: ValidatorVote):
        """Record a validator's vote on a submission."""
        self._votes.append(vote)

    def compute_epoch_weights(self, epoch_number: int,
                               start_block: int,
                               end_block: int) -> EpochResult:
        """
        Compute final weights for an epoch from all collected votes.

        Returns EpochResult with normalized weight vector.
        """
        result = EpochResult(
            epoch_number=epoch_number,
            start_block=start_block,
            end_block=end_block,
        )

        # Group votes by (task_id, submission_hash)
        vote_groups: dict[str, list[ValidatorVote]] = {}
        for vote in self._votes:
            key = f"{vote.task_id}::{vote.submission_hash}"
            if key not in vote_groups:
                vote_groups[key] = []
            vote_groups[key].append(vote)

        result.total_submissions = len(vote_groups)

        # Process each submission
        for key, votes in vote_groups.items():
            consensus = self._achieve_consensus(votes)
            if consensus is None:
                continue  # No consensus reached

            task_id, submission_hash = key.split("::", 1)
            miner_hotkey = self._extract_miner_hotkey(votes)

            if miner_hotkey not in result.miner_scores:
                result.miner_scores[miner_hotkey] = MinerScore(miner_hotkey=miner_hotkey)

            score = result.miner_scores[miner_hotkey]

            if consensus["result"] == "VALID":
                result.total_valid += 1
                score.valid_exploits += 1
                score.total_severity += consensus["severity_score"]

                if consensus.get("is_first_fingerprint", False):
                    score.unique_fingerprints += 1
                else:
                    score.duplicate_fingerprints += 1

                if consensus.get("earliest_commit", False):
                    score.earliest_commits += 1
            else:
                score.invalid_submissions += 1

        # Compute raw scores
        for hotkey, score in result.miner_scores.items():
            score.raw_score = self._compute_raw_score(score)

        # Normalize to weight vector
        result.weights = self._normalize_weights(result.miner_scores)

        # Update normalized scores
        for hotkey, weight in result.weights.items():
            if hotkey in result.miner_scores:
                result.miner_scores[hotkey].normalized_score = weight

        self._epoch_results.append(result)
        self._votes = []  # Clear for next epoch

        return result

    def get_weight_vector(
        self,
        epoch_result: EpochResult,
        metagraph_hotkeys: Optional[list[str]] = None,
    ) -> tuple[list[int], list[float]]:
        """
        Convert EpochResult to Bittensor weight format.

        Args:
            epoch_result: Computed epoch with hotkey→weight mapping.
            metagraph_hotkeys: If provided, the list from `metagraph.hotkeys`
                used to map hotkeys → UIDs.  When ``None`` (local mode),
                UIDs are assigned sequentially.

        Returns:
            (uids, weights) tuple ready for subtensor.set_weights()
        """
        uids: list[int] = []
        weights: list[float] = []

        for hotkey, weight in epoch_result.weights.items():
            if metagraph_hotkeys is not None:
                # Production path: map hotkey to UID via metagraph
                if hotkey in metagraph_hotkeys:
                    uid = metagraph_hotkeys.index(hotkey)
                    uids.append(uid)
                    weights.append(weight)
                # Skip hotkeys not in metagraph (deregistered miners)
            else:
                # Local mode: sequential UID assignment
                uids.append(len(uids))
                weights.append(weight)

        return uids, weights

    # ── Consensus Logic ───────────────────────────────────────────────────

    def _achieve_consensus(self, votes: list[ValidatorVote]) -> Optional[dict]:
        """
        Achieve consensus from multiple validator votes.

        With full quorum (>= MIN_VALIDATOR_QUORUM): requires CONSENSUS_THRESHOLD agreement.
        Below quorum (early deployment): accepts single-validator results with
        reduced confidence so the subnet doesn't appear dead on launch.
        """
        if not votes:
            return None

        below_quorum = len(votes) < MIN_VALIDATOR_QUORUM

        # Count results
        result_counts: dict[str, int] = {}
        fingerprints: dict[str, int] = {}
        severity_sum = 0.0
        severity_count = 0

        for vote in votes:
            result_counts[vote.result] = result_counts.get(vote.result, 0) + 1
            if vote.fingerprint:
                fingerprints[vote.fingerprint] = fingerprints.get(vote.fingerprint, 0) + 1
            if vote.severity_score > 0:
                severity_sum += vote.severity_score
                severity_count += 1

        # Check for consensus
        total_votes = len(votes)
        threshold = CONSENSUS_THRESHOLD if not below_quorum else 0.51
        for result, count in result_counts.items():
            if count / total_votes >= threshold:
                consensus = {
                    "result": result,
                    "agreement_ratio": count / total_votes,
                    "total_votes": total_votes,
                    "severity_score": severity_sum / severity_count if severity_count > 0 else 0.0,
                    "low_confidence": below_quorum,
                }

                # Consensus on fingerprint
                if fingerprints:
                    top_fp = max(fingerprints, key=fingerprints.get)
                    consensus["fingerprint"] = top_fp
                    consensus["fingerprint_agreement"] = fingerprints[top_fp] / total_votes

                return consensus

        return None  # No consensus

    # ── Scoring Logic ─────────────────────────────────────────────────────

    def _compute_raw_score(self, score: MinerScore) -> float:
        """
        Compute raw score for a miner.

        Formula:
          raw = (unique_exploits * severity) + (duplicate_exploits * severity * 0.1)
                + (earliest_commits * COMMIT_REVEAL_BONUS)
                - (invalid_submissions * 0.05)
        """
        unique_weight = score.unique_fingerprints * (
            score.total_severity / max(score.valid_exploits, 1)
        )
        duplicate_weight = score.duplicate_fingerprints * (
            score.total_severity / max(score.valid_exploits, 1) * (1 - DUPLICATE_PENALTY)
        )
        commit_bonus = score.earliest_commits * COMMIT_REVEAL_BONUS
        spam_penalty = score.invalid_submissions * 0.05

        raw = unique_weight + duplicate_weight + commit_bonus - spam_penalty
        return max(0.0, raw)

    def _normalize_weights(self, scores: dict[str, MinerScore]) -> dict[str, float]:
        """
        Normalize raw scores to weight vector summing to 1.0.

        Miners with no valid exploits get zero weight.
        """
        # Filter miners with minimum submissions
        eligible = {
            k: v for k, v in scores.items()
            if v.valid_exploits >= MIN_SUBMISSIONS_FOR_WEIGHT
        }

        if not eligible:
            return {}

        total_raw = sum(s.raw_score for s in eligible.values())
        if total_raw <= 0:
            # Equal weight among eligible miners
            n = len(eligible)
            return {k: 1.0 / n for k in eligible}

        return {k: s.raw_score / total_raw for k, s in eligible.items()}

    def _extract_miner_hotkey(self, votes: list[ValidatorVote]) -> str:
        """Extract miner hotkey from votes.

        The miner hotkey is embedded by the orchestrator when it records
        a ValidatorVote: the `submission_hash` field is the sha256 of
        the exploit source, and the miner_address is carried as the
        vote key prefix.  When a real Bittensor submission occurs, the
        miner_hotkey is set explicitly from the synapse dendrite.

        We look for an explicit `miner_hotkey` attribute first (set in
        production), then fall back to a deterministic derivation.
        """
        if not votes:
            return "unknown"
        # Prefer explicit miner_hotkey if set by caller
        first = votes[0]
        miner_key = getattr(first, "miner_hotkey", None)
        if miner_key:
            return miner_key
        # Deterministic fallback: hash of submission_hash (for local mode)
        return hashlib.sha256(first.submission_hash.encode()).hexdigest()[:16]

    # ── Serialization ─────────────────────────────────────────────────────

    def export_epoch(self, epoch_result: EpochResult) -> dict:
        """Export epoch result for storage/transmission."""
        return {
            "epoch_number": epoch_result.epoch_number,
            "start_block": epoch_result.start_block,
            "end_block": epoch_result.end_block,
            "total_submissions": epoch_result.total_submissions,
            "total_valid": epoch_result.total_valid,
            "weights": epoch_result.weights,
            "miner_scores": {k: asdict(v) for k, v in epoch_result.miner_scores.items()},
        }
