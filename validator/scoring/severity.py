"""
Severity Scoring — Algorithmic Only. No Human Grading.

Severity is computed from measurable execution outputs:

  fundsDrainedScore = log10(weiDrained + 1)
  privilegeEscalationScore = boolean → fixed weight
  invariantBrokenScore = boolean → fixed weight
  permanentLockScore = boolean → fixed weight

  final_severity = weighted_sum (normalized to 0-1)

Weights are CONSTANT in v1. Governance can adjust later.
Dynamic scoring invites manipulation.
"""

import math
from dataclasses import dataclass, asdict


# ── Constants (v1 — FIXED, DO NOT MAKE DYNAMIC) ─────────────────────────────

# Weights for severity components
W_FUNDS_DRAINED = 0.40
W_PRIVILEGE_ESCALATION = 0.25
W_INVARIANT_BROKEN = 0.20
W_PERMANENT_LOCK = 0.15

# Normalization: log10(max_reasonable_drain) for scaling funds score to [0,1]
# 10^24 wei = ~1M ETH — anything above this is capped
MAX_LOG_DRAIN = 24.0

# Well-known storage slots that indicate ownership/privilege
OWNER_SLOT_INDICES = {"0x0", "0x00", "0x1", "0x01"}
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class SeverityBreakdown:
    """Detailed breakdown of severity components."""
    funds_drained_score: float = 0.0       # [0, 1]
    privilege_escalation_score: float = 0.0  # 0 or 1
    invariant_broken_score: float = 0.0      # 0 or 1
    permanent_lock_score: float = 0.0        # 0 or 1
    final_severity: float = 0.0              # [0, 1] weighted sum
    wei_drained: int = 0
    detail: str = ""


# ── Severity Scorer ──────────────────────────────────────────────────────────

class SeverityScorer:
    """
    Algorithmic severity scoring from execution traces.

    All inputs are measurable. All weights are constant.
    No subjectivity. No governance interference in v1.
    """

    def __init__(self,
                 w_funds: float = W_FUNDS_DRAINED,
                 w_priv: float = W_PRIVILEGE_ESCALATION,
                 w_invariant: float = W_INVARIANT_BROKEN,
                 w_lock: float = W_PERMANENT_LOCK):
        self.w_funds = w_funds
        self.w_priv = w_priv
        self.w_invariant = w_invariant
        self.w_lock = w_lock

        # Sanity check: weights must sum to 1.0
        total = self.w_funds + self.w_priv + self.w_invariant + self.w_lock
        assert abs(total - 1.0) < 1e-9, f"Weights must sum to 1.0, got {total}"

    def score(self, trace) -> float:
        """
        Compute severity score from an ExecutionTrace object.

        Args:
            trace: ExecutionTrace (or dict with same fields)

        Returns:
            float in [0, 1] — normalized severity
        """
        breakdown = self.score_detailed(trace)
        return breakdown.final_severity

    def score_detailed(self, trace) -> SeverityBreakdown:
        """Compute severity with full breakdown.

        For multi-tx exploits with per-function results, each step's
        impact is evaluated independently to avoid net-delta masking
        (e.g. setup deposits then attack drains → net zero misleads).
        """
        breakdown = SeverityBreakdown()

        # Handle both object and dict inputs
        if isinstance(trace, dict):
            balance_delta = trace.get("balance_delta", 0)
            if not isinstance(balance_delta, (int, float)):
                balance_delta = 0
            storage_diffs = trace.get("storage_diffs", [])
            if not isinstance(storage_diffs, list):
                storage_diffs = []
            event_logs = trace.get("event_logs", [])
            if not isinstance(event_logs, list):
                event_logs = []
            reverted = bool(trace.get("reverted", False))
            test_results = trace.get("test_results", {})
            is_multi_tx = trace.get("is_multi_tx", False)
        else:
            balance_delta = getattr(trace, "balance_delta", 0)
            storage_diffs = getattr(trace, "storage_diffs", [])
            if storage_diffs and hasattr(storage_diffs[0], "slot"):
                storage_diffs = [{"slot": d.slot, "before": d.before, "after": d.after} for d in storage_diffs]
            event_logs = getattr(trace, "event_logs", [])
            reverted = getattr(trace, "reverted", False)
            test_results = getattr(trace, "test_results", {})
            is_multi_tx = getattr(trace, "is_multi_tx", False)

        if reverted:
            return breakdown

        # ── 1. Funds Drained Score ────────────────────────────────────────
        # S-3 fix: For multi-tx exploits, compute the maximum absolute
        # per-step balance delta. This prevents masking when an exploit
        # deposits in step 1 and drains in step 2 (net zero).
        if is_multi_tx and test_results:
            total_gas = sum(
                r.get("gas_used", 0) for r in test_results.values()
                if isinstance(r, dict)
            )
            # Use max per-step delta if available, else fall back to aggregate
            per_step_deltas = [
                abs(r.get("balance_delta", 0))
                for r in test_results.values()
                if isinstance(r, dict) and r.get("balance_delta", 0) != 0
            ]
            wei_drained = max(per_step_deltas) if per_step_deltas else (
                abs(balance_delta) if balance_delta < 0 else 0
            )
            complexity_bonus = min(0.10, math.log10(max(total_gas, 1)) / 80.0)
        else:
            wei_drained = abs(balance_delta) if balance_delta < 0 else 0
            complexity_bonus = 0.0

        breakdown.wei_drained = wei_drained

        if wei_drained > 0:
            log_drain = math.log10(wei_drained + 1)
            breakdown.funds_drained_score = min(
                (log_drain / MAX_LOG_DRAIN) + complexity_bonus, 1.0
            )

        # ── 2. Privilege Escalation Score ─────────────────────────────────
        # Check if any ownership/admin slots changed
        # S-7 fix: normalize slot format to strip leading zeros for comparison
        for diff in storage_diffs:
            slot = diff.get("slot", "") if isinstance(diff, dict) else diff.slot
            if isinstance(slot, int):
                slot = hex(slot)
            # Normalize: strip leading zeros after 0x for comparison
            slot_norm = "0x" + slot.lstrip("0x").lstrip("0") if isinstance(slot, str) and slot.startswith("0x") else slot
            if not slot_norm or slot_norm == "0x":
                slot_norm = "0x0"
            if slot_norm in OWNER_SLOT_INDICES or slot == EIP1967_ADMIN_SLOT:
                breakdown.privilege_escalation_score = 1.0
                break

        # ── 3. Invariant Broken Score ─────────────────────────────────────
        # Invariant is considered broken if:
        # - Storage changed in unexpected ways (proxy impl slot modified)
        # - Balance drained (any amount)
        # - Multiple *meaningful* storage slots changed simultaneously
        for diff in storage_diffs:
            slot = diff.get("slot", "") if isinstance(diff, dict) else diff.slot
            if slot == EIP1967_IMPL_SLOT:
                breakdown.invariant_broken_score = 1.0
                break

        if wei_drained > 0:
            breakdown.invariant_broken_score = 1.0

        # S-2 fix: only count storage diffs where before != after and
        # the change is non-trivial (not just writing the same value).
        # This prevents gaming via 3 harmless writes to inflate severity.
        meaningful_diffs = [
            d for d in storage_diffs
            if (d.get("before", "") if isinstance(d, dict) else d.before)
            != (d.get("after", "") if isinstance(d, dict) else d.after)
        ]
        if len(meaningful_diffs) >= 3:
            breakdown.invariant_broken_score = 1.0

        # ── 4. Permanent Lock Score ───────────────────────────────────────
        # Permanent lock conditions:
        # - Selfdestruct detected (code gone)
        # - Admin set to zero address
        # - Implementation set to zero address
        for diff in storage_diffs:
            slot = diff.get("slot", "") if isinstance(diff, dict) else diff.slot
            after = diff.get("after", "") if isinstance(diff, dict) else diff.after

            # Check if a critical slot was zeroed out
            if slot in OWNER_SLOT_INDICES or slot == EIP1967_ADMIN_SLOT:
                if after == "0x" + "0" * 64:
                    breakdown.permanent_lock_score = 1.0
                    break

        # ── Final Weighted Sum ────────────────────────────────────────────
        breakdown.final_severity = (
            self.w_funds * breakdown.funds_drained_score
            + self.w_priv * breakdown.privilege_escalation_score
            + self.w_invariant * breakdown.invariant_broken_score
            + self.w_lock * breakdown.permanent_lock_score
        )

        # Clamp to [0, 1]
        breakdown.final_severity = max(0.0, min(1.0, breakdown.final_severity))

        # Build detail string
        details = []
        if is_multi_tx:
            details.append(f"multi_tx({len(test_results)}_steps)")
        if breakdown.funds_drained_score > 0:
            details.append(f"drain={breakdown.wei_drained}wei(score={breakdown.funds_drained_score:.3f})")
        if breakdown.privilege_escalation_score > 0:
            details.append("priv_escalation=true")
        if breakdown.invariant_broken_score > 0:
            details.append("invariant_broken=true")
        if breakdown.permanent_lock_score > 0:
            details.append("permanent_lock=true")
        breakdown.detail = "; ".join(details) if details else "no_impact"

        return breakdown

    def score_from_dict(self, trace_dict: dict) -> SeverityBreakdown:
        """Score from a plain dictionary (for JSON deserialization)."""
        return self.score_detailed(trace_dict)


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Score exploit severity from execution trace")
    parser.add_argument("--trace", type=str, required=True, help="Path to execution trace JSON")
    args = parser.parse_args()

    with open(args.trace) as f:
        trace = json.load(f)
    scorer = SeverityScorer()
    breakdown = scorer.score_detailed(trace)

    print(f"Severity: {breakdown.final_severity:.4f}")
    print(f"  Funds drained: {breakdown.funds_drained_score:.4f} (weight={W_FUNDS_DRAINED})")
    print(f"  Priv escalation: {breakdown.privilege_escalation_score:.1f} (weight={W_PRIVILEGE_ESCALATION})")
    print(f"  Invariant broken: {breakdown.invariant_broken_score:.1f} (weight={W_INVARIANT_BROKEN})")
    print(f"  Permanent lock: {breakdown.permanent_lock_score:.1f} (weight={W_PERMANENT_LOCK})")
    print(f"  Detail: {breakdown.detail}")


if __name__ == "__main__":
    main()
