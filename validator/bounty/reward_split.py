"""
Reward Split — Distributes bounty payouts between miner, validator, and treasury.

When a bounty platform pays for a validated exploit, the reward is split:
  - Miner:      70% (they found the bug)
  - Validator:   20% (ran infra, validated, submitted)
  - Treasury:    10% (subnet development fund)

These are v1 defaults.  Governance can adjust via config.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── Constants (v1 — configurable via env) ────────────────────────────────────

DEFAULT_MINER_SHARE = 0.70
DEFAULT_VALIDATOR_SHARE = 0.20
DEFAULT_TREASURY_SHARE = 0.10


def _load_shares() -> tuple[float, float, float]:
    """Load split percentages from env or use defaults."""
    miner = float(os.environ.get("VALAYR_MINER_SHARE", DEFAULT_MINER_SHARE))
    validator = float(os.environ.get("VALAYR_VALIDATOR_SHARE", DEFAULT_VALIDATOR_SHARE))
    treasury = float(os.environ.get("VALAYR_TREASURY_SHARE", DEFAULT_TREASURY_SHARE))
    for name, val in [("miner", miner), ("validator", validator), ("treasury", treasury)]:
        if not (0.0 <= val <= 1.0):
            raise ValueError(f"{name} share must be in [0, 1], got {val}")
    total = miner + validator + treasury
    if abs(total - 1.0) > 1e-6:
        raise ValueError(
            f"Reward shares must sum to 1.0, got {total:.6f} "
            f"(miner={miner}, validator={validator}, treasury={treasury})"
        )
    return miner, validator, treasury


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class RewardSplit:
    """Computed reward distribution for a single bounty payout."""
    report_id: str
    platform: str
    total_amount: float           # Total payout (USD or token units)
    currency: str                 # e.g. "USD", "USDC", "ETH"
    miner_hotkey: str
    validator_id: str
    miner_amount: float = 0.0
    validator_amount: float = 0.0
    treasury_amount: float = 0.0
    miner_share: float = DEFAULT_MINER_SHARE
    validator_share: float = DEFAULT_VALIDATOR_SHARE
    treasury_share: float = DEFAULT_TREASURY_SHARE
    computed_at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PayoutRecord:
    """Tracks payout state from detection through distribution."""
    report_id: str
    platform: str
    task_id: str
    fingerprint: str
    miner_hotkey: str
    validator_id: str
    bounty_amount: float = 0.0
    currency: str = "USD"
    split: Optional[RewardSplit] = None
    status: str = "pending"       # pending | computed | distributed | failed
    detected_at: float = 0.0
    distributed_at: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.split:
            d["split"] = self.split.to_dict()
        return d


# ── Reward Split Engine ──────────────────────────────────────────────────────

class RewardSplitEngine:
    """Computes and tracks reward distributions for bounty payouts."""

    def __init__(self, data_dir: Path, treasury_address: str = ""):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._payouts_path = self.data_dir / "payouts.json"
        self._payouts: dict[str, PayoutRecord] = {}  # report_id → record
        self.treasury_address = treasury_address or os.environ.get(
            "VALAYR_TREASURY_ADDRESS", ""
        )
        self._miner_share, self._validator_share, self._treasury_share = _load_shares()
        self._load()

    def compute_split(
        self,
        report_id: str,
        platform: str,
        task_id: str,
        fingerprint: str,
        miner_hotkey: str,
        validator_id: str,
        bounty_amount: float,
        currency: str = "USD",
    ) -> RewardSplit:
        """Compute the reward split for a bounty payout.

        The split is deterministic: same inputs always produce same outputs.
        """
        if bounty_amount < 0:
            raise ValueError("bounty_amount must be non-negative")

        split = RewardSplit(
            report_id=report_id,
            platform=platform,
            total_amount=bounty_amount,
            currency=currency,
            miner_hotkey=miner_hotkey,
            validator_id=validator_id,
            miner_share=self._miner_share,
            validator_share=self._validator_share,
            treasury_share=self._treasury_share,
            computed_at=time.time(),
        )

        # S-6 fix: compute shares with integer-safe arithmetic to prevent
        # floating-point rounding from losing funds. Compute miner and
        # validator amounts first, then assign remainder to treasury.
        split.miner_amount = round(bounty_amount * self._miner_share, 6)
        split.validator_amount = round(bounty_amount * self._validator_share, 6)
        split.treasury_amount = round(
            bounty_amount - split.miner_amount - split.validator_amount, 6
        )

        record = PayoutRecord(
            report_id=report_id,
            platform=platform,
            task_id=task_id,
            fingerprint=fingerprint,
            miner_hotkey=miner_hotkey,
            validator_id=validator_id,
            bounty_amount=bounty_amount,
            currency=currency,
            split=split,
            status="computed",
            detected_at=time.time(),
        )
        self._payouts[report_id] = record
        self._save()

        return split

    def mark_distributed(self, report_id: str) -> bool:
        """Mark a payout as successfully distributed."""
        record = self._payouts.get(report_id)
        if not record:
            return False
        record.status = "distributed"
        record.distributed_at = time.time()
        self._save()
        return True

    def mark_failed(self, report_id: str, reason: str = "") -> bool:
        """Mark a payout as failed."""
        record = self._payouts.get(report_id)
        if not record:
            return False
        record.status = f"failed: {reason}" if reason else "failed"
        self._save()
        return True

    def get_payout(self, report_id: str) -> Optional[PayoutRecord]:
        return self._payouts.get(report_id)

    def list_payouts(
        self,
        miner_hotkey: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[PayoutRecord]:
        """List payouts, optionally filtered."""
        records = list(self._payouts.values())
        if miner_hotkey:
            records = [r for r in records if r.miner_hotkey == miner_hotkey]
        if status:
            records = [r for r in records if r.status == status]
        return records

    def total_distributed(self, miner_hotkey: Optional[str] = None) -> float:
        """Total bounty amount distributed (optionally per miner)."""
        records = self.list_payouts(miner_hotkey=miner_hotkey, status="distributed")
        return sum(r.bounty_amount for r in records)

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._payouts_path.exists():
            return
        try:
            data = json.loads(self._payouts_path.read_text())
            for rid, entry in data.items():
                split_data = entry.pop("split", None)
                split = RewardSplit(**split_data) if split_data else None
                self._payouts[rid] = PayoutRecord(**entry, split=split)
        except (json.JSONDecodeError, OSError, TypeError) as exc:
            logging.getLogger(__name__).warning(
                "Failed to load payouts from %s: %s — starting empty",
                self._payouts_path, exc,
            )

    def _save(self) -> None:
        data = {rid: r.to_dict() for rid, r in self._payouts.items()}
        payload = json.dumps(data, indent=2, sort_keys=True)
        tmp_path = self._payouts_path.with_suffix(self._payouts_path.suffix + ".tmp")
        tmp_path.write_text(payload)
        # H-7 fix: fsync before rename to prevent data loss on crash
        fd = os.open(str(tmp_path), os.O_RDONLY)
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp_path, self._payouts_path)
