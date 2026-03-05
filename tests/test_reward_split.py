"""Tests for reward split engine."""

import tempfile
from pathlib import Path

import pytest

from validator.bounty.reward_split import (
    RewardSplitEngine,
    RewardSplit,
    PayoutRecord,
    DEFAULT_MINER_SHARE,
    DEFAULT_VALIDATOR_SHARE,
    DEFAULT_TREASURY_SHARE,
)


class TestRewardSplitEngine:
    """Tests for reward split computation and tracking."""

    def _make_engine(self, tmp_path: Path) -> RewardSplitEngine:
        return RewardSplitEngine(data_dir=tmp_path / "rewards")

    def test_basic_split(self, tmp_path):
        engine = self._make_engine(tmp_path)
        split = engine.compute_split(
            report_id="rpt-001",
            platform="immunefi",
            task_id="task-1",
            fingerprint="0xfp1",
            miner_hotkey="miner-a",
            validator_id="val-0",
            bounty_amount=10000.0,
            currency="USD",
        )
        assert split.miner_amount == pytest.approx(7000.0)
        assert split.validator_amount == pytest.approx(2000.0)
        assert split.treasury_amount == pytest.approx(1000.0)
        assert split.total_amount == 10000.0
        assert split.currency == "USD"

    def test_zero_bounty(self, tmp_path):
        engine = self._make_engine(tmp_path)
        split = engine.compute_split(
            report_id="rpt-002", platform="code4rena",
            task_id="t2", fingerprint="0xfp2",
            miner_hotkey="m", validator_id="v",
            bounty_amount=0.0,
        )
        assert split.miner_amount == 0.0
        assert split.validator_amount == 0.0
        assert split.treasury_amount == 0.0

    def test_negative_bounty_rejected(self, tmp_path):
        engine = self._make_engine(tmp_path)
        with pytest.raises(ValueError, match="non-negative"):
            engine.compute_split(
                report_id="rpt-003", platform="immunefi",
                task_id="t3", fingerprint="0xfp3",
                miner_hotkey="m", validator_id="v",
                bounty_amount=-100.0,
            )

    def test_mark_distributed(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.compute_split(
            report_id="rpt-004", platform="immunefi",
            task_id="t4", fingerprint="0xfp4",
            miner_hotkey="m", validator_id="v",
            bounty_amount=5000.0,
        )
        assert engine.mark_distributed("rpt-004")
        record = engine.get_payout("rpt-004")
        assert record.status == "distributed"

    def test_mark_failed(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.compute_split(
            report_id="rpt-005", platform="immunefi",
            task_id="t5", fingerprint="0xfp5",
            miner_hotkey="m", validator_id="v",
            bounty_amount=1000.0,
        )
        assert engine.mark_failed("rpt-005", "payment timeout")
        record = engine.get_payout("rpt-005")
        assert "failed" in record.status

    def test_list_by_miner(self, tmp_path):
        engine = self._make_engine(tmp_path)
        for i in range(3):
            engine.compute_split(
                report_id=f"rpt-{i}", platform="immunefi",
                task_id=f"t{i}", fingerprint=f"fp{i}",
                miner_hotkey="miner-x" if i < 2 else "miner-y",
                validator_id="v", bounty_amount=1000.0 * (i + 1),
            )
        assert len(engine.list_payouts(miner_hotkey="miner-x")) == 2
        assert len(engine.list_payouts(miner_hotkey="miner-y")) == 1

    def test_total_distributed(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.compute_split(
            report_id="r1", platform="immunefi",
            task_id="t1", fingerprint="fp1",
            miner_hotkey="m", validator_id="v",
            bounty_amount=5000.0,
        )
        engine.mark_distributed("r1")
        engine.compute_split(
            report_id="r2", platform="immunefi",
            task_id="t2", fingerprint="fp2",
            miner_hotkey="m", validator_id="v",
            bounty_amount=3000.0,
        )
        # r2 not distributed
        assert engine.total_distributed() == 5000.0

    def test_persistence(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.compute_split(
            report_id="rpt-persist", platform="immunefi",
            task_id="t-persist", fingerprint="fp-persist",
            miner_hotkey="m-persist", validator_id="v",
            bounty_amount=2000.0,
        )
        # Create new engine from same path
        engine2 = self._make_engine(tmp_path)
        record = engine2.get_payout("rpt-persist")
        assert record is not None
        assert record.bounty_amount == 2000.0
        assert record.split is not None
        assert record.split.miner_amount == pytest.approx(1400.0)

    def test_shares_sum_to_one(self):
        total = DEFAULT_MINER_SHARE + DEFAULT_VALIDATOR_SHARE + DEFAULT_TREASURY_SHARE
        assert abs(total - 1.0) < 1e-9

    def test_mark_nonexistent_returns_false(self, tmp_path):
        engine = self._make_engine(tmp_path)
        assert not engine.mark_distributed("nonexistent")
        assert not engine.mark_failed("nonexistent")
