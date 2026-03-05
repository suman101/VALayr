"""Tests for orchestrator integration of anti-bypass, bounty, and uniqueness."""

import hashlib
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from orchestrator import Orchestrator, SubmissionResult
from validator.bounty.anti_bypass import AntiBypassEngine, SubnetReceipt
from validator.bounty.identity import IdentityStore
from validator.bounty.platform import (
    BountyReport,
    SubmissionReceipt,
    SubmissionStatus,
    create_default_registry,
)
from validator.bounty.reward_split import RewardSplitEngine
from validator.scoring.uniqueness import UniquenessScorer
from validator.utils.difficulty import get_epoch_config


class TestOrchestratorAntiBypass:
    """Test that anti-bypass is wired into the orchestrator."""

    def test_orchestrator_has_anti_bypass(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            assert hasattr(orch, "anti_bypass")
            assert isinstance(orch.anti_bypass, AntiBypassEngine)

    def test_orchestrator_has_identity_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            assert hasattr(orch, "identity_store")
            assert isinstance(orch.identity_store, IdentityStore)

    def test_orchestrator_has_reward_split(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            assert hasattr(orch, "reward_split")
            assert isinstance(orch.reward_split, RewardSplitEngine)

    def test_orchestrator_has_uniqueness_scorer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            assert hasattr(orch, "uniqueness_scorer")
            assert isinstance(orch.uniqueness_scorer, UniquenessScorer)


class TestOrchestratorBountySubmission:
    """Test bounty submission pipeline."""

    def _make_orch(self, tmpdir):
        return Orchestrator(
            data_dir=Path(tmpdir) / "data",
            corpus_dir=Path(tmpdir) / "corpus",
        )

    def test_submit_no_receipt_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orch(tmpdir)
            result = orch.submit_to_bounty_platforms(
                task_id="t1", miner_address="m1",
                fingerprint="0xnope", severity_score=0.8,
                exploit_source="code", target_address="0xabc",
            )
            assert result == []

    def test_submit_with_receipt_but_no_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orch(tmpdir)
            # Record a receipt first
            orch.anti_bypass.record_subnet_receipt(
                task_id="t1", miner_hotkey="m1", fingerprint="0xfp1",
            )
            result = orch.submit_to_bounty_platforms(
                task_id="t1", miner_address="m1",
                fingerprint="0xfp1", severity_score=0.8,
                exploit_source="code",
            )
            assert result == []  # No identity linked

    def test_bypass_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orch(tmpdir)
            orch.anti_bypass.record_subnet_receipt(
                task_id="t1", miner_hotkey="m1", fingerprint="0xfp1",
            )
            # Platform timestamp way before subnet — bypass
            violation = orch.check_platform_bypass(
                fingerprint="0xfp1",
                platform="immunefi",
                platform_timestamp=int(time.time()) - 7200,  # 2 hours ago
            )
            assert violation is not None
            assert violation["severity"] in ("violation", "critical")

    def test_bypass_check_no_violation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orch(tmpdir)
            orch.anti_bypass.record_subnet_receipt(
                task_id="t1", miner_hotkey="m1", fingerprint="0xfp2",
            )
            # Platform timestamp after subnet — legitimate
            result = orch.check_platform_bypass(
                fingerprint="0xfp2",
                platform="immunefi",
                platform_timestamp=int(time.time()) + 60,
            )
            assert result is None


class TestOrchestratorPayoutProcessing:
    """Test bounty payout and reward split."""

    def test_process_bounty_payout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            split = orch.process_bounty_payout(
                report_id="rpt-1",
                platform="immunefi",
                task_id="t1",
                fingerprint="fp1",
                miner_address="miner-1",
                bounty_amount=10000.0,
                currency="USDC",
            )
            assert split["miner_amount"] == pytest.approx(7000.0)
            assert split["validator_amount"] == pytest.approx(2000.0)
            assert split["treasury_amount"] == pytest.approx(1000.0)


class TestOrchestratorRefreshCorpus:
    """Test corpus refresh with difficulty ramping."""

    def test_refresh_epoch_1(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            summary = orch.refresh_corpus(epoch=1)
            assert summary["epoch"] == 1
            assert summary["max_difficulty"] == 1
            assert summary["mainnet_ratio"] == 0.0
            assert summary["synthetic_tasks"] > 0

    def test_refresh_epoch_100(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            summary = orch.refresh_corpus(epoch=100)
            assert summary["max_difficulty"] == 2
            assert summary["mainnet_ratio"] == 0.3

    def test_reset_clears_uniqueness(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            orch.uniqueness_scorer.score_submission("t1", "code", "m1")
            orch.reset()
            assert len(orch.uniqueness_scorer._submissions) == 0
            assert orch._current_epoch == 0

    def test_close_epoch_updates_current_epoch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = Orchestrator(
                data_dir=Path(tmpdir) / "data",
                corpus_dir=Path(tmpdir) / "corpus",
            )
            orch.close_epoch(5, 100, 200)
            assert orch._current_epoch == 5
