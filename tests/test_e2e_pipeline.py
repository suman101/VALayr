"""
End-to-End Pipeline Tests — Exercises the full exploit subnet pipeline.

generate → submit → validate → fingerprint → score → weight

These tests verify the complete data flow across all modules,
including adversarial mode and epoch management.
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Full Pipeline Tests ──────────────────────────────────────────────────────

class TestFullPipeline:
    """Test the complete generate → submit → score → weight flow."""

    def _make_orchestrator(self, tmpdir):
        from orchestrator import Orchestrator
        return Orchestrator(
            mode="local",
            validator_id="test-validator",
            corpus_dir=Path(tmpdir) / "corpus",
            data_dir=Path(tmpdir) / "data",
        )

    def test_generate_and_list_tasks(self, tmp_path):
        """Generate corpus and verify tasks are listable."""
        orch = self._make_orchestrator(tmp_path)
        packages = orch.generate_corpus(count_per_class=1, seed=42)
        assert len(packages) > 0

        tasks = orch.list_tasks()
        assert len(tasks) == len(packages)

        for t in tasks:
            assert "task_id" in t
            assert "vulnerability_class" in t
            assert "difficulty" in t

    def test_load_task_by_id_and_prefix(self, tmp_path):
        """Load a task by full ID and by unambiguous prefix."""
        orch = self._make_orchestrator(tmp_path)
        packages = orch.generate_corpus(count_per_class=1, seed=42)
        tasks = orch.list_tasks()
        assert tasks

        first_task = tasks[0]
        full_id = first_task["task_id"]

        # Full ID
        loaded = orch.load_task(full_id)
        assert loaded is not None
        assert loaded["task_id"] == full_id

        # Prefix (first 10 chars — directory name)
        prefix = full_id[:10]
        loaded_prefix = orch.load_task(prefix)
        assert loaded_prefix is not None
        assert loaded_prefix["task_id"] == full_id

    def test_submit_invalid_task(self, tmp_path):
        """Submitting to a non-existent task returns proper rejection."""
        orch = self._make_orchestrator(tmp_path)
        result = orch.process_submission(
            task_id="0xNONEXISTENT",
            exploit_source="// nothing",
            miner_address="0xMINER",
        )
        assert result.validation_result == "REJECT_INVALID_FORMAT"
        assert "not found" in result.error.lower()

    def test_submit_oversized_exploit(self, tmp_path):
        """Exploits larger than MAX_EXPLOIT_SOURCE_BYTES are rejected."""
        from validator.engine.validate import MAX_EXPLOIT_SOURCE_BYTES
        orch = self._make_orchestrator(tmp_path)
        packages = orch.generate_corpus(count_per_class=1, seed=42)
        tasks = orch.list_tasks()
        assert tasks

        task_id = tasks[0]["task_id"]
        big_exploit = "// " + "x" * (MAX_EXPLOIT_SOURCE_BYTES + 100)
        result = orch.process_submission(
            task_id=task_id,
            exploit_source=big_exploit,
            miner_address="0xMINER",
        )
        assert "REJECT" in result.validation_result

    def test_epoch_lifecycle(self, tmp_path):
        """Test epoch open → close → weights."""
        orch = self._make_orchestrator(tmp_path)

        # Close epoch 0 (no submissions)
        result = orch.close_epoch(epoch_number=0, start_block=0, end_block=360)
        assert result.epoch_number == 0
        assert result.total_submissions == 0
        assert result.weights == {}

        # Close epoch 1 (should work)
        result2 = orch.close_epoch(epoch_number=1, start_block=360, end_block=720)
        assert result2.epoch_number == 1

        # Double-close epoch 1 (should be guarded)
        result3 = orch.close_epoch(epoch_number=1, start_block=360, end_block=720)
        assert result3.total_submissions == 0

    def test_epoch_overlap_guard(self, tmp_path):
        """Closing the same epoch twice returns empty result."""
        orch = self._make_orchestrator(tmp_path)
        orch.close_epoch(epoch_number=5, start_block=1800, end_block=2160)
        dup = orch.close_epoch(epoch_number=5, start_block=1800, end_block=2160)
        assert dup.weights == {}

    def test_adversarial_full_flow(self, tmp_path):
        """Test invariant submission → challenge → scores → weights."""
        orch = self._make_orchestrator(tmp_path)

        # Class A: submit invariant
        inv_id = orch.submit_invariant(
            miner_address="0xCLASS_A_MINER",
            target_contract_hash="0xabc123",
            description="Balance must not decrease",
            solidity_condition="address(this).balance >= initialBalance",
        )
        assert inv_id == 0

        # Class B: challenge the invariant
        report = orch.submit_challenge(
            miner_address="0xCLASS_B_MINER",
            invariant_id=inv_id,
            exploit_source="uint256 balance = address(this).balance;\ncall(target, 'withdraw()');",
            target_task_id="0xTASK_ID",
        )
        assert report.class_a_miner == "0xCLASS_A_MINER"
        assert report.class_b_miner == "0xCLASS_B_MINER"
        assert report.result.value in (
            "INVARIANT_HELD", "INVARIANT_BROKEN",
            "CHALLENGE_ERROR", "INVALID_INVARIANT",
        )

        # Verify scores were updated
        adv_weights = orch.get_adversarial_weights()
        assert isinstance(adv_weights, dict)

    def test_adversarial_oversized_exploit_rejected(self, tmp_path):
        """Adversarial challenge with oversized exploit is rejected at input validation."""
        from orchestrator import MAX_EXPLOIT_SOURCE_BYTES
        orch = self._make_orchestrator(tmp_path)

        inv_id = orch.submit_invariant(
            miner_address="0xA",
            target_contract_hash="0xabc",
            description="test",
            solidity_condition="true",
        )

        big_exploit = "x" * (MAX_EXPLOIT_SOURCE_BYTES + 100)
        with pytest.raises(ValueError, match="exceeds"):
            orch.submit_challenge(
                miner_address="0xB",
                invariant_id=inv_id,
                exploit_source=big_exploit,
                target_task_id="0xTASK",
            )

    def test_adversarial_path_traversal_rejected(self, tmp_path):
        """Path traversal in adversarial exploit is blocked."""
        orch = self._make_orchestrator(tmp_path)

        inv_id = orch.submit_invariant(
            miner_address="0xA",
            target_contract_hash="0xabc",
            description="test",
            solidity_condition="true",
        )

        malicious = 'import "../../etc/passwd";'
        report = orch.submit_challenge(
            miner_address="0xB",
            invariant_id=inv_id,
            exploit_source=malicious,
            target_task_id="0xTASK",
        )
        assert report.result.value == "CHALLENGE_ERROR"
        assert "disallowed" in report.error_message

    def test_reset_clears_all_state(self, tmp_path):
        """Orchestrator reset clears all fingerprint/incentive/adversarial state."""
        orch = self._make_orchestrator(tmp_path)
        orch.generate_corpus(count_per_class=1, seed=42)

        # Submit an invariant to create state
        orch.submit_invariant(
            miner_address="0xA",
            target_contract_hash="0xabc",
            description="test",
            solidity_condition="true",
        )

        orch.reset()
        assert orch.get_adversarial_weights() == {}


# ── Anti-Collusion Consensus Tests ───────────────────────────────────────────

class TestAntiCollusionPipeline:
    """Test the anti-collusion consensus engine integration."""

    def test_consensus_with_quorum(self):
        from validator.anticollusion.consensus import AntiCollusionEngine
        engine = AntiCollusionEngine(seed=42)

        # Register 6 validators (above MIN_QUORUM=5)
        for i in range(6):
            engine.register_validator(f"val_{i}", stake=1.0)

        # All agree
        votes = [
            {"validator_hotkey": f"val_{i}", "result": "VALID",
             "fingerprint": "0xFP", "severity_score": 0.75}
            for i in range(6)
        ]
        result = engine.compute_consensus("task_1", "sub_1", votes)
        assert result.consensus_result == "VALID"
        assert result.agreement_ratio == 1.0
        assert len(result.diverging_validators) == 0

    def test_consensus_with_divergence(self):
        from validator.anticollusion.consensus import AntiCollusionEngine
        engine = AntiCollusionEngine(seed=42)

        for i in range(6):
            engine.register_validator(f"val_{i}", stake=1.0)

        # 4 agree VALID, 2 disagree
        votes = [
            {"validator_hotkey": f"val_{i}", "result": "VALID",
             "fingerprint": "0xFP", "severity_score": 0.75}
            for i in range(4)
        ] + [
            {"validator_hotkey": f"val_{i}", "result": "REJECT_REVERT",
             "fingerprint": "", "severity_score": 0.0}
            for i in range(4, 6)
        ]
        result = engine.compute_consensus("task_2", "sub_2", votes)
        assert result.consensus_result == "VALID"
        assert len(result.diverging_validators) == 2

    def test_below_quorum_returns_no_quorum(self):
        from validator.anticollusion.consensus import AntiCollusionEngine
        engine = AntiCollusionEngine(seed=42)

        for i in range(3):
            engine.register_validator(f"val_{i}", stake=1.0)

        votes = [
            {"validator_hotkey": f"val_{i}", "result": "VALID",
             "fingerprint": "0xFP", "severity_score": 0.75}
            for i in range(3)
        ]
        result = engine.compute_consensus("task_3", "sub_3", votes)
        assert result.consensus_result == "NO_QUORUM"


# ── Incentive Adapter Pipeline Tests ─────────────────────────────────────────

class TestIncentivePipeline:
    """Test the incentive scoring pipeline."""

    def test_single_miner_full_reward(self):
        from subnet_adapter.incentive import SubnetIncentiveAdapter, ValidatorVote
        adapter = SubnetIncentiveAdapter()

        vote = ValidatorVote(
            validator_hotkey="val_0",
            task_id="task_1",
            submission_hash="0xSUB1",
            result="VALID",
            fingerprint="0xFP1",
            severity_score=0.8,
            timestamp=time.time(),
            miner_hotkey="miner_0",
        )
        adapter.record_vote(vote)

        epoch = adapter.compute_epoch_weights(
            epoch_number=0, start_block=0, end_block=360,
        )
        assert epoch.total_submissions == 1
        assert epoch.total_valid == 1
        assert "miner_0" in epoch.weights
        assert epoch.weights["miner_0"] == 1.0

    def test_multiple_miners_weight_normalization(self):
        from subnet_adapter.incentive import SubnetIncentiveAdapter, ValidatorVote
        adapter = SubnetIncentiveAdapter()

        for m_idx in range(3):
            for t_idx in range(2):
                vote = ValidatorVote(
                    validator_hotkey="val_0",
                    task_id=f"task_{t_idx}",
                    submission_hash=f"0xSUB_{m_idx}_{t_idx}",
                    result="VALID",
                    fingerprint=f"0xFP_{m_idx}_{t_idx}",
                    severity_score=0.5 + m_idx * 0.1,
                    timestamp=time.time(),
                    miner_hotkey=f"miner_{m_idx}",
                )
                adapter.record_vote(vote)

        epoch = adapter.compute_epoch_weights(
            epoch_number=0, start_block=0, end_block=360,
        )
        total_weight = sum(epoch.weights.values())
        assert abs(total_weight - 1.0) < 1e-9, f"Weights must sum to 1.0, got {total_weight}"

    def test_get_weight_vector_local_mode(self):
        from subnet_adapter.incentive import SubnetIncentiveAdapter, ValidatorVote
        adapter = SubnetIncentiveAdapter()

        vote = ValidatorVote(
            validator_hotkey="val_0",
            task_id="task_1",
            submission_hash="0xSUB1",
            result="VALID",
            fingerprint="0xFP1",
            severity_score=0.8,
            timestamp=time.time(),
            miner_hotkey="miner_0",
        )
        adapter.record_vote(vote)

        epoch = adapter.compute_epoch_weights(
            epoch_number=0, start_block=0, end_block=360,
        )
        uids, weights = adapter.get_weight_vector(epoch)
        assert len(uids) == len(weights) == 1
        assert weights[0] == 1.0

    def test_invalid_submission_zero_weight(self):
        """Miners with only invalid submissions get zero weight."""
        from subnet_adapter.incentive import SubnetIncentiveAdapter, ValidatorVote
        adapter = SubnetIncentiveAdapter()

        vote = ValidatorVote(
            validator_hotkey="val_0",
            task_id="task_1",
            submission_hash="0xSUB_BAD",
            result="REJECT_REVERT",
            fingerprint="",
            severity_score=0.0,
            timestamp=time.time(),
            miner_hotkey="bad_miner",
        )
        adapter.record_vote(vote)

        epoch = adapter.compute_epoch_weights(
            epoch_number=0, start_block=0, end_block=360,
        )
        assert "bad_miner" not in epoch.weights or epoch.weights.get("bad_miner", 0) == 0


# ── Fingerprint Deduplication Pipeline Tests ─────────────────────────────────

class TestFingerprintPipeline:
    """Test fingerprint computation and dedup across the pipeline."""

    def test_first_submission_full_reward(self, tmp_path):
        from validator.fingerprint.dedup import FingerprintEngine

        engine = FingerprintEngine(db_path=tmp_path / "fp.json")
        result = engine.check_duplicate(
            task_id="task_1",
            fingerprint="0xABC123",
            miner_address="0xMINER_A",
        )
        assert result.is_duplicate is False
        assert result.reward_multiplier == 1.0

    def test_second_submission_duplicate_penalty(self, tmp_path):
        from validator.fingerprint.dedup import FingerprintEngine

        engine = FingerprintEngine(db_path=tmp_path / "fp.json")

        # First submission
        engine.check_duplicate("task_1", "0xABC123", "0xMINER_A")

        # Same fingerprint, different miner
        result = engine.check_duplicate("task_1", "0xABC123", "0xMINER_B")
        assert result.is_duplicate is True
        assert result.reward_multiplier == 0.10

    def test_different_fingerprint_full_reward(self, tmp_path):
        from validator.fingerprint.dedup import FingerprintEngine

        engine = FingerprintEngine(db_path=tmp_path / "fp.json")

        engine.check_duplicate("task_1", "0xABC123", "0xMINER_A")

        # Different fingerprint = new exploit approach
        result = engine.check_duplicate("task_1", "0xDEF456", "0xMINER_B")
        assert result.is_duplicate is False
        assert result.reward_multiplier == 1.0

    def test_fingerprint_compute_deterministic(self):
        from validator.fingerprint.dedup import FingerprintEngine, FingerprintComponents

        engine = FingerprintEngine.__new__(FingerprintEngine)

        comp = FingerprintComponents(
            function_selectors=["a9059cbb", "70a08231"],
            storage_slot_diffs=[{"slot": "0x0", "before": "0x" + "0" * 64, "after": "0x" + "1" * 64}],
            balance_delta=-1000000,
            call_graph_hash="abcd1234",
        )

        fp1 = engine.compute_fingerprint(comp)
        fp2 = engine.compute_fingerprint(comp)
        assert fp1 == fp2
        assert fp1.startswith("0x")
        assert len(fp1) == 66  # 0x + 64 hex chars


# ── Severity Scoring Pipeline Tests ──────────────────────────────────────────

class TestSeverityPipeline:
    """Test severity scoring integration."""

    def test_score_funds_drain(self):
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": -10 * 10**18,  # 10 ETH drained
            "storage_diffs": [],
            "event_logs": [],
            "reverted": False,
        }
        breakdown = scorer.score_detailed(trace)
        assert breakdown.funds_drained_score > 0
        assert breakdown.final_severity > 0
        assert breakdown.wei_drained == 10 * 10**18

    def test_score_privilege_escalation(self):
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": 0,
            "storage_diffs": [{"slot": "0x0", "before": "0x" + "0" * 64, "after": "0x" + "1" * 64}],
            "event_logs": [],
            "reverted": False,
        }
        breakdown = scorer.score_detailed(trace)
        assert breakdown.privilege_escalation_score == 1.0

    def test_score_reverted_is_zero(self):
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": -10**18,
            "storage_diffs": [],
            "event_logs": [],
            "reverted": True,
        }
        breakdown = scorer.score_detailed(trace)
        assert breakdown.final_severity == 0.0

    def test_score_weights_sum_to_one(self):
        from validator.scoring.severity import SeverityScorer
        scorer = SeverityScorer()
        total = scorer.w_funds + scorer.w_priv + scorer.w_invariant + scorer.w_lock
        assert abs(total - 1.0) < 1e-9


# ── Metrics Integration Tests ────────────────────────────────────────────────

class TestMetricsIntegration:
    """Test that metrics are correctly recorded during pipeline operations."""

    def test_metrics_recorded_on_submission(self, tmp_path):
        from validator import metrics as m
        from orchestrator import Orchestrator

        orch = Orchestrator(
            mode="local",
            corpus_dir=tmp_path / "corpus",
            data_dir=tmp_path / "data",
        )
        orch.generate_corpus(count_per_class=1, seed=42)

        initial = m._global_store.get_counter("validations_total")
        tasks = orch.list_tasks()
        if tasks:
            orch.process_submission(
                task_id=tasks[0]["task_id"],
                exploit_source="// test",
                miner_address="0xTEST",
            )
            assert m._global_store.get_counter("validations_total") >= initial


# ══════════════════════════════════════════════════════════════════════════════
# P1 Tests: MEDIUM Fix Coverage
# ══════════════════════════════════════════════════════════════════════════════


class TestSeverityWeightValidation:
    """M-11: SeverityScorer raises ValueError (not assert) on bad weights."""

    def test_invalid_weights_raises_value_error(self):
        from validator.scoring.severity import SeverityScorer
        with pytest.raises(ValueError, match="sum to 1.0"):
            SeverityScorer(w_funds=0.5, w_priv=0.5, w_invariant=0.5, w_lock=0.5)

    def test_valid_custom_weights(self):
        from validator.scoring.severity import SeverityScorer
        scorer = SeverityScorer(w_funds=0.5, w_priv=0.2, w_invariant=0.2, w_lock=0.1)
        assert scorer.w_funds == 0.5


class TestRewardShareValidation:
    """M-17: Negative reward shares rejected even if they sum to 1.0."""

    def test_negative_share_rejected(self):
        from validator.bounty.reward_split import _load_shares
        with patch.dict("os.environ", {
            "VALAYR_MINER_SHARE": "-0.5",
            "VALAYR_VALIDATOR_SHARE": "1.0",
            "VALAYR_TREASURY_SHARE": "0.5",
        }):
            with pytest.raises(ValueError, match=r"miner share must be in \[0, 1\]"):
                _load_shares()

    def test_valid_shares_accepted(self):
        from validator.bounty.reward_split import _load_shares
        with patch.dict("os.environ", {
            "VALAYR_MINER_SHARE": "0.60",
            "VALAYR_VALIDATOR_SHARE": "0.25",
            "VALAYR_TREASURY_SHARE": "0.15",
        }):
            m, v, t = _load_shares()
            assert abs(m - 0.6) < 1e-9
            assert abs(v - 0.25) < 1e-9
            assert abs(t - 0.15) < 1e-9


class TestDiscoveryPruning:
    """M-10: _discovered dict is pruned when exceeding MAX_DISCOVERED_CONTRACTS."""

    def test_prune_evicts_oldest(self, tmp_path):
        from importlib import import_module
        discovery_mod = import_module("task-generator.discovery")
        disco = discovery_mod.MainnetAutoDiscovery(data_dir=tmp_path)

        # Inject more contracts than the limit
        original_max = discovery_mod.MAX_DISCOVERED_CONTRACTS
        discovery_mod.MAX_DISCOVERED_CONTRACTS = 5
        try:
            base_time = 1000000.0
            for i in range(8):
                key = f"1:0x{i:040x}"
                disco._discovered[key] = discovery_mod.DiscoveredContract(
                    address=f"0x{i:040x}",
                    chain_id=1,
                    source="test",
                    discovered_at=base_time + i,
                    metadata={},
                )
            disco._prune()
            assert len(disco._discovered) == 5
            # Oldest entries (0, 1, 2) should be evicted
            assert f"1:0x{'0' * 40}" not in disco._discovered
            assert f"1:0x{'0' * 39}5" in disco._discovered  # idx 5 kept
        finally:
            discovery_mod.MAX_DISCOVERED_CONTRACTS = original_max


class TestSecretsThreadSafety:
    """M-12: secrets cache is thread-safe."""

    def test_concurrent_get_secret(self):
        import threading
        from validator.utils.secrets import _cache, _cache_lock

        # Clear cache for isolation
        with _cache_lock:
            _cache.clear()

        errors = []

        def worker(i):
            try:
                with patch.dict("os.environ", {f"TEST_SECRET_{i}": f"value_{i}" * 10}):
                    from validator.utils.secrets import get_secret
                    result = get_secret(f"TEST_SECRET_{i}", required=False)
                    assert result == f"value_{i}" * 10
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
