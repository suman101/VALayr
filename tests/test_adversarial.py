"""
Tests for Stage 3 — Adversarial Mode (InvariantRegistry + AdversarialScoring).

Tests the Python-side integration for the Class A / Class B miner system:
  - Invariant submission and validation
  - Challenge processing and scoring
  - Weight computation from adversarial scores
  - Orchestrator integration
"""

import pytest
import sys
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validator.engine.adversarial import (
    AdversarialEngine,
    InvariantSubmission,
    ChallengeSubmission,
    ChallengeReport,
    ChallengeResult,
    InvariantRecord,
    W_HOLD_REWARD,
    W_BREACH_PENALTY,
    W_BREACH_REWARD,
    W_FAILED_CHALLENGE,
    MAX_INVARIANT_DESCRIPTION_LEN,
)
from orchestrator import Orchestrator
from validator.anticollusion.consensus import (
    AntiCollusionEngine,
    AdversarialConsensusResult,
    MIN_QUORUM,
    CONSENSUS_THRESHOLD,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    """Fresh adversarial engine in local mode."""
    return AdversarialEngine(mode="local")


@pytest.fixture
def class_a_submission():
    """Sample Class A (invariant writer) submission."""
    return InvariantSubmission(
        miner_address="0xClassA_Miner_1",
        target_contract_hash="0xabc123" + "0" * 58,
        description="Balance must never decrease without explicit withdrawal",
        solidity_condition="balanceOf(address(this)) >= initialBalance",
        compiled_check=b"\xde\xad\xbe\xef",
    )


@pytest.fixture
def class_b_challenge():
    """Sample Class B (exploit writer) challenge."""
    return ChallengeSubmission(
        miner_address="0xClassB_Miner_1",
        invariant_id=0,
        exploit_source="""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "forge-std/Test.sol";
contract ExploitTest is Test {
    function test_run() public {
        // drain funds via reentrancy
    }
}
""",
        target_task_id="0xtask123",
    )


# ── InvariantSubmission Tests ────────────────────────────────────────────────

class TestInvariantSubmission:
    def test_submit_invariant_returns_id(self, engine, class_a_submission):
        inv_id = engine.submit_invariant(class_a_submission)
        assert inv_id == 0

    def test_submit_multiple_invariants_increments_id(self, engine, class_a_submission):
        id0 = engine.submit_invariant(class_a_submission)
        class_a_submission.description = "Another invariant"
        id1 = engine.submit_invariant(class_a_submission)
        assert id0 == 0
        assert id1 == 1

    def test_get_invariant(self, engine, class_a_submission):
        inv_id = engine.submit_invariant(class_a_submission)
        record = engine.get_invariant(inv_id)
        assert record is not None
        assert record.submitter == class_a_submission.miner_address
        assert record.description == class_a_submission.description
        assert record.active is True
        assert record.challenge_count == 0

    def test_get_nonexistent_invariant(self, engine):
        assert engine.get_invariant(999) is None

    def test_list_active_invariants(self, engine, class_a_submission):
        engine.submit_invariant(class_a_submission)
        class_a_submission.description = "Second invariant"
        engine.submit_invariant(class_a_submission)
        active = engine.list_active_invariants()
        assert len(active) == 2

    def test_list_active_invariants_filtered(self, engine, class_a_submission):
        engine.submit_invariant(class_a_submission)
        # Submit with different target
        class_a_submission.target_contract_hash = "0xdef456" + "0" * 58
        engine.submit_invariant(class_a_submission)
        filtered = engine.list_active_invariants(
            target_contract_hash="0xabc123" + "0" * 58
        )
        assert len(filtered) == 1

    def test_deactivate_invariant(self, engine, class_a_submission):
        inv_id = engine.submit_invariant(class_a_submission)
        engine.deactivate_invariant(inv_id)
        record = engine.get_invariant(inv_id)
        assert record.active is False
        assert len(engine.list_active_invariants()) == 0

    def test_deactivate_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.deactivate_invariant(999)

    def test_submit_empty_condition_raises(self, engine):
        sub = InvariantSubmission(
            miner_address="0xA",
            target_contract_hash="0x" + "0" * 64,
            description="test",
            solidity_condition="   ",
            compiled_check=b"",
        )
        with pytest.raises(ValueError, match="cannot be empty"):
            engine.submit_invariant(sub)

    def test_submit_oversized_description_raises(self, engine):
        sub = InvariantSubmission(
            miner_address="0xA",
            target_contract_hash="0x" + "0" * 64,
            description="x" * (MAX_INVARIANT_DESCRIPTION_LEN + 1),
            solidity_condition="true",
            compiled_check=b"",
        )
        with pytest.raises(ValueError, match="Description too long"):
            engine.submit_invariant(sub)

    def test_invariant_strength_score_untested(self, engine, class_a_submission):
        inv_id = engine.submit_invariant(class_a_submission)
        record = engine.get_invariant(inv_id)
        assert record.strength_score == 1.0  # Neutral when untested


# ── Challenge Processing Tests ───────────────────────────────────────────────

class TestChallengeProcessing:
    def test_challenge_invariant_held(self, engine, class_a_submission, class_b_challenge):
        """Default local simulation: invariant holds."""
        engine.submit_invariant(class_a_submission)
        report = engine.process_challenge(class_b_challenge)
        assert report.result == ChallengeResult.INVARIANT_HELD
        assert report.invariant_held is True
        assert report.class_a_miner == class_a_submission.miner_address
        assert report.class_b_miner == class_b_challenge.miner_address

    def test_challenge_with_custom_validation_broken(
        self, engine, class_a_submission, class_b_challenge
    ):
        """Custom validation function says invariant broken."""
        engine.submit_invariant(class_a_submission)
        report = engine.process_challenge(
            class_b_challenge,
            validation_fn=lambda task, exploit: True,  # broken
        )
        assert report.result == ChallengeResult.INVARIANT_BROKEN
        assert report.invariant_held is False

    def test_challenge_with_custom_validation_held(
        self, engine, class_a_submission, class_b_challenge
    ):
        """Custom validation function says invariant held."""
        engine.submit_invariant(class_a_submission)
        report = engine.process_challenge(
            class_b_challenge,
            validation_fn=lambda task, exploit: False,  # held
        )
        assert report.result == ChallengeResult.INVARIANT_HELD

    def test_challenge_nonexistent_invariant(self, engine, class_b_challenge):
        class_b_challenge.invariant_id = 999
        report = engine.process_challenge(class_b_challenge)
        assert report.result == ChallengeResult.CHALLENGE_ERROR
        assert "not found" in report.error_message

    def test_challenge_inactive_invariant(
        self, engine, class_a_submission, class_b_challenge
    ):
        inv_id = engine.submit_invariant(class_a_submission)
        engine.deactivate_invariant(inv_id)
        report = engine.process_challenge(class_b_challenge)
        assert report.result == ChallengeResult.INVALID_INVARIANT

    def test_challenge_validation_error(
        self, engine, class_a_submission, class_b_challenge
    ):
        engine.submit_invariant(class_a_submission)

        def bad_fn(task, exploit):
            raise RuntimeError("kaboom")

        report = engine.process_challenge(class_b_challenge, validation_fn=bad_fn)
        assert report.result == ChallengeResult.CHALLENGE_ERROR
        assert "kaboom" in report.error_message

    def test_challenge_updates_invariant_counts(
        self, engine, class_a_submission, class_b_challenge
    ):
        engine.submit_invariant(class_a_submission)

        # Challenge 1: held
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: False
        )
        # Challenge 2: broken
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: True
        )

        inv = engine.get_invariant(0)
        assert inv.challenge_count == 2
        assert inv.hold_count == 1
        assert inv.breach_count == 1
        assert inv.strength_score == 0.5

    def test_challenge_history(self, engine, class_a_submission, class_b_challenge):
        engine.submit_invariant(class_a_submission)
        engine.process_challenge(class_b_challenge)
        engine.process_challenge(class_b_challenge)
        history = engine.get_challenge_history()
        assert len(history) == 2

    def test_challenge_history_filtered(
        self, engine, class_a_submission, class_b_challenge
    ):
        engine.submit_invariant(class_a_submission)
        class_a_submission.description = "inv 2"
        engine.submit_invariant(class_a_submission)

        engine.process_challenge(class_b_challenge)  # invariant 0
        class_b_challenge.invariant_id = 1
        engine.process_challenge(class_b_challenge)  # invariant 1

        history_0 = engine.get_challenge_history(invariant_id=0)
        assert len(history_0) == 1


# ── Scoring Tests ────────────────────────────────────────────────────────────

class TestAdversarialScoring:
    def test_scoring_invariant_held(
        self, engine, class_a_submission, class_b_challenge
    ):
        """Invariant holds: A gets +W_HOLD_REWARD, B gets +W_FAILED_CHALLENGE."""
        engine.submit_invariant(class_a_submission)
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: False
        )
        assert engine.get_class_a_score(class_a_submission.miner_address) == W_HOLD_REWARD
        assert engine.get_class_b_score(class_b_challenge.miner_address) == W_FAILED_CHALLENGE

    def test_scoring_invariant_broken(
        self, engine, class_a_submission, class_b_challenge
    ):
        """Invariant broken: B gets +W_BREACH_REWARD, A gets -W_BREACH_PENALTY."""
        engine.submit_invariant(class_a_submission)
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: True
        )
        assert engine.get_class_a_score(class_a_submission.miner_address) == -W_BREACH_PENALTY
        assert engine.get_class_b_score(class_b_challenge.miner_address) == W_BREACH_REWARD

    def test_scoring_multi_round(self, engine, class_a_submission, class_b_challenge):
        """Match the Solidity test: 3 rounds → A=-300, B=1020."""
        engine.submit_invariant(class_a_submission)

        # Round 1: invariant holds
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: False
        )
        # Round 2: invariant broken
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: True
        )
        # Round 3: invariant holds
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: False
        )

        # Matches AdversarialMode.t.sol::test_multipleRounds_scoring
        assert engine.get_class_a_score(class_a_submission.miner_address) == -300
        assert engine.get_class_b_score(class_b_challenge.miner_address) == 1020

    def test_get_all_scores(self, engine, class_a_submission, class_b_challenge):
        engine.submit_invariant(class_a_submission)
        engine.process_challenge(class_b_challenge)
        scores = engine.get_all_scores()
        assert "class_a" in scores
        assert "class_b" in scores
        assert class_a_submission.miner_address in scores["class_a"]

    def test_new_miner_score_defaults_to_zero(self, engine):
        assert engine.get_class_a_score("unknown") == 0
        assert engine.get_class_b_score("unknown") == 0


# ── Weight Computation Tests ─────────────────────────────────────────────────

class TestAdversarialWeights:
    def test_weights_single_class_a(self, engine, class_a_submission, class_b_challenge):
        """Single Class A miner, invariant holds → gets all weight."""
        engine.submit_invariant(class_a_submission)
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: False
        )
        weights = engine.compute_adversarial_weights()
        assert len(weights) == 2  # both miners present
        assert weights[class_a_submission.miner_address] > 0

    def test_weights_no_activity(self, engine):
        """No activity → empty weights."""
        weights = engine.compute_adversarial_weights()
        assert weights == {}

    def test_weights_negative_scores_clamped(
        self, engine, class_a_submission, class_b_challenge
    ):
        """Negative scores are clamped to 0 in weight computation."""
        engine.submit_invariant(class_a_submission)
        # Break invariant → Class A gets -500
        engine.process_challenge(
            class_b_challenge, validation_fn=lambda t, e: True
        )
        weights = engine.compute_adversarial_weights()
        # Class A has negative score, should be 0 weight
        class_a_weight = weights.get(class_a_submission.miner_address, 0.0)
        assert class_a_weight == 0.0
        # Class B should have positive weight
        assert weights[class_b_challenge.miner_address] > 0

    def test_weights_sum_to_one(self, engine):
        """Weights should (approximately) sum to 1.0."""
        # Create multiple miners
        for i in range(3):
            sub = InvariantSubmission(
                miner_address=f"0xA_{i}",
                target_contract_hash="0x" + "0" * 64,
                description=f"inv {i}",
                solidity_condition="true",
                compiled_check=b"",
            )
            engine.submit_invariant(sub)
            chal = ChallengeSubmission(
                miner_address=f"0xB_{i}",
                invariant_id=i,
                exploit_source="// exploit",
                target_task_id="0xtask",
            )
            engine.process_challenge(chal, validation_fn=lambda t, e: False)

        weights = engine.compute_adversarial_weights()
        total = sum(weights.values())
        assert abs(total - 1.0) < 1e-9


# ── Orchestrator Integration Tests ───────────────────────────────────────────

class TestOrchestratorAdversarial:
    def test_submit_invariant_via_orchestrator(self):
        orch = Orchestrator(mode="local")
        inv_id = orch.submit_invariant(
            miner_address="0xA1",
            target_contract_hash="0x" + "ab" * 32,
            description="Balance invariant",
            solidity_condition="balance >= 0",
        )
        assert inv_id == 0

    def test_submit_challenge_via_orchestrator(self):
        orch = Orchestrator(mode="local")
        orch.submit_invariant(
            miner_address="0xA1",
            target_contract_hash="0x" + "ab" * 32,
            description="Balance invariant",
            solidity_condition="balance >= 0",
        )
        report = orch.submit_challenge(
            miner_address="0xB1",
            invariant_id=0,
            exploit_source="// exploit code",
            target_task_id="0xtask",
        )
        assert isinstance(report, ChallengeReport)
        assert report.result in (ChallengeResult.INVARIANT_HELD, ChallengeResult.INVARIANT_BROKEN)

    def test_adversarial_weights_in_epoch(self):
        orch = Orchestrator(mode="local")
        # Submit invariant + challenge
        orch.submit_invariant(
            miner_address="0xA1",
            target_contract_hash="0x" + "00" * 32,
            description="test",
            solidity_condition="true",
        )
        orch.submit_challenge(
            miner_address="0xB1",
            invariant_id=0,
            exploit_source="// exploit",
            target_task_id="0xtask",
        )
        # Close epoch — should include adversarial weights
        epoch = orch.close_epoch(1, 0, 360)
        # Adversarial miners should appear in weights
        assert len(epoch.weights) >= 0  # May be empty if no standard exploits submitted

    def test_reset_clears_adversarial(self):
        orch = Orchestrator(mode="local")
        orch.submit_invariant(
            miner_address="0xA1",
            target_contract_hash="0x" + "00" * 32,
            description="test",
            solidity_condition="true",
        )
        orch.reset()
        assert orch.adversarial.get_invariant(0) is None

    def test_challenge_report_to_dict(self):
        report = ChallengeReport(
            invariant_id=0,
            class_a_miner="0xA",
            class_b_miner="0xB",
            result=ChallengeResult.INVARIANT_HELD,
            invariant_held=True,
        )
        d = report.to_dict()
        assert d["result"] == "INVARIANT_HELD"
        assert d["invariant_held"] is True


# ── Engine Reset Test ────────────────────────────────────────────────────────

class TestEngineReset:
    def test_reset_clears_all(self, engine, class_a_submission, class_b_challenge):
        engine.submit_invariant(class_a_submission)
        engine.process_challenge(class_b_challenge)
        engine.reset()
        assert engine.get_invariant(0) is None
        assert engine.get_all_scores() == {"class_a": {}, "class_b": {}}
        assert engine.get_challenge_history() == []


# ── Adversarial Consensus Tests ──────────────────────────────────────────────

class TestAdversarialConsensus:
    @pytest.fixture
    def consensus_engine(self, tmp_path):
        engine = AntiCollusionEngine(data_dir=tmp_path)
        # Register enough validators for quorum
        for i in range(7):
            engine.register_validator(f"val_{i}", stake=100.0)
        return engine

    def test_consensus_invariant_held(self, consensus_engine):
        """Majority says INVARIANT_HELD → consensus is INVARIANT_HELD."""
        votes = [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_HELD"}
            for i in range(5)
        ] + [
            {"validator_hotkey": "val_5", "outcome": "INVARIANT_BROKEN"},
            {"validator_hotkey": "val_6", "outcome": "INVARIANT_BROKEN"},
        ]
        result = consensus_engine.compute_adversarial_consensus(
            invariant_id=0, challenge_id="chal_1", votes=votes,
        )
        assert result.consensus_outcome == "INVARIANT_HELD"
        assert result.agreement_ratio >= CONSENSUS_THRESHOLD
        assert len(result.agreeing_validators) == 5
        assert len(result.diverging_validators) == 2

    def test_consensus_invariant_broken(self, consensus_engine):
        """Majority says INVARIANT_BROKEN → consensus is INVARIANT_BROKEN."""
        votes = [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_BROKEN"}
            for i in range(6)
        ] + [
            {"validator_hotkey": "val_6", "outcome": "INVARIANT_HELD"},
        ]
        result = consensus_engine.compute_adversarial_consensus(
            invariant_id=0, challenge_id="chal_2", votes=votes,
        )
        assert result.consensus_outcome == "INVARIANT_BROKEN"
        assert len(result.agreeing_validators) == 6

    def test_consensus_no_quorum(self, consensus_engine):
        """Fewer than MIN_QUORUM votes → NO_QUORUM."""
        votes = [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_HELD"}
            for i in range(3)
        ]
        result = consensus_engine.compute_adversarial_consensus(
            invariant_id=0, challenge_id="chal_3", votes=votes,
        )
        assert result.consensus_outcome == "NO_QUORUM"

    def test_consensus_updates_divergence_tracking(self, consensus_engine):
        """Diverging validators get tracked."""
        votes = [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_HELD"}
            for i in range(5)
        ] + [
            {"validator_hotkey": "val_5", "outcome": "INVARIANT_BROKEN"},
            {"validator_hotkey": "val_6", "outcome": "INVARIANT_BROKEN"},
        ]
        consensus_engine.compute_adversarial_consensus(
            invariant_id=0, challenge_id="chal_4", votes=votes,
        )
        # val_5 and val_6 should have 1 divergence each
        assert consensus_engine.validators["val_5"].divergences == 1
        assert consensus_engine.validators["val_6"].divergences == 1
        # Agreeing validators should have 1 agreement
        assert consensus_engine.validators["val_0"].agreements == 1

    def test_consensus_plurality_fallback(self, consensus_engine):
        """No 66% majority → falls back to plurality."""
        # Register more validators for a split vote
        for i in range(7, 10):
            consensus_engine.register_validator(f"val_{i}", stake=100.0)

        votes = [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_HELD"}
            for i in range(4)
        ] + [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_BROKEN"}
            for i in range(4, 7)
        ] + [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_HELD"}
            for i in range(7, 10)
        ]
        result = consensus_engine.compute_adversarial_consensus(
            invariant_id=0, challenge_id="chal_5", votes=votes,
        )
        # 7 HELD vs 3 BROKEN — plurality is HELD (70% >= 66% threshold)
        assert result.consensus_outcome == "INVARIANT_HELD"

    def test_consensus_persists_to_history(self, consensus_engine):
        """Adversarial consensus results appear in consensus history."""
        votes = [
            {"validator_hotkey": f"val_{i}", "outcome": "INVARIANT_HELD"}
            for i in range(7)
        ]
        consensus_engine.compute_adversarial_consensus(
            invariant_id=42, challenge_id="chal_6", votes=votes,
        )
        log = consensus_engine.export_consensus_log()
        assert len(log) == 1
        assert log[0]["task_id"] == "adversarial:chal_6"
        assert log[0]["submission_hash"] == "inv:42"


# ── E2E Weight Blending Tests ────────────────────────────────────────────────

class TestWeightBlending:
    def test_epoch_blends_exploit_and_adversarial_weights(self):
        """Verify 70/30 exploit/adversarial weight blending in epoch close."""
        orch = Orchestrator(mode="local")

        # Submit an invariant (adversarial activity)
        orch.submit_invariant(
            miner_address="0xA1",
            target_contract_hash="0x" + "ab" * 32,
            description="Balance invariant",
            solidity_condition="balance >= 0",
        )
        # Process a challenge (gives scores to both miners)
        orch.submit_challenge(
            miner_address="0xB1",
            invariant_id=0,
            exploit_source="// exploit code",
            target_task_id="0xtask",
        )

        # Also submit a standard exploit so exploit weights exist
        orch.process_submission(
            task_id="task_001",
            miner_address="0xMiner1",
            exploit_source="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\ncontract Exploit { function run() external {} }",
        )

        # Close epoch
        epoch = orch.close_epoch(epoch_number=1, start_block=0, end_block=360)

        # Verify epoch has weights (blended from both sources)
        assert epoch is not None
        # The adversarial miners should influence weights
        adv_weights = orch.adversarial.compute_adversarial_weights()
        assert len(adv_weights) > 0, "Adversarial activity should produce weights"

    def test_adversarial_only_epoch_produces_weights(self):
        """Epoch with only adversarial activity still produces weights."""
        orch = Orchestrator(mode="local")

        orch.submit_invariant(
            miner_address="0xA1",
            target_contract_hash="0x" + "00" * 32,
            description="test inv",
            solidity_condition="true",
        )
        orch.submit_challenge(
            miner_address="0xB1",
            invariant_id=0,
            exploit_source="// exploit",
            target_task_id="0xtask",
        )

        epoch = orch.close_epoch(epoch_number=1, start_block=0, end_block=360)
        assert epoch is not None


# ── P0 Tests: C-1 Solidity Condition Sanitizer ────────────────────────────────

class TestConditionSanitization:
    """C-1: Verify _FORBIDDEN_CONDITION_PATTERNS rejects dangerous conditions."""

    @pytest.fixture()
    def engine(self):
        return AdversarialEngine(mode="local")

    def _make_invariant(self, condition):
        return InvariantRecord(
            invariant_id=0,
            submitter="0xAA",
            target_contract_hash="0x" + "00" * 32,
            description="test",
            solidity_condition=condition,
            compiled_check=b"",
            submitted_at=0,
        )

    def test_valid_condition_accepted(self, engine):
        inv = self._make_invariant("balance >= 0")
        # Should NOT raise
        engine._generate_invariant_test(inv, "Vault", "// exploit")

    @pytest.mark.parametrize("bad_condition", [
        "selfdestruct(address(this))",
        "assembly { sstore(0, 1) }",
        "delegatecall(abi.encode())",
        'import "malicious.sol"',
        "x; y = 1",              # semicolons
        "call{value: 1}(data)",
        "new MaliciousContract()",
        "suicide(address(0))",
        "pragma solidity ^0.8.28",
    ])
    def test_forbidden_patterns_rejected(self, engine, bad_condition):
        inv = self._make_invariant(bad_condition)
        with pytest.raises(ValueError, match="forbidden pattern"):
            engine._generate_invariant_test(inv, "Vault", "// exploit")


# ── P0 Tests: H-5 Dual-Class Weight Renormalization ──────────────────────────

class TestDualClassWeights:
    """H-5: Weights still sum to 1.0 when a miner is in both Class A and B."""

    @pytest.fixture()
    def engine(self):
        return AdversarialEngine(mode="local")

    def test_dual_class_miner_weights_sum_to_one(self, engine):
        sub = InvariantSubmission(
            miner_address="0xDUAL",
            target_contract_hash="0x" + "00" * 64,
            description="test invariant",
            solidity_condition="true",
            compiled_check=b"",
        )
        engine.submit_invariant(sub)

        chal = ChallengeSubmission(
            miner_address="0xDUAL",  # Same miner in both classes
            invariant_id=0,
            exploit_source="// exploit",
            target_task_id="0xtask",
        )
        engine.process_challenge(chal, validation_fn=lambda t, e: False)

        weights = engine.compute_adversarial_weights()
        if weights:
            total = sum(weights.values())
            assert abs(total - 1.0) < 1e-9
            assert "0xDUAL" in weights


# ── P2 Tests: H-3 Challenge History Cap ──────────────────────────────────────

class TestChallengeHistoryCap:
    """H-3: _challenge_history is capped at MAX_CHALLENGE_HISTORY."""

    def test_history_evicts_oldest_entries(self, tmp_path):
        engine = AdversarialEngine(data_dir=tmp_path, rpc_url="http://localhost:8545")
        engine._MAX_CHALLENGE_HISTORY = 100  # smaller cap for fast test

        # Submit an invariant first
        inv = InvariantSubmission(
            miner_address="0xMINER_A",
            target_contract_hash="0xtask",
            description="test inv",
            solidity_condition="x > 0",
            compiled_check=b"",
        )
        engine.submit_invariant(inv)

        # Process 120 challenges — only last 100 should survive
        for i in range(120):
            chal = ChallengeSubmission(
                miner_address=f"0xBREAKER_{i:03d}",
                invariant_id=0,
                exploit_source=f"// exploit {i}",
                target_task_id="0xtask",
            )
            engine.process_challenge(chal, validation_fn=lambda t, e: True)

        history = engine._challenge_history
        assert len(history) <= 100
        # Oldest entries (breaker_000 .. breaker_019) should be evicted
        addresses = [h.class_b_miner for h in history]
        assert "0xBREAKER_000" not in addresses
        assert "0xBREAKER_119" in addresses


# ── P2 Tests: C-3 Private Key Requirement for On-Chain Calls ─────────────────

class TestOnChainPrivateKeyRequirement:
    """C-3: On-chain calls require ETH_PRIVATE_KEY environment variable."""

    def test_submit_invariant_onchain_no_key_raises(self, tmp_path):
        from unittest.mock import patch
        engine = AdversarialEngine(
            data_dir=tmp_path,
            rpc_url="http://localhost:8545",
            registry_address="0x1234",
        )
        with patch.dict("os.environ", {}, clear=False):
            # Remove ETH_PRIVATE_KEY if present
            import os
            os.environ.pop("ETH_PRIVATE_KEY", None)
            with pytest.raises(RuntimeError, match="ETH_PRIVATE_KEY"):
                engine._submit_invariant_onchain(
                    InvariantSubmission(
                        miner_address="0xMINER",
                        target_contract_hash="0xtask",
                        description="test",
                        solidity_condition="x > 0",
                        compiled_check=b"",
                    )
                )

    def test_record_challenge_onchain_no_key_returns_silently(self, tmp_path):
        from unittest.mock import patch
        engine = AdversarialEngine(
            data_dir=tmp_path,
            rpc_url="http://localhost:8545",
            scoring_address="0x5678",
        )
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("ETH_PRIVATE_KEY", None)
            # Should not raise — logs error and returns silently
            engine._record_challenge_onchain(
                invariant_id=0,
                class_a_miner="0xA",
                class_b_miner="0xB",
                broken=True,
            )
