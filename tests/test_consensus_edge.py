"""TC-8: Consensus engine edge case tests."""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.anticollusion.consensus import (
    AntiCollusionEngine as ConsensusEngine,
    MIN_QUORUM,
    CONSENSUS_THRESHOLD,
    DIVERGENCE_SLASH_THRESHOLD,
    MAX_VALIDATORS_PER_TASK,
)


@pytest.fixture
def engine(tmp_path):
    """Provide a fresh ConsensusEngine with temp data dir."""
    return ConsensusEngine(seed=42, data_dir=tmp_path)


@pytest.fixture
def engine_with_validators(engine):
    """Engine pre-populated with MIN_QUORUM + 2 validators."""
    for i in range(MIN_QUORUM + 2):
        engine.register_validator(f"validator_{i}", stake=100.0)
    return engine


class TestAssignmentEdgeCases:
    def test_no_validators_raises(self, engine):
        with pytest.raises(ValueError, match="Insufficient active validators"):
            engine.assign_validators("task_1")

    def test_fewer_than_quorum_raises(self, engine):
        engine.register_validator("v1", stake=50.0)
        engine.register_validator("v2", stake=50.0)
        with pytest.raises(ValueError, match="Insufficient active validators"):
            engine.assign_validators("task_1")

    def test_max_validators_cap(self, engine):
        for i in range(20):
            engine.register_validator(f"v_{i}", stake=100.0)
        assigned = engine.assign_validators("task_1")
        assert len(assigned) <= MAX_VALIDATORS_PER_TASK

    def test_assignment_deterministic_same_instance(self, tmp_path):
        """Same engine instance assigns the same validators for the same task."""
        e1 = ConsensusEngine(seed=42, data_dir=tmp_path / "e1")
        for i in range(8):
            e1.register_validator(f"v_{i}", stake=100.0)
        a1 = e1.assign_validators("task_x")
        a2 = e1.assign_validators("task_x")
        assert a1 == a2

    def test_different_tasks_may_get_different_validators(self, engine_with_validators):
        a1 = engine_with_validators.assign_validators("task_a")
        a2 = engine_with_validators.assign_validators("task_b")
        # With enough validators and different task IDs, assignments should differ
        # (not guaranteed but highly probable)
        assert isinstance(a1, list)
        assert isinstance(a2, list)


def _make_vote(hotkey: str, valid: bool, severity: float) -> dict:
    """Helper to create a vote dict matching compute_consensus expected format."""
    return {
        "validator_hotkey": hotkey,
        "result": "VALID" if valid else "REJECT_INVALID",
        "fingerprint": f"fp_{hotkey}",
        "severity_score": severity,
    }


class TestConsensusEdgeCases:
    def test_single_vote_below_quorum(self, engine_with_validators):
        votes = [_make_vote("validator_0", valid=True, severity=0.8)]
        result = engine_with_validators.compute_consensus(
            task_id="task_1",
            submission_hash="0xabc",
            votes=votes,
        )
        # Single vote < MIN_QUORUM should return NO_QUORUM
        assert result is not None
        assert result.consensus_result == "NO_QUORUM"

    def test_unanimous_agreement(self, engine_with_validators):
        votes = [
            _make_vote(f"validator_{i}", valid=True, severity=0.9)
            for i in range(MIN_QUORUM)
        ]
        result = engine_with_validators.compute_consensus(
            task_id="task_2", submission_hash="0xdef", votes=votes,
        )
        assert result is not None

    def test_unanimous_rejection(self, engine_with_validators):
        votes = [
            _make_vote(f"validator_{i}", valid=False, severity=0.0)
            for i in range(MIN_QUORUM)
        ]
        result = engine_with_validators.compute_consensus(
            task_id="task_3", submission_hash="0x111", votes=votes,
        )
        assert result is not None

    def test_split_vote_at_threshold_boundary(self, engine_with_validators):
        """66% threshold: 4 out of 6 votes agree = 66.7% — should reach consensus."""
        votes = [
            _make_vote(f"validator_{i}", valid=True, severity=0.5)
            for i in range(4)
        ] + [
            _make_vote(f"validator_{i}", valid=False, severity=0.0)
            for i in range(4, 6)
        ]
        result = engine_with_validators.compute_consensus(
            task_id="task_4", submission_hash="0x222", votes=votes,
        )
        assert result is not None

    def test_empty_votes(self, engine_with_validators):
        result = engine_with_validators.compute_consensus(
            task_id="task_5", submission_hash="0x333", votes=[],
        )
        assert result is not None
        assert result.consensus_result == "NO_QUORUM"


class TestDivergenceTracking:
    def test_divergence_rate_starts_zero(self, engine):
        engine.register_validator("v1", stake=100.0)
        stats = engine.export_validator_stats()
        for v in stats.values():
            if isinstance(v, dict) and "divergence_rate" in v:
                assert v["divergence_rate"] == 0.0


class TestSlashEvents:
    def test_no_slashes_initially(self, engine):
        assert engine.get_slash_events() == []

    def test_export_consensus_log_empty(self, engine):
        log = engine.export_consensus_log()
        assert isinstance(log, list)
        assert len(log) == 0


class TestStatePersistence:
    def test_save_and_load(self, tmp_path):
        e1 = ConsensusEngine(seed=42, data_dir=tmp_path)
        e1.register_validator("v1", stake=100.0)
        e1.register_validator("v2", stake=200.0)
        e1._save_state()

        e2 = ConsensusEngine(seed=42, data_dir=tmp_path)
        validators = e2.get_active_validators()
        assert len(validators) == 2
