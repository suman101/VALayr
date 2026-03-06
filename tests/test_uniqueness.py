"""Tests for anti-LLM uniqueness scoring."""

import time
from unittest.mock import patch

import pytest

from validator.scoring.uniqueness import (
    UniquenessScorer,
    StructuralProfile,
    HERD_THRESHOLD,
    HERD_PENALTY,
    SPEED_COOLDOWN_SECONDS,
    TIMING_BONUS_MAX,
    MIN_GAS_BY_DIFFICULTY,
    MIN_SELECTORS_BY_DIFFICULTY,
)


SAMPLE_EXPLOIT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "forge-std/Test.sol";
contract ExploitTest is Test {
    function test_attack() public {
        VulnerableVault vault = new VulnerableVault();
        vault.deposit{value: 1 ether}();
        Attacker atk = new Attacker(address(vault));
        atk.attack();
    }
}
"""

DIFFERENT_EXPLOIT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "forge-std/Test.sol";
contract ExploitTest is Test {
    function test_drain() public {
        address target = address(new VulnerableVault());
        for (uint i = 0; i < 10; i++) {
            (bool ok, ) = target.call(abi.encodeWithSignature("withdraw(uint256)", 100));
            require(ok);
        }
    }
}
"""


class TestStructuralProfile:

    def test_compute_profile_basic(self):
        scorer = UniquenessScorer()
        profile = scorer._compute_profile(SAMPLE_EXPLOIT)
        assert profile.function_count >= 1
        assert profile.structural_hash != ""
        assert len(profile.structural_hash) == 16

    def test_different_exploits_different_hashes(self):
        scorer = UniquenessScorer()
        p1 = scorer._compute_profile(SAMPLE_EXPLOIT)
        p2 = scorer._compute_profile(DIFFERENT_EXPLOIT)
        assert p1.structural_hash != p2.structural_hash

    def test_same_exploit_same_hash(self):
        scorer = UniquenessScorer()
        p1 = scorer._compute_profile(SAMPLE_EXPLOIT)
        p2 = scorer._compute_profile(SAMPLE_EXPLOIT)
        assert p1.structural_hash == p2.structural_hash

    def test_detect_loop(self):
        scorer = UniquenessScorer()
        profile = scorer._compute_profile(DIFFERENT_EXPLOIT)
        assert profile.has_loop is True

    def test_no_loop(self):
        scorer = UniquenessScorer()
        profile = scorer._compute_profile(SAMPLE_EXPLOIT)
        assert profile.has_loop is False


class TestUniquenessScorer:

    def test_first_submission_no_penalty(self):
        scorer = UniquenessScorer()
        result = scorer.score_submission(
            task_id="task-1",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
            gas_used=100_000,
            selector_count=3,
            difficulty=1,
        )
        assert not result.is_herd
        assert result.herd_penalty == 0.0
        assert result.complexity_pass is True
        assert result.final_multiplier >= 0.9

    def test_herd_detection(self):
        scorer = UniquenessScorer()
        # Submit HERD_THRESHOLD + 1 identical exploits from different miners
        for i in range(HERD_THRESHOLD + 1):
            result = scorer.score_submission(
                task_id="task-herd",
                exploit_source=SAMPLE_EXPLOIT,
                miner_address=f"miner-{i}",
                gas_used=100_000,
                selector_count=3,
                difficulty=1,
            )
        # Last submission should trigger herd
        assert result.is_herd is True
        assert result.herd_size > HERD_THRESHOLD
        assert result.herd_penalty == HERD_PENALTY
        assert result.final_multiplier < 1.0

    def test_unique_submissions_no_herd(self):
        scorer = UniquenessScorer()
        # Different exploits from different miners
        r1 = scorer.score_submission(
            task_id="task-unique",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
        )
        r2 = scorer.score_submission(
            task_id="task-unique",
            exploit_source=DIFFERENT_EXPLOIT,
            miner_address="miner-B",
        )
        assert not r1.is_herd
        assert not r2.is_herd

    def test_timing_bonus_after_cooldown(self):
        scorer = UniquenessScorer()
        # Register task 5 minutes ago
        scorer.register_task("task-timing", published_at=time.time() - 300)
        result = scorer.score_submission(
            task_id="task-timing",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
        )
        assert result.timing_bonus > 0

    def test_no_timing_bonus_during_cooldown(self):
        scorer = UniquenessScorer()
        # Register task just now
        scorer.register_task("task-fast", published_at=time.time())
        result = scorer.score_submission(
            task_id="task-fast",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
        )
        assert result.timing_bonus == 0.0

    def test_complexity_floor_gas(self):
        scorer = UniquenessScorer()
        result = scorer.score_submission(
            task_id="task-gas",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
            gas_used=10_000,  # Below minimum for any difficulty
            selector_count=5,
            difficulty=2,
        )
        assert not result.complexity_pass
        assert result.final_multiplier < 1.0

    def test_complexity_floor_selectors(self):
        scorer = UniquenessScorer()
        result = scorer.score_submission(
            task_id="task-sel",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
            gas_used=200_000,
            selector_count=1,  # Below minimum for difficulty 3
            difficulty=3,
        )
        assert not result.complexity_pass

    def test_reset(self):
        scorer = UniquenessScorer()
        scorer.score_submission("t1", SAMPLE_EXPLOIT, "m1")
        scorer.reset()
        assert len(scorer._submissions) == 0
        assert len(scorer._task_timestamps) == 0

    def test_multiplier_clamped(self):
        scorer = UniquenessScorer()
        # Even with timing bonus, multiplier should not exceed 1.5
        scorer.register_task("task-clamp", published_at=time.time() - 10000)
        result = scorer.score_submission(
            task_id="task-clamp",
            exploit_source=SAMPLE_EXPLOIT,
            miner_address="miner-A",
        )
        assert result.final_multiplier <= 1.5
        assert result.final_multiplier >= 0.0


# ── P0 Tests: C-6 MAX_TRACKED_TASKS Pruning ──────────────────────────────────

class TestUniquenessScalerPruning:
    """C-6: Oldest task is evicted when MAX_TRACKED_TASKS is exceeded."""

    @patch("validator.scoring.uniqueness.MAX_TRACKED_TASKS", 5)
    def test_prune_oldest_task_when_cap_exceeded(self):
        scorer = UniquenessScorer()
        for i in range(6):
            scorer.score_submission(
                task_id=f"task-{i}",
                exploit_source=SAMPLE_EXPLOIT,
                miner_address=f"miner-{i}",
            )
        assert len(scorer._submissions) == 5
        assert "task-0" not in scorer._submissions

    @patch("validator.scoring.uniqueness.MAX_TRACKED_TASKS", 5)
    def test_prune_removes_corresponding_timestamp(self):
        scorer = UniquenessScorer()
        for i in range(6):
            scorer.register_task(f"task-{i}")
            scorer.score_submission(
                task_id=f"task-{i}",
                exploit_source=SAMPLE_EXPLOIT,
                miner_address=f"miner-{i}",
            )
        assert "task-0" not in scorer._task_timestamps


# ── P0 Tests: H-11 Thread-Safety ─────────────────────────────────────────────

class TestConcurrentUniquenessScorer:
    """H-11: Concurrent score_submission calls don't corrupt state."""

    def test_concurrent_submissions_no_corruption(self):
        import threading
        scorer = UniquenessScorer()
        errors = []

        def worker(i):
            try:
                for j in range(20):
                    scorer.score_submission(
                        task_id=f"task-{i}-{j}",
                        exploit_source=SAMPLE_EXPLOIT,
                        miner_address=f"miner-{i}",
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(scorer._submissions) == 200  # 10 workers * 20 tasks each
