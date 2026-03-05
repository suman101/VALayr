"""
Full Pipeline Integration Test — End-to-End.

Tests the complete flow:
  1. Generate task corpus
  2. Submit exploit (reentrancy, auth bypass, overflow)
  3. Validate each exploit
  4. Fingerprint + dedup
  5. Score severity
  6. Compute epoch weights
  7. Verify determinism

This test runs WITHOUT Anvil/Forge (unit-level simulation).
For live Anvil testing, use test_live_pipeline.py.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Resolve imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from task_generator.generate import CorpusGenerator, TaskPackage, VULNERABILITY_TEMPLATES
from validator.engine.validate import (
    ValidationEngine, ExploitSubmission, ValidationResult,
    ExecutionTrace, StorageSlotDiff,
)
from validator.fingerprint.dedup import FingerprintEngine, FingerprintComponents
from validator.scoring.severity import SeverityScorer, SeverityBreakdown
from subnet_adapter.incentive import (
    SubnetIncentiveAdapter, ValidatorVote, EpochResult, MinerScore,
)
from orchestrator import Orchestrator, SubmissionResult

def test_corpus_generation():
    """Test deterministic task corpus generation."""
    print("[1/7] Testing corpus generation...")

    with tempfile.TemporaryDirectory() as tmpdir:
        gen = CorpusGenerator(output_dir=Path(tmpdir))
        packages = gen.generate_batch(count_per_class=2, seed=42)

        assert len(packages) > 0, "Should generate at least 1 package"

        # Verify determinism: same seed → same IDs
        gen2 = CorpusGenerator(output_dir=Path(tmpdir + "_2"))
        packages2 = gen2.generate_batch(count_per_class=2, seed=42)
        assert len(packages) == len(packages2), "Same seed should produce same count"

        for p1, p2 in zip(packages, packages2):
            assert p1.task_id == p2.task_id, f"Task IDs should match: {p1.task_id[:16]} != {p2.task_id[:16]}"

        # Verify all vulnerability classes represented
        classes = set(p.vulnerability_class for p in packages)
        assert "reentrancy" in classes
        assert "auth-bypass" in classes
        assert "integer-overflow" in classes

        # Verify save + manifest
        paths = gen.save_batch(packages)
        assert len(paths) == len(packages)
        for p in paths:
            assert (p / "task.json").exists()
            assert (p / "Vulnerable.sol").exists()

        manifest = gen.generate_manifest(packages)
        assert manifest["total_tasks"] == len(packages)

    print(f"  [+] Generated {len(packages)} tasks across {len(classes)} classes")


def test_validation_simulation():
    """Test validation engine with simulated execution traces."""
    print("[2/7] Testing validation simulation...")

    # Simulate a valid exploit trace
    trace = ExecutionTrace(
        storage_diffs=[
            StorageSlotDiff(slot="0x0", before="0x" + "0" * 64,
                           after="0x" + "0" * 40 + "dead" + "0" * 20),
        ],
        balance_before=10 * 10**18,
        balance_after=1 * 10**18,
        balance_delta=-(9 * 10**18),
        gas_used=150_000,
        reverted=False,
    )

    engine = ValidationEngine()

    # Test state change detection
    assert engine._has_state_change(trace), "Should detect state change"

    # Test fingerprint computation
    fp = engine._compute_fingerprint(trace)
    assert fp.startswith("0x"), "Fingerprint should be hex"
    assert len(fp) == 66, "Should be 256-bit hash"  # 0x + 64 hex chars

    # Fingerprint determinism
    fp2 = engine._compute_fingerprint(trace)
    assert fp == fp2, "Same trace should produce same fingerprint"

    # Reverted trace → no state change
    reverted_trace = ExecutionTrace(reverted=True, revert_reason="EvmError: Revert")
    assert not engine._has_state_change(reverted_trace), "Reverted should not count"

    print("  [+] Validation simulation OK")


def test_fingerprint_dedup():
    """Test fingerprint engine and deduplication."""
    print("[3/7] Testing fingerprint + dedup...")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "fp.json"
        engine = FingerprintEngine(db_path=db_path)

        # Build components for two different exploits
        comp1 = FingerprintComponents(
            function_selectors=["withdraw", "deposit"],
            storage_slot_diffs=[{"slot": "0x0", "before": "0x01", "after": "0x00"}],
            balance_delta=-5 * 10**18,
            ownership_changed=False,
        )
        comp2 = FingerprintComponents(
            function_selectors=["setOwner", "withdrawTreasury"],
            storage_slot_diffs=[{"slot": "0x0", "before": "0xABC", "after": "0xDEAD"}],
            balance_delta=-5 * 10**18,
            ownership_changed=True,
        )

        fp1 = engine.compute_fingerprint(comp1)
        fp2 = engine.compute_fingerprint(comp2)
        assert fp1 != fp2, "Different exploits should have different fingerprints"

        # First submission → FULL reward
        task_id = "0x" + "a" * 64
        dedup1 = engine.check_duplicate(task_id, fp1, "miner_A")
        assert not dedup1.is_duplicate
        assert dedup1.reward_multiplier == 1.0
        assert dedup1.submission_number == 1

        # Same fingerprint → DUPLICATE reward
        dedup2 = engine.check_duplicate(task_id, fp1, "miner_B")
        assert dedup2.is_duplicate
        assert dedup2.reward_multiplier == 0.10
        assert dedup2.submission_number == 2

        # Different fingerprint → FULL reward
        dedup3 = engine.check_duplicate(task_id, fp2, "miner_C")
        assert not dedup3.is_duplicate
        assert dedup3.reward_multiplier == 1.0

        # Persistence check
        engine2 = FingerprintEngine(db_path=db_path)
        assert engine2.get_fingerprint_count(task_id) == 2

    print("  [+] Fingerprint + dedup OK (3 submissions, 2 unique)")


def test_severity_scoring():
    """Test algorithmic severity scorer."""
    print("[4/7] Testing severity scoring...")

    scorer = SeverityScorer()

    # Exploit 1: Funds drained (reentrancy)
    trace1 = {
        "balance_delta": -(9 * 10**18),
        "storage_diffs": [
            {"slot": "0x5", "before": "0x" + "f" * 64, "after": "0x" + "0" * 64},
        ],
        "reverted": False,
    }
    s1 = scorer.score_detailed(trace1)
    assert s1.final_severity > 0, "Fund drain should have severity > 0"
    assert s1.funds_drained_score > 0
    assert s1.invariant_broken_score > 0  # Balance drained → invariant broken

    # Exploit 2: Privilege escalation (auth bypass)
    trace2 = {
        "balance_delta": -(5 * 10**18),
        "storage_diffs": [
            {"slot": "0x0", "before": "0x" + "0" * 24 + "CAFE" * 5, "after": "0x" + "0" * 24 + "DEAD" * 5},
        ],
        "reverted": False,
    }
    s2 = scorer.score_detailed(trace2)
    assert s2.privilege_escalation_score == 1.0, "Owner slot change = priv escalation"
    assert s2.final_severity > s1.final_severity * 0.5, "Priv escalation should score high"

    # Exploit 3: Permanent lock
    trace3 = {
        "balance_delta": 0,
        "storage_diffs": [
            {"slot": "0x0", "before": "0x" + "0" * 24 + "CAFE" * 5, "after": "0x" + "0" * 64},
        ],
        "reverted": False,
    }
    s3 = scorer.score_detailed(trace3)
    assert s3.permanent_lock_score == 1.0, "Zeroed owner = permanent lock"

    # Reverted exploit → zero severity
    trace_rev = {"reverted": True}
    s_rev = scorer.score_detailed(trace_rev)
    assert s_rev.final_severity == 0, "Reverted should be zero severity"

    print(f"  [+] Severity scoring OK (drain={s1.final_severity:.3f}, "
          f"priv={s2.final_severity:.3f}, lock={s3.final_severity:.3f})")


def test_incentive_adapter():
    """Test subnet incentive adapter + epoch weight computation."""
    print("[5/7] Testing incentive adapter...")

    adapter = SubnetIncentiveAdapter()

    # Simulate 6 validators voting on 2 submissions
    for i in range(6):
        # Submission 1: Valid reentrancy exploit
        adapter.record_vote(ValidatorVote(
            validator_hotkey=f"val_{i}",
            task_id="task_001",
            submission_hash="sub_reentrancy",
            result="VALID",
            fingerprint="0x" + "a" * 64,
            severity_score=0.65,
            timestamp=1700000000 + i,
        ))
        # Submission 2: Invalid attempt
        adapter.record_vote(ValidatorVote(
            validator_hotkey=f"val_{i}",
            task_id="task_002",
            submission_hash="sub_invalid",
            result="REJECT_REVERT",
            fingerprint="",
            severity_score=0.0,
            timestamp=1700000000 + i,
        ))

    epoch = adapter.compute_epoch_weights(
        epoch_number=1, start_block=100, end_block=460
    )

    assert epoch.total_submissions == 2
    assert epoch.total_valid == 1
    assert len(epoch.weights) >= 1, "Should have at least one miner with weight"

    # Valid submission miner should have positive weight
    total_weight = sum(epoch.weights.values())
    assert abs(total_weight - 1.0) < 1e-9, f"Weights should sum to 1.0, got {total_weight}"

    # Export and verify structure
    exported = adapter.export_epoch(epoch)
    assert "weights" in exported
    assert "miner_scores" in exported

    print(f"  [+] Incentive adapter OK (epoch: {epoch.total_valid}/{epoch.total_submissions} valid, "
          f"{len(epoch.weights)} miners weighted)")


def test_orchestrator_unit():
    """Test the orchestrator's non-Anvil components."""
    print("[6/7] Testing orchestrator (unit)...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        orch = Orchestrator(
            corpus_dir=tmppath / "corpus",
            data_dir=tmppath / "data",
        )

        # Generate corpus
        packages = orch.generate_corpus(count_per_class=1, seed=42)
        assert len(packages) > 0

        # List tasks
        tasks = orch.list_tasks()
        assert len(tasks) == len(packages)

        # Load a task
        first_task = tasks[0]
        loaded = orch.load_task(first_task["task_id"][:10])
        assert loaded is not None
        assert loaded["task_id"] == first_task["task_id"]

        # Test epoch closing (empty — no submissions)
        epoch = orch.close_epoch(epoch_number=0, start_block=0, end_block=360)
        assert epoch.total_submissions == 0

        # Verify data dirs were created
        assert (tmppath / "data" / "epochs").exists()

    print(f"  [+] Orchestrator unit OK ({len(packages)} tasks, load/list/epoch)")


def test_determinism_across_runs():
    """Verify byte-for-byte determinism of the full pipeline."""
    print("[7/7] Testing determinism...")

    results = []
    for run in range(3):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = CorpusGenerator(output_dir=Path(tmpdir))
            packages = gen.generate_batch(count_per_class=2, seed=42)

            # Collect all task IDs
            task_ids = [p.task_id for p in packages]

            # Compute fingerprints from simulated traces
            fe = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")
            comp = FingerprintComponents(
                function_selectors=["withdraw"],
                storage_slot_diffs=[{"slot": "0x0", "before": "0x1", "after": "0x0"}],
                balance_delta=-10**18,
            )
            fp = fe.compute_fingerprint(comp)

            # Score
            scorer = SeverityScorer()
            trace = {"balance_delta": -10**18, "storage_diffs": [], "reverted": False}
            severity = scorer.score(trace)

            results.append({
                "task_ids": task_ids,
                "fingerprint": fp,
                "severity": severity,
            })

    # Compare all runs
    for i in range(1, len(results)):
        assert results[i]["task_ids"] == results[0]["task_ids"], \
            f"Run {i} task IDs differ from run 0"
        assert results[i]["fingerprint"] == results[0]["fingerprint"], \
            f"Run {i} fingerprint differs from run 0"
        assert results[i]["severity"] == results[0]["severity"], \
            f"Run {i} severity differs from run 0"

    print(f"  [+] Determinism verified across {len(results)} runs")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Exploit Subnet — Full Pipeline Integration Test")
    print("=" * 60)

    tests = [
        test_corpus_generation,
        test_validation_simulation,
        test_fingerprint_dedup,
        test_severity_scoring,
        test_incentive_adapter,
        test_orchestrator_unit,
        test_determinism_across_runs,
    ]

    passed = 0
    failed = 0
    errors = []

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test.__name__, str(e)))
            print(f"  [FAIL] {test.__name__}: {e}")

    print(f"\n{'='*60}")
    print(f"  Results: {passed} passed, {failed} failed")
    if errors:
        print(f"\n  Failures:")
        for name, err in errors:
            print(f"    - {name}: {err}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


def test_task_package_save_path_traversal():
    """TaskPackage.save() rejects task_ids that would escape output_dir."""
    from task_generator.generate import TaskPackage, DeploymentConfig

    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = TaskPackage(
            source_code="contract T {}",
            solc_version="0.8.28",
            deployment_config=DeploymentConfig(),
            vulnerability_class="test",
            difficulty=1,
        )
        # Force a malicious task_id (non-hex chars are stripped, so
        # the sanitization reduces it to empty → "unknown", which is safe).
        pkg.task_id = "../../etc/passwd"
        # Should NOT raise because sanitized_id strips non-hex, result is "aed"
        # but let's verify the path stays inside output_dir
        saved = pkg.save(Path(tmpdir))
        assert str(saved.resolve()).startswith(str(Path(tmpdir).resolve()))


if __name__ == "__main__":
    sys.exit(main())
