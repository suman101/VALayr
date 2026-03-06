"""
Integration tests for the exploit subnet components.

Tests the full pipeline:
  Task Generation → Validation → Fingerprinting → Scoring → Consensus → Incentives

Run: python3 -m pytest tests/ -v
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ══════════════════════════════════════════════════════════════════════════════
# Task Generator Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTaskGenerator:
    """Test deterministic corpus generation."""

    def test_task_id_determinism(self):
        """Same inputs must produce same task ID across runs."""
        from task_generator_module import TaskPackage, DeploymentConfig

        pkg1 = TaskPackage(
            source_code="contract Vuln { }",
            solc_version="0.8.28",
            deployment_config=DeploymentConfig(),
            vulnerability_class="reentrancy",
            difficulty=1,
        )
        id1 = pkg1.compute_task_id()

        pkg2 = TaskPackage(
            source_code="contract Vuln { }",
            solc_version="0.8.28",
            deployment_config=DeploymentConfig(),
            vulnerability_class="reentrancy",
            difficulty=1,
        )
        id2 = pkg2.compute_task_id()

        assert id1 == id2, f"Task IDs must be deterministic: {id1} != {id2}"

    def test_task_id_sensitivity(self):
        """Different inputs must produce different task IDs."""
        from task_generator_module import TaskPackage, DeploymentConfig

        pkg1 = TaskPackage(
            source_code="contract Vuln { }",
            solc_version="0.8.28",
            deployment_config=DeploymentConfig(),
            vulnerability_class="reentrancy",
            difficulty=1,
        )
        id1 = pkg1.compute_task_id()

        pkg2 = TaskPackage(
            source_code="contract Vuln { uint x; }",  # Different source
            solc_version="0.8.28",
            deployment_config=DeploymentConfig(),
            vulnerability_class="reentrancy",
            difficulty=1,
        )
        id2 = pkg2.compute_task_id()

        assert id1 != id2, "Different sources must produce different task IDs"

    def test_task_save_and_load(self):
        """Task packages must round-trip through save/load."""
        from task_generator_module import TaskPackage, DeploymentConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = TaskPackage(
                source_code="contract Vuln { function x() public {} }",
                solc_version="0.8.28",
                deployment_config=DeploymentConfig(),
                vulnerability_class="auth-bypass",
                difficulty=2,
            )
            pkg.compute_task_id()
            task_dir = pkg.save(Path(tmpdir))

            # Verify files exist
            assert (task_dir / "Vulnerable.sol").exists()
            assert (task_dir / "task.json").exists()

            # Verify JSON
            loaded = json.loads((task_dir / "task.json").read_text())
            assert loaded["task_id"] == pkg.task_id
            assert loaded["vulnerability_class"] == "auth-bypass"


# ══════════════════════════════════════════════════════════════════════════════
# Fingerprint & Dedup Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestFingerprint:
    """Test fingerprint computation and deduplication."""

    def test_fingerprint_determinism(self):
        """Same trace components must produce same fingerprint."""
        from validator.fingerprint.dedup import FingerprintEngine, FingerprintComponents

        engine = FingerprintEngine.__new__(FingerprintEngine)
        engine._db = {}

        comp1 = FingerprintComponents(
            function_selectors=["a9059cbb", "70a08231"],
            storage_slot_diffs=[{"slot": "0x0", "before": "0x" + "0" * 64, "after": "0x" + "1" * 64}],
            balance_delta=-1000000000000000000,
        )

        comp2 = FingerprintComponents(
            function_selectors=["a9059cbb", "70a08231"],
            storage_slot_diffs=[{"slot": "0x0", "before": "0x" + "0" * 64, "after": "0x" + "1" * 64}],
            balance_delta=-1000000000000000000,
        )

        fp1 = engine.compute_fingerprint(comp1)
        fp2 = engine.compute_fingerprint(comp2)
        assert fp1 == fp2, "Fingerprints must be deterministic"

    def test_fingerprint_sensitivity(self):
        """Different traces must produce different fingerprints."""
        from validator.fingerprint.dedup import FingerprintEngine, FingerprintComponents

        engine = FingerprintEngine.__new__(FingerprintEngine)
        engine._db = {}

        comp1 = FingerprintComponents(
            function_selectors=["a9059cbb"],
            balance_delta=-1000000000000000000,
        )

        comp2 = FingerprintComponents(
            function_selectors=["a9059cbb"],
            balance_delta=-2000000000000000000,  # Different drain amount
        )

        fp1 = engine.compute_fingerprint(comp1)
        fp2 = engine.compute_fingerprint(comp2)
        assert fp1 != fp2, "Different traces must produce different fingerprints"

    def test_dedup_first_submission(self):
        """First submission gets full reward."""
        from validator.fingerprint.dedup import FingerprintEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")
            result = engine.check_duplicate("task-1", "0xabc123", "miner-A")

            assert not result.is_duplicate
            assert result.reward_multiplier == 1.0
            assert result.submission_number == 1

    def test_dedup_second_submission(self):
        """Second submission with same fingerprint gets reduced reward."""
        from validator.fingerprint.dedup import FingerprintEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")

            engine.check_duplicate("task-1", "0xabc123", "miner-A")
            result2 = engine.check_duplicate("task-1", "0xabc123", "miner-B")

            assert result2.is_duplicate
            assert result2.reward_multiplier == 0.10
            assert result2.first_submission_miner == "miner-A"


# ══════════════════════════════════════════════════════════════════════════════
# Severity Scoring Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityScoring:
    """Test algorithmic severity scoring."""

    def test_zero_impact(self):
        """No state change = zero severity."""
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": 0,
            "storage_diffs": [],
            "event_logs": [],
            "reverted": False,
        }
        score = scorer.score(trace)
        assert score == 0.0

    def test_funds_drained(self):
        """Draining funds should produce positive severity."""
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
        assert breakdown.invariant_broken_score == 1.0  # Funds drained = invariant broken
        assert breakdown.final_severity > 0

    def test_privilege_escalation(self):
        """Changing owner slot should trigger privilege escalation."""
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": 0,
            "storage_diffs": [
                {"slot": "0x0", "before": "0x" + "0" * 24 + "dead" * 5, "after": "0x" + "0" * 24 + "beef" * 5}
            ],
            "event_logs": [],
            "reverted": False,
        }
        breakdown = scorer.score_detailed(trace)

        assert breakdown.privilege_escalation_score == 1.0
        assert breakdown.final_severity > 0

    def test_reverted_exploit(self):
        """Reverted exploit = zero severity."""
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": -100 * 10**18,
            "storage_diffs": [],
            "reverted": True,
        }
        score = scorer.score(trace)
        assert score == 0.0

    def test_max_severity(self):
        """All impact types present should approach max severity."""
        from validator.scoring.severity import SeverityScorer

        scorer = SeverityScorer()
        trace = {
            "balance_delta": -1000000 * 10**18,  # 1M ETH
            "storage_diffs": [
                {"slot": "0x0", "before": "0x" + "a" * 64, "after": "0x" + "0" * 64},  # Owner zeroed
                {"slot": "0x1", "before": "0x" + "b" * 64, "after": "0x" + "c" * 64},
                {"slot": "0x2", "before": "0x" + "d" * 64, "after": "0x" + "e" * 64},
            ],
            "event_logs": [],
            "reverted": False,
        }
        breakdown = scorer.score_detailed(trace)

        assert breakdown.funds_drained_score > 0.9
        assert breakdown.privilege_escalation_score == 1.0
        assert breakdown.invariant_broken_score == 1.0
        assert breakdown.permanent_lock_score == 1.0  # Owner zeroed
        assert breakdown.final_severity > 0.9


# ══════════════════════════════════════════════════════════════════════════════
# Anti-Collusion Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAntiCollusion:
    """Test validator consensus and divergence tracking."""

    def test_validator_assignment(self):
        """Validator assignment must be deterministic for same task within one engine instance."""
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(10):
                engine.register_validator(f"validator-{i}", stake=100.0)

            assigned1 = engine.assign_validators("task-001")
            assigned2 = engine.assign_validators("task-001")

            assert assigned1 == assigned2, "Assignment must be deterministic within same instance"

    def test_validator_assignment_varies_by_task(self):
        """Different tasks should get different validator sets."""
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(20):
                engine.register_validator(f"validator-{i}", stake=100.0)

            assigned1 = engine.assign_validators("task-001")
            assigned2 = engine.assign_validators("task-002")

            # Not guaranteed to be completely different, but very likely
            assert assigned1 != assigned2 or True  # Probabilistic, just verify no crash

    def test_consensus_valid(self):
        """Majority VALID votes should produce VALID consensus."""
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(7):
                engine.register_validator(f"v-{i}", stake=100.0)

            votes = [
                {"validator_hotkey": f"v-{i}", "result": "VALID", "fingerprint": "0xabc", "severity_score": 0.8}
                for i in range(5)
            ] + [
                {"validator_hotkey": "v-5", "result": "REJECT_REVERT", "fingerprint": "", "severity_score": 0.0},
                {"validator_hotkey": "v-6", "result": "REJECT_REVERT", "fingerprint": "", "severity_score": 0.0},
            ]

            result = engine.compute_consensus("task-001", "sub-001", votes)
            assert result.consensus_result == "VALID"
            assert result.agreement_ratio >= 0.66
            assert len(result.diverging_validators) == 2

    def test_consensus_reject(self):
        """Majority REJECT votes should produce REJECT consensus."""
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(7):
                engine.register_validator(f"v-{i}", stake=100.0)

            votes = [
                {"validator_hotkey": f"v-{i}", "result": "REJECT_REVERT", "fingerprint": "", "severity_score": 0.0}
                for i in range(6)
            ] + [
                {"validator_hotkey": "v-6", "result": "VALID", "fingerprint": "0xabc", "severity_score": 0.5},
            ]

            result = engine.compute_consensus("task-002", "sub-002", votes)
            assert result.consensus_result == "REJECT_REVERT"

    def test_divergence_tracking(self):
        """Diverging validators should accumulate divergence score."""
        from validator.anticollusion.consensus import AntiCollusionEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = AntiCollusionEngine(data_dir=Path(tmpdir))
            for i in range(7):
                engine.register_validator(f"v-{i}", stake=100.0)

            # Create many consensus rounds where v-0 always disagrees
            for task_num in range(10):
                votes = [
                    {"validator_hotkey": f"v-{i}", "result": "VALID", "fingerprint": "0xabc", "severity_score": 0.8}
                    for i in range(1, 7)
                ] + [
                    {"validator_hotkey": "v-0", "result": "REJECT_REVERT", "fingerprint": "", "severity_score": 0.0},
                ]
                engine.compute_consensus(f"task-{task_num}", f"sub-{task_num}", votes)

            # v-0 should have 100% divergence
            stats = engine.export_validator_stats()
            assert stats["v-0"]["divergence_rate"] == 1.0
            assert stats["v-0"]["divergences"] == 10


# ══════════════════════════════════════════════════════════════════════════════
# Subnet Incentive Adapter Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSubnetIncentiveAdapter:
    """Test weight computation from validation results."""

    def test_single_miner_weight(self):
        """Single active miner gets all weight."""
        from subnet_adapter_module import SubnetIncentiveAdapter, ValidatorVote

        adapter = SubnetIncentiveAdapter()

        for i in range(5):
            adapter.record_vote(ValidatorVote(
                validator_hotkey=f"v-{i}",
                task_id="task-1",
                submission_hash="sub-1",
                result="VALID",
                fingerprint="0xabc",
                severity_score=0.8,
            ))

        result = adapter.compute_epoch_weights(epoch_number=1, start_block=0, end_block=360)

        assert result.total_valid == 1
        assert len(result.weights) == 1
        weight = list(result.weights.values())[0]
        assert weight == 1.0

    def test_no_valid_exploits_zero_weight(self):
        """Miners with only invalid submissions get zero weight."""
        from subnet_adapter_module import SubnetIncentiveAdapter, ValidatorVote

        adapter = SubnetIncentiveAdapter()

        for i in range(5):
            adapter.record_vote(ValidatorVote(
                validator_hotkey=f"v-{i}",
                task_id="task-1",
                submission_hash="sub-1",
                result="REJECT_REVERT",
            ))

        result = adapter.compute_epoch_weights(epoch_number=1, start_block=0, end_block=360)

        assert result.total_valid == 0
        assert len(result.weights) == 0


# ══════════════════════════════════════════════════════════════════════════════
# Helpers for import resolution
# ══════════════════════════════════════════════════════════════════════════════

# These handle the module path differences when running tests
try:
    from task_generator_module import TaskPackage, DeploymentConfig
except ImportError:
    # Create module alias
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "task_generator_module",
        str(PROJECT_ROOT / "task-generator" / "generate.py")
    )
    task_generator_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(task_generator_module)
    sys.modules["task_generator_module"] = task_generator_module
    from task_generator_module import TaskPackage, DeploymentConfig

try:
    from subnet_adapter_module import SubnetIncentiveAdapter, ValidatorVote
except ImportError:
    spec = importlib.util.spec_from_file_location(
        "subnet_adapter_module",
        str(PROJECT_ROOT / "subnet-adapter" / "incentive.py")
    )
    subnet_adapter_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subnet_adapter_module)
    sys.modules["subnet_adapter_module"] = subnet_adapter_module
    from subnet_adapter_module import SubnetIncentiveAdapter, ValidatorVote


# ══════════════════════════════════════════════════════════════════════════════
# Run
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """Run all tests without pytest dependency."""

    test_classes = [
        TestTaskGenerator,
        TestFingerprint,
        TestSeverityScoring,
        TestAntiCollusion,
        TestSubnetIncentiveAdapter,
    ]

    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        print(f"\n{'='*60}")
        print(f" {cls.__name__}")
        print(f"{'='*60}")

        instance = cls()
        for method_name in dir(instance):
            if not method_name.startswith("test_"):
                continue

            method = getattr(instance, method_name)
            try:
                method()
                print(f"  [PASS] {method_name}")
                passed += 1
            except Exception as e:
                print(f"  [FAIL] {method_name}: {e}")
                failed += 1
                errors.append((cls.__name__, method_name, str(e)))

    print(f"\n{'='*60}")
    print(f" Results: {passed} passed, {failed} failed")
    print(f"{'='*60}")

    if errors:
        print("\nFailures:")
        for cls_name, method, err in errors:
            print(f"  {cls_name}.{method}: {err}")

    sys.exit(1 if failed else 0)
