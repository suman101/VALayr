"""
Multi-Transaction Exploit Support — Unit Tests.

Tests the complete multi-tx pipeline:
  1. Detection of multiple test_* functions in exploit source
  2. Wrapping preserves multi-function structure
  3. Per-function selector grouping in execution traces
  4. Sequence-aware fingerprinting (order matters)
  5. Multi-tx severity scoring (net-delta vs per-function)
  6. Protocol synapse carries entry_functions
  7. Orchestrator passes entry_functions through pipeline
"""

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.engine.validate import (
    ValidationEngine, ExploitSubmission, ExecutionTrace, StorageSlotDiff,
)
from validator.fingerprint.dedup import FingerprintEngine, FingerprintComponents
from validator.scoring.severity import SeverityScorer
from neurons.protocol import ExploitSubmissionSynapse


# ── Sample Multi-TX Exploit Source ──────────────────────────────────────────

MULTI_TX_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function setUp() public {}

    function test_step1_setup() public {
        // Step 1: deposit collateral
    }

    function test_step2_manipulate() public {
        // Step 2: manipulate oracle
    }

    function test_step3_drain() public {
        // Step 3: drain funds
    }
}
"""

SINGLE_TX_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function test_run() public {
        // Single-step exploit
    }
}
"""

RAW_MULTI_FUNCTION = """
function test_attack1() public {
    // attack step 1
}

function test_attack2() public {
    // attack step 2
}
"""


# ── 1. Detection Tests ─────────────────────────────────────────────────────

def test_detect_test_functions_multi():
    """_detect_test_functions finds all test_* functions."""
    engine = ValidationEngine()
    funcs = engine._detect_test_functions(MULTI_TX_SOURCE)
    assert funcs == ["test_step1_setup", "test_step2_manipulate", "test_step3_drain"], \
        f"Expected 3 test functions, got {funcs}"
    print("  [+] Multi-function detection OK")


def test_detect_test_functions_single():
    """Single test_run is detected correctly."""
    engine = ValidationEngine()
    funcs = engine._detect_test_functions(SINGLE_TX_SOURCE)
    assert funcs == ["test_run"], f"Expected ['test_run'], got {funcs}"
    print("  [+] Single-function detection OK")


def test_detect_test_functions_raw():
    """Raw source without pragma still detects test_*."""
    engine = ValidationEngine()
    funcs = engine._detect_test_functions(RAW_MULTI_FUNCTION)
    assert funcs == ["test_attack1", "test_attack2"], f"Expected 2, got {funcs}"
    print("  [+] Raw multi-function detection OK")


def test_detect_test_functions_empty():
    """No test_* functions → empty list."""
    engine = ValidationEngine()
    funcs = engine._detect_test_functions("function helper() public {}")
    assert funcs == [], f"Expected [], got {funcs}"
    print("  [+] Empty detection OK")


# ── 2. Wrapping Tests ──────────────────────────────────────────────────────

def test_wrap_preserves_multi_function():
    """_wrap_exploit preserves multi-function structure when pragma+contract present."""
    engine = ValidationEngine()
    wrapped = engine._wrap_exploit(MULTI_TX_SOURCE, "Vulnerable")
    # Should preserve all 3 test functions
    funcs = engine._detect_test_functions(wrapped)
    assert len(funcs) == 3, f"Wrapped should still have 3 funcs, got {len(funcs)}"
    assert "test_step1_setup" in funcs
    assert "test_step2_manipulate" in funcs
    assert "test_step3_drain" in funcs
    print("  [+] Wrap preserves multi-function OK")


def test_wrap_raw_multi_function():
    """Raw multi-function source gets wrapped with contract boilerplate."""
    engine = ValidationEngine()
    wrapped = engine._wrap_exploit(RAW_MULTI_FUNCTION, "Vulnerable")
    funcs = engine._detect_test_functions(wrapped)
    assert "test_attack1" in funcs
    assert "test_attack2" in funcs
    assert "pragma solidity" in wrapped
    print("  [+] Raw wrap multi-function OK")


def test_wrap_single_function_fallback():
    """Single raw function without pragma → wrapped with test_run."""
    engine = ValidationEngine()
    raw = "target.withdraw();"
    wrapped = engine._wrap_exploit(raw, "test_run")
    funcs = engine._detect_test_functions(wrapped)
    assert "test_run" in funcs
    print("  [+] Single function fallback wrap OK")


# ── 3. ExecutionTrace Multi-TX Fields ───────────────────────────────────────

def test_execution_trace_multi_tx_fields():
    """ExecutionTrace has all multi-tx fields."""
    trace = ExecutionTrace()
    assert trace.test_results == {}
    assert trace.test_function_order == []
    assert trace.per_function_selectors == {}
    assert trace.is_multi_tx is False

    # Populate multi-tx data
    trace.test_results = {
        "test_step1": {"gas_used": 50000, "status": "Success", "reason": "", "selectors": ["a1b2c3d4"]},
        "test_step2": {"gas_used": 100000, "status": "Success", "reason": "", "selectors": ["e5f6a7b8"]},
    }
    trace.test_function_order = ["test_step1", "test_step2"]
    trace.per_function_selectors = {
        "test_step1": ["a1b2c3d4"],
        "test_step2": ["e5f6a7b8"],
    }
    trace.is_multi_tx = True

    assert trace.is_multi_tx
    assert len(trace.test_results) == 2
    assert trace.test_function_order[0] == "test_step1"
    print("  [+] ExecutionTrace multi-tx fields OK")


# ── 4. Fingerprint Sequence Awareness ───────────────────────────────────────

def test_fingerprint_sequence_differs():
    """Two exploits with same selectors in different order → different fingerprints."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")

        # Exploit A: step1 calls deposit, step2 calls withdraw
        comp_a = FingerprintComponents(
            function_selectors=["d0e30db0", "2e1a7d4d"],
            storage_slot_diffs=[{"slot": "0x5", "before": "0x01", "after": "0x00"}],
            balance_delta=-1000,
            test_function_order=["test_step1", "test_step2"],
            per_function_selectors={
                "test_step1": ["d0e30db0"],  # deposit
                "test_step2": ["2e1a7d4d"],  # withdraw
            },
        )

        # Exploit B: same selectors but reversed order
        comp_b = FingerprintComponents(
            function_selectors=["d0e30db0", "2e1a7d4d"],
            storage_slot_diffs=[{"slot": "0x5", "before": "0x01", "after": "0x00"}],
            balance_delta=-1000,
            test_function_order=["test_step1", "test_step2"],
            per_function_selectors={
                "test_step1": ["2e1a7d4d"],  # withdraw
                "test_step2": ["d0e30db0"],  # deposit
            },
        )

        fp_a = engine.compute_fingerprint(comp_a)
        fp_b = engine.compute_fingerprint(comp_b)

        assert fp_a != fp_b, \
            f"Different selector order should yield different fingerprints: {fp_a} == {fp_b}"
    print("  [+] Fingerprint sequence awareness OK")


def test_fingerprint_single_tx_unchanged():
    """Single-tx exploits still work with the old flat-selector path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")

        comp = FingerprintComponents(
            function_selectors=["a1b2c3d4", "e5f6a7b8"],
            storage_slot_diffs=[{"slot": "0x0", "before": "0x01", "after": "0x00"}],
            balance_delta=-5000,
        )

        fp = engine.compute_fingerprint(comp)
        assert fp.startswith("0x")
        assert len(fp) == 66

        # Determinism
        fp2 = engine.compute_fingerprint(comp)
        assert fp == fp2
    print("  [+] Fingerprint single-tx backward compat OK")


def test_extract_components_multi_tx():
    """extract_components picks up per_function_selectors and test_function_order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")

        trace_dict = {
            "function_selectors": ["a1b2c3d4", "e5f6a7b8"],
            "per_function_selectors": {
                "test_step1": ["a1b2c3d4"],
                "test_step2": ["e5f6a7b8"],
            },
            "test_function_order": ["test_step1", "test_step2"],
            "storage_diffs": [],
            "balance_delta": -1000,
        }

        fc = engine.extract_components(trace_dict)
        assert fc.per_function_selectors == trace_dict["per_function_selectors"]
        assert fc.test_function_order == ["test_step1", "test_step2"]
    print("  [+] extract_components multi-tx OK")


# ── 5. Severity Scoring Multi-TX ───────────────────────────────────────────

def test_severity_multi_tx_complexity_bonus():
    """Multi-tx exploits get a complexity bonus for multi-step gas."""
    scorer = SeverityScorer()

    # Single-tx exploit draining 1 ETH
    single_trace = {
        "balance_delta": -(1 * 10**18),
        "storage_diffs": [],
        "reverted": False,
        "is_multi_tx": False,
        "test_results": {},
    }
    s_single = scorer.score_detailed(single_trace)

    # Multi-tx exploit draining same amount with multiple steps
    multi_trace = {
        "balance_delta": -(1 * 10**18),
        "storage_diffs": [],
        "reverted": False,
        "is_multi_tx": True,
        "test_results": {
            "test_step1": {"gas_used": 200000, "status": "Success", "reason": ""},
            "test_step2": {"gas_used": 500000, "status": "Success", "reason": ""},
        },
    }
    s_multi = scorer.score_detailed(multi_trace)

    assert s_multi.final_severity >= s_single.final_severity, \
        f"Multi-tx ({s_multi.final_severity:.4f}) should score >= single ({s_single.final_severity:.4f})"
    assert "multi_tx(2_steps)" in s_multi.detail
    print(f"  [+] Multi-tx scoring OK (single={s_single.final_severity:.4f}, multi={s_multi.final_severity:.4f})")


def test_severity_multi_tx_abs_delta():
    """Multi-tx uses abs(balance_delta) to avoid net-zero masking."""
    scorer = SeverityScorer()

    # Multi-tx: setup deposits 5 ETH, attack drains 5 ETH → net delta = 0
    # But abs(0) = 0, so we test with net positive which single-tx ignores
    trace_positive_delta = {
        "balance_delta": 5 * 10**18,  # positive (target gained)
        "storage_diffs": [],
        "reverted": False,
        "is_multi_tx": True,
        "test_results": {
            "test_setup": {"gas_used": 100000, "status": "Success", "reason": ""},
            "test_drain": {"gas_used": 300000, "status": "Success", "reason": ""},
        },
    }
    s = scorer.score_detailed(trace_positive_delta)
    assert s.funds_drained_score > 0, \
        "Multi-tx should use abs(delta) so positive delta still counts"
    print("  [+] Multi-tx abs delta OK")


def test_severity_single_tx_positive_delta_ignored():
    """Single-tx with positive balance delta → zero funds score."""
    scorer = SeverityScorer()
    trace = {
        "balance_delta": 5 * 10**18,
        "storage_diffs": [],
        "reverted": False,
        "is_multi_tx": False,
        "test_results": {},
    }
    s = scorer.score_detailed(trace)
    assert s.funds_drained_score == 0, "Single-tx positive delta should be 0"
    print("  [+] Single-tx positive delta ignored OK")


# ── 6. Protocol Synapse ────────────────────────────────────────────────────

def test_synapse_entry_functions_field():
    """ExploitSubmissionSynapse accepts entry_functions."""
    syn = ExploitSubmissionSynapse(
        task_id="0x" + "a" * 64,
        exploit_source="contract X {}",
        entry_functions=["test_step1", "test_step2"],
    )
    assert syn.entry_functions == ["test_step1", "test_step2"]
    print("  [+] Synapse entry_functions OK")


def test_synapse_entry_functions_default():
    """Default entry_functions is empty list."""
    syn = ExploitSubmissionSynapse(
        task_id="0x" + "a" * 64,
        exploit_source="contract X {}",
    )
    assert syn.entry_functions == []
    print("  [+] Synapse default entry_functions OK")


# ── 7. ExploitSubmission Multi-TX ──────────────────────────────────────────

def test_exploit_submission_entry_functions():
    """ExploitSubmission has entry_functions field."""
    sub = ExploitSubmission(
        task_id="0x123",
        exploit_source="source",
        entry_functions=["test_step1", "test_step2"],
    )
    assert sub.entry_functions == ["test_step1", "test_step2"]
    print("  [+] ExploitSubmission entry_functions OK")


def test_exploit_submission_entry_functions_default():
    """ExploitSubmission default entry_functions is empty."""
    sub = ExploitSubmission(task_id="0x123", exploit_source="source")
    assert sub.entry_functions == []
    print("  [+] ExploitSubmission default entry_functions OK")


# ── 8. Build Trace Multi-TX ────────────────────────────────────────────────

def test_build_trace_multi_tx_flags():
    """_build_trace sets is_multi_tx when multiple test_results exist."""
    engine = ValidationEngine()
    pre_state = {"balance": 10 * 10**18, "storage": {}, "logs": []}
    post_state = {"balance": 1 * 10**18, "storage": {}, "logs": []}

    # Simulate forge JSON output with 2 test functions
    import json
    forge_json = json.dumps({
        "ExploitTest.sol:ExploitTest": {
            "test_results": {
                "test_step1_setup()": {"gas_used": 50000, "status": "Success", "reason": ""},
                "test_step2_drain()": {"gas_used": 120000, "status": "Success", "reason": ""},
            }
        }
    })

    exec_result = {
        "returncode": 0,
        "stdout": forge_json,
        "stderr": "",
        "success": True,
    }

    trace = engine._build_trace(pre_state, post_state, exec_result)
    assert trace.is_multi_tx, "Should be multi-tx with 2 test results"
    assert len(trace.test_results) == 2
    assert trace.gas_used == 170000  # 50k + 120k
    print("  [+] build_trace multi-tx flags OK")


def test_build_trace_single_tx():
    """_build_trace with single test → is_multi_tx = False."""
    engine = ValidationEngine()
    pre_state = {"balance": 0, "storage": {}, "logs": []}
    post_state = {"balance": 0, "storage": {}, "logs": []}

    import json
    forge_json = json.dumps({
        "ExploitTest.sol:ExploitTest": {
            "test_results": {
                "test_run()": {"gas_used": 80000, "status": "Success", "reason": ""},
            }
        }
    })

    trace = engine._build_trace(
        pre_state, post_state,
        {"returncode": 0, "stdout": forge_json, "stderr": "", "success": True},
    )
    assert not trace.is_multi_tx
    assert len(trace.test_results) == 1
    print("  [+] build_trace single-tx OK")


def test_build_trace_per_function_selectors_from_stderr():
    """_build_trace groups selectors by test function from forge stderr."""
    engine = ValidationEngine()
    pre_state = {"balance": 0, "storage": {}, "logs": []}
    post_state = {"balance": 0, "storage": {}, "logs": []}

    # Simulate forge stderr with trace lines
    stderr = """
[PASS] test_step1() (gas: 50000)
    ├─ VulnerableContract::deposit(uint256)
    └─ VulnerableContract::approve(address)
[PASS] test_step2() (gas: 80000)
    ├─ VulnerableContract::withdraw(uint256)
    └─ VulnerableContract::transfer(address)
"""
    import json
    forge_json = json.dumps({
        "ExploitTest.sol:ExploitTest": {
            "test_results": {
                "test_step1()": {"gas_used": 50000, "status": "Success", "reason": ""},
                "test_step2()": {"gas_used": 80000, "status": "Success", "reason": ""},
            }
        }
    })

    trace = engine._build_trace(
        pre_state, post_state,
        {"returncode": 0, "stdout": forge_json, "stderr": stderr, "success": True},
    )

    assert "test_step1" in trace.per_function_selectors
    assert "test_step2" in trace.per_function_selectors
    assert trace.test_function_order == ["test_step1", "test_step2"]
    assert len(trace.per_function_selectors["test_step1"]) == 2
    assert len(trace.per_function_selectors["test_step2"]) == 2
    print("  [+] build_trace per-function selectors OK")


# ── Runner ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("Multi-Transaction Exploit Support — Test Suite")
    print("=" * 60)

    tests = [
        # Detection
        test_detect_test_functions_multi,
        test_detect_test_functions_single,
        test_detect_test_functions_raw,
        test_detect_test_functions_empty,
        # Wrapping
        test_wrap_preserves_multi_function,
        test_wrap_raw_multi_function,
        test_wrap_single_function_fallback,
        # ExecutionTrace fields
        test_execution_trace_multi_tx_fields,
        # Fingerprint
        test_fingerprint_sequence_differs,
        test_fingerprint_single_tx_unchanged,
        test_extract_components_multi_tx,
        # Scoring
        test_severity_multi_tx_complexity_bonus,
        test_severity_multi_tx_abs_delta,
        test_severity_single_tx_positive_delta_ignored,
        # Protocol
        test_synapse_entry_functions_field,
        test_synapse_entry_functions_default,
        # ExploitSubmission
        test_exploit_submission_entry_functions,
        test_exploit_submission_entry_functions_default,
        # Build trace
        test_build_trace_multi_tx_flags,
        test_build_trace_single_tx,
        test_build_trace_per_function_selectors_from_stderr,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {test_fn.__name__}: {e}")

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
