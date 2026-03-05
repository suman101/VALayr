"""
Tests for validator.engine.validate — mock-based unit tests for the validation pipeline.

Covers: sanitize_source, _compute_fingerprint, _build_trace, _has_state_change,
        ValidationReport serialization, and all rejection paths.
"""

import json
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from validator.engine.validate import (
    ValidationEngine,
    ValidationResult,
    ValidationReport,
    ExploitSubmission,
    ExecutionTrace,
    StorageSlotDiff,
    MAX_EXPLOIT_SOURCE_BYTES,
    MIN_GAS_THRESHOLD,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_engine():
    return ValidationEngine(validator_id="test-v", anvil_port=19999)


def _make_submission(source="// valid", task_id="task-test"):
    return ExploitSubmission(task_id=task_id, exploit_source=source)


def _make_task_json(task_id="task-test"):
    return {
        "task_id": task_id,
        "source_code": "pragma solidity ^0.8.0; contract T {}",
        "solc_version": "0.8.28",
        "deployment_config": {"constructor_args": [], "initial_balance": 0},
        "vulnerability_class": "reentrancy",
        "_source_dir": "/tmp/fake",
    }


# ── ValidationReport Tests ──────────────────────────────────────────────────


class TestValidationReport:
    def test_to_dict_without_trace(self):
        report = ValidationReport(
            task_id="t1",
            result=ValidationResult.VALID,
            fingerprint="fp1",
            severity_score=0.7,
            validator_id="v0",
        )
        d = report.to_dict()
        assert d["result"] == "VALID"
        assert d["fingerprint"] == "fp1"
        assert "execution_trace" not in d

    def test_to_dict_with_trace(self):
        trace = ExecutionTrace(gas_used=50000, balance_delta=100)
        report = ValidationReport(
            task_id="t1",
            result=ValidationResult.VALID,
            execution_trace=trace,
        )
        d = report.to_dict()
        assert "execution_trace" in d
        assert d["execution_trace"]["gas_used"] == 50000


# ── _sanitize_source Tests ──────────────────────────────────────────────────


class TestSanitizeSource:
    """Unit tests for _sanitize_source (complements test_security.py T1)."""

    def test_clean_source_passes(self):
        src = 'import "../src/Vulnerable.sol";\ncontract Exploit {}'
        assert ValidationEngine._sanitize_source(src) is True

    def test_deep_traversal_rejected(self):
        assert ValidationEngine._sanitize_source('import "../../etc/passwd";') is False

    def test_url_import_rejected(self):
        assert ValidationEngine._sanitize_source('import "https://evil.com/lib.sol";') is False

    def test_absolute_path_rejected(self):
        assert ValidationEngine._sanitize_source('import "/etc/shadow";') is False

    def test_windows_path_rejected(self):
        assert ValidationEngine._sanitize_source('import "C:\\\\Windows\\\\system32";') is False

    def test_assembly_delegatecall_rejected(self):
        src = "contract X { function f() external { assembly { delegatecall(gas(), 0, 0, 0, 0, 0) } } }"
        assert ValidationEngine._sanitize_source(src) is False

    def test_assembly_sstore_rejected(self):
        src = "contract X { function f() external { assembly { sstore(0, 1) } } }"
        assert ValidationEngine._sanitize_source(src) is False


# ── _has_state_change Tests ──────────────────────────────────────────────────


class TestHasStateChange:
    def test_storage_diff_counts(self):
        engine = _make_engine()
        trace = ExecutionTrace(
            storage_diffs=[StorageSlotDiff(slot="0x0", before="0x0", after="0x1")]
        )
        assert engine._has_state_change(trace) is True

    def test_balance_delta_counts(self):
        engine = _make_engine()
        trace = ExecutionTrace(balance_delta=100)
        assert engine._has_state_change(trace) is True

    def test_event_logs_count(self):
        engine = _make_engine()
        trace = ExecutionTrace(event_logs=[{"topic": "0x123"}])
        assert engine._has_state_change(trace) is True

    def test_no_changes(self):
        engine = _make_engine()
        trace = ExecutionTrace()
        assert engine._has_state_change(trace) is False


# ── _build_trace Tests ───────────────────────────────────────────────────────


class TestBuildTrace:
    def test_basic_trace_construction(self):
        """_build_trace reads gas from stdout JSON (forge format), balance from state dicts."""
        engine = _make_engine()
        pre_state = {
            "balance": 1000,
            "storage": {"0x0": "0xaa"},
        }
        post_state = {
            "balance": 500,
            "storage": {"0x0": "0xbb"},
        }
        # Forge JSON output with test_results containing gas_used
        forge_json = json.dumps({
            "test/Exploit.t.sol:ExploitTest": {
                "test_results": {
                    "test_run": {"gas_used": 50000, "status": "Success", "reason": ""}
                }
            }
        })
        exec_result = {"success": True, "stdout": forge_json, "stderr": ""}
        trace = engine._build_trace(pre_state, post_state, exec_result)
        assert trace.gas_used == 50000
        assert trace.balance_before == 1000
        assert trace.balance_after == 500
        assert trace.balance_delta == -500
        assert len(trace.storage_diffs) == 1
        assert trace.storage_diffs[0].before == "0xaa"
        assert trace.storage_diffs[0].after == "0xbb"
        assert not trace.reverted

    def test_reverted_trace(self):
        engine = _make_engine()
        exec_result = {
            "success": False,
            "stdout": "",
            "stderr": "Ownable: caller is not the owner",
        }
        trace = engine._build_trace(
            {"balance": 0, "storage": {}},
            {"balance": 0, "storage": {}},
            exec_result,
        )
        assert trace.reverted is True
        assert "Ownable" in trace.revert_reason

    def test_multi_tx_trace(self):
        engine = _make_engine()
        forge_json = json.dumps({
            "test/Exploit.t.sol:ExploitTest": {
                "test_results": {
                    "test_step1": {"gas_used": 50000, "status": "Success", "reason": ""},
                    "test_step2": {"gas_used": 50000, "status": "Success", "reason": ""},
                }
            }
        })
        exec_result = {"success": True, "stdout": forge_json, "stderr": ""}
        trace = engine._build_trace(
            {"balance": 0, "storage": {}},
            {"balance": 0, "storage": {}},
            exec_result,
        )
        assert trace.is_multi_tx is True
        assert trace.gas_used == 100000

    def test_malformed_exec_result_defaults(self):
        engine = _make_engine()
        # Non-JSON stdout triggers the except block which estimates gas
        exec_result = {"success": True, "stdout": "{bad json", "stderr": ""}
        trace = engine._build_trace(
            {"balance": 0, "storage": {}},
            {"balance": 0, "storage": {}},
            exec_result,
        )
        # Fallback: 21000 + 0 storage diffs * 5000
        assert trace.gas_used == 21000
        assert trace.event_logs == []


# ── Rejection Path Tests (mocked pipeline) ──────────────────────────────────


class TestRejectionPaths:
    def test_oversized_source_rejected(self):
        engine = _make_engine()
        huge_source = "x" * (MAX_EXPLOIT_SOURCE_BYTES + 1)
        sub = _make_submission(source=huge_source)
        report = engine.validate(_make_task_json(), sub)
        assert report.result == ValidationResult.REJECT_INVALID_FORMAT
        assert "byte limit" in report.error_message

    def test_unsanitized_source_rejected(self):
        engine = _make_engine()
        bad_source = 'import "../../etc/passwd";\ncontract X {}'
        sub = _make_submission(source=bad_source)
        report = engine.validate(_make_task_json(), sub)
        assert report.result == ValidationResult.REJECT_INVALID_FORMAT
        assert "disallowed" in report.error_message

    @patch.object(ValidationEngine, "_setup_workspace", return_value=None)
    def test_workspace_setup_failure(self, mock_ws):
        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_INVALID_FORMAT
        assert "workspace" in report.error_message.lower()

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_compile", return_value=False)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_compile_failure(self, mock_ws, mock_compile, mock_stop, mock_clean):
        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_COMPILE_FAIL

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_start_anvil", return_value=False)
    @patch.object(ValidationEngine, "_compile", return_value=True)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_anvil_startup_failure(self, mock_ws, mock_compile, mock_anvil, mock_stop, mock_clean):
        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_INVALID_FORMAT
        assert "anvil" in report.error_message.lower()

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_compute_fingerprint", return_value="fp123")
    @patch.object(ValidationEngine, "_has_state_change", return_value=True)
    @patch.object(ValidationEngine, "_build_trace")
    @patch.object(ValidationEngine, "_capture_state", side_effect=[{"balance": 0, "storage": {}, "nonce": 0}] * 2)
    @patch.object(ValidationEngine, "_execute_exploit", return_value={"gas_used": 50000})
    @patch.object(ValidationEngine, "_deploy_target", return_value="0xTARGET")
    @patch.object(ValidationEngine, "_start_anvil", return_value=True)
    @patch.object(ValidationEngine, "_compile", return_value=True)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_valid_exploit_happy_path(
        self, mock_ws, mock_compile, mock_anvil, mock_deploy,
        mock_exec, mock_capture, mock_trace, mock_state, mock_fp,
        mock_stop, mock_clean,
    ):
        trace = ExecutionTrace(gas_used=50000, balance_delta=-100, reverted=False)
        mock_trace.return_value = trace

        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.VALID
        assert report.fingerprint == "fp123"

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_build_trace")
    @patch.object(ValidationEngine, "_capture_state", side_effect=[{"balance": 0, "storage": {}, "nonce": 0}] * 2)
    @patch.object(ValidationEngine, "_execute_exploit", return_value={"gas_used": 50000})
    @patch.object(ValidationEngine, "_deploy_target", return_value="0xTARGET")
    @patch.object(ValidationEngine, "_start_anvil", return_value=True)
    @patch.object(ValidationEngine, "_compile", return_value=True)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_revert_rejected(
        self, mock_ws, mock_compile, mock_anvil, mock_deploy,
        mock_exec, mock_capture, mock_trace,
        mock_stop, mock_clean,
    ):
        trace = ExecutionTrace(gas_used=50000, reverted=True, revert_reason="re-entrancy guard")
        mock_trace.return_value = trace

        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_REVERT

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_build_trace")
    @patch.object(ValidationEngine, "_capture_state", side_effect=[{"balance": 0, "storage": {}, "nonce": 0}] * 2)
    @patch.object(ValidationEngine, "_execute_exploit", return_value={"gas_used": 100})
    @patch.object(ValidationEngine, "_deploy_target", return_value="0xTARGET")
    @patch.object(ValidationEngine, "_start_anvil", return_value=True)
    @patch.object(ValidationEngine, "_compile", return_value=True)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_below_gas_threshold_rejected(
        self, mock_ws, mock_compile, mock_anvil, mock_deploy,
        mock_exec, mock_capture, mock_trace,
        mock_stop, mock_clean,
    ):
        trace = ExecutionTrace(gas_used=100, reverted=False)
        mock_trace.return_value = trace

        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_BELOW_GAS_THRESHOLD

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_has_state_change", return_value=False)
    @patch.object(ValidationEngine, "_build_trace")
    @patch.object(ValidationEngine, "_capture_state", side_effect=[{"balance": 0, "storage": {}, "nonce": 0}] * 2)
    @patch.object(ValidationEngine, "_execute_exploit", return_value={"gas_used": 50000})
    @patch.object(ValidationEngine, "_deploy_target", return_value="0xTARGET")
    @patch.object(ValidationEngine, "_start_anvil", return_value=True)
    @patch.object(ValidationEngine, "_compile", return_value=True)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_no_state_change_rejected(
        self, mock_ws, mock_compile, mock_anvil, mock_deploy,
        mock_exec, mock_capture, mock_trace, mock_state,
        mock_stop, mock_clean,
    ):
        trace = ExecutionTrace(gas_used=50000, reverted=False)
        mock_trace.return_value = trace

        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_NO_STATE_CHANGE

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_compute_fingerprint", return_value="")
    @patch.object(ValidationEngine, "_has_state_change", return_value=True)
    @patch.object(ValidationEngine, "_build_trace")
    @patch.object(ValidationEngine, "_capture_state", side_effect=[{"balance": 0, "storage": {}, "nonce": 0}] * 2)
    @patch.object(ValidationEngine, "_execute_exploit", return_value={"gas_used": 50000})
    @patch.object(ValidationEngine, "_deploy_target", return_value="0xTARGET")
    @patch.object(ValidationEngine, "_start_anvil", return_value=True)
    @patch.object(ValidationEngine, "_compile", return_value=True)
    @patch.object(ValidationEngine, "_setup_workspace", return_value=Path("/tmp/ws"))
    def test_fingerprint_error_rejected(
        self, mock_ws, mock_compile, mock_anvil, mock_deploy,
        mock_exec, mock_capture, mock_trace, mock_state, mock_fp,
        mock_stop, mock_clean,
    ):
        trace = ExecutionTrace(gas_used=50000, balance_delta=-100, reverted=False)
        mock_trace.return_value = trace

        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_FINGERPRINT_ERROR

    @patch.object(ValidationEngine, "_cleanup_workspace")
    @patch.object(ValidationEngine, "_stop_anvil")
    @patch.object(ValidationEngine, "_setup_workspace", side_effect=subprocess.TimeoutExpired("cmd", 120))
    def test_timeout_rejected(self, mock_ws, mock_stop, mock_clean):
        engine = _make_engine()
        report = engine.validate(_make_task_json(), _make_submission())
        assert report.result == ValidationResult.REJECT_TIMEOUT


# ── _compute_fingerprint Tests ──────────────────────────────────────────────


class TestComputeFingerprint:
    @patch("validator.fingerprint.dedup.FingerprintEngine.compute_fingerprint", return_value="abc123")
    @patch("validator.fingerprint.dedup.FingerprintEngine.extract_components")
    def test_basic_fingerprint(self, mock_extract, mock_fp):
        engine = _make_engine()
        trace = ExecutionTrace(
            storage_diffs=[StorageSlotDiff(slot="0x0", before="0x0", after="0x1")],
            gas_used=50000,
        )
        result = engine._compute_fingerprint(trace)
        assert result == "abc123"
        mock_extract.assert_called_once()


# ── _detect_test_functions Tests ─────────────────────────────────────────────


class TestDetectTestFunctions:
    def test_single_function(self):
        src = """
        contract Exploit {
            function test_run() external { }
        }
        """
        result = ValidationEngine._detect_test_functions(src)
        assert "test_run" in result

    def test_multiple_functions(self):
        src = """
        contract Exploit {
            function test_step1() external { }
            function test_step2() external { }
            function helper() internal { }
        }
        """
        result = ValidationEngine._detect_test_functions(src)
        assert "test_step1" in result
        assert "test_step2" in result
        assert "helper" not in result

    def test_no_test_functions(self):
        src = "contract Exploit { function run() external { } }"
        result = ValidationEngine._detect_test_functions(src)
        assert len(result) == 0
