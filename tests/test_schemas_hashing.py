"""Tests for validator.utils.schemas and validator.utils.hashing (P0 gaps)."""

import pytest
from jsonschema import ValidationError

from validator.utils.schemas import (
    validate_submission,
    validate_task,
    validate_trace,
)
from validator.utils.hashing import keccak256, _KNOWN_HELLO_HASH


# ── keccak256 tests ──────────────────────────────────────────────────────────


class TestKeccak256:
    def test_hello_vector(self):
        assert keccak256(b"hello") == _KNOWN_HELLO_HASH

    def test_empty_bytes(self):
        result = keccak256(b"")
        # Known: keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert result == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    def test_returns_0x_prefixed_hex(self):
        result = keccak256(b"test")
        assert result.startswith("0x")
        assert len(result) == 66  # 0x + 64 hex chars

    def test_deterministic(self):
        assert keccak256(b"abc") == keccak256(b"abc")

    def test_different_inputs_different_hashes(self):
        assert keccak256(b"a") != keccak256(b"b")


# ── validate_submission tests ────────────────────────────────────────────────


class TestValidateSubmission:
    def test_valid_minimal(self):
        validate_submission({"task_id": "t1", "exploit_source": "code"})

    def test_valid_full(self):
        validate_submission({
            "task_id": "task-001",
            "exploit_source": "pragma solidity ^0.8.0;",
            "entry_function": "test_exploit",
            "expected_state_diff": {"slot": "0x0"},
        })

    def test_missing_task_id(self):
        with pytest.raises(ValidationError):
            validate_submission({"exploit_source": "code"})

    def test_missing_exploit_source(self):
        with pytest.raises(ValidationError):
            validate_submission({"task_id": "t1"})

    def test_empty_task_id(self):
        with pytest.raises(ValidationError):
            validate_submission({"task_id": "", "exploit_source": "code"})

    def test_empty_exploit_source(self):
        with pytest.raises(ValidationError):
            validate_submission({"task_id": "t1", "exploit_source": ""})

    def test_additional_properties_rejected(self):
        with pytest.raises(ValidationError):
            validate_submission({
                "task_id": "t1",
                "exploit_source": "code",
                "unknown_field": "bad",
            })

    def test_entry_function_must_start_with_test(self):
        with pytest.raises(ValidationError):
            validate_submission({
                "task_id": "t1",
                "exploit_source": "code",
                "entry_function": "exploit",  # doesn't start with test_
            })

    def test_entry_function_valid(self):
        validate_submission({
            "task_id": "t1",
            "exploit_source": "code",
            "entry_function": "test_reentrancy",
        })

    def test_exploit_source_max_length(self):
        with pytest.raises(ValidationError):
            validate_submission({
                "task_id": "t1",
                "exploit_source": "x" * 65537,
            })

    def test_expected_state_diff_null_allowed(self):
        validate_submission({
            "task_id": "t1",
            "exploit_source": "code",
            "expected_state_diff": None,
        })


# ── validate_task tests ──────────────────────────────────────────────────────


class TestValidateTask:
    def test_valid_minimal(self):
        validate_task({"task_id": "t1", "vulnerability_class": "reentrancy"})

    def test_valid_full(self):
        validate_task({
            "task_id": "task-001",
            "vulnerability_class": "reentrancy",
            "source_code": "pragma solidity ^0.8.0;",
            "solc_version": "0.8.28",
            "deployment_config": {"initial_balance": 100},
            "difficulty": 3,
            "source_hash": "0xabc",
        })

    def test_missing_task_id(self):
        with pytest.raises(ValidationError):
            validate_task({"vulnerability_class": "reentrancy"})

    def test_missing_vulnerability_class(self):
        with pytest.raises(ValidationError):
            validate_task({"task_id": "t1"})

    def test_difficulty_bounds(self):
        validate_task({"task_id": "t1", "vulnerability_class": "x", "difficulty": 1})
        validate_task({"task_id": "t1", "vulnerability_class": "x", "difficulty": 5})
        with pytest.raises(ValidationError):
            validate_task({"task_id": "t1", "vulnerability_class": "x", "difficulty": 0})
        with pytest.raises(ValidationError):
            validate_task({"task_id": "t1", "vulnerability_class": "x", "difficulty": 6})

    def test_solc_version_format(self):
        validate_task({"task_id": "t1", "vulnerability_class": "x", "solc_version": "0.8.28"})
        with pytest.raises(ValidationError):
            validate_task({"task_id": "t1", "vulnerability_class": "x", "solc_version": "latest"})


# ── validate_trace tests ─────────────────────────────────────────────────────


class TestValidateTrace:
    def test_valid_empty(self):
        validate_trace({})

    def test_valid_full(self):
        validate_trace({
            "storage_diffs": [
                {"slot": "0x0", "before": "0x0", "after": "0x1"},
            ],
            "balance_before": 1000,
            "balance_after": 0,
            "balance_delta": -1000,
            "event_logs": [],
            "gas_used": 21000,
            "reverted": False,
            "revert_reason": "",
        })

    def test_storage_diff_requires_fields(self):
        with pytest.raises(ValidationError):
            validate_trace({
                "storage_diffs": [{"slot": "0x0"}],  # missing before/after
            })

    def test_gas_used_non_negative(self):
        with pytest.raises(ValidationError):
            validate_trace({"gas_used": -1})

    def test_reverted_must_be_boolean(self):
        with pytest.raises(ValidationError):
            validate_trace({"reverted": "yes"})


# ── P0 Tests: H-4 Additional Properties ──────────────────────────────────────

class TestAdditionalPropertiesRejection:
    """H-4: additionalProperties: false on schemas rejects unknown fields."""

    def test_task_additional_properties_rejected(self):
        with pytest.raises(ValidationError):
            validate_task({
                "task_id": "t1",
                "vulnerability_class": "reentrancy",
                "unknown_field": "malicious",
            })

    def test_trace_additional_properties_rejected(self):
        with pytest.raises(ValidationError):
            validate_trace({
                "gas_used": 50000,
                "unknown_field": "inject",
            })
