"""
JSON Schema definitions for system-boundary validation.

Validates miner submissions, task definitions, and execution traces
at the boundary before they enter the validation pipeline.
"""

from jsonschema import validate, ValidationError

# ── Exploit Submission Schema ────────────────────────────────────────────────

EXPLOIT_SUBMISSION_SCHEMA = {
    "type": "object",
    "required": ["task_id", "exploit_source"],
    "properties": {
        "task_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
        },
        "exploit_source": {
            "type": "string",
            "minLength": 1,
            "maxLength": 65536,
        },
        "entry_function": {
            "type": "string",
            "pattern": "^test_[a-zA-Z0-9_]+$",
        },
        "expected_state_diff": {
            "type": ["object", "null"],
        },
    },
    "additionalProperties": False,
}

# ── Task Definition Schema ───────────────────────────────────────────────────

TASK_DEFINITION_SCHEMA = {
    "type": "object",
    "required": ["task_id", "vulnerability_class"],
    "properties": {
        "task_id": {
            "type": "string",
            "minLength": 1,
        },
        "vulnerability_class": {
            "type": "string",
            "minLength": 1,
        },
        "source_code": {
            "type": "string",
        },
        "solc_version": {
            "type": "string",
            "pattern": r"^0\.\d+\.\d+$",
        },
        "deployment_config": {
            "type": "object",
            "properties": {
                "initial_balance": {"type": "integer", "minimum": 0},
            },
        },
        "difficulty": {
            "type": "integer",
            "minimum": 1,
            "maximum": 5,
        },
        "source_hash": {
            "type": "string",
        },
    },
}

# ── Execution Trace Schema ───────────────────────────────────────────────────

EXECUTION_TRACE_SCHEMA = {
    "type": "object",
    "properties": {
        "storage_diffs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["slot", "before", "after"],
                "properties": {
                    "slot": {"type": "string"},
                    "before": {"type": "string"},
                    "after": {"type": "string"},
                },
            },
        },
        "balance_before": {"type": "integer"},
        "balance_after": {"type": "integer"},
        "balance_delta": {"type": ["integer", "number"]},
        "event_logs": {"type": "array"},
        "gas_used": {"type": "integer", "minimum": 0},
        "reverted": {"type": "boolean"},
        "revert_reason": {"type": "string"},
    },
}


def validate_submission(data: dict) -> None:
    """Validate a miner submission dict. Raises ValidationError on failure."""
    validate(instance=data, schema=EXPLOIT_SUBMISSION_SCHEMA)


def validate_task(data: dict) -> None:
    """Validate a task definition dict. Raises ValidationError on failure."""
    validate(instance=data, schema=TASK_DEFINITION_SCHEMA)


def validate_trace(data: dict) -> None:
    """Validate an execution trace dict. Raises ValidationError on failure."""
    validate(instance=data, schema=EXECUTION_TRACE_SCHEMA)
