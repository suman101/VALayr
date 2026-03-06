"""TC-2: Protocol synapse round-trip serialization tests."""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from neurons.protocol import ExploitSubmissionSynapse, ExploitQuerySynapse


class TestExploitSubmissionRoundTrip:
    """Verify ExploitSubmissionSynapse field persistence."""

    def test_basic_fields(self):
        s = ExploitSubmissionSynapse(
            task_id="0xabcdef1234567890",
            exploit_source="contract Exploit {}",
            entry_functions=["test_attack"],
        )
        assert s.task_id == "0xabcdef1234567890"
        assert s.exploit_source == "contract Exploit {}"
        assert s.entry_functions == ["test_attack"]

    def test_empty_entry_functions_default(self):
        s = ExploitSubmissionSynapse(task_id="0x1", exploit_source="x")
        assert s.entry_functions == []

    def test_result_initially_none(self):
        s = ExploitSubmissionSynapse()
        assert s.result is None

    def test_result_set_by_validator(self):
        s = ExploitSubmissionSynapse(task_id="0x1", exploit_source="x")
        s.result = {"valid": True, "severity": 0.9}
        assert s.result["valid"] is True
        assert s.result["severity"] == 0.9

    def test_multi_entry_functions(self):
        funcs = ["test_step1", "test_step2", "test_step3"]
        s = ExploitSubmissionSynapse(
            task_id="0xmulti",
            exploit_source="contract Multi {}",
            entry_functions=funcs,
        )
        assert len(s.entry_functions) == 3
        assert s.entry_functions == funcs


class TestExploitQueryRoundTrip:
    """Verify ExploitQuerySynapse field persistence."""

    def test_default_query_type(self):
        s = ExploitQuerySynapse()
        assert s.query_type == "status"
        assert s.task_id == ""

    def test_submit_query(self):
        s = ExploitQuerySynapse(query_type="submit", task_id="0xabc")
        assert s.query_type == "submit"
        assert s.task_id == "0xabc"

    def test_heartbeat_query(self):
        s = ExploitQuerySynapse(query_type="heartbeat")
        assert s.query_type == "heartbeat"

    def test_response_initially_none(self):
        s = ExploitQuerySynapse()
        assert s.response is None

    def test_response_set_by_miner(self):
        s = ExploitQuerySynapse()
        s.response = {"status": "ready", "tasks": 5}
        assert s.response["status"] == "ready"


class TestSynapseShim:
    """Verify the _SynapseBase shim works without bittensor."""

    def test_dendrite_hotkey_accessible(self):
        s = ExploitSubmissionSynapse()
        assert hasattr(s, "dendrite")
        assert hasattr(s.dendrite, "hotkey")
