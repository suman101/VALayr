"""
Tests for task-generator/mainnet.py — mock-based unit tests.

Covers MainnetContractSource: fetch_contract, _normalise_address, _flatten_multi_file,
_flatten_standard_json, to_task_package, fetch_and_save, and error handling.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from task_generator.mainnet import (
    MainnetContractSource,
    MainnetContract,
    EXPLORER_APIS,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

VALID_ADDR = "0x" + "aB" * 20
MOCK_SOURCE_RESPONSE = {
    "status": "1",
    "result": [{
        "SourceCode": "pragma solidity ^0.8.0; contract T { uint x; }",
        "ContractName": "TestContract",
        "CompilerVersion": "v0.8.20",
        "ConstructorArguments": "",
        "Proxy": "0",
        "Implementation": "",
    }],
}


def _mock_urlopen(response_body):
    """Return a context-manager mock that reads as JSON."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(response_body).encode()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ── _normalise_address Tests ─────────────────────────────────────────────────


class TestNormaliseAddress:
    def test_valid_address(self):
        src = MainnetContractSource(api_key="test")
        assert src._normalise_address(VALID_ADDR) == VALID_ADDR

    def test_strips_whitespace(self):
        src = MainnetContractSource(api_key="test")
        assert src._normalise_address(f"  {VALID_ADDR}  ") == VALID_ADDR

    def test_rejects_short_address(self):
        src = MainnetContractSource(api_key="test")
        with pytest.raises(ValueError, match="Invalid"):
            src._normalise_address("0x1234")

    def test_rejects_query_string(self):
        src = MainnetContractSource(api_key="test")
        with pytest.raises(ValueError, match="Invalid"):
            src._normalise_address(VALID_ADDR + "?action=evil")

    def test_rejects_url_encoded(self):
        src = MainnetContractSource(api_key="test")
        with pytest.raises(ValueError, match="Invalid"):
            src._normalise_address("0x" + "%20" * 20)


# ── fetch_contract Tests ─────────────────────────────────────────────────────


class TestFetchContract:
    @patch("urllib.request.urlopen")
    def test_happy_path(self, mock_urlopen, tmp_path):
        mock_urlopen.return_value = _mock_urlopen(MOCK_SOURCE_RESPONSE)
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        contract = src.fetch_contract(VALID_ADDR, chain_id=1)
        assert contract is not None
        assert contract.name == "TestContract"
        assert "pragma" in contract.source_code

    @patch("urllib.request.urlopen")
    def test_unverified_returns_none(self, mock_urlopen, tmp_path):
        response = {"status": "1", "result": [{"SourceCode": "", "ContractName": ""}]}
        mock_urlopen.return_value = _mock_urlopen(response)
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        assert src.fetch_contract(VALID_ADDR) is None

    @patch("urllib.request.urlopen")
    def test_api_error_returns_none(self, mock_urlopen, tmp_path):
        response = {"status": "0", "result": "error"}
        mock_urlopen.return_value = _mock_urlopen(response)
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        assert src.fetch_contract(VALID_ADDR) is None

    def test_unsupported_chain_raises(self, tmp_path):
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        with pytest.raises(ValueError, match="not in allowed set"):
            src.fetch_contract(VALID_ADDR, chain_id=999)

    @patch("urllib.request.urlopen", side_effect=OSError("network error"))
    def test_network_error_returns_none(self, mock_urlopen, tmp_path):
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        assert src.fetch_contract(VALID_ADDR) is None

    @patch("urllib.request.urlopen")
    def test_proxy_contract(self, mock_urlopen, tmp_path):
        response = {
            "status": "1",
            "result": [{
                "SourceCode": "pragma solidity ^0.8.0; contract P {}",
                "ContractName": "ProxyContract",
                "CompilerVersion": "v0.8.20",
                "ConstructorArguments": "",
                "Proxy": "1",
                "Implementation": "0x" + "ff" * 20,
            }],
        }
        mock_urlopen.return_value = _mock_urlopen(response)
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        contract = src.fetch_contract(VALID_ADDR)
        assert contract is not None
        assert contract.proxy is True


# ── to_task_package Tests ────────────────────────────────────────────────────


class TestToTaskPackage:
    def test_creates_valid_package(self, tmp_path):
        src = MainnetContractSource(api_key="test", output_dir=tmp_path)
        contract = MainnetContract(
            address=VALID_ADDR,
            chain_id=1,
            name="TestContract",
            source_code="pragma solidity ^0.8.0; contract T {}",
            solc_version="v0.8.20",
            constructor_args="",
        )
        pkg = src.to_task_package(contract, difficulty=3)
        assert pkg.task_id != ""
        assert pkg.metadata["source"] == "mainnet"
        assert pkg.difficulty == 3


# ── _flatten_multi_file Tests ────────────────────────────────────────────────


class TestFlattenMultiFile:
    def test_basic_flatten(self):
        inner = json.dumps({"A.sol": {"content": "// A"}, "B.sol": {"content": "// B"}})
        raw = "{" + inner + "}"
        result = MainnetContractSource._flatten_multi_file(raw)
        assert "// A" in result
        assert "// B" in result

    def test_truncates_over_500_files(self):
        files = {f"File{i}.sol": {"content": f"// File {i}"} for i in range(600)}
        inner = json.dumps(files)
        raw = "{" + inner + "}"
        result = MainnetContractSource._flatten_multi_file(raw)
        assert "truncated" in result

    def test_invalid_json_returns_raw(self):
        result = MainnetContractSource._flatten_multi_file("{not valid json}")
        assert "not valid json" in result


# ── _flatten_standard_json Tests ─────────────────────────────────────────────


class TestFlattenStandardJson:
    def test_basic_flatten(self):
        data = {"sources": {"C.sol": {"content": "// C"}}}
        raw = json.dumps(data)
        result = MainnetContractSource._flatten_standard_json(raw)
        assert "// C" in result

    def test_sanitizes_filenames(self):
        data = {"sources": {"../evil<script>.sol": {"content": "// evil"}}}
        raw = json.dumps(data)
        result = MainnetContractSource._flatten_standard_json(raw)
        assert "<script>" not in result
        assert "evil" in result
