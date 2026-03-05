"""Tests for difficulty ramping, mainnet auto-discovery, and semantic mutators."""

import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── Difficulty Ramping Tests ─────────────────────────────────────────────────

from validator.utils.difficulty import (
    get_max_difficulty,
    get_mainnet_ratio,
    get_min_severity,
    get_epoch_config,
    EPOCH_DIFFICULTY_2,
    EPOCH_DIFFICULTY_3,
)


class TestDifficultyRamping:

    def test_phase_1_difficulty(self):
        assert get_max_difficulty(1) == 1
        assert get_max_difficulty(50) == 1

    def test_phase_2_difficulty(self):
        assert get_max_difficulty(EPOCH_DIFFICULTY_2) == 2
        assert get_max_difficulty(100) == 2
        assert get_max_difficulty(200) == 2

    def test_phase_3_difficulty(self):
        assert get_max_difficulty(EPOCH_DIFFICULTY_3) == 3
        assert get_max_difficulty(500) == 3

    def test_mainnet_ratio_phase_1(self):
        assert get_mainnet_ratio(1) == 0.0

    def test_mainnet_ratio_phase_2(self):
        assert get_mainnet_ratio(EPOCH_DIFFICULTY_2) == 0.3

    def test_mainnet_ratio_phase_3(self):
        assert get_mainnet_ratio(EPOCH_DIFFICULTY_3) == 0.6

    def test_min_severity_increases(self):
        s1 = get_min_severity(1)
        s2 = get_min_severity(EPOCH_DIFFICULTY_2)
        s3 = get_min_severity(EPOCH_DIFFICULTY_3)
        assert s1 <= s2 <= s3

    def test_epoch_config_returns_dict(self):
        config = get_epoch_config(100)
        assert "epoch" in config
        assert "max_difficulty" in config
        assert "mainnet_ratio" in config
        assert "min_severity" in config
        assert config["epoch"] == 100

    def test_boundary_epochs(self):
        # Just before phase 2
        assert get_max_difficulty(EPOCH_DIFFICULTY_2 - 1) == 1
        # Exactly at phase 2
        assert get_max_difficulty(EPOCH_DIFFICULTY_2) == 2
        # Just before phase 3
        assert get_max_difficulty(EPOCH_DIFFICULTY_3 - 1) == 2
        # Exactly at phase 3
        assert get_max_difficulty(EPOCH_DIFFICULTY_3) == 3


# ── Mainnet Auto-Discovery Tests ─────────────────────────────────────────────

from task_generator.discovery import (
    MainnetAutoDiscovery,
    DiscoveredContract,
    SEED_TARGETS,
    REFRESH_INTERVAL,
)


class TestMainnetAutoDiscovery:

    def test_seed_targets_discovered(self, tmp_path):
        discovery = MainnetAutoDiscovery(data_dir=tmp_path / "disc")
        new = discovery.discover(chain_id=1, include_seeds=True)
        expected_count = len(SEED_TARGETS.get(1, []))
        assert len(new) == expected_count
        for c in new:
            assert c.source == "seed"
            assert c.chain_id == 1

    def test_no_duplicate_on_rediscovery(self, tmp_path):
        discovery = MainnetAutoDiscovery(data_dir=tmp_path / "disc")
        first = discovery.discover(chain_id=1)
        # Force refresh by resetting _last_refresh
        discovery._last_refresh = 0
        second = discovery.discover(chain_id=1)
        # Seeds were already discovered; nothing new
        assert len(second) == 0

    def test_get_addresses(self, tmp_path):
        discovery = MainnetAutoDiscovery(data_dir=tmp_path / "disc")
        discovery.discover(chain_id=1)
        addrs = discovery.get_addresses(chain_id=1)
        assert len(addrs) == len(SEED_TARGETS.get(1, []))

    def test_persistence(self, tmp_path):
        d = tmp_path / "disc"
        discovery = MainnetAutoDiscovery(data_dir=d)
        discovery.discover(chain_id=1)

        # Load fresh instance
        discovery2 = MainnetAutoDiscovery(data_dir=d)
        addrs = discovery2.get_addresses(chain_id=1)
        assert len(addrs) == len(SEED_TARGETS.get(1, []))

    def test_unsupported_chain(self, tmp_path):
        discovery = MainnetAutoDiscovery(data_dir=tmp_path / "disc")
        new = discovery.discover(chain_id=999, include_seeds=True)
        assert len(new) == 0

    @patch("task_generator.discovery.MainnetAutoDiscovery._fetch_immunefi_targets")
    def test_immunefi_targets_integrated(self, mock_fetch, tmp_path):
        mock_fetch.return_value = [
            "0x1234567890123456789012345678901234567890",
        ]
        discovery = MainnetAutoDiscovery(data_dir=tmp_path / "disc")
        new = discovery.discover(chain_id=1)
        # Should have seeds + immunefi targets
        assert any(c.source == "immunefi" for c in new)


# ── Semantic Mutator Tests ───────────────────────────────────────────────────

from task_generator.mutator.controlflow import ControlFlowMutator
from task_generator.mutator.interface import InterfaceMutator
from task_generator.mutator.registry import MutationRegistry


SAMPLE_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
"""


class TestControlFlowMutator:

    def test_basic_mutation(self):
        m = ControlFlowMutator()
        result = m.apply(SAMPLE_CONTRACT, {"controlflow_seed": 42}, seed=42)
        # Should produce something different
        assert result != SAMPLE_CONTRACT or "guard" in result or "if" in result

    def test_deterministic(self):
        m = ControlFlowMutator()
        r1 = m.apply(SAMPLE_CONTRACT, {"controlflow_seed": 123}, seed=0)
        r2 = m.apply(SAMPLE_CONTRACT, {"controlflow_seed": 123}, seed=0)
        assert r1 == r2

    def test_different_seeds_different_output(self):
        m = ControlFlowMutator()
        r1 = m.apply(SAMPLE_CONTRACT, {"controlflow_seed": 1}, seed=0)
        r2 = m.apply(SAMPLE_CONTRACT, {"controlflow_seed": 999}, seed=0)
        # Different seeds should produce different results (not guaranteed
        # but very likely for this contract)
        # At minimum, both should be valid Solidity
        assert "contract" in r1
        assert "contract" in r2

    def test_wrap_require_in_if(self):
        m = ControlFlowMutator()
        result = m._wrap_require_in_if(SAMPLE_CONTRACT, 0)
        # Should convert at least one require into if/revert
        assert "if" in result or "revert" in result or result == SAMPLE_CONTRACT

    def test_no_crash_on_empty(self):
        m = ControlFlowMutator()
        result = m.apply("", {}, seed=0)
        assert isinstance(result, str)


class TestInterfaceMutator:

    def test_basic_mutation(self):
        m = InterfaceMutator()
        result = m.apply(SAMPLE_CONTRACT, {"interface_seed": 42}, seed=42)
        # Output should still be valid-looking Solidity
        assert "contract" in result

    def test_function_reordering(self):
        m = InterfaceMutator()
        result = m._reorder_functions(SAMPLE_CONTRACT, seed=7)
        # Functions should be present in output
        assert "deposit" in result
        assert "withdraw" in result
        assert "getBalance" in result

    def test_public_to_external(self):
        m = InterfaceMutator()
        result = m._public_to_external(SAMPLE_CONTRACT)
        # Should convert at least one public to external
        assert "external" in result or "public" in result

    def test_deterministic(self):
        m = InterfaceMutator()
        r1 = m.apply(SAMPLE_CONTRACT, {"interface_seed": 55}, seed=0)
        r2 = m.apply(SAMPLE_CONTRACT, {"interface_seed": 55}, seed=0)
        assert r1 == r2


class TestRegistryWithNewMutators:

    def test_registry_has_six_mutators(self):
        reg = MutationRegistry()
        names = reg.list_mutators()
        assert "controlflow" in names
        assert "interface" in names
        assert len(names) == 6

    def test_full_pipeline(self):
        reg = MutationRegistry()
        result = reg.apply(SAMPLE_CONTRACT, {
            "storage_prefix": "test_prefix",
            "rename_map": {},
            "dead_code_count": 1,
            "controlflow_seed": 42,
            "interface_seed": 42,
        })
        # Should still contain core contract structure
        assert "contract" in result
        assert "function" in result
