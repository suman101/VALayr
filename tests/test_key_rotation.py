"""
Tests for validator.utils.key_rotation — mock-based unit tests.

Covers rotate_validator, transfer_ownership, batch_rotate_validators,
_find_cast, _wallet_address, and _check_key_rotation in ValidatorNeuron.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from validator.utils.key_rotation import (
    _find_cast,
    _wallet_address,
    rotate_validator,
    transfer_ownership,
    batch_rotate_validators,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

FAKE_CAST = "/usr/local/bin/cast"
FAKE_CONTRACT = "0x" + "ab" * 20
FAKE_OWNER_KEY = "0x" + "11" * 32
FAKE_NEW_KEY = "0x" + "22" * 32
FAKE_OWNER_ADDR = "0x" + "AA" * 20
FAKE_NEW_ADDR = "0x" + "BB" * 20
FAKE_OLD_VALIDATOR = "0x" + "CC" * 20
FAKE_NEW_VALIDATOR = "0x" + "DD" * 20
FAKE_RPC = "http://127.0.0.1:8545"


def _mock_run_version(cmd, **kwargs):
    """Simulate a successful 'cast --version' call."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = "cast 0.3.0 (abc123 2024-12-01T00:00:00.000000000Z)"
    return result


# ── _find_cast Tests ─────────────────────────────────────────────────────────


class TestFindCast:
    @patch("shutil.which", return_value="/usr/local/bin/cast")
    @patch("os.path.realpath", return_value="/usr/local/bin/cast")
    @patch("subprocess.run", side_effect=_mock_run_version)
    def test_find_cast_success(self, mock_run, mock_realpath, mock_which):
        result = _find_cast()
        assert result == "/usr/local/bin/cast"

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_find_cast_not_found_raises(self, mock_run):
        with pytest.raises(RuntimeError, match="cast not found"):
            _find_cast()

    @patch("subprocess.run")
    def test_find_cast_rejects_non_foundry_binary(self, mock_run):
        """A binary that doesn't output 'cast' or 'foundry' in version is rejected."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "some other tool v1.0"
        mock_run.return_value = mock_result
        with pytest.raises(RuntimeError, match="cast not found"):
            _find_cast()


# ── _wallet_address Tests ────────────────────────────────────────────────────


class TestWalletAddress:
    @patch("subprocess.Popen")
    def test_valid_address(self, mock_popen):
        proc = MagicMock()
        proc.communicate.return_value = (FAKE_OWNER_ADDR, "")
        proc.returncode = 0
        mock_popen.return_value = proc

        result = _wallet_address(FAKE_CAST, FAKE_OWNER_KEY)
        assert result == FAKE_OWNER_ADDR

    @patch("subprocess.Popen")
    def test_invalid_address_rejected(self, mock_popen):
        proc = MagicMock()
        proc.communicate.return_value = ("not-an-address", "")
        proc.returncode = 0
        mock_popen.return_value = proc

        with pytest.raises(RuntimeError, match="invalid address"):
            _wallet_address(FAKE_CAST, FAKE_OWNER_KEY)

    @patch("subprocess.Popen")
    def test_cast_failure_raises(self, mock_popen):
        proc = MagicMock()
        proc.communicate.return_value = ("", "error")
        proc.returncode = 1
        mock_popen.return_value = proc

        with pytest.raises(RuntimeError, match="cast wallet address failed"):
            _wallet_address(FAKE_CAST, FAKE_OWNER_KEY)


# ── rotate_validator Tests ───────────────────────────────────────────────────


class TestRotateValidator:
    @patch("validator.utils.key_rotation._cast_call")
    @patch("validator.utils.key_rotation._cast_send")
    @patch("validator.utils.key_rotation._wallet_address", return_value=FAKE_OWNER_ADDR)
    @patch("validator.utils.key_rotation._find_cast", return_value=FAKE_CAST)
    def test_happy_path(self, mock_find, mock_wallet, mock_send, mock_call):
        # owner() returns the caller's address
        # validators(old) returns "true"
        # validators(new) returns "true" after add
        # validators(old) returns "false" after remove
        mock_call.side_effect = [
            FAKE_OWNER_ADDR,  # owner()
            "true",           # validators(old)
            "true",           # validators(new) — after add
            "false",          # validators(old) — after remove
        ]
        result = rotate_validator(
            FAKE_CONTRACT, FAKE_RPC, FAKE_OWNER_KEY,
            FAKE_OLD_VALIDATOR, FAKE_NEW_VALIDATOR,
        )
        assert result["success"] is True
        assert result["action"] == "rotate-validator"
        assert mock_send.call_count == 2  # add + remove

    @patch("validator.utils.key_rotation._cast_call")
    @patch("validator.utils.key_rotation._wallet_address", return_value=FAKE_OWNER_ADDR)
    @patch("validator.utils.key_rotation._find_cast", return_value=FAKE_CAST)
    def test_not_owner_raises(self, mock_find, mock_wallet, mock_call):
        mock_call.return_value = "0x" + "99" * 20  # different owner
        with pytest.raises(PermissionError, match="is not the contract owner"):
            rotate_validator(
                FAKE_CONTRACT, FAKE_RPC, FAKE_OWNER_KEY,
                FAKE_OLD_VALIDATOR, FAKE_NEW_VALIDATOR,
            )

    @patch("validator.utils.key_rotation._cast_call")
    @patch("validator.utils.key_rotation._cast_send")
    @patch("validator.utils.key_rotation._wallet_address", return_value=FAKE_OWNER_ADDR)
    @patch("validator.utils.key_rotation._find_cast", return_value=FAKE_CAST)
    def test_add_failure_raises(self, mock_find, mock_wallet, mock_send, mock_call):
        mock_call.side_effect = [
            FAKE_OWNER_ADDR,  # owner()
            "true",           # validators(old)
            "false",          # validators(new) — add FAILED
        ]
        with pytest.raises(RuntimeError, match="Failed to add new validator"):
            rotate_validator(
                FAKE_CONTRACT, FAKE_RPC, FAKE_OWNER_KEY,
                FAKE_OLD_VALIDATOR, FAKE_NEW_VALIDATOR,
            )


# ── transfer_ownership Tests ─────────────────────────────────────────────────


class TestTransferOwnership:
    @patch("validator.utils.key_rotation._cast_call")
    @patch("validator.utils.key_rotation._cast_send")
    @patch("validator.utils.key_rotation._wallet_address")
    @patch("validator.utils.key_rotation._find_cast", return_value=FAKE_CAST)
    def test_happy_path(self, mock_find, mock_wallet, mock_send, mock_call):
        mock_wallet.side_effect = [FAKE_OWNER_ADDR, FAKE_NEW_ADDR]
        mock_call.side_effect = [
            FAKE_OWNER_ADDR,  # current owner check
            FAKE_NEW_ADDR,    # pendingOwner
            FAKE_NEW_ADDR,    # final owner
        ]
        result = transfer_ownership(
            FAKE_CONTRACT, FAKE_RPC, FAKE_OWNER_KEY, FAKE_NEW_KEY,
        )
        assert result["success"] is True
        assert result["new_owner"] == FAKE_NEW_ADDR
        assert mock_send.call_count == 2

    @patch("validator.utils.key_rotation._cast_call")
    @patch("validator.utils.key_rotation._wallet_address")
    @patch("validator.utils.key_rotation._find_cast", return_value=FAKE_CAST)
    def test_not_owner_raises(self, mock_find, mock_wallet, mock_call):
        mock_wallet.side_effect = [FAKE_OWNER_ADDR, FAKE_NEW_ADDR]
        mock_call.return_value = "0x" + "99" * 20
        with pytest.raises(PermissionError):
            transfer_ownership(
                FAKE_CONTRACT, FAKE_RPC, FAKE_OWNER_KEY, FAKE_NEW_KEY,
            )


# ── batch_rotate_validators Tests ────────────────────────────────────────────


class TestBatchRotate:
    @patch("validator.utils.key_rotation.rotate_validator")
    def test_all_succeed(self, mock_rotate):
        mock_rotate.return_value = {"success": True, "action": "rotate-validator"}
        contracts = [f"0x{i:040x}" for i in range(3)]
        results = batch_rotate_validators(
            contracts, FAKE_RPC, FAKE_OWNER_KEY,
            FAKE_OLD_VALIDATOR, FAKE_NEW_VALIDATOR,
        )
        assert len(results) == 3
        assert all(r["success"] for r in results)

    @patch("validator.utils.key_rotation.rotate_validator")
    def test_partial_failure(self, mock_rotate):
        """One contract fails, others succeed."""
        mock_rotate.side_effect = [
            {"success": True, "action": "rotate-validator"},
            RuntimeError("cast failed"),
            {"success": True, "action": "rotate-validator"},
        ]
        contracts = [f"0x{i:040x}" for i in range(3)]
        results = batch_rotate_validators(
            contracts, FAKE_RPC, FAKE_OWNER_KEY,
            FAKE_OLD_VALIDATOR, FAKE_NEW_VALIDATOR,
        )
        assert len(results) == 3
        assert results[0]["success"] is True
        assert results[1]["success"] is False
        assert results[2]["success"] is True


# ── ValidatorNeuron._check_key_rotation Tests ───────────────────────────────


class TestCheckKeyRotation:
    def test_no_config_file_noop(self, tmp_path):
        """No rotation config file → nothing happens."""
        from neurons.validator import ValidatorNeuron
        neuron = ValidatorNeuron(mode="local")
        neuron._rotation_config = tmp_path / "pending_rotation.json"
        # Should not raise
        neuron._check_key_rotation()

    @patch("validator.utils.key_rotation.batch_rotate_validators")
    def test_valid_config_executes(self, mock_batch, tmp_path):
        """Rotation config present with env-based key → executes."""
        from neurons.validator import ValidatorNeuron
        config = {
            "contracts": ["0x" + "ab" * 20],
            "rpc_url": "http://127.0.0.1:8545",
            "owner_key_env": "DEPLOYER_KEY",
            "old_validator": "0x" + "cc" * 20,
            "new_validator": "0x" + "dd" * 20,
        }
        config_path = tmp_path / "pending_rotation.json"
        config_path.write_text(json.dumps(config))

        mock_batch.return_value = [{"success": True}]
        neuron = ValidatorNeuron(mode="local")
        neuron._rotation_config = config_path

        with patch.dict(os.environ, {"DEPLOYER_KEY": "0x" + "11" * 32}):
            neuron._check_key_rotation()

        assert mock_batch.called
        # Config should be archived
        assert not config_path.exists()
        assert config_path.with_suffix(".done").exists()

    def test_incomplete_config_skips(self, tmp_path):
        """Config missing required fields → skips."""
        from neurons.validator import ValidatorNeuron
        config = {"contracts": [], "rpc_url": ""}
        config_path = tmp_path / "pending_rotation.json"
        config_path.write_text(json.dumps(config))

        neuron = ValidatorNeuron(mode="local")
        neuron._rotation_config = config_path
        neuron._check_key_rotation()
        # Config file should still exist (not archived)
        assert config_path.exists()

    @patch("validator.utils.key_rotation.batch_rotate_validators")
    def test_disallowed_env_var_rejected(self, mock_batch, tmp_path):
        """H-1: owner_key_env not in allowlist → rotation skipped."""
        from neurons.validator import ValidatorNeuron
        config = {
            "contracts": [FAKE_CONTRACT],
            "rpc_url": FAKE_RPC,
            "owner_key_env": "AWS_SECRET_KEY",  # Not in allowlist
            "old_validator": FAKE_OLD_VALIDATOR,
            "new_validator": FAKE_NEW_VALIDATOR,
        }
        config_path = tmp_path / "pending_rotation.json"
        config_path.write_text(json.dumps(config))

        neuron = ValidatorNeuron(mode="local")
        neuron._rotation_config = config_path

        with patch.dict(os.environ, {"AWS_SECRET_KEY": "0x" + "11" * 32}):
            neuron._check_key_rotation()

        assert not mock_batch.called
        assert config_path.exists()  # NOT archived — rejected
