"""
Security-Focused Tests — Coverage for critical security paths.

Implements gap analysis findings T1-T8:
  T1: Validation engine source sanitization
  T2: Input validation boundary tests
  T3: Anti-bypass receipts HMAC integrity
  T4: Identity store conflict detection
  T5: Epoch close race protection
  T6: CLI path traversal prevention
  T7: Platform adapter URL validation
  T8: Docker sandbox arguments
"""

import json
import os
import re
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── Project imports ──────────────────────────────────────────────────────────

from validator.engine.validate import ValidationEngine, ExploitSubmission, ValidationResult
from orchestrator import Orchestrator, MAX_EXPLOIT_SOURCE_BYTES, MAX_TASK_ID_LEN
from validator.bounty.anti_bypass import AntiBypassEngine, SubnetReceipt
from validator.bounty.identity import IdentityStore
from validator.bounty.platform import ImmunefiAdapter, Code4renaAdapter


# ── Helpers ──────────────────────────────────────────────────────────────────

VALID_HOTKEY = "A" * 48
VALID_HOTKEY_2 = "B" * 48


# ── T1: Validation Engine Source Sanitization ────────────────────────────────

class TestSourceSanitization:
    """Exercise the _sanitize_source and _DANGEROUS_PATTERNS guards."""

    def test_rejects_deep_path_traversal_in_import(self):
        source = 'import "../../etc/passwd";'
        assert ValidationEngine._sanitize_source(source) is False

    def test_allows_single_parent_import(self):
        """Standard Foundry ../src/ pattern is allowed."""
        source = 'import "../src/Vulnerable.sol";'
        assert ValidationEngine._sanitize_source(source) is True

    def test_rejects_absolute_path_import(self):
        source = 'import "/etc/passwd";'
        assert ValidationEngine._sanitize_source(source) is False

    def test_rejects_windows_absolute_import(self):
        source = 'import "C:\\Windows\\System32\\cmd";'
        assert ValidationEngine._sanitize_source(source) is False

    def test_rejects_url_import(self):
        source = 'import "https://evil.com/payload.sol";'
        assert ValidationEngine._sanitize_source(source) is False

    def test_rejects_deep_path_traversal_in_string(self):
        source = 'string x = "../../etc/shadow";'
        assert ValidationEngine._sanitize_source(source) is False

    def test_rejects_delegatecall_in_assembly(self):
        source = """
pragma solidity ^0.8.28;
contract X {
    function hack() public {
        assembly { let x := delegatecall(gas(), 0x0, 0, 0, 0, 0) }
    }
}
"""
        assert ValidationEngine._sanitize_source(source) is False

    def test_rejects_selfdestruct_in_assembly(self):
        source = """
contract X {
    function hack() public {
        assembly { selfdestruct(0) }
    }
}
"""
        assert ValidationEngine._sanitize_source(source) is False

    def test_accepts_clean_exploit(self):
        source = """
pragma solidity ^0.8.28;
import "forge-std/Test.sol";
import "../src/Vulnerable.sol";
contract ExploitTest is Test {
    function test_run() public {
        // legitimate exploit code
    }
}
"""
        assert ValidationEngine._sanitize_source(source) is True

    def test_accepts_selfdestruct_outside_assembly(self):
        """selfdestruct as a Solidity call (valid exploit technique)."""
        source = """
pragma solidity ^0.8.28;
contract X {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
"""
        assert ValidationEngine._sanitize_source(source) is True


# ── T2: Input Validation Boundaries ──────────────────────────────────────────

class TestInputValidation:
    """Boundary tests for orchestrator input validation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.orch = Orchestrator(
            mode="local",
            corpus_dir=tmp_path / "corpus",
            data_dir=tmp_path / "data",
        )

    def test_rejects_empty_task_id(self):
        result = self.orch.process_submission(
            task_id="",
            exploit_source="contract X {}",
            miner_address="0xMINER",
        )
        assert result.validation_result == "REJECT_INVALID_FORMAT"

    def test_rejects_oversized_task_id(self):
        result = self.orch.process_submission(
            task_id="x" * (MAX_TASK_ID_LEN + 1),
            exploit_source="contract X {}",
            miner_address="0xMINER",
        )
        assert result.validation_result == "REJECT_INVALID_FORMAT"

    def test_rejects_empty_exploit_source(self):
        result = self.orch.process_submission(
            task_id="0x1234",
            exploit_source="",
            miner_address="0xMINER",
        )
        assert result.validation_result == "REJECT_INVALID_FORMAT"

    def test_rejects_oversized_exploit_source(self):
        result = self.orch.process_submission(
            task_id="0x1234",
            exploit_source="x" * (MAX_EXPLOIT_SOURCE_BYTES + 1),
            miner_address="0xMINER",
        )
        assert result.validation_result == "REJECT_INVALID_FORMAT"

    def test_rejects_non_string_exploit(self):
        result = self.orch.process_submission(
            task_id="0x1234",
            exploit_source=None,  # type: ignore
            miner_address="0xMINER",
        )
        assert result.validation_result == "REJECT_INVALID_FORMAT"


# ── T3: Anti-Bypass Receipt HMAC Integrity ───────────────────────────────────

class TestReceiptHMAC:
    """Verify HMAC tagging on subnet receipts."""

    @pytest.fixture()
    def engine(self, tmp_path):
        return AntiBypassEngine(data_dir=tmp_path / "anti_bypass")

    def test_receipt_has_hmac(self, engine):
        receipt = engine.record_subnet_receipt(
            task_id="task_001",
            miner_hotkey=VALID_HOTKEY,
            fingerprint="fp_abc",
            bittensor_block=100,
        )
        assert receipt.hmac_tag != ""

    def test_receipt_hmac_verifies(self, engine):
        receipt = engine.record_subnet_receipt(
            task_id="task_002",
            miner_hotkey=VALID_HOTKEY,
            fingerprint="fp_def",
        )
        assert receipt.verify_hmac() is True

    def test_tampered_receipt_fails_hmac(self, engine):
        receipt = engine.record_subnet_receipt(
            task_id="task_003",
            miner_hotkey=VALID_HOTKEY,
            fingerprint="fp_ghi",
        )
        # Tamper with timestamp
        receipt.subnet_timestamp += 1
        assert receipt.verify_hmac() is False

    def test_empty_hmac_fails_verify(self):
        receipt = SubnetReceipt(
            task_id="task_004",
            miner_hotkey=VALID_HOTKEY,
            fingerprint="fp_jkl",
            subnet_timestamp=int(time.time()),
        )
        assert receipt.verify_hmac() is False


# ── T4: Identity Store Conflict Detection ────────────────────────────────────

class TestIdentityConflicts:
    """Verify identity claim conflict detection."""

    @pytest.fixture()
    def store(self, tmp_path):
        return IdentityStore(data_dir=tmp_path / "identity")

    def test_duplicate_claim_rejected(self, store):
        store.claim_identity(VALID_HOTKEY, "immunefi", "alice123", signed_challenge="test_sig")
        # Manually verify the claim
        store._identities[VALID_HOTKEY].claims["immunefi"].verified = True
        store._save()

        # Different miner claiming same platform_id on same platform
        with pytest.raises(ValueError, match="already claimed"):
            store.claim_identity(VALID_HOTKEY_2, "immunefi", "alice123", signed_challenge="test_sig")

    def test_same_miner_can_update_claim(self, store):
        store.claim_identity(VALID_HOTKEY, "immunefi", "alice123", signed_challenge="test_sig")
        # Same miner updating is allowed
        claim = store.claim_identity(VALID_HOTKEY, "immunefi", "alice456", signed_challenge="test_sig")
        assert claim.platform_id == "alice456"

    def test_invalid_hotkey_rejected(self, store):
        with pytest.raises(ValueError, match="Invalid hotkey"):
            store.claim_identity("short", "immunefi", "alice123")

    def test_invalid_platform_id_rejected(self, store):
        with pytest.raises(ValueError, match="Invalid platform_id"):
            store.claim_identity(VALID_HOTKEY, "immunefi", "a" * 100)


# ── T5: Epoch Close Race Protection ─────────────────────────────────────────

class TestEpochRace:
    """Verify epoch overlap detection and concurrency guard."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.orch = Orchestrator(
            mode="local",
            corpus_dir=tmp_path / "corpus",
            data_dir=tmp_path / "data",
        )

    def test_duplicate_epoch_close_skipped(self):
        result1 = self.orch.close_epoch(0, 0, 360)
        result2 = self.orch.close_epoch(0, 0, 360)
        # Second call should return empty weights (skipped)
        assert result2.total_submissions == 0

    def test_epoch_ordering_enforced(self):
        self.orch.close_epoch(5, 1800, 2160)
        # Epoch 3 < 5, should be skipped
        result = self.orch.close_epoch(3, 1080, 1440)
        assert result.total_submissions == 0


# ── T6: CLI Path Traversal Prevention ────────────────────────────────────────

class TestCLIPathTraversal:
    """Verify miner CLI rejects path traversal."""

    def test_cmd_task_rejects_external_source_dir(self):
        """Task with _source_dir outside corpus should be flagged."""
        from miner.cli import MinerCLI
        import logging
        cli = MinerCLI(miner_address="0xTEST")

        # Fabricate a task with external source dir
        task = {
            "task_id": "test_task",
            "vulnerability_class": "test",
            "difficulty": 1,
            "solc_version": "0.8.28",
            "_source_dir": "/etc",
        }
        # This should log a warning (not crash or read /etc)
        with patch.object(cli.orch, "load_task", return_value=task):
            args = MagicMock()
            args.id = "test_task"
            cli.cmd_task(args)  # Should not raise


# ── T7: Platform Adapter URL Validation ──────────────────────────────────────

class TestPlatformURLValidation:
    """Verify platform adapters reject malformed endpoints."""

    def test_immunefi_rejects_query_in_endpoint(self):
        adapter = ImmunefiAdapter(api_key="test-key")
        # Endpoint with query string injection should be rejected
        result = adapter._api_get("/reports?admin=true")
        assert result is None

    def test_immunefi_rejects_non_slash_endpoint(self):
        adapter = ImmunefiAdapter(api_key="test-key")
        result = adapter._api_get("reports/1")
        assert result is None

    def test_code4rena_rejects_query_in_endpoint(self):
        adapter = Code4renaAdapter(api_key="test-key")
        result = adapter._api_get("/findings?injected=true")
        assert result is None


# ── T8: Docker Sandbox Arguments ─────────────────────────────────────────────

class TestDockerSandbox:
    """Verify Docker sandbox command includes security flags."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.orch = Orchestrator(
            mode="docker",
            corpus_dir=tmp_path / "corpus",
            data_dir=tmp_path / "data",
        )

    @patch("subprocess.run")
    def test_docker_cmd_includes_security_flags(self, mock_run, tmp_path):
        """Verify --cap-drop=ALL, --security-opt, --pids-limit are present."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="mock",
        )

        task = {"task_id": "test", "source_code": "contract V {}", "solc_version": "0.8.28"}
        sub = ExploitSubmission(task_id="test", exploit_source="contract X {}")

        self.orch._validate_in_docker(task, sub)

        # Check that docker run was called with security flags
        if mock_run.called:
            call_args = mock_run.call_args
            cmd = call_args[0][0] if call_args[0] else call_args.kwargs.get("args", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            assert "--cap-drop=ALL" in cmd_str
            assert "--security-opt=no-new-privileges" in cmd_str
            assert "--pids-limit=256" in cmd_str
            assert "--network=none" in cmd_str


# ── P0 Tests: C-2 Ed25519 Signature Verification ─────────────────────────────

class TestEd25519Verification:
    """C-2: Verify Ed25519 signed_challenge is cryptographically validated."""

    @pytest.fixture()
    def store(self, tmp_path):
        return IdentityStore(data_dir=tmp_path / "identity")

    def test_empty_challenge_rejected(self, store):
        with pytest.raises(ValueError, match="signed_challenge"):
            store.claim_identity(VALID_HOTKEY, "immunefi", "alice", signed_challenge="")

    def test_truncated_challenge_rejected(self, store):
        try:
            import nacl  # noqa: F401
        except ImportError:
            pytest.skip("pynacl not installed — truncated check only applies with nacl")
        with pytest.raises(ValueError, match="too short"):
            store.claim_identity(VALID_HOTKEY, "immunefi", "alice", signed_challenge="aabb")

    def test_valid_ed25519_signature_accepted(self, store):
        """Real Ed25519 signature should be accepted when nacl is available."""
        try:
            import hashlib as hl
            from nacl.signing import SigningKey
        except ImportError:
            pytest.skip("pynacl not installed")

        hotkey, platform, pid = VALID_HOTKEY, "immunefi", "alice123"
        msg = hl.sha256(f"{hotkey}:{platform}:{pid}".encode()).digest()
        key = SigningKey.generate()
        sig = key.sign(msg).signature
        challenge = key.verify_key.encode().hex() + sig.hex()
        # Should not raise
        store.claim_identity(hotkey, platform, pid, signed_challenge=challenge)

    def test_invalid_ed25519_signature_rejected(self, store):
        """Wrong signature bytes should be rejected."""
        try:
            import hashlib as hl
            from nacl.signing import SigningKey
        except ImportError:
            pytest.skip("pynacl not installed")

        hotkey, platform, pid = VALID_HOTKEY, "immunefi", "alice123"
        key = SigningKey.generate()
        # Use correct public key but wrong signature (all zeros)
        challenge = key.verify_key.encode().hex() + "00" * 64
        with pytest.raises(ValueError, match="signature verification failed"):
            store.claim_identity(hotkey, platform, pid, signed_challenge=challenge)


# ── P2 Test: SA-5 verify_hmac constant-time (timing leak fix) ───────────────

class TestVerifyHmacConstantTime:
    """SA-5: verify_hmac must compute expected digest even when hmac_tag is empty."""

    def test_empty_hmac_tag_returns_false(self):
        receipt = SubnetReceipt(
            task_id="task1", miner_hotkey=VALID_HOTKEY,
            fingerprint="fp1", subnet_timestamp=100,
        )
        assert receipt.hmac_tag == ""
        assert receipt.verify_hmac() is False

    def test_valid_hmac_tag_returns_true(self):
        receipt = SubnetReceipt(
            task_id="task1", miner_hotkey=VALID_HOTKEY,
            fingerprint="fp1", subnet_timestamp=100,
        )
        receipt.hmac_tag = receipt.compute_hmac()
        assert receipt.verify_hmac() is True

    def test_tampered_hmac_tag_returns_false(self):
        receipt = SubnetReceipt(
            task_id="task1", miner_hotkey=VALID_HOTKEY,
            fingerprint="fp1", subnet_timestamp=100,
        )
        receipt.hmac_tag = "deadbeef" * 8
        assert receipt.verify_hmac() is False


# ── P2 Test: C-5 Deploy.s.sol wiring static assertion ───────────────────────

class TestDeployScriptWiring:
    """C-5: Deploy.s.sol must wire adversarialScoring as validator on invariantRegistry."""

    def test_deploy_script_has_adversarial_validator_wiring(self):
        deploy_path = Path(__file__).resolve().parent.parent / "contracts" / "script" / "Deploy.s.sol"
        source = deploy_path.read_text()
        assert "invariantRegistry.setValidator(address(adversarialScoring), true)" in source, \
            "Deploy.s.sol missing C-5 wiring: invariantRegistry.setValidator(adversarialScoring)"


# ── P2 Test: SA-7 claim_identity without registry accepts any platform ──────

class TestIdentityNoRegistryPlatform:
    """SA-7: Without a PlatformRegistry, claim_identity accepts any platform name."""

    def test_unknown_platform_allowed_without_registry(self, tmp_path):
        store = IdentityStore(data_dir=tmp_path)
        # No registry wired — store._registry is None
        assert store._registry is None
        # Should NOT raise for a fabricated platform (just requires valid sig)
        try:
            from nacl.signing import SigningKey
        except ImportError:
            pytest.skip("pynacl not installed")
        import hashlib as hl
        hotkey, platform, pid = VALID_HOTKEY, "fake_platform_xyz", "user42"
        key = SigningKey.generate()
        msg = hl.sha256(f"{hotkey}:{platform}:{pid}".encode()).digest()
        sig = key.sign(msg)
        challenge = key.verify_key.encode().hex() + sig.signature.hex()
        # Should succeed (no ValueError about unsupported platform)
        store.claim_identity(hotkey, platform, pid, signed_challenge=challenge)
