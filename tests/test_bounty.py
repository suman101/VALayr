"""
Test suite for the validator.bounty module — identity, anti-bypass, platform.

Covers T-1 from the gap analysis: bounty module test coverage.
"""

import json
import os
import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from validator.bounty.identity import IdentityStore, IdentityClaim
from validator.bounty.anti_bypass import (
    AntiBypassEngine,
    BYPASS_THRESHOLD_SECONDS,
    RELAY_GRACE_SECONDS,
)
from validator.bounty.platform import (
    PlatformRegistry,
    create_default_registry,
    ImmunefiAdapter,
    Code4renaAdapter,
    BountyReport,
    SubmissionStatus,
)
from validator.utils.secrets import get_secret, clear_cache, validate_environment


# ── Helpers ──────────────────────────────────────────────────────────────────

VALID_HOTKEY = "A" * 48  # 48 alphanumeric chars
VALID_HOTKEY_2 = "B" * 48
VALID_PLATFORM_ID = "alice_on_immunefi"


@pytest.fixture()
def tmp_data_dir(tmp_path):
    return tmp_path / "bounty_data"


# ── IdentityStore Tests ──────────────────────────────────────────────────────


class TestIdentityStore:
    def test_claim_and_verify(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        claim = store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        assert claim.miner_hotkey == VALID_HOTKEY
        assert claim.platform == "immunefi"
        assert not claim.verified

        # Verify without external registry (returns True)
        assert store.verify_claim(VALID_HOTKEY, "immunefi")
        identity = store.get_identity(VALID_HOTKEY)
        assert identity is not None
        assert identity.claims["immunefi"].verified

    def test_get_platform_id_unverified_returns_none(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        assert store.get_platform_id(VALID_HOTKEY, "immunefi") is None

    def test_get_platform_id_verified(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        store.verify_claim(VALID_HOTKEY, "immunefi")
        assert store.get_platform_id(VALID_HOTKEY, "immunefi") == VALID_PLATFORM_ID

    def test_duplicate_platform_id_raises(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        store.verify_claim(VALID_HOTKEY, "immunefi")

        with pytest.raises(ValueError, match="already claimed"):
            store.claim_identity(VALID_HOTKEY_2, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")

    def test_invalid_hotkey_raises(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        with pytest.raises(ValueError, match="Invalid hotkey"):
            store.claim_identity("bad", "immunefi", VALID_PLATFORM_ID)

    def test_invalid_platform_id_raises(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        with pytest.raises(ValueError, match="Invalid platform_id"):
            store.claim_identity(VALID_HOTKEY, "immunefi", "has spaces!")

    def test_revoke_claim(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        assert store.revoke_claim(VALID_HOTKEY, "immunefi")
        assert store.get_identity(VALID_HOTKEY).claims == {}

    def test_revoke_nonexistent_returns_false(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        assert not store.revoke_claim(VALID_HOTKEY, "immunefi")

    def test_list_verified(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        store.verify_claim(VALID_HOTKEY, "immunefi")
        verified = store.list_verified("immunefi")
        assert len(verified) == 1
        assert verified[0].platform_id == VALID_PLATFORM_ID

    def test_persistence_roundtrip(self, tmp_data_dir):
        """Data survives store re-creation (atomic write)."""
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID, signed_challenge="test_sig")
        store.verify_claim(VALID_HOTKEY, "immunefi")

        store2 = IdentityStore(tmp_data_dir)
        assert store2.get_platform_id(VALID_HOTKEY, "immunefi") == VALID_PLATFORM_ID

    def test_verify_unknown_miner_returns_false(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        assert not store.verify_claim(VALID_HOTKEY, "immunefi")


# ── AntiBypassEngine Tests ───────────────────────────────────────────────────


class TestAntiBypass:
    def test_record_and_check_legitimate(self, tmp_data_dir):
        engine = AntiBypassEngine(tmp_data_dir)
        receipt = engine.record_subnet_receipt("task1", VALID_HOTKEY, "fp1")
        assert receipt.fingerprint == "fp1"

        # Platform submit AFTER subnet → legitimate
        result = engine.check_platform_submission(
            "fp1", "immunefi", receipt.subnet_timestamp + 60
        )
        assert result is None  # No violation

    def test_bypass_detected(self, tmp_data_dir):
        engine = AntiBypassEngine(tmp_data_dir)
        now = int(time.time())
        engine.record_subnet_receipt("task1", VALID_HOTKEY, "fp1")

        # Platform submit BEFORE subnet by a large margin → bypass
        violation = engine.check_platform_submission(
            "fp1", "immunefi", now - 3600
        )
        assert violation is not None
        assert violation.severity in ("violation", "critical")

    def test_slash_after_bypass(self, tmp_data_dir):
        engine = AntiBypassEngine(tmp_data_dir)
        now = int(time.time())
        engine.record_subnet_receipt("task1", VALID_HOTKEY, "fp1")
        engine.check_platform_submission("fp1", "immunefi", now - 7200)

        assert engine.is_slashed(VALID_HOTKEY)

    def test_no_receipt_returns_none(self, tmp_data_dir):
        engine = AntiBypassEngine(tmp_data_dir)
        result = engine.check_platform_submission("unknown_fp", "immunefi", int(time.time()))
        assert result is None

    def test_get_violations(self, tmp_data_dir):
        engine = AntiBypassEngine(tmp_data_dir)
        now = int(time.time())
        engine.record_subnet_receipt("task1", VALID_HOTKEY, "fp1")
        engine.check_platform_submission("fp1", "immunefi", now - 3600)

        all_v = engine.get_violations()
        assert len(all_v) == 1
        miner_v = engine.get_violations(VALID_HOTKEY)
        assert len(miner_v) == 1
        assert engine.get_violations(VALID_HOTKEY_2) == []

    def test_persistence_roundtrip(self, tmp_data_dir):
        engine = AntiBypassEngine(tmp_data_dir)
        engine.record_subnet_receipt("task1", VALID_HOTKEY, "fp1")

        engine2 = AntiBypassEngine(tmp_data_dir)
        assert engine2.get_receipt("fp1") is not None


# ── PlatformRegistry Tests ───────────────────────────────────────────────────


class TestPlatformRegistry:
    def test_default_adapters_registered(self):
        registry = create_default_registry()
        adapters = registry.list_platforms()
        assert "immunefi" in adapters
        assert "code4rena" in adapters

    def test_get_nonexistent_returns_none(self):
        registry = PlatformRegistry()
        assert registry.get("nonexistent_platform") is None

    def test_immunefi_adapter_has_methods(self):
        registry = create_default_registry()
        adapter = registry.get("immunefi")
        assert adapter is not None
        assert callable(getattr(adapter, "submit_report", None))
        assert callable(getattr(adapter, "check_status", None))
        assert callable(getattr(adapter, "verify_identity", None))


# ── Adapter Mock Tests ──────────────────────────────────────────────────────


def _make_report():
    return BountyReport(
        task_id="task-1",
        miner_hotkey="A" * 48,
        platform_id="alice",
        target_address="0x" + "ab" * 20,
        chain_id=1,
        vulnerability_class="reentrancy",
        severity_score=0.8,
        exploit_description="test exploit",
        exploit_source="pragma solidity ^0.8.0; contract X { function exploit() public {} }",
        fingerprint="fp1",
        subnet_timestamp=int(time.time()),
    )


class TestImmunefiAdapter:
    def test_submit_without_api_key_returns_rejected(self):
        adapter = ImmunefiAdapter(api_key="")
        receipt = adapter.submit_report(_make_report())
        assert receipt.status == SubmissionStatus.REJECTED
        assert receipt.error == "API request failed"

    @patch("urllib.request.urlopen")
    def test_submit_with_key_succeeds(self, mock_urlopen):
        resp = MagicMock()
        resp.read.return_value = json.dumps({"id": "rpt-123", "url": "https://immunefi.com/rpt-123"}).encode()
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        adapter = ImmunefiAdapter(api_key="test-key")
        receipt = adapter.submit_report(_make_report())
        assert receipt.status == SubmissionStatus.SUBMITTED
        assert receipt.report_id == "rpt-123"

    @patch("urllib.request.urlopen", side_effect=OSError("boom"))
    def test_submit_network_error_returns_rejected(self, mock_urlopen):
        adapter = ImmunefiAdapter(api_key="test-key")
        receipt = adapter.submit_report(_make_report())
        assert receipt.status == SubmissionStatus.REJECTED

    @patch("urllib.request.urlopen")
    def test_check_status(self, mock_urlopen):
        resp = MagicMock()
        resp.read.return_value = json.dumps({"status": "accepted"}).encode()
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        adapter = ImmunefiAdapter(api_key="test-key")
        status = adapter.check_status("rpt-123")
        assert status == SubmissionStatus.ACCEPTED

    def test_severity_mapping(self):
        assert ImmunefiAdapter._map_severity(0.95) == "critical"
        assert ImmunefiAdapter._map_severity(0.75) == "high"
        assert ImmunefiAdapter._map_severity(0.5) == "medium"
        assert ImmunefiAdapter._map_severity(0.2) == "low"

    def test_api_rejects_bad_endpoint(self):
        adapter = ImmunefiAdapter(api_key="test-key")
        assert adapter._api_post("no-slash", {}) is None
        assert adapter._api_get("/endpoint?injected=true") is None


class TestCode4renaAdapter:
    def test_submit_without_api_key_returns_rejected(self):
        adapter = Code4renaAdapter(api_key="")
        receipt = adapter.submit_report(_make_report())
        assert receipt.status == SubmissionStatus.REJECTED

    @patch("urllib.request.urlopen")
    def test_submit_with_key_succeeds(self, mock_urlopen):
        resp = MagicMock()
        resp.read.return_value = json.dumps({"id": "c4r-456", "url": "https://code4rena.com/c4r-456"}).encode()
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        adapter = Code4renaAdapter(api_key="test-key")
        receipt = adapter.submit_report(_make_report())
        assert receipt.status == SubmissionStatus.SUBMITTED

    def test_severity_mapping(self):
        assert Code4renaAdapter._map_severity(0.95) == "3 (High)"
        assert Code4renaAdapter._map_severity(0.6) == "2 (Med)"
        assert Code4renaAdapter._map_severity(0.3) == "QA (Low)"


# ── Unified Secrets Manager Tests ────────────────────────────────────────────


class TestSecretsManager:
    def setup_method(self):
        clear_cache()

    def test_get_secret_required_missing_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            clear_cache()
            with pytest.raises(RuntimeError, match="Required secret"):
                get_secret("VALAYR_RECEIPT_HMAC_KEY", required=True)

    def test_get_secret_optional_missing_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            clear_cache()
            result = get_secret("ETHERSCAN_API_KEY", required=False)
            assert result == ""

    def test_get_secret_valid_key(self):
        with patch.dict(os.environ, {"ETHERSCAN_API_KEY": "abc123"}):
            clear_cache()
            assert get_secret("ETHERSCAN_API_KEY", required=False) == "abc123"

    def test_get_secret_too_short_required_raises(self):
        with patch.dict(os.environ, {"VALAYR_RECEIPT_HMAC_KEY": "short"}):
            clear_cache()
            with pytest.raises(RuntimeError, match="too short"):
                get_secret("VALAYR_RECEIPT_HMAC_KEY", required=True)

    def test_validate_environment_reports_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            errors = validate_environment(["ETHERSCAN_API_KEY"])
            assert len(errors) == 1
            assert "not set" in errors[0]

    def test_validate_environment_reports_ok(self):
        with patch.dict(os.environ, {"ETHERSCAN_API_KEY": "valid-key-here"}):
            errors = validate_environment(["ETHERSCAN_API_KEY"])
            assert len(errors) == 0

    def test_caching(self):
        with patch.dict(os.environ, {"ETHERSCAN_API_KEY": "cached-val"}):
            clear_cache()
            val1 = get_secret("ETHERSCAN_API_KEY", required=False)
            # Change env — cached value should persist
            os.environ["ETHERSCAN_API_KEY"] = "new-val"
            val2 = get_secret("ETHERSCAN_API_KEY", required=False)
            assert val1 == val2 == "cached-val"
            clear_cache()

    def teardown_method(self):
        clear_cache()
