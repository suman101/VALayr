"""
Test suite for the validator.bounty module — identity, anti-bypass, platform.

Covers T-1 from the gap analysis: bounty module test coverage.
"""

import json
import os
import time
import tempfile
from pathlib import Path

import pytest

from validator.bounty.identity import IdentityStore, IdentityClaim
from validator.bounty.anti_bypass import (
    AntiBypassEngine,
    BYPASS_THRESHOLD_SECONDS,
    RELAY_GRACE_SECONDS,
)
from validator.bounty.platform import PlatformRegistry, create_default_registry


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
        claim = store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
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
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
        assert store.get_platform_id(VALID_HOTKEY, "immunefi") is None

    def test_get_platform_id_verified(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
        store.verify_claim(VALID_HOTKEY, "immunefi")
        assert store.get_platform_id(VALID_HOTKEY, "immunefi") == VALID_PLATFORM_ID

    def test_duplicate_platform_id_raises(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
        store.verify_claim(VALID_HOTKEY, "immunefi")

        with pytest.raises(ValueError, match="already claimed"):
            store.claim_identity(VALID_HOTKEY_2, "immunefi", VALID_PLATFORM_ID)

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
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
        assert store.revoke_claim(VALID_HOTKEY, "immunefi")
        assert store.get_identity(VALID_HOTKEY).claims == {}

    def test_revoke_nonexistent_returns_false(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        assert not store.revoke_claim(VALID_HOTKEY, "immunefi")

    def test_list_verified(self, tmp_data_dir):
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
        store.verify_claim(VALID_HOTKEY, "immunefi")
        verified = store.list_verified("immunefi")
        assert len(verified) == 1
        assert verified[0].platform_id == VALID_PLATFORM_ID

    def test_persistence_roundtrip(self, tmp_data_dir):
        """Data survives store re-creation (atomic write)."""
        store = IdentityStore(tmp_data_dir)
        store.claim_identity(VALID_HOTKEY, "immunefi", VALID_PLATFORM_ID)
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
