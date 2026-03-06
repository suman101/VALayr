"""
Anti-Bypass — Detect and penalise miners who submit to bounty platforms
before routing through the VALayr subnet.

Strategy:
  1. **Timestamped Subnet Receipt** — Bittensor records when an exploit arrives
     on the subnet (block number + timestamp).  This is the authoritative
     first-seen proof.
  2. **Platform Monitoring** — After a miner links their bounty platform
     identity, the validator can cross-reference the subnet timestamp against
     the platform's submission timestamp.
  3. **Slashing** — If the platform timestamp predates the subnet timestamp
     by more than the grace window, the miner is flagged and their incentive
     score is zeroed for the epoch (or longer).

Limitations:
  - Relies on accurate platform timestamps (API-provided).
  - A determined adversary could use an unlinked account. This is
    mitigated by requiring identity linking for bounty reward splits.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from validator.utils.secrets import get_secret


# ── Constants ──────────────────────────────────────────────────────────────────────

# HMAC secret for receipt integrity.  Loaded via the unified secrets
# manager.  Falls back to a persistent file-backed key for single-validator
# dev deployments (multi-validator setups MUST share the key via env).
_hmac_str = get_secret("VALAYR_RECEIPT_HMAC_KEY", required=False)
if _hmac_str:
    _RECEIPT_HMAC_KEY = _hmac_str.encode()
else:
    # AG-1 fix: persist the random key to disk so it survives restarts.
    # Without this, all existing receipts fail HMAC verification after
    # any process restart.
    _KEY_PATH = Path(__file__).resolve().parent.parent.parent / "data" / ".hmac_key"
    try:
        if _KEY_PATH.exists():
            _RECEIPT_HMAC_KEY = _KEY_PATH.read_bytes()
        else:
            _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
            _RECEIPT_HMAC_KEY = os.urandom(32)
            _KEY_PATH.write_bytes(_RECEIPT_HMAC_KEY)
            # Restrict permissions so only the owner can read the key
            os.chmod(_KEY_PATH, 0o600)
    except OSError:
        # Last resort: in-memory only (container w/ read-only filesystem)
        _RECEIPT_HMAC_KEY = os.urandom(32)

# Grace window: platform submission within this many seconds AFTER subnet
# submission is considered legitimate (accounts for relay latency).
RELAY_GRACE_SECONDS = 300  # 5 minutes

# If platform submission predates subnet by more than this, it's a bypass.
BYPASS_THRESHOLD_SECONDS = 60


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class SubnetReceipt:
    """Record of when an exploit was first seen on the subnet."""
    task_id: str
    miner_hotkey: str
    fingerprint: str
    subnet_timestamp: int      # Unix timestamp of subnet receipt
    bittensor_block: int = 0   # Bittensor block number (on-chain proof)
    hmac_tag: str = ""         # HMAC-SHA256 of the receipt fields

    def compute_hmac(self) -> str:
        """Compute HMAC tag over the canonical fields."""
        message = f"{self.task_id}|{self.miner_hotkey}|{self.fingerprint}|{self.subnet_timestamp}|{self.bittensor_block}"
        return hmac.new(_RECEIPT_HMAC_KEY, message.encode(), hashlib.sha256).hexdigest()

    def verify_hmac(self) -> bool:
        """Verify the HMAC tag is valid."""
        if not self.hmac_tag:
            return False
        return hmac.compare_digest(self.hmac_tag, self.compute_hmac())


@dataclass
class BypassViolation:
    """Evidence of a miner bypassing the subnet."""
    miner_hotkey: str
    task_id: str
    fingerprint: str
    subnet_timestamp: int
    platform_timestamp: int
    platform: str
    delta_seconds: int         # platform_ts - subnet_ts (negative = bypass)
    severity: str              # "warning" | "violation" | "critical"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Anti-Bypass Engine ────────────────────────────────────────────────────────

class AntiBypassEngine:
    """Monitors for miner bypass attempts and issues violations."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._receipts_path = self.data_dir / "subnet_receipts.json"
        self._violations_path = self.data_dir / "violations.json"
        self._receipts: dict[str, SubnetReceipt] = {}  # fingerprint → receipt
        self._violations: list[BypassViolation] = []
        self._slashed: dict[str, int] = {}  # hotkey → slash_until_timestamp
        self._load()

    def record_subnet_receipt(
        self,
        task_id: str,
        miner_hotkey: str,
        fingerprint: str,
        bittensor_block: int = 0,
    ) -> SubnetReceipt:
        """Record that an exploit was received on the subnet."""
        receipt = SubnetReceipt(
            task_id=task_id,
            miner_hotkey=miner_hotkey,
            fingerprint=fingerprint,
            subnet_timestamp=int(time.time()),
            bittensor_block=bittensor_block,
        )
        receipt.hmac_tag = receipt.compute_hmac()
        self._receipts[fingerprint] = receipt
        # AG-5 fix: prune old receipts to prevent unbounded memory growth
        self._prune_receipts()
        self._save_receipts()
        return receipt

    def check_platform_submission(
        self,
        fingerprint: str,
        platform: str,
        platform_timestamp: int,
    ) -> Optional[BypassViolation]:
        """Check if a platform submission predates the subnet receipt.

        Returns a BypassViolation if bypass is detected, None otherwise.
        """
        receipt = self._receipts.get(fingerprint)
        if not receipt:
            # No subnet receipt found — likely unlinked miner or new exploit
            return None

        delta = platform_timestamp - receipt.subnet_timestamp

        # Platform submission after subnet + grace: legitimate
        if delta >= -BYPASS_THRESHOLD_SECONDS:
            return None

        # Platform submission significantly before subnet: bypass
        if delta < -3600:
            severity = "critical"
        elif delta < -BYPASS_THRESHOLD_SECONDS:
            severity = "violation"
        else:
            severity = "warning"

        violation = BypassViolation(
            miner_hotkey=receipt.miner_hotkey,
            task_id=receipt.task_id,
            fingerprint=fingerprint,
            subnet_timestamp=receipt.subnet_timestamp,
            platform_timestamp=platform_timestamp,
            platform=platform,
            delta_seconds=delta,
            severity=severity,
        )
        self._violations.append(violation)
        self._save_violations()

        # Auto-slash for violations
        if severity in ("violation", "critical"):
            slash_duration = 86400 if severity == "violation" else 604800  # 1d or 7d
            self._slashed[receipt.miner_hotkey] = int(time.time()) + slash_duration

        return violation

    def is_slashed(self, miner_hotkey: str) -> bool:
        """Check if a miner is currently slashed."""
        until = self._slashed.get(miner_hotkey, 0)
        return int(time.time()) < until

    def get_violations(self, miner_hotkey: Optional[str] = None) -> list[BypassViolation]:
        """Get all violations, optionally filtered by miner."""
        if miner_hotkey is None:
            return list(self._violations)
        return [v for v in self._violations if v.miner_hotkey == miner_hotkey]

    def get_receipt(self, fingerprint: str) -> Optional[SubnetReceipt]:
        return self._receipts.get(fingerprint)

    # Maximum number of receipts to keep in memory / on disk
    _MAX_RECEIPTS = 50_000
    # Receipts older than 30 days are eligible for pruning
    _RECEIPT_MAX_AGE = 30 * 24 * 3600

    def _prune_receipts(self) -> None:
        """Remove oldest receipts when the store exceeds _MAX_RECEIPTS."""
        if len(self._receipts) <= self._MAX_RECEIPTS:
            return
        cutoff = int(time.time()) - self._RECEIPT_MAX_AGE
        stale = [
            fp for fp, r in self._receipts.items()
            if r.subnet_timestamp < cutoff
        ]
        for fp in stale:
            del self._receipts[fp]
        # If still over limit, drop oldest by timestamp
        if len(self._receipts) > self._MAX_RECEIPTS:
            by_time = sorted(self._receipts.items(), key=lambda kv: kv[1].subnet_timestamp)
            to_drop = len(self._receipts) - self._MAX_RECEIPTS
            for fp, _ in by_time[:to_drop]:
                del self._receipts[fp]

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._receipts_path.exists():
            try:
                data = json.loads(self._receipts_path.read_text())
                for fp, r in data.items():
                    self._receipts[fp] = SubnetReceipt(**r)
            except (json.JSONDecodeError, OSError, TypeError) as exc:
                logging.getLogger(__name__).warning(
                    "Failed to load receipts from %s: %s — starting empty",
                    self._receipts_path, exc,
                )

        if self._violations_path.exists():
            try:
                data = json.loads(self._violations_path.read_text())
                self._violations = [BypassViolation(**v) for v in data]
            except (json.JSONDecodeError, OSError, TypeError) as exc:
                logging.getLogger(__name__).warning(
                    "Failed to load violations from %s: %s — starting empty",
                    self._violations_path, exc,
                )

    def _save_receipts(self) -> None:
        data = {fp: asdict(r) for fp, r in self._receipts.items()}
        payload = json.dumps(data, indent=2, sort_keys=True)
        tmp_path = self._receipts_path.with_suffix(self._receipts_path.suffix + ".tmp")
        tmp_path.write_text(payload)
        os.replace(tmp_path, self._receipts_path)

    def _save_violations(self) -> None:
        data = [asdict(v) for v in self._violations]
        payload = json.dumps(data, indent=2)
        tmp_path = self._violations_path.with_suffix(self._violations_path.suffix + ".tmp")
        tmp_path.write_text(payload)
        os.replace(tmp_path, self._violations_path)
