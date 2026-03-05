"""
Bounty Platform Integration — Submit validated exploits to bug-bounty platforms.

Defines the abstract ``BountyPlatform`` interface and concrete adapters for
Immunefi, Code4rena, and other platforms.  The orchestrator calls
``submit_report()`` after an exploit passes validation, so miners get
automatic bounty submission via the subnet.

Architecture:
    Miner → Subnet (validate + fingerprint) → BountyPlatform adapter → Platform API

This keeps the miner honest: they *must* submit through the subnet first
(which timestamps the exploit on-chain via Bittensor), and the subnet then
forwards to the bounty platform using the miner's linked identity.
"""

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ── Data Structures ──────────────────────────────────────────────────────────

class SubmissionStatus(Enum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    PAID = "paid"


@dataclass
class BountyReport:
    """A validated exploit report ready for platform submission."""
    task_id: str
    miner_hotkey: str
    platform_id: str          # Miner's identity on the bounty platform
    target_address: str       # Mainnet contract address
    chain_id: int
    vulnerability_class: str
    severity_score: float
    exploit_description: str
    exploit_source: str       # Solidity exploit code
    fingerprint: str          # VALayr dedup fingerprint
    subnet_timestamp: int     # When the subnet received the submission
    metadata: dict = field(default_factory=dict)


@dataclass
class SubmissionReceipt:
    """Receipt returned after submitting to a bounty platform."""
    platform: str
    report_id: str            # Platform-assigned ID
    status: SubmissionStatus
    submitted_at: int
    url: str = ""             # Link to the submission on the platform
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ── Abstract Platform Interface ──────────────────────────────────────────────

class BountyPlatform(ABC):
    """Interface for bounty platform adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Platform name (e.g., 'immunefi', 'code4rena')."""
        ...

    @abstractmethod
    def submit_report(self, report: BountyReport) -> SubmissionReceipt:
        """Submit a validated exploit report to the platform."""
        ...

    @abstractmethod
    def check_status(self, report_id: str) -> SubmissionStatus:
        """Check the status of a previously submitted report."""
        ...

    @abstractmethod
    def verify_identity(self, platform_id: str) -> bool:
        """Verify that a miner's platform identity is valid."""
        ...


# ── Immunefi Adapter ─────────────────────────────────────────────────────────

class ImmunefiAdapter(BountyPlatform):
    """Adapter for the Immunefi bug bounty platform.

    Requires an API key set via IMMUNEFI_API_KEY env var or constructor arg.
    """

    BASE_URL = "https://api.immunefi.com/v1"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get("IMMUNEFI_API_KEY", "")

    @property
    def name(self) -> str:
        return "immunefi"

    def submit_report(self, report: BountyReport) -> SubmissionReceipt:
        payload = {
            "target": report.target_address,
            "chain_id": report.chain_id,
            "severity": self._map_severity(report.severity_score),
            "title": f"[VALayr] {report.vulnerability_class} in {report.target_address[:10]}",
            "description": report.exploit_description,
            "proof_of_concept": report.exploit_source,
            "reporter_id": report.platform_id,
            "metadata": {
                "subnet_fingerprint": report.fingerprint,
                "subnet_timestamp": report.subnet_timestamp,
                "miner_hotkey": report.miner_hotkey,
            },
        }

        result = self._api_post("/reports", payload)
        if result is None:
            return SubmissionReceipt(
                platform=self.name,
                report_id="",
                status=SubmissionStatus.REJECTED,
                submitted_at=int(time.time()),
                error="API request failed",
            )

        return SubmissionReceipt(
            platform=self.name,
            report_id=result.get("id", ""),
            status=SubmissionStatus.SUBMITTED,
            submitted_at=int(time.time()),
            url=result.get("url", ""),
        )

    def check_status(self, report_id: str) -> SubmissionStatus:
        result = self._api_get(f"/reports/{report_id}")
        if result is None:
            return SubmissionStatus.PENDING
        status_map = {
            "pending": SubmissionStatus.PENDING,
            "triaging": SubmissionStatus.PENDING,
            "accepted": SubmissionStatus.ACCEPTED,
            "rejected": SubmissionStatus.REJECTED,
            "duplicate": SubmissionStatus.DUPLICATE,
            "paid": SubmissionStatus.PAID,
        }
        return status_map.get(result.get("status", ""), SubmissionStatus.PENDING)

    def verify_identity(self, platform_id: str) -> bool:
        result = self._api_get(f"/researchers/{platform_id}")
        return result is not None and result.get("active", False)

    @staticmethod
    def _map_severity(score: float) -> str:
        if score >= 0.9:
            return "critical"
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"

    def _api_post(self, endpoint: str, payload: dict) -> Optional[dict]:
        if not self.api_key:
            return None
        if not endpoint.startswith("/") or "?" in endpoint:
            return None
        url = self.BASE_URL + endpoint
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "VALayr-Subnet/0.1")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return None

    def _api_get(self, endpoint: str) -> Optional[dict]:
        if not self.api_key:
            return None
        if not endpoint.startswith("/") or "?" in endpoint:
            return None
        url = self.BASE_URL + endpoint
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("User-Agent", "VALayr-Subnet/0.1")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return None


# ── Code4rena Adapter ─────────────────────────────────────────────────────────

class Code4renaAdapter(BountyPlatform):
    """Adapter for the Code4rena audit contest platform."""

    BASE_URL = "https://api.code4rena.com/v1"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get("CODE4RENA_API_KEY", "")

    @property
    def name(self) -> str:
        return "code4rena"

    def submit_report(self, report: BountyReport) -> SubmissionReceipt:
        payload = {
            "contest_id": report.metadata.get("contest_id", ""),
            "severity": self._map_severity(report.severity_score),
            "title": f"{report.vulnerability_class} vulnerability",
            "body": report.exploit_description,
            "proof_of_concept": report.exploit_source,
            "warden_id": report.platform_id,
        }

        result = self._api_post("/findings", payload)
        if result is None:
            return SubmissionReceipt(
                platform=self.name,
                report_id="",
                status=SubmissionStatus.REJECTED,
                submitted_at=int(time.time()),
                error="API request failed",
            )

        return SubmissionReceipt(
            platform=self.name,
            report_id=result.get("id", ""),
            status=SubmissionStatus.SUBMITTED,
            submitted_at=int(time.time()),
            url=result.get("url", ""),
        )

    def check_status(self, report_id: str) -> SubmissionStatus:
        result = self._api_get(f"/findings/{report_id}")
        if result is None:
            return SubmissionStatus.PENDING
        status_map = {
            "pending": SubmissionStatus.PENDING,
            "confirmed": SubmissionStatus.ACCEPTED,
            "rejected": SubmissionStatus.REJECTED,
            "duplicate": SubmissionStatus.DUPLICATE,
        }
        return status_map.get(result.get("status", ""), SubmissionStatus.PENDING)

    def verify_identity(self, platform_id: str) -> bool:
        result = self._api_get(f"/wardens/{platform_id}")
        return result is not None

    @staticmethod
    def _map_severity(score: float) -> str:
        if score >= 0.9:
            return "3 (High)"
        if score >= 0.5:
            return "2 (Med)"
        return "QA (Low)"

    def _api_post(self, endpoint: str, payload: dict) -> Optional[dict]:
        if not self.api_key:
            return None
        if not endpoint.startswith("/") or "?" in endpoint:
            return None
        url = self.BASE_URL + endpoint
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "VALayr-Subnet/0.1")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return None

    def _api_get(self, endpoint: str) -> Optional[dict]:
        if not self.api_key:
            return None
        if not endpoint.startswith("/") or "?" in endpoint:
            return None
        url = self.BASE_URL + endpoint
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("User-Agent", "VALayr-Subnet/0.1")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return None


# ── Platform Registry ─────────────────────────────────────────────────────────

class PlatformRegistry:
    """Registry of available bounty platform adapters."""

    def __init__(self):
        self._platforms: dict[str, BountyPlatform] = {}

    def register(self, platform: BountyPlatform) -> None:
        self._platforms[platform.name] = platform

    def get(self, name: str) -> Optional[BountyPlatform]:
        return self._platforms.get(name)

    def list_platforms(self) -> list[str]:
        return list(self._platforms.keys())

    def submit_to_all(self, report: BountyReport) -> list[SubmissionReceipt]:
        """Submit a report to all registered platforms."""
        receipts = []
        for platform in self._platforms.values():
            receipt = platform.submit_report(report)
            receipts.append(receipt)
        return receipts


def create_default_registry() -> PlatformRegistry:
    """Create a registry with all supported platform adapters."""
    registry = PlatformRegistry()
    registry.register(ImmunefiAdapter())
    registry.register(Code4renaAdapter())
    return registry
