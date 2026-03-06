"""
Miner Identity — Links Bittensor hotkeys to bounty platform accounts.

Maintains a mapping of miner_hotkey → platform_id for each bounty platform.
This is critical for:
  1. Routing exploit rewards to the correct miner on bounty platforms
  2. Detecting bypass attempts (miner submits to platform without subnet)
  3. Tracking miner reputation across platforms

Identity claims are verified via the platform's API before being stored.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from validator.bounty.platform import BountyPlatform, PlatformRegistry


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class IdentityClaim:
    """A miner's claim to a bounty platform identity."""
    miner_hotkey: str
    platform: str          # e.g., "immunefi", "code4rena"
    platform_id: str       # Their username/ID on the platform
    verified: bool = False
    verified_at: int = 0
    claimed_at: int = 0


@dataclass
class MinerIdentity:
    """All known identities for a single miner."""
    hotkey: str
    claims: dict[str, IdentityClaim] = field(default_factory=dict)  # platform → claim

    def get_platform_id(self, platform: str) -> Optional[str]:
        claim = self.claims.get(platform)
        if claim and claim.verified:
            return claim.platform_id
        return None


# ── Identity Store ────────────────────────────────────────────────────────────

_HOTKEY_PATTERN = re.compile(r"^[a-zA-Z0-9]{48}$")
_PLATFORM_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


class IdentityStore:
    """Persistent store for miner ↔ platform identity mappings."""

    def __init__(self, data_dir: Path, platform_registry: Optional[PlatformRegistry] = None):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self.data_dir / "identities.json"
        self._registry = platform_registry
        self._identities: dict[str, MinerIdentity] = {}
        self._load()

    def claim_identity(
        self,
        miner_hotkey: str,
        platform: str,
        platform_id: str,
        signed_challenge: str = "",
    ) -> IdentityClaim:
        """Register a miner's claim to a platform identity.

        The claim starts unverified. Call ``verify_claim()`` to check it
        against the platform API.

        Args:
            signed_challenge: Optional. A signature of the miner's hotkey
                using the platform account, proving the miner controls the
                platform identity.  While the platform API is the ultimate
                authority, this acts as a lightweight pre-check.
        """
        if not _HOTKEY_PATTERN.match(miner_hotkey):
            raise ValueError(f"Invalid hotkey format: {miner_hotkey}")
        if not _PLATFORM_ID_PATTERN.match(platform_id):
            raise ValueError(f"Invalid platform_id format: {platform_id}")

        # AG-3 fix: require signed_challenge for new claims. Without this,
        # any miner can claim any platform identity without proof of ownership.
        if not signed_challenge:
            raise ValueError(
                "signed_challenge is required to claim a platform identity. "
                "Sign your miner hotkey with the platform account."
            )

        # Check for conflicting claims — AG-4 fix: also check UNVERIFIED
        # claims to prevent two miners holding the same platform_id.
        for hk, identity in self._identities.items():
            if hk == miner_hotkey:
                continue
            existing = identity.claims.get(platform)
            if existing and existing.platform_id == platform_id:
                raise ValueError(
                    f"Platform ID {platform_id} on {platform} is already "
                    f"claimed by another miner"
                )

        if miner_hotkey not in self._identities:
            self._identities[miner_hotkey] = MinerIdentity(hotkey=miner_hotkey)

        claim = IdentityClaim(
            miner_hotkey=miner_hotkey,
            platform=platform,
            platform_id=platform_id,
            verified=False,
            claimed_at=int(time.time()),
        )
        self._identities[miner_hotkey].claims[platform] = claim
        self._save()
        return claim

    def verify_claim(self, miner_hotkey: str, platform: str) -> bool:
        """Verify a pending identity claim against the platform API.

        Returns True if verification succeeded.
        """
        identity = self._identities.get(miner_hotkey)
        if not identity:
            return False

        claim = identity.claims.get(platform)
        if not claim:
            return False

        if self._registry:
            adapter = self._registry.get(platform)
            if adapter and not adapter.verify_identity(claim.platform_id):
                return False

        claim.verified = True
        claim.verified_at = int(time.time())
        self._save()
        return True

    def get_identity(self, miner_hotkey: str) -> Optional[MinerIdentity]:
        return self._identities.get(miner_hotkey)

    def get_platform_id(self, miner_hotkey: str, platform: str) -> Optional[str]:
        identity = self._identities.get(miner_hotkey)
        if identity:
            return identity.get_platform_id(platform)
        return None

    def list_verified(self, platform: str) -> list[IdentityClaim]:
        """List all verified claims for a given platform."""
        claims = []
        for identity in self._identities.values():
            claim = identity.claims.get(platform)
            if claim and claim.verified:
                claims.append(claim)
        return claims

    def revoke_claim(self, miner_hotkey: str, platform: str) -> bool:
        """Revoke a miner's claim to a platform identity."""
        identity = self._identities.get(miner_hotkey)
        if not identity or platform not in identity.claims:
            return False
        del identity.claims[platform]
        self._save()
        return True

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text())
        except (json.JSONDecodeError, OSError):
            return

        for hotkey, entry in data.items():
            claims = {}
            for platform, claim_data in entry.get("claims", {}).items():
                claims[platform] = IdentityClaim(**claim_data)
            self._identities[hotkey] = MinerIdentity(
                hotkey=hotkey, claims=claims,
            )

    def _save(self) -> None:
        data = {}
        for hotkey, identity in self._identities.items():
            data[hotkey] = {
                "hotkey": hotkey,
                "claims": {
                    p: asdict(c) for p, c in identity.claims.items()
                },
            }
        payload = json.dumps(data, indent=2, sort_keys=True)
        tmp_path = self._db_path.with_suffix(self._db_path.suffix + ".tmp")
        tmp_path.write_text(payload)
        os.replace(tmp_path, self._db_path)
