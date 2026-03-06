"""
Mainnet Auto-Discovery — Finds bounty-eligible contracts without manual input.

Strategies:
  1. Platform target lists — scrape Immunefi/Code4rena active bounty targets
  2. High-TVL contracts — top DeFi protocols by deposited value
  3. Recently deployed — new contracts with > N ETH value locked

The feed runs periodically and adds discovered contracts to the corpus.
"""

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from validator.utils.logging import get_logger

logger = get_logger(__name__)


# ── Constants ────────────────────────────────────────────────────────────────

# Well-known DeFi contracts that are always good targets (high TVL, active bounties)
# These are public, verified mainnet contracts with Immunefi bounties.
# Override via VALAYR_SEED_TARGETS (comma-separated addresses) for custom seeds.
_DEFAULT_SEED_TARGETS: dict[int, list[str]] = {
    1: [
        # Aave V3 Pool
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        # Compound V3 USDC Comet
        "0xc3d688B66703497DAA19211EEdff47f25384cdc3",
        # Uniswap V3 Factory
        "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        # Lido stETH
        "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",
        # Maker DSPause
        "0xbE286431454714F511008713973d3B053A2d38f3",
    ],
}


def _load_seed_targets() -> dict[int, list[str]]:
    """Load seed targets from env override or defaults."""
    custom = os.environ.get("VALAYR_SEED_TARGETS", "").strip()
    if custom:
        addrs = [a.strip() for a in custom.split(",") if a.strip()]
        chain_id = int(os.environ.get("VALAYR_SEED_CHAIN_ID", "1"))
        return {chain_id: addrs}
    return _DEFAULT_SEED_TARGETS


SEED_TARGETS = _load_seed_targets()

# How often to refresh the contract list (seconds)
REFRESH_INTERVAL = 86400  # 24 hours

# Maximum contracts to add per refresh cycle
MAX_CONTRACTS_PER_CYCLE = 20

# Maximum discovered contracts to keep in memory
MAX_DISCOVERED_CONTRACTS = 10_000


@dataclass
class DiscoveredContract:
    """A contract discovered for potential inclusion in the corpus."""
    address: str
    chain_id: int
    source: str          # "seed" | "immunefi" | "tvl"
    discovered_at: float
    metadata: dict


class MainnetAutoDiscovery:
    """Automated mainnet contract discovery for the exploit corpus."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self.data_dir / "discovery_state.json"
        self._discovered: dict[str, DiscoveredContract] = {}
        self._last_refresh: float = 0
        self._load()

    def discover(
        self,
        chain_id: int = 1,
        include_seeds: bool = True,
    ) -> list[DiscoveredContract]:
        """Run discovery and return newly-found contracts.

        Only runs if REFRESH_INTERVAL has elapsed since last run.
        """
        now = time.time()
        if now - self._last_refresh < REFRESH_INTERVAL and self._discovered:
            return []

        new_contracts: list[DiscoveredContract] = []

        # Strategy 1: Seed targets (always included on first run)
        if include_seeds:
            for addr in SEED_TARGETS.get(chain_id, []):
                key = f"{chain_id}:{addr.lower()}"
                if key not in self._discovered:
                    c = DiscoveredContract(
                        address=addr,
                        chain_id=chain_id,
                        source="seed",
                        discovered_at=now,
                        metadata={"reason": "well-known DeFi with active bounty"},
                    )
                    self._discovered[key] = c
                    new_contracts.append(c)

        # Strategy 2: Immunefi active targets
        immunefi_targets = self._fetch_immunefi_targets()
        for addr in immunefi_targets[:MAX_CONTRACTS_PER_CYCLE]:
            key = f"{chain_id}:{addr.lower()}"
            if key not in self._discovered:
                c = DiscoveredContract(
                    address=addr,
                    chain_id=chain_id,
                    source="immunefi",
                    discovered_at=now,
                    metadata={"reason": "active Immunefi bounty"},
                )
                self._discovered[key] = c
                new_contracts.append(c)

        self._last_refresh = now
        self._prune()
        self._save()

        logger.info(
            "Discovery: %d new contracts found (%d total tracked)",
            len(new_contracts), len(self._discovered),
        )
        return new_contracts

    def get_addresses(self, chain_id: int = 1) -> list[str]:
        """Return all discovered addresses for a chain."""
        return [
            c.address for c in self._discovered.values()
            if c.chain_id == chain_id
        ]

    def _fetch_immunefi_targets(self) -> list[str]:
        """Fetch active bounty target addresses from Immunefi.

        Returns a list of Ethereum addresses.  Falls back to empty list
        on any error (Immunefi API is best-effort).
        """
        try:
            url = "https://api.immunefi.com/v1/bounties?status=active"
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "VALayr-Subnet/0.1")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            addresses = []
            if isinstance(data, list):
                for bounty in data:
                    assets = bounty.get("assets", [])
                    if isinstance(assets, list):
                        for asset in assets:
                            addr = asset.get("address", "")
                            if addr and addr.startswith("0x") and len(addr) == 42:
                                addresses.append(addr)
            return addresses
        except (urllib.error.URLError, json.JSONDecodeError, OSError, KeyError, TypeError):
            logger.debug("Immunefi target fetch failed (non-fatal)")
            return []

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text())
            self._last_refresh = data.get("last_refresh", 0)
            for key, entry in data.get("discovered", {}).items():
                self._discovered[key] = DiscoveredContract(**entry)
        except (json.JSONDecodeError, OSError, TypeError) as exc:
            logger.warning("Failed to load discovery state from %s: %s — starting empty", self._state_path, exc)

    def _prune(self) -> None:
        """Evict oldest entries if _discovered exceeds MAX_DISCOVERED_CONTRACTS."""
        if len(self._discovered) <= MAX_DISCOVERED_CONTRACTS:
            return
        # Sort by discovered_at ascending, keep the newest entries
        sorted_keys = sorted(
            self._discovered, key=lambda k: self._discovered[k].discovered_at,
        )
        excess = len(sorted_keys) - MAX_DISCOVERED_CONTRACTS
        for key in sorted_keys[:excess]:
            del self._discovered[key]

    def _save(self) -> None:
        data = {
            "last_refresh": self._last_refresh,
            "discovered": {
                k: {
                    "address": c.address,
                    "chain_id": c.chain_id,
                    "source": c.source,
                    "discovered_at": c.discovered_at,
                    "metadata": c.metadata,
                }
                for k, c in self._discovered.items()
            },
        }
        payload = json.dumps(data, indent=2, sort_keys=True)
        # H-8 fix: use atomic temp + fsync + replace pattern
        tmp = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        tmp.write_text(payload)
        fd = os.open(str(tmp), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._state_path)
