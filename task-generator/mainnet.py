"""
Mainnet Contract Source — Fetch live contracts for exploit challenges.

Integrates with block explorers (Etherscan, etc.) to pull verified source
code from deployed mainnet contracts.  This prevents miners from overfitting
to the synthetic template corpus and forces models to generalise.

Usage:
    source = MainnetContractSource(api_key="...")
    packages = source.fetch_batch(addresses=["0x..."], chain_id=1)

Or via the CLI:
    python -m task_generator.mainnet --address 0x... --chain 1
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from task_generator.generate import (
    TaskPackage,
    DeploymentConfig,
    InvariantSpec,
    SOLC_VERSION,
    DEFAULT_BLOCK_TIMESTAMP,
    _safe_keccak,
)


# ── Explorer Endpoints ───────────────────────────────────────────────────────

EXPLORER_APIS: dict[int, str] = {
    1: "https://api.etherscan.io/api",
    5: "https://api-goerli.etherscan.io/api",
    11155111: "https://api-sepolia.etherscan.io/api",
    137: "https://api.polygonscan.com/api",
    42161: "https://api.arbiscan.io/api",
    10: "https://api-optimistic.etherscan.io/api",
    8453: "https://api.basescan.org/api",
}

# Maximum source size we'll accept (512 KB).
MAX_SOURCE_BYTES = 512 * 1024

# Rate-limit: seconds between Etherscan requests.
REQUEST_DELAY = 0.5
MAX_API_RETRIES = 4
BACKOFF_BASE_SECONDS = 1.0


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class MainnetContract:
    """Verified contract fetched from a block explorer."""
    address: str
    chain_id: int
    name: str
    source_code: str
    solc_version: str
    constructor_args: str  # ABI-encoded hex
    proxy: bool = False
    implementation_address: str = ""


# ── Source Fetcher ────────────────────────────────────────────────────────────

class MainnetContractSource:
    """Fetches verified source code from block explorers."""

    def __init__(
        self,
        api_key: str = "",
        output_dir: Optional[Path] = None,
        allowed_chains: Optional[set[int]] = None,
    ):
        self.api_key = api_key or os.environ.get("ETHERSCAN_API_KEY", "")
        self.output_dir = output_dir or (
            Path(__file__).parent.parent / "contracts" / "corpus"
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.allowed_chains = allowed_chains or {1, 137, 42161, 10, 8453}

    # ── Public API ───────────────────────────────────────────────────────

    def fetch_contract(
        self, address: str, chain_id: int = 1
    ) -> Optional[MainnetContract]:
        """Fetch verified source for a single contract address.

        Returns None when the contract is unverified or the explorer
        returns an error.
        """
        address = self._normalise_address(address)
        if chain_id not in self.allowed_chains:
            raise ValueError(
                f"Chain {chain_id} not in allowed set {self.allowed_chains}"
            )

        base_url = EXPLORER_APIS.get(chain_id)
        if not base_url:
            raise ValueError(f"No explorer API configured for chain {chain_id}")

        data = self._api_get_source(base_url, address)
        if data is None:
            return None

        source = data.get("SourceCode", "")
        if not source:
            return None

        # Etherscan wraps multi-file sources in double braces: {{...}}
        if source.startswith("{{"):
            source = self._flatten_multi_file(source)
        elif source.startswith("{"):
            source = self._flatten_standard_json(source)

        if len(source.encode()) > MAX_SOURCE_BYTES:
            return None

        return MainnetContract(
            address=address,
            chain_id=chain_id,
            name=data.get("ContractName", "Unknown"),
            source_code=source,
            solc_version=data.get("CompilerVersion", SOLC_VERSION),
            constructor_args=data.get("ConstructorArguments", ""),
            proxy=bool(data.get("Proxy", "0") == "1"),
            implementation_address=data.get("Implementation", ""),
        )

    def fetch_batch(
        self,
        addresses: list[str],
        chain_id: int = 1,
    ) -> list[MainnetContract]:
        """Fetch multiple contracts with rate-limiting."""
        contracts = []
        for addr in addresses:
            contract = self.fetch_contract(addr, chain_id)
            if contract is not None:
                contracts.append(contract)
            time.sleep(REQUEST_DELAY)
        return contracts

    def to_task_package(
        self,
        contract: MainnetContract,
        difficulty: int = 3,
        vulnerability_class: str = "mainnet-unknown",
    ) -> TaskPackage:
        """Convert a fetched mainnet contract into a TaskPackage."""
        pkg = TaskPackage(
            source_code=contract.source_code,
            solc_version=SOLC_VERSION,
            deployment_config=DeploymentConfig(
                initial_balance=10 * 10**18,
            ),
            vulnerability_class=vulnerability_class,
            difficulty=difficulty,
            metadata={
                "source": "mainnet",
                "address": contract.address,
                "chain_id": contract.chain_id,
                "contract_name": contract.name,
                "original_solc": contract.solc_version,
                "proxy": contract.proxy,
                "implementation": contract.implementation_address,
                "fetched_at": int(time.time()),
            },
        )
        pkg.compute_task_id()
        return pkg

    def fetch_and_save(
        self,
        addresses: list[str],
        chain_id: int = 1,
        difficulty: int = 3,
    ) -> list[TaskPackage]:
        """Fetch contracts, convert to TaskPackages, and save to corpus."""
        contracts = self.fetch_batch(addresses, chain_id)
        packages = []
        for contract in contracts:
            pkg = self.to_task_package(contract, difficulty=difficulty)
            pkg.save(self.output_dir)
            packages.append(pkg)
        return packages

    # ── Private Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _normalise_address(address: str) -> str:
        """Validate and normalise an Ethereum address."""
        address = address.strip()
        if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
            raise ValueError(f"Invalid Ethereum address: {address}")
        return address

    def _api_get_source(
        self, base_url: str, address: str
    ) -> Optional[dict]:
        """Call the block explorer getsourcecode endpoint."""
        query = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if self.api_key:
            query["apikey"] = self.api_key
        url = f"{base_url}?{urllib.parse.urlencode(query)}"

        body = None
        for attempt in range(MAX_API_RETRIES):
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "VALayr-Subnet/0.1")
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as e:
                if e.code != 429 or attempt == MAX_API_RETRIES - 1:
                    return None
                backoff = BACKOFF_BASE_SECONDS * (2 ** attempt)
                time.sleep(backoff)
            except (urllib.error.URLError, json.JSONDecodeError, OSError):
                return None

        if body is None:
            return None

        if body.get("status") != "1" or not body.get("result"):
            return None

        result = body["result"]
        if isinstance(result, list) and len(result) > 0:
            return result[0]
        return None

    @staticmethod
    def _flatten_multi_file(raw: str) -> str:
        """Flatten Etherscan multi-file double-brace format into one file.

        Etherscan wraps multi-file sources as:
            {{  "file.sol": { "content": "..." }, ... }}
        """
        # Strip outer double braces
        inner = raw[1:-1]
        try:
            files = json.loads(inner)
        except json.JSONDecodeError:
            return raw

        # Etherscan sometimes nests under "sources"
        if "sources" in files and isinstance(files["sources"], dict):
            files = files["sources"]

        parts = []
        for filename, entry in sorted(files.items()):
            content = entry.get("content", "") if isinstance(entry, dict) else str(entry)
            parts.append(f"// ── {filename} ──\n{content}")

        return "\n\n".join(parts)

    @staticmethod
    def _flatten_standard_json(raw: str) -> str:
        """Flatten Etherscan standard-json-input format."""
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return raw

        sources = obj.get("sources", {})
        parts = []
        for filename, entry in sorted(sources.items()):
            content = entry.get("content", "")
            parts.append(f"// ── {filename} ──\n{content}")

        return "\n\n".join(parts) if parts else raw


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Fetch mainnet contracts for the exploit corpus"
    )
    parser.add_argument(
        "--address",
        type=str,
        action="append",
        required=True,
        help="Contract address to fetch (repeatable)",
    )
    parser.add_argument(
        "--chain",
        type=int,
        default=1,
        help="Chain ID (default: 1 = Ethereum mainnet)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory (default: contracts/corpus)",
    )
    parser.add_argument(
        "--difficulty",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="Task difficulty rating",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default="",
        help="Etherscan API key (or set ETHERSCAN_API_KEY env var)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output) if args.output else None
    source = MainnetContractSource(api_key=args.api_key, output_dir=output_dir)

    print(f"[*] Fetching {len(args.address)} contract(s) from chain {args.chain}")
    packages = source.fetch_and_save(
        addresses=args.address,
        chain_id=args.chain,
        difficulty=args.difficulty,
    )

    for pkg in packages:
        print(
            f"  {pkg.metadata.get('contract_name', '?'):30s} "
            f"difficulty={pkg.difficulty}  task_id={pkg.task_id[:10]}"
        )

    if not packages:
        print("[!] No contracts fetched (unverified or API error)")
    else:
        print(f"[+] Saved {len(packages)} task package(s)")


if __name__ == "__main__":
    main()
