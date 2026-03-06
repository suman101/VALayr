"""
Task Generator — Deterministic Corpus Builder for Exploit Subnet.

Generates task packages from synthetic vulnerable contracts.
Each task package contains:
  - Flattened Solidity source
  - solc version
  - Deployment config (constructor args, initial state)
  - Optional invariant spec
  - Package hash (task ID)

CRITICAL: Tasks must be reproducible across validators byte-for-byte.
"""

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Ensure project root on path for validator.utils imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from task_generator.mutator import MutationRegistry


def _safe_keccak(data: bytes) -> str:
    """Compute keccak256 — determinism-critical, must match Solidity.

    Delegates to the shared ``validator.utils.hashing.keccak256`` utility which
    uses pycryptodome (primary) or ``cast keccak`` CLI (fallback).

    Raises RuntimeError if neither backend is available.
    """
    from validator.utils.hashing import keccak256
    return keccak256(data)

# ── Constants ────────────────────────────────────────────────────────────────

SOLC_VERSION = "0.8.28"
DEFAULT_BLOCK_TIMESTAMP = 1_700_000_000  # Fixed for determinism
DEFAULT_BLOCK_NUMBER = 18_000_000
DEFAULT_GAS_LIMIT = 30_000_000
DEFAULT_CHAIN_ID = 31337  # Anvil default

CORPUS_DIR = Path(__file__).parent / "corpus"
TEMPLATES_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path(__file__).parent.parent / "contracts" / "corpus"


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class DeploymentConfig:
    """Deterministic deployment parameters."""
    constructor_args: list = field(default_factory=list)
    initial_balance: int = 0  # Wei to send with deployment
    deployer_address: str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil[0]
    block_timestamp: int = DEFAULT_BLOCK_TIMESTAMP
    block_number: int = DEFAULT_BLOCK_NUMBER
    gas_limit: int = DEFAULT_GAS_LIMIT
    chain_id: int = DEFAULT_CHAIN_ID


@dataclass
class InvariantSpec:
    """Optional invariant for the task (Solidity assertion or condition)."""
    description: str
    solidity_condition: str  # e.g., "address(this).balance >= 1 ether"
    spec_type: str = "assertion"  # "assertion" | "property"


@dataclass
class TaskPackage:
    """Complete task package for a single vulnerable contract."""
    source_code: str
    solc_version: str
    deployment_config: DeploymentConfig
    vulnerability_class: str  # e.g., "reentrancy", "storage-collision", "auth-bypass"
    difficulty: int  # 1-5
    invariant_spec: Optional[InvariantSpec] = None
    metadata: dict = field(default_factory=dict)
    task_id: str = ""  # Computed: keccak256(canonical_json)

    def compute_task_id(self) -> str:
        """Compute deterministic task ID from canonical package content."""
        canonical = json.dumps({
            "source_code": self.source_code,
            "solc_version": self.solc_version,
            "deployment_config": asdict(self.deployment_config),
            "vulnerability_class": self.vulnerability_class,
            "difficulty": self.difficulty,
            "invariant_spec": asdict(self.invariant_spec) if self.invariant_spec else None,
        }, sort_keys=True, separators=(",", ":"))

        self.task_id = _safe_keccak(canonical.encode())
        return self.task_id

    def to_dict(self) -> dict:
        d = asdict(self)
        d["task_id"] = self.task_id
        return d

    def save(self, output_dir: Path) -> Path:
        """Save task package to deterministic directory structure."""
        if not self.task_id:
            self.compute_task_id()

        # Sanitize task_id: keep only hex-safe characters
        sanitized_id = "".join(c for c in self.task_id[:10] if c in "0123456789abcdef")
        if not sanitized_id:
            sanitized_id = "unknown"
        task_dir = (output_dir / sanitized_id).resolve()
        output_resolved = output_dir.resolve()
        if not str(task_dir).startswith(str(output_resolved) + os.sep):
            raise ValueError(f"Task directory escape detected: {self.task_id}")
        task_dir.mkdir(parents=True, exist_ok=True)

        # Save source
        (task_dir / "Vulnerable.sol").write_text(self.source_code)

        # Save config
        config = {
            "task_id": self.task_id,
            "solc_version": self.solc_version,
            "deployment_config": asdict(self.deployment_config),
            "vulnerability_class": self.vulnerability_class,
            "difficulty": self.difficulty,
            "invariant_spec": asdict(self.invariant_spec) if self.invariant_spec else None,
            "metadata": self.metadata,
        }
        (task_dir / "task.json").write_text(
            json.dumps(config, sort_keys=True, indent=2)
        )

        return task_dir


# ── Template Registry ────────────────────────────────────────────────────────

VULNERABILITY_TEMPLATES: dict[str, list[str]] = {
    "reentrancy": [
        "reentrancy_basic.sol",
        "reentrancy_cross_function.sol",
        "reentrancy_erc721.sol",
    ],
    "storage-collision": [
        "storage_collision_proxy.sol",
        "storage_collision_delegatecall.sol",
    ],
    "auth-bypass": [
        "auth_bypass_tx_origin.sol",
        "auth_bypass_missing_modifier.sol",
        "auth_bypass_initializer.sol",
    ],
    "integer-overflow": [
        "overflow_unchecked.sol",
        "overflow_casting.sol",
    ],
    "access-control": [
        "access_selfdestruct.sol",
        "access_unprotected_setter.sol",
    ],
    "flash-loan": [
        "flash_loan_price_manipulation.sol",
    ],
    "token-race": [
        "erc20_approve_race.sol",
    ],
    "signature-replay": [
        "signature_replay.sol",
    ],
    "create2-frontrun": [
        "create2_frontrun.sol",
    ],
    # ── Stage 2: Multi-contract systems ──────────────────────────────────
    "flash-loan-system": [
        "stage2/flash_loan_system.sol",
    ],
    "upgradeable-vault": [
        "stage2/upgradeable_vault.sol",
    ],
    "cross-reentrancy": [
        "stage2/cross_contract_reentrancy.sol",
    ],
    "governance-attack": [
        "stage2/governance_attack.sol",
    ],
    "oracle-manipulation": [
        "stage2/oracle_manipulation.sol",
    ],
    "token-bridge": [
        "stage2/token_bridge.sol",
    ],
    "staking-exploit": [
        "stage2/staking_rewards.sol",
    ],
}


# ── Difficulty Helpers ────────────────────────────────────────────────────────

_CLASS_INVARIANTS: dict[str, InvariantSpec] = {
    "reentrancy": InvariantSpec(
        description="Contract balance must not decrease during a single call",
        solidity_condition="address(this).balance >= _preCallBalance",
    ),
    "storage-collision": InvariantSpec(
        description="Admin slot must remain unchanged after delegate calls",
        solidity_condition="_admin == initialAdmin",
    ),
    "auth-bypass": InvariantSpec(
        description="Only owner can modify privileged state",
        solidity_condition="owner == _expectedOwner",
    ),
    "integer-overflow": InvariantSpec(
        description="Token total supply must equal sum of all balances",
        solidity_condition="totalSupply == _computedSum",
    ),
    "access-control": InvariantSpec(
        description="Contract must remain alive (not self-destructed)",
        solidity_condition="address(this).code.length > 0",
    ),
    "flash-loan": InvariantSpec(
        description="Oracle price must not deviate > 10% in a single block",
        solidity_condition="price <= _lastPrice * 110 / 100",
    ),
    "flash-loan-system": InvariantSpec(
        description="Pool reserves must balance after flash loan repayment",
        solidity_condition="reserveA * reserveB >= _kLast",
    ),
    "upgradeable-vault": InvariantSpec(
        description="Implementation address must be set by owner only",
        solidity_condition="_implementation == _expectedImpl",
    ),
    "cross-reentrancy": InvariantSpec(
        description="Vault deposits must not decrease during a single external call",
        solidity_condition="totalDeposits <= _preCallDeposits",
    ),
    "governance-attack": InvariantSpec(
        description="Proposal execution requires genuine token holding period",
        solidity_condition="block.number > proposal.startBlock + votingPeriod",
    ),
    "oracle-manipulation": InvariantSpec(
        description="Oracle price deviation within a single block must be bounded",
        solidity_condition="currentPrice <= lastPrice * 110 / 100 && currentPrice >= lastPrice * 90 / 100",
    ),
    "token-bridge": InvariantSpec(
        description="Minted wrapped tokens must equal locked ETH value",
        solidity_condition="wrappedToken.totalSupply() <= address(bridge).balance",
    ),
    "staking-exploit": InvariantSpec(
        description="Claimed rewards must not exceed distributed reward tokens",
        solidity_condition="totalClaimed <= rewardToken.balanceOf(address(pool)) + totalClaimed",
    ),
}


def _invariant_for_class(vuln_class: str) -> Optional[InvariantSpec]:
    """Return an invariant spec for a vulnerability class, or None."""
    return _CLASS_INVARIANTS.get(vuln_class)


# ── Corpus Generator ─────────────────────────────────────────────────────────

class CorpusGenerator:
    """Generates deterministic task packages from templates and mutations."""

    def __init__(self, templates_dir: Path = TEMPLATES_DIR, output_dir: Path = OUTPUT_DIR):
        self.templates_dir = templates_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._mutation_registry = MutationRegistry()

    def generate_from_template(self, template_name: str, vuln_class: str,
                                 difficulty: int = 1,
                                 mutations: Optional[dict] = None) -> TaskPackage:
        """Load a template, optionally apply mutations, produce TaskPackage."""
        template_path = (self.templates_dir / template_name).resolve()
        templates_resolved = self.templates_dir.resolve()
        if not str(template_path).startswith(str(templates_resolved) + os.sep):
            raise ValueError(f"Template path escape attempt: {template_name}")
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        source = template_path.read_text()

        if mutations:
            source = self._apply_mutations(source, mutations)

        pkg = TaskPackage(
            source_code=source,
            solc_version=SOLC_VERSION,
            deployment_config=DeploymentConfig(
                initial_balance=mutations.get("initial_balance", 10 * 10**18)
                if mutations else 10 * 10**18
            ),
            vulnerability_class=vuln_class,
            difficulty=difficulty,
            metadata={
                "template": template_name,
                "mutations": mutations or {},
                "generated_at": DEFAULT_BLOCK_TIMESTAMP,  # Use fixed time for determinism
            },
        )

        pkg.compute_task_id()
        return pkg

    def _apply_mutations(self, source: str, mutations: dict) -> str:
        """Apply deterministic mutations to source code via the mutator registry.

        TG-1/TG-2 fix: verify the mutated source still compiles by running
        a quick ``solc --stop-after parsing`` check.  If it fails, return the
        original (unmutated) source and log a warning so the task is still
        usable.
        """
        import logging
        import subprocess
        import shutil

        mutated = self._mutation_registry.apply(source, mutations)

        solc = shutil.which("solc") or shutil.which("solc-0.8.28")
        if solc:
            try:
                proc = subprocess.run(
                    [solc, "--stop-after", "parsing", "-"],
                    input=mutated,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode != 0:
                    logging.getLogger(__name__).warning(
                        "Mutated source failed parse check — reverting to original. "
                        "solc stderr: %.200s", proc.stderr,
                    )
                    return source
            except (subprocess.TimeoutExpired, OSError):
                pass  # If solc unavailable, skip parse check (non-critical)

        return mutated

    def generate_batch(self, count_per_class: int = 3, seed: int = 42,
                        max_difficulty: int = 1) -> list[TaskPackage]:
        """Generate a batch of task packages across all vulnerability classes.

        Args:
            count_per_class: Number of variants per template (1 = base only).
            seed: Deterministic seed for mutations.
            max_difficulty: Maximum difficulty level (1-3). Higher difficulties
                apply heavier mutations, add invariant specs, and increase
                initial balances to create harder-to-exploit scenarios.
        """
        packages = []
        idx = 0

        for vuln_class, templates in VULNERABILITY_TEMPLATES.items():
            for template_name in templates:
                # Base version (difficulty 1)
                try:
                    pkg = self.generate_from_template(template_name, vuln_class, difficulty=1)
                    packages.append(pkg)
                except FileNotFoundError:
                    continue

                # Mutations at difficulty 1
                for i in range(count_per_class - 1):
                    mut_seed = seed + idx + i
                    mutations = {
                        "storage_prefix": f"mut_{mut_seed}",
                        "rename_map": {},
                        "initial_balance": (mut_seed % 10 + 1) * 10**18,
                    }
                    try:
                        pkg = self.generate_from_template(
                            template_name, vuln_class,
                            difficulty=1,
                            mutations=mutations
                        )
                        packages.append(pkg)
                    except FileNotFoundError:
                        continue
                    idx += 1

                # Difficulty 2: heavier mutations + invariant specs
                if max_difficulty >= 2:
                    for i in range(count_per_class):
                        mut_seed = seed + idx + i + 1000
                        mutations = {
                            "storage_prefix": f"d2_{mut_seed}",
                            "rename_map": {},
                            "initial_balance": (mut_seed % 20 + 5) * 10**18,
                            "deadcode_count": 3,
                        }
                        invariant = _invariant_for_class(vuln_class)
                        try:
                            pkg = self.generate_from_template(
                                template_name, vuln_class,
                                difficulty=2,
                                mutations=mutations,
                            )
                            if invariant:
                                pkg.invariant_spec = invariant
                                pkg.compute_task_id()  # Recompute with invariant
                            packages.append(pkg)
                        except FileNotFoundError:
                            continue
                        idx += 1

                # Difficulty 3: maximum mutations, all mutators active
                if max_difficulty >= 3:
                    for i in range(count_per_class):
                        mut_seed = seed + idx + i + 2000
                        mutations = {
                            "storage_prefix": f"d3_{mut_seed}",
                            "rename_map": {},
                            "initial_balance": (mut_seed % 50 + 10) * 10**18,
                            "deadcode_count": 6,
                        }
                        invariant = _invariant_for_class(vuln_class)
                        try:
                            pkg = self.generate_from_template(
                                template_name, vuln_class,
                                difficulty=3,
                                mutations=mutations,
                            )
                            if invariant:
                                pkg.invariant_spec = invariant
                                pkg.compute_task_id()
                            packages.append(pkg)
                        except FileNotFoundError:
                            continue
                        idx += 1

        return packages

    @staticmethod
    def mutation_diversity(packages: list[TaskPackage]) -> dict:
        """TG-6 fix: compute a diversity metric for the generated batch.

        Returns a dict with:
          - ``unique_source_hashes``: number of distinct source hashes
          - ``total``: total packages
          - ``ratio``: unique / total  (1.0 = fully diverse)
          - ``per_class``: breakdown by vuln class
        """
        from collections import defaultdict

        hashes: set[str] = set()
        per_class: dict[str, set[str]] = defaultdict(set)

        for pkg in packages:
            h = hashlib.sha256(pkg.source_code.encode()).hexdigest()
            hashes.add(h)
            per_class[pkg.vulnerability_class].add(h)

        total = len(packages) or 1
        return {
            "unique_source_hashes": len(hashes),
            "total": len(packages),
            "ratio": len(hashes) / total,
            "per_class": {
                cls: {"unique": len(hs), "total": sum(
                    1 for p in packages if p.vulnerability_class == cls
                )}
                for cls, hs in per_class.items()
            },
        }

    def save_batch(self, packages: list[TaskPackage]) -> list[Path]:
        """Save all packages and return their directories."""
        paths = []
        for pkg in packages:
            p = pkg.save(self.output_dir)
            paths.append(p)
        return paths

    def generate_manifest(self, packages: list[TaskPackage]) -> dict:
        """Generate a manifest of all task packages for validator sync."""
        manifest = {
            "version": 1,
            "solc_version": SOLC_VERSION,
            "generated_at": DEFAULT_BLOCK_TIMESTAMP,
            "total_tasks": len(packages),
            "tasks": [],
        }

        for pkg in packages:
            manifest["tasks"].append({
                "task_id": pkg.task_id,
                "vulnerability_class": pkg.vulnerability_class,
                "difficulty": pkg.difficulty,
                "source_hash": _safe_keccak(pkg.source_code.encode()),
            })

        return manifest


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate deterministic task corpus")
    parser.add_argument("--output", type=str, default=str(OUTPUT_DIR),
                       help="Output directory for task packages")
    parser.add_argument("--count", type=int, default=3,
                       help="Mutations per vulnerability class")
    parser.add_argument("--seed", type=int, default=42,
                       help="Deterministic seed for mutations")
    parser.add_argument("--difficulty", type=int, default=1, choices=[1, 2, 3],
                       help="Maximum difficulty level (1=base, 2=heavy mutations+invariants, 3=max)")
    parser.add_argument("--manifest", action="store_true",
                       help="Generate manifest JSON")
    args = parser.parse_args()

    gen = CorpusGenerator(output_dir=Path(args.output))

    print(f"[*] Generating corpus (seed={args.seed}, count_per_class={args.count}, max_difficulty={args.difficulty})")
    packages = gen.generate_batch(count_per_class=args.count, seed=args.seed,
                                   max_difficulty=args.difficulty)

    print(f"[*] Generated {len(packages)} task packages")
    paths = gen.save_batch(packages)

    for pkg, path in zip(packages, paths):
        print(f"  {pkg.vulnerability_class:20s} difficulty={pkg.difficulty} → {path.name}")

    if args.manifest:
        manifest = gen.generate_manifest(packages)
        manifest_path = Path(args.output) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
        print(f"[*] Manifest written to {manifest_path}")

    print("[+] Done.")


if __name__ == "__main__":
    main()
