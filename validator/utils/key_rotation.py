"""
Validator Key Rotation Utility — Rotate validator keys on deployed contracts.

Supports two operations:
  1. Rotate validator address: remove old validator, add new one.
  2. Transfer contract ownership: initiate 2-step ownership transfer.

Usage:
  python -m validator.utils.key_rotation \\
      --contract 0x1234...abcd \\
      --rpc-url http://127.0.0.1:8545 \\
      --old-key 0xOLD_PRIVATE_KEY \\
      --new-address 0xNEW_VALIDATOR_ADDRESS \\
      --action rotate-validator

  python -m validator.utils.key_rotation \\
      --contract 0x1234...abcd \\
      --rpc-url http://127.0.0.1:8545 \\
      --old-key 0xOLD_PRIVATE_KEY \\
      --new-key 0xNEW_PRIVATE_KEY \\
      --action transfer-ownership
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.utils.logging import get_logger

logger = get_logger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_cast() -> str:
    """Find the cast binary, checking common locations.

    Returns the *resolved absolute path* to the binary so that subsequent
    calls cannot be hijacked via PATH manipulation.
    """
    for candidate in [
        "cast",
        os.path.expanduser("~/.foundry/bin/cast"),
    ]:
        try:
            result = subprocess.run(
                [candidate, "--version"],
                capture_output=True, check=True, timeout=5, text=True,
            )
            # Verify the version output looks legitimate (contains "cast")
            if "cast" not in result.stdout.lower() and "foundry" not in result.stdout.lower():
                continue
            # Resolve to absolute path to prevent PATH hijacking
            import shutil
            resolved = shutil.which(candidate)
            if resolved:
                return os.path.realpath(resolved)
            return candidate
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
    raise RuntimeError("cast not found. Install Foundry: https://book.getfoundry.sh")


def _cast_send(
    cast_bin: str,
    contract: str,
    sig: str,
    args: list[str],
    rpc_url: str,
    private_key: str,
) -> str:
    """Execute a cast send transaction.

    SECURITY: The private key is passed via environment variable (not CLI arg)
    to prevent exposure in ``ps aux`` or ``/proc/*/cmdline``.
    ``cast`` reads ``ETH_PRIVATE_KEY`` from the environment natively.
    """
    cmd = [
        cast_bin, "send",
        contract, sig, *args,
        "--rpc-url", rpc_url,
    ]
    from validator.utils.retry import retry_subprocess
    result = retry_subprocess(
        cmd, max_retries=3, timeout=60,
        env={**os.environ, "ETH_PRIVATE_KEY": private_key},
    )
    if result.returncode != 0:
        raise RuntimeError(f"cast send failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _cast_call(
    cast_bin: str,
    contract: str,
    sig: str,
    args: list[str],
    rpc_url: str,
) -> str:
    """Execute a cast call (read-only)."""
    cmd = [
        cast_bin, "call",
        contract, sig, *args,
        "--rpc-url", rpc_url,
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cast call failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _wallet_address(cast_bin: str, private_key: str) -> str:
    """Get the address corresponding to a private key.

    Uses ``cast wallet address --private-key`` via stdin to avoid
    exposing the key in the process argument list.
    """
    proc = subprocess.Popen(
        [cast_bin, "wallet", "address", "--private-key-stdin"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate(input=private_key, timeout=10)
    if proc.returncode != 0:
        raise RuntimeError(
            f"cast wallet address failed: {stderr.strip()}. "
            "Requires cast version with --private-key-stdin support."
        )
    address = stdout.strip()
    # Validate output looks like an Ethereum address
    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        raise RuntimeError(f"cast wallet address returned invalid address: {address[:20]}")
    return address


# ── Key Rotation Operations ─────────────────────────────────────────────────

def rotate_validator(
    contract: str,
    rpc_url: str,
    owner_key: str,
    old_validator: str,
    new_validator: str,
) -> dict:
    """
    Rotate a validator address on ProtocolRegistry or ExploitRegistry.

    Steps:
      1. Verify caller is contract owner
      2. Add new validator via setValidator(new, true)
      3. Remove old validator via setValidator(old, false)
      4. Verify the swap

    Returns dict with result details.
    """
    cast_bin = _find_cast()
    owner_addr = _wallet_address(cast_bin, owner_key)

    logger.info("Rotating validator on %s", contract[:20])
    logger.info("  Owner:          %s", owner_addr)
    logger.info("  Old validator:  %s", old_validator)
    logger.info("  New validator:  %s", new_validator)

    # Verify owner
    on_chain_owner = _cast_call(cast_bin, contract, "owner()(address)", [], rpc_url)
    if on_chain_owner.lower() != owner_addr.lower():
        raise PermissionError(
            f"Caller {owner_addr} is not the contract owner ({on_chain_owner})"
        )

    # Check old validator is actually a validator
    is_old = _cast_call(cast_bin, contract, "validators(address)(bool)", [old_validator], rpc_url)
    if is_old != "true":
        logger.warning("Old address %s is not currently a validator!", old_validator)

    # Step 1: Add new validator
    logger.info("  [1/2] Adding new validator...")
    _cast_send(
        cast_bin, contract,
        "setValidator(address,bool)", [new_validator, "true"],
        rpc_url, owner_key,
    )

    # Verify new validator was added
    is_new = _cast_call(cast_bin, contract, "validators(address)(bool)", [new_validator], rpc_url)
    if is_new != "true":
        raise RuntimeError("Failed to add new validator!")

    # Step 2: Remove old validator
    logger.info("  [2/2] Removing old validator...")
    _cast_send(
        cast_bin, contract,
        "setValidator(address,bool)", [old_validator, "false"],
        rpc_url, owner_key,
    )

    # Verify removal
    is_old_after = _cast_call(
        cast_bin, contract, "validators(address)(bool)", [old_validator], rpc_url
    )
    if is_old_after == "true":
        raise RuntimeError("Failed to remove old validator!")

    logger.info("  Validator rotation complete.")
    return {
        "action": "rotate-validator",
        "contract": contract,
        "old_validator": old_validator,
        "new_validator": new_validator,
        "success": True,
    }


def transfer_ownership(
    contract: str,
    rpc_url: str,
    current_owner_key: str,
    new_owner_key: str,
) -> dict:
    """
    Transfer contract ownership using 2-step Ownable2Step pattern.

    Steps:
      1. Current owner calls transferOwnership(newOwner)
      2. New owner calls acceptOwnership()
      3. Verify ownership transferred

    Returns dict with result details.
    """
    cast_bin = _find_cast()
    current_addr = _wallet_address(cast_bin, current_owner_key)
    new_addr = _wallet_address(cast_bin, new_owner_key)

    logger.info("Transferring ownership of %s", contract[:20])
    logger.info("  Current owner: %s", current_addr)
    logger.info("  New owner:     %s", new_addr)

    # Verify current owner
    on_chain_owner = _cast_call(cast_bin, contract, "owner()(address)", [], rpc_url)
    if on_chain_owner.lower() != current_addr.lower():
        raise PermissionError(
            f"Caller {current_addr} is not the contract owner ({on_chain_owner})"
        )

    # Step 1: Initiate transfer
    logger.info("  [1/2] Initiating ownership transfer...")
    _cast_send(
        cast_bin, contract,
        "transferOwnership(address)", [new_addr],
        rpc_url, current_owner_key,
    )

    # Verify pending owner is set
    pending = _cast_call(cast_bin, contract, "pendingOwner()(address)", [], rpc_url)
    if pending.lower() != new_addr.lower():
        raise RuntimeError(f"pendingOwner mismatch: expected {new_addr}, got {pending}")

    # Step 2: Accept transfer (as new owner)
    logger.info("  [2/2] Accepting ownership...")
    _cast_send(
        cast_bin, contract,
        "acceptOwnership()", [],
        rpc_url, new_owner_key,
    )

    # Verify
    final_owner = _cast_call(cast_bin, contract, "owner()(address)", [], rpc_url)
    if final_owner.lower() != new_addr.lower():
        raise RuntimeError(f"Ownership transfer failed! Owner is {final_owner}")

    logger.info("  Ownership transfer complete.")
    return {
        "action": "transfer-ownership",
        "contract": contract,
        "old_owner": current_addr,
        "new_owner": new_addr,
        "success": True,
    }


def batch_rotate_validators(
    contracts: list[str],
    rpc_url: str,
    owner_key: str,
    old_validator: str,
    new_validator: str,
) -> list[dict]:
    """Rotate a validator across multiple contracts at once."""
    results = []
    for contract in contracts:
        try:
            r = rotate_validator(contract, rpc_url, owner_key, old_validator, new_validator)
            results.append(r)
        except Exception as e:
            logger.error("Failed to rotate on %s: %s", contract[:20], e)
            results.append({
                "action": "rotate-validator",
                "contract": contract,
                "success": False,
                "error": str(e),
            })
    return results


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Validator Key Rotation Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Rotate validator on ProtocolRegistry
  python -m validator.utils.key_rotation \\
      --action rotate-validator \\
      --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 \\
      --rpc-url http://127.0.0.1:8545 \\
      --old-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \\
      --new-address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

  # Transfer ownership via 2-step pattern
  python -m validator.utils.key_rotation \\
      --action transfer-ownership \\
      --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 \\
      --rpc-url http://127.0.0.1:8545 \\
      --old-key 0xac0974...OLD_KEY \\
      --new-key 0x59c697...NEW_KEY
""",
    )
    parser.add_argument("--action", required=True,
                        choices=["rotate-validator", "transfer-ownership"],
                        help="Action to perform")
    parser.add_argument("--contract", required=True,
                        help="Contract address (or comma-separated for batch)")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545",
                        help="JSON-RPC endpoint")
    parser.add_argument("--old-key", required=True,
                        help="Private key of current owner / old validator")
    parser.add_argument("--new-address", default="",
                        help="New validator address (for rotate-validator)")
    parser.add_argument("--new-key", default="",
                        help="New owner private key (for transfer-ownership)")
    parser.add_argument("--old-validator", default="",
                        help="Old validator address to remove (defaults to old-key address)")

    args = parser.parse_args()

    if args.action == "rotate-validator":
        if not args.new_address:
            parser.error("--new-address required for rotate-validator")

        old_validator = args.old_validator
        if not old_validator:
            cast_bin = _find_cast()
            old_validator = _wallet_address(cast_bin, args.old_key)

        contracts = [c.strip() for c in args.contract.split(",")]
        if len(contracts) == 1:
            result = rotate_validator(
                contracts[0], args.rpc_url, args.old_key,
                old_validator, args.new_address,
            )
            print(json.dumps(result, indent=2))
        else:
            results = batch_rotate_validators(
                contracts, args.rpc_url, args.old_key,
                old_validator, args.new_address,
            )
            print(json.dumps(results, indent=2))

    elif args.action == "transfer-ownership":
        if not args.new_key:
            parser.error("--new-key required for transfer-ownership")

        contracts = [c.strip() for c in args.contract.split(",")]
        for contract in contracts:
            result = transfer_ownership(
                contract, args.rpc_url, args.old_key, args.new_key,
            )
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
