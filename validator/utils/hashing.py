"""
Shared keccak256 utility — Ethereum-compatible hashing.

Provides a single `keccak256()` function used throughout the project.
Uses pycryptodome (primary) or `cast keccak` CLI (fallback).

IMPORTANT: Python's `hashlib.sha3_256` is NIST SHA-3, which is
NOT the same as Ethereum's keccak256. This module ensures all
hashes match Solidity's `keccak256()` exactly.
"""

from __future__ import annotations

import subprocess


def keccak256(data: bytes) -> str:
    """Compute Ethereum keccak256 and return as 0x-prefixed 64-char hex string.

    >>> keccak256(b"hello")
    '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
    """
    # Primary: pycryptodome (fast, no subprocess)
    try:
        from Crypto.Hash import keccak as _keccak

        k = _keccak.new(digest_bits=256)
        k.update(data)
        return "0x" + k.hexdigest()
    except ImportError:
        pass

    # Fallback: Foundry's `cast keccak` CLI
    try:
        result = subprocess.run(
            ["cast", "keccak", "0x" + data.hex()],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip().startswith("0x"):
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    raise RuntimeError(
        "Cannot compute Ethereum keccak256: install pycryptodome "
        "(pip install pycryptodome) or ensure `cast` is on PATH"
    )
