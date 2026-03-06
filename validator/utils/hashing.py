"""
Shared keccak256 utility — Ethereum-compatible hashing.

Provides a single `keccak256()` function used throughout the project.
Uses pycryptodome (primary) or `cast keccak` CLI (fallback).

IMPORTANT: Python's `hashlib.sha3_256` is NIST SHA-3, which is
NOT the same as Ethereum's keccak256. This module ensures all
hashes match Solidity's `keccak256()` exactly.
"""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)

# Cached backend function set by _validate_backend()
_backend_fn = None

# Known test vector: keccak256(b"hello")
_KNOWN_HELLO_HASH = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"


def keccak256(data: bytes) -> str:
    """Compute Ethereum keccak256 and return as 0x-prefixed 64-char hex string.

    >>> keccak256(b"hello")
    '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
    """
    if _backend_fn is not None:
        return _backend_fn(data)
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


def _validate_backend() -> None:
    """Verify the active keccak256 backend produces correct results."""
    global _backend_fn
    result = keccak256(b"hello")
    if result != _KNOWN_HELLO_HASH:
        raise RuntimeError(
            f"keccak256 backend produces incorrect hash for b'hello': "
            f"got {result}, expected {_KNOWN_HELLO_HASH}"
        )
    # Cache the working backend to avoid repeated import/subprocess attempts
    try:
        from Crypto.Hash import keccak as _keccak  # noqa: F401
        def _pycryptodome_keccak(data: bytes) -> str:
            k = _keccak.new(digest_bits=256)
            k.update(data)
            return "0x" + k.hexdigest()
        _backend_fn = _pycryptodome_keccak
        logger.info("keccak256 backend: pycryptodome (preferred)")
    except ImportError:
        logger.info("keccak256 backend: cast CLI (fallback)")


_validate_backend()
