"""
Unified Secrets Manager — Centralised loading and validation of all secrets.

All environment-based secrets are loaded once at import time through
``get_secret()``.  This avoids scattered ``os.environ.get()`` calls,
provides fail-fast validation, and logs which secrets are configured
(without leaking values).

Usage::

    from validator.utils.secrets import get_secret

    hmac_key = get_secret("VALAYR_RECEIPT_HMAC_KEY")          # required by default
    etherscan = get_secret("ETHERSCAN_API_KEY", required=False)  # optional
"""

import logging
import os
import re
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ── Registry of known secrets with validation rules ──────────────────────────

_SECRET_SPECS: dict[str, dict] = {
    "VALAYR_RECEIPT_HMAC_KEY": {
        "min_length": 32,
        # SEC-1.6: require hex-encoded key to guarantee sufficient entropy.
        # Low-entropy values like "0" * 32 are rejected by the pattern check.
        "pattern": r"^[0-9a-fA-F]{64,}$",
        "description": "HMAC key for subnet receipt integrity (hex-encoded, >= 32 bytes)",
    },
    "IMMUNEFI_API_KEY": {
        "min_length": 1,
        "description": "Immunefi bug-bounty platform API key",
    },
    "CODE4RENA_API_KEY": {
        "min_length": 1,
        "description": "Code4rena bug-bounty platform API key",
    },
    "ETHERSCAN_API_KEY": {
        "min_length": 1,
        "description": "Etherscan/block-explorer API key",
    },
    "DEPLOYER_KEY": {
        "min_length": 64,
        "pattern": r"^0x[0-9a-fA-F]{64}$",
        "description": "Private key for contract deployment/ownership",
    },
}

_cache: dict[str, str] = {}
_cache_lock = threading.Lock()


def get_secret(
    name: str,
    *,
    required: bool = True,
    min_length: Optional[int] = None,
) -> str:
    """Return the value of a secret from the environment.

    Parameters
    ----------
    name:
        Environment variable name.
    required:
        If *True* (default), raise ``RuntimeError`` when the variable
        is missing or empty.  If *False*, return ``""`` instead.
    min_length:
        Override the minimum-length check from the spec registry.

    Raises
    ------
    RuntimeError
        If a *required* secret is missing, empty, or fails validation.
    """
    with _cache_lock:
        if name in _cache:
            return _cache[name]

    value = os.environ.get(name, "").strip()

    spec = _SECRET_SPECS.get(name, {})
    effective_min = min_length if min_length is not None else spec.get("min_length", 1)
    pattern = spec.get("pattern")

    if not value:
        if required:
            desc = spec.get("description", name)
            raise RuntimeError(
                f"Required secret {name} ({desc}) is not set. "
                f"Set it via environment variable or .env file."
            )
        return ""

    if len(value) < effective_min:
        if required:
            raise RuntimeError(
                f"Secret {name} is too short (got {len(value)}, need >= {effective_min})."
            )
        logger.warning("Secret %s is shorter than recommended (%d < %d)", name, len(value), effective_min)

    if pattern and not re.match(pattern, value):
        if required:
            raise RuntimeError(f"Secret {name} does not match expected format.")
        logger.warning("Secret %s does not match expected format", name)

    with _cache_lock:
        _cache[name] = value
    return value


def log_secret_status() -> None:
    """Log which secrets are configured (values are never logged)."""
    for name, spec in _SECRET_SPECS.items():
        value = os.environ.get(name, "")
        status = "SET" if value else "NOT SET"
        logger.info("  %-30s %s  (%s)", name, status, spec.get("description", ""))


def clear_cache() -> None:
    """Clear cached secret values (useful for testing)."""
    _cache.clear()


def validate_environment(required_secrets: Optional[list[str]] = None) -> list[str]:
    """Validate that all required secrets are present and correctly formatted.

    Parameters
    ----------
    required_secrets:
        List of secret names to check.  Defaults to all known secrets.

    Returns
    -------
    list[str]
        List of error messages (empty if all OK).
    """
    errors: list[str] = []
    names = required_secrets or list(_SECRET_SPECS.keys())

    for name in names:
        value = os.environ.get(name, "").strip()
        spec = _SECRET_SPECS.get(name, {})

        if not value:
            errors.append(f"{name}: not set ({spec.get('description', '')})")
            continue

        min_len = spec.get("min_length", 1)
        if len(value) < min_len:
            errors.append(f"{name}: too short ({len(value)} < {min_len})")

        pattern = spec.get("pattern")
        if pattern and not re.match(pattern, value):
            errors.append(f"{name}: invalid format")

    return errors
