"""
Structured Logging — Unified logging for the Exploit Subnet.

All modules should import `get_logger(__name__)` instead of using print().
This provides:
  - Consistent format across all components
  - Log-level filtering (DEBUG/INFO/WARNING/ERROR/CRITICAL)
  - Structured fields for machine parsability
  - File + console output in production
  - Easy switch to JSON output for log aggregators

Usage:
    from validator.utils.logging import get_logger
    logger = get_logger(__name__)

    logger.info("Validating exploit", extra={"task_id": task_id[:16]})
    logger.warning("Compilation failed", extra={"workspace": str(ws)})
    logger.error("Anvil unreachable", exc_info=True)
"""

import logging
import os
import sys
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

_DEFAULT_LEVEL = os.environ.get("EXPLOIT_LOG_LEVEL", "INFO").upper()
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Optional file log (set EXPLOIT_LOG_FILE=/path/to/file.log)
_LOG_FILE = os.environ.get("EXPLOIT_LOG_FILE", "")

# ── Root Logger Setup ────────────────────────────────────────────────────────

_root_configured = False


def _configure_root():
    """Configure the root 'exploit_subnet' logger once."""
    global _root_configured
    if _root_configured:
        return

    root = logging.getLogger("exploit_subnet")
    root.setLevel(getattr(logging, _DEFAULT_LEVEL, logging.INFO))

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG)
    console.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT))
    root.addHandler(console)

    # File handler (optional) — rotating to prevent unbounded growth
    if _LOG_FILE:
        from logging.handlers import RotatingFileHandler
        log_path = Path(_LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            str(log_path), maxBytes=50_000_000, backupCount=5,
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT))
        root.addHandler(fh)

    # Prevent propagation to Python root logger (avoids duplicate output)
    root.propagate = False
    _root_configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger under the 'exploit_subnet' hierarchy.

    Args:
        name: Module name, typically ``__name__``.

    Returns:
        A configured :class:`logging.Logger`.

    Examples:
        >>> logger = get_logger("validator.engine.validate")
        >>> logger.info("Anvil started on port %d", 18545)
    """
    _configure_root()
    # Nest all loggers under "exploit_subnet" for unified control
    return logging.getLogger(f"exploit_subnet.{name}")
