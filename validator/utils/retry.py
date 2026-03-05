"""
Retry utility for subprocess calls with exponential backoff.

Usage:
    from validator.utils.retry import retry_subprocess
    result = retry_subprocess(["cast", "send", ...], max_retries=3)
"""

from __future__ import annotations

import logging
import subprocess
import time

logger = logging.getLogger(__name__)


def retry_subprocess(
    cmd: list[str],
    *,
    max_retries: int = 3,
    backoff_base: float = 2.0,
    timeout: int = 30,
    capture_output: bool = True,
    text: bool = True,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a subprocess with retry and exponential backoff.

    Retries on non-zero exit codes or timeouts. Raises on final failure.
    """
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                **kwargs,
            )
            if result.returncode == 0:
                return result

            last_exc = RuntimeError(
                f"Command failed (exit {result.returncode}): {result.stderr}"
            )
        except subprocess.TimeoutExpired as e:
            last_exc = e
        except FileNotFoundError:
            raise  # Fail fast — executable not found, retrying won't help
        except OSError as e:
            last_exc = e

        if attempt < max_retries - 1:
            delay = backoff_base ** attempt
            logger.warning(
                "Subprocess %s failed (attempt %d/%d), retrying in %.1fs: %s",
                cmd[0],
                attempt + 1,
                max_retries,
                delay,
                last_exc,
            )
            time.sleep(delay)

    raise last_exc  # type: ignore[misc]
