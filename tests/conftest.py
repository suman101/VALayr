"""Shared pytest fixtures for exploit subnet tests."""

import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Ensure Foundry tools are on PATH
FOUNDRY_BIN = Path.home() / ".foundry" / "bin"
if FOUNDRY_BIN.exists():
    os.environ["PATH"] = str(FOUNDRY_BIN) + ":" + os.environ.get("PATH", "")

# ── Module aliases for hyphenated directories ────────────────────────────────
# These allow `from task_generator_module import ...` across all test files
# when the real directories are task-generator/ and subnet-adapter/.

import importlib.util

def _ensure_module_alias(alias: str, file_path: Path) -> None:
    """Register a module alias if not already present."""
    if alias in sys.modules:
        return
    if not file_path.exists():
        return
    spec = importlib.util.spec_from_file_location(alias, str(file_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.modules[alias] = mod

_ensure_module_alias(
    "task_generator_module",
    PROJECT_ROOT / "task-generator" / "generate.py",
)
_ensure_module_alias(
    "subnet_adapter_module",
    PROJECT_ROOT / "subnet-adapter" / "incentive.py",
)


# ── Anvil fixture ────────────────────────────────────────────────────────────

def _foundry_available() -> bool:
    """Check if Foundry (anvil) is installed."""
    import shutil
    return shutil.which("anvil") is not None


@pytest.fixture(scope="session")
def anvil():
    """Provide a running AnvilInstance for the entire test session.

    Skips all tests that require this fixture if Foundry is not installed.
    """
    if not _foundry_available():
        pytest.skip("Foundry (anvil) not installed — skipping live tests")

    # Import AnvilInstance here to avoid import errors in environments
    # without Foundry / the validator module (it imports ANVIL_CONFIG).
    from tests.test_live_anvil import AnvilInstance, ANVIL_PORT

    instance = AnvilInstance(port=ANVIL_PORT)
    if not instance.start():
        pytest.skip("Anvil failed to start")

    yield instance

    instance.stop()
