"""
Difficulty Ramping — Progresses challenge difficulty over subnet lifetime.

Schedule:
  - Epoch  1-50:    difficulty 1 (base templates, low bar)
  - Epoch  51-200:  difficulty 2 (heavy mutations, invariant specs)
  - Epoch  201+:    difficulty 3 (max mutations, mainnet contracts mandatory)

Also controls the mainnet task ratio:
  - Epoch  1-50:    0% mainnet  (pure synthetic)
  - Epoch  51-200:  30% mainnet
  - Epoch  201+:    60% mainnet

All thresholds are configurable via environment variables.
"""

import os


# ── Configurable Thresholds ──────────────────────────────────────────────────

EPOCH_DIFFICULTY_2 = int(os.environ.get("VALAYR_EPOCH_DIFFICULTY_2", "51"))
EPOCH_DIFFICULTY_3 = int(os.environ.get("VALAYR_EPOCH_DIFFICULTY_3", "201"))

MAINNET_RATIO_PHASE_1 = float(os.environ.get("VALAYR_MAINNET_RATIO_1", "0.0"))
MAINNET_RATIO_PHASE_2 = float(os.environ.get("VALAYR_MAINNET_RATIO_2", "0.3"))
MAINNET_RATIO_PHASE_3 = float(os.environ.get("VALAYR_MAINNET_RATIO_3", "0.6"))

# Minimum severity to earn rewards at each difficulty level
MIN_SEVERITY_PHASE_1 = float(os.environ.get("VALAYR_MIN_SEVERITY_1", "0.0"))
MIN_SEVERITY_PHASE_2 = float(os.environ.get("VALAYR_MIN_SEVERITY_2", "0.1"))
MIN_SEVERITY_PHASE_3 = float(os.environ.get("VALAYR_MIN_SEVERITY_3", "0.2"))


def get_max_difficulty(epoch: int) -> int:
    """Return the maximum difficulty level for a given epoch."""
    if epoch >= EPOCH_DIFFICULTY_3:
        return 3
    if epoch >= EPOCH_DIFFICULTY_2:
        return 2
    return 1


def get_mainnet_ratio(epoch: int) -> float:
    """Return the target mainnet task ratio for a given epoch."""
    if epoch >= EPOCH_DIFFICULTY_3:
        return MAINNET_RATIO_PHASE_3
    if epoch >= EPOCH_DIFFICULTY_2:
        return MAINNET_RATIO_PHASE_2
    return MAINNET_RATIO_PHASE_1


def get_min_severity(epoch: int) -> float:
    """Return the minimum severity threshold for reward eligibility."""
    if epoch >= EPOCH_DIFFICULTY_3:
        return MIN_SEVERITY_PHASE_3
    if epoch >= EPOCH_DIFFICULTY_2:
        return MIN_SEVERITY_PHASE_2
    return MIN_SEVERITY_PHASE_1


def get_epoch_config(epoch: int) -> dict:
    """Return full epoch configuration as a dict."""
    return {
        "epoch": epoch,
        "max_difficulty": get_max_difficulty(epoch),
        "mainnet_ratio": get_mainnet_ratio(epoch),
        "min_severity": get_min_severity(epoch),
    }
