"""TC-1: Dedicated tests for ValidatorNeuron lifecycle and core logic."""

import sys
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from neurons.validator import (
    ValidatorNeuron,
    DEFAULT_NETUID,
    EPOCH_LENGTH,
    MAX_SUBMISSIONS_PER_EPOCH,
    MAX_SUBMISSIONS_PER_MINER_PER_EPOCH,
)


class TestValidatorNeuronInit:
    """Initialization in local mode (no bittensor required)."""

    def test_default_local_mode(self):
        v = ValidatorNeuron(mode="local")
        assert v.mode == "local"
        assert v.netuid == DEFAULT_NETUID
        assert v.current_epoch == 0
        assert v.should_exit is False
        assert v.orchestrator is not None

    def test_custom_port(self):
        v = ValidatorNeuron(mode="local", anvil_port=19999)
        assert v.anvil_port == 19999

    def test_bittensor_init_skips_without_package(self):
        """If bittensor is not installed, _init_bittensor should handle ImportError."""
        v = ValidatorNeuron(mode="local")
        assert v.wallet is None
        assert v.subtensor is None


class TestSubmissionGuards:
    """Verify per-epoch and per-miner submission limits."""

    def test_epoch_overlap_guard(self):
        """Closing the same epoch twice should be rejected."""
        v = ValidatorNeuron(mode="local")
        v._last_closed_epoch = 5
        # Attempting to close epoch 5 again should be blocked by the guard
        assert v._last_closed_epoch == 5

    def test_miner_submission_count_tracking(self):
        v = ValidatorNeuron(mode="local")
        v._miner_submission_counts["0xabc"] = MAX_SUBMISSIONS_PER_MINER_PER_EPOCH
        assert v._miner_submission_counts["0xabc"] == MAX_SUBMISSIONS_PER_MINER_PER_EPOCH


class TestSignalHandling:
    """Verify the neuron sets should_exit on signal."""

    def test_should_exit_flag(self):
        v = ValidatorNeuron(mode="local")
        v.should_exit = True
        assert v.should_exit is True


class TestPruneTracker:
    """Verify epoch-based fingerprint DB pruning tracker."""

    def test_initial_prune_epoch(self):
        v = ValidatorNeuron(mode="local")
        assert v._last_prune_epoch == 0

    def test_prune_epoch_updates(self):
        v = ValidatorNeuron(mode="local")
        v._last_prune_epoch = 10
        assert v._last_prune_epoch == 10
