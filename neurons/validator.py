"""
Bittensor Validator Neuron — Bridge between Bittensor network and exploit subnet.

This module wraps the Orchestrator with Bittensor's metagraph,
subtensor, and incentive mechanism. It runs the validation loop:

  1. Sync metagraph → know which miners are registered
  2. Generate/publish task corpus each epoch
  3. Receive exploit submissions from miners
  4. Validate → Fingerprint → Score → Commit weights
  5. Set weights on-chain via subtensor.set_weights()

Usage:
  # With Bittensor installed:
  python neurons/validator.py --netuid <NETUID> --wallet.name <WALLET> --wallet.hotkey <HOTKEY>

  # Local simulation (no Bittensor dependency):
  python neurons/validator.py --local
"""

import argparse
import json
import os
import signal
import sys
import time
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.utils.logging import get_logger

logger = get_logger(__name__)

from orchestrator import Orchestrator, SubmissionResult
from neurons.protocol import ExploitSubmissionSynapse, ExploitQuerySynapse
from validator.utils.schemas import validate_submission, ValidationError

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_NETUID = 1  # Set to actual netuid when registered on Bittensor
EPOCH_LENGTH = 360  # Blocks per epoch (~60 minutes at ~10s/block)
TASK_REFRESH_EPOCHS = 6  # Refresh task corpus every N epochs
WEIGHT_SET_INTERVAL = 100  # Blocks between weight sets
MAX_SUBMISSIONS_PER_EPOCH = 1000
MAX_SUBMISSIONS_PER_MINER_PER_EPOCH = 50  # Per-miner cap to prevent one miner starving others
HANDLER_TIMEOUT = 300  # Max seconds for a single submission handler before timeout


# ── Validator Neuron ─────────────────────────────────────────────────────────

class ValidatorNeuron:
    """
    Bittensor validator neuron for the exploit discovery subnet.

    Modes:
      - 'bittensor': Full integration with Bittensor network (requires bittensor package)
      - 'local':     Standalone mode for development and testing
    """

    def __init__(
        self,
        mode: str = "local",
        netuid: int = DEFAULT_NETUID,
        wallet_name: str = "default",
        wallet_hotkey: str = "default",
        subtensor_network: str = "test",
        anvil_port: int = 18545,
    ):
        self.mode = mode
        self.netuid = netuid
        self.anvil_port = anvil_port
        self.current_epoch = 0
        self.current_block = 0
        self.epoch_start_block = 0
        self.should_exit = False
        self._submission_lock = threading.Lock()
        self.submissions_this_epoch: list[SubmissionResult] = []
        self._miner_submission_counts: dict[str, int] = {}  # hotkey → count
        self._last_closed_epoch: int = -1  # Epoch overlap guard
        self._last_prune_epoch: int = 0  # Fingerprint DB pruning tracker
        self._rotation_config = Path("data/pending_rotation.json")

        # Initialize orchestrator
        self.orchestrator = Orchestrator(
            mode="docker" if mode == "bittensor" else "local",
            validator_id=f"validator-{wallet_hotkey[:8]}",
            anvil_port=anvil_port,
        )

        # Bittensor integration (lazy-loaded)
        self.wallet = None
        self.subtensor = None
        self.metagraph = None
        self.dendrite = None
        self.axon = None

        if mode == "bittensor":
            self._init_bittensor(wallet_name, wallet_hotkey, subtensor_network)

    def _init_bittensor(self, wallet_name: str, hotkey: str, network: str):
        """Initialize Bittensor components."""
        try:
            import bittensor as bt

            self.wallet = bt.wallet(name=wallet_name, hotkey=hotkey)
            self.subtensor = bt.subtensor(network=network)
            self.metagraph = self.subtensor.metagraph(self.netuid)
            self.dendrite = bt.dendrite(wallet=self.wallet)

            # Set up axon to receive submissions
            self.axon = bt.axon(wallet=self.wallet)
            self.axon.attach(
                forward_fn=self._handle_submission,
                blacklist_fn=self._blacklist_check,
                synapse_type=ExploitSubmissionSynapse,
            )
            self.axon.serve(netuid=self.netuid, subtensor=self.subtensor)
            self.axon.start()

            logger.info("Bittensor validator initialized")
            logger.info("  Network: %s", network)
            logger.info("  Netuid:  %d", self.netuid)
            logger.info("  Hotkey:  %s", self.wallet.hotkey.ss58_address)
            logger.info("  UID:     %d", self.metagraph.hotkeys.index(self.wallet.hotkey.ss58_address))

        except ImportError:
            logger.warning("bittensor package not installed — pip install bittensor")
            logger.warning("Falling back to local mode.")
            self.mode = "local"
        except Exception as e:
            logger.error("Bittensor init failed: %s", e, exc_info=True)
            logger.warning("Falling back to local mode.")
            self.mode = "local"

    # ── Main Loop ─────────────────────────────────────────────────────────

    def run(self) -> None:
        """Main validator loop."""
        logger.info("Exploit Subnet Validator — %s mode", self.mode.upper())

        # Generate initial task corpus
        self.orchestrator.generate_corpus(count_per_class=2, seed=42)

        if self.mode == "local":
            self._run_local()
        else:
            self._run_bittensor()

    def _run_local(self):
        """Local mode: single epoch simulation."""
        logger.info("Running local simulation...")
        logger.info("Waiting for submissions (Ctrl+C to end epoch)...")

        try:
            # Simulate a few epochs
            for epoch in range(3):
                self.current_epoch = epoch
                self.epoch_start_block = epoch * EPOCH_LENGTH
                self.submissions_this_epoch = []

                logger.info("Epoch %d (blocks %d-%d)",
                            epoch, self.epoch_start_block,
                            self.epoch_start_block + EPOCH_LENGTH)

                # In local mode, there are no live miners to receive from
                # The orchestrator's process_submission is called directly via CLI

                # Close epoch and compute weights
                time.sleep(0.1)  # Simulate block time
                epoch_result = self.orchestrator.close_epoch(
                    epoch_number=epoch,
                    start_block=self.epoch_start_block,
                    end_block=self.epoch_start_block + EPOCH_LENGTH,
                )

                if epoch_result.weights:
                    logger.info("Set weights: %d miners", len(epoch_result.weights))
                else:
                    logger.info("No weights to set (no valid submissions)")

        except KeyboardInterrupt:
            logger.info("Validator stopped.")

    def _run_bittensor(self):
        """Bittensor mode: continuous validation loop."""
        import bittensor as bt

        logger.info("Starting Bittensor validation loop...")

        last_weight_block = 0
        last_refresh_epoch = 0
        consecutive_errors = 0
        MAX_BACKOFF = 300  # 5 minutes cap

        while not self.should_exit:
            try:
                # Sync metagraph
                self.metagraph.sync(subtensor=self.subtensor)
                self.current_block = self.subtensor.get_current_block()
                new_epoch = self.current_block // EPOCH_LENGTH

                # Epoch transition
                if new_epoch > self.current_epoch:
                    self._close_current_epoch()
                    self.current_epoch = new_epoch
                    self.epoch_start_block = new_epoch * EPOCH_LENGTH
                    with self._submission_lock:
                        self.submissions_this_epoch = []
                        self._miner_submission_counts = {}

                    # Refresh corpus periodically
                    if new_epoch - last_refresh_epoch >= TASK_REFRESH_EPOCHS:
                        self.orchestrator.generate_corpus(
                            count_per_class=2,
                            seed=new_epoch,
                        )
                        last_refresh_epoch = new_epoch

                    # Prune stale fingerprints every 24 epochs (~1 day)
                    PRUNE_INTERVAL_EPOCHS = 24
                    if new_epoch - self._last_prune_epoch >= PRUNE_INTERVAL_EPOCHS:
                        pruned = self.orchestrator.fingerprinter.prune()
                        if pruned > 0:
                            logger.info("Pruned %d stale fingerprint records", pruned)
                        self._last_prune_epoch = new_epoch

                    # Check for pending key rotation
                    self._check_key_rotation()

                # Set weights periodically
                if self.current_block - last_weight_block >= WEIGHT_SET_INTERVAL:
                    self._set_weights()
                    last_weight_block = self.current_block

                # Reset backoff on success
                consecutive_errors = 0

                time.sleep(12)  # ~1 block

            except KeyboardInterrupt:
                logger.info("Validator shutting down...")
                self._close_current_epoch()
                break
            except Exception as e:
                consecutive_errors += 1
                backoff = min(30 * (2 ** (consecutive_errors - 1)), MAX_BACKOFF)
                logger.error(
                    "Error in validator loop (attempt %d, backoff %ds): %s",
                    consecutive_errors, backoff, e, exc_info=True,
                )
                time.sleep(backoff)

        logger.info("Validator exited main loop.")

    # ── Submission Handling ───────────────────────────────────────────────

    def _handle_submission(self, synapse: ExploitSubmissionSynapse) -> ExploitSubmissionSynapse:
        """
        Handle an incoming exploit submission from a miner.

        Called via Bittensor axon when a miner sends a submission.
        Supports two flows:
          1. Direct submission: validate and score immediately
        """
        if len(self.submissions_this_epoch) >= MAX_SUBMISSIONS_PER_EPOCH:
            synapse.result = {"error": "Epoch submission limit reached"}
            return synapse

        try:
            task_id = synapse.task_id
            exploit_source = synapse.exploit_source
            miner_hotkey = synapse.dendrite.hotkey

            # Schema validation at system boundary
            try:
                validate_submission({
                    "task_id": task_id,
                    "exploit_source": exploit_source,
                })
            except ValidationError as ve:
                synapse.result = {"error": f"Invalid submission format: {ve.message}"}
                return synapse

            # Per-miner rate limiting + epoch-level cap (both under lock)
            with self._submission_lock:
                if len(self.submissions_this_epoch) >= MAX_SUBMISSIONS_PER_EPOCH:
                    synapse.result = {"error": "Epoch submission limit reached"}
                    return synapse
                miner_count = self._miner_submission_counts.get(miner_hotkey, 0)
                if miner_count >= MAX_SUBMISSIONS_PER_MINER_PER_EPOCH:
                    synapse.result = {"error": "Per-miner epoch submission limit reached"}
                    return synapse
                # Increment count atomically with check to prevent race condition
                self._miner_submission_counts[miner_hotkey] = miner_count + 1

            # Run validation with a hard timeout to prevent DoS from slow/malicious exploits
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.orchestrator.process_submission,
                    task_id=task_id,
                    exploit_source=exploit_source,
                    miner_address=miner_hotkey,
                    entry_functions=getattr(synapse, "entry_functions", None) or [],
                )
                try:
                    result = future.result(timeout=HANDLER_TIMEOUT)
                except FutureTimeout:
                    synapse.result = {"error": f"Validation timed out ({HANDLER_TIMEOUT}s)"}
                    logger.warning("Submission handler timed out for miner %s", miner_hotkey[:16])
                    return synapse

            with self._submission_lock:
                self.submissions_this_epoch.append(result)

            synapse.result = result.to_dict()
            return synapse

        except (OSError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            logger.error("Error in submission handler: %s", e, exc_info=True)
            synapse.result = {"error": "Validation error"}
            return synapse
        except Exception as e:  # pragma: no cover — safety net
            logger.exception("Unexpected error in submission handler")
            synapse.result = {"error": "Internal error"}
            return synapse

    def _blacklist_check(self, synapse: ExploitSubmissionSynapse) -> tuple[bool, str]:
        """Check if a miner is blacklisted (not registered on subnet)."""
        if self.mode != "bittensor" or self.metagraph is None:
            return False, ""

        hotkey = synapse.dendrite.hotkey
        if hotkey not in self.metagraph.hotkeys:
            return True, f"Hotkey {hotkey[:16]}... not registered on subnet {self.netuid}"
        return False, ""

    # ── Epoch Management ─────────────────────────────────────────────────

    def _close_current_epoch(self):
        """Close the current epoch and compute weights."""
        if self.current_epoch < self._last_closed_epoch:
            logger.warning(
                "Epoch %d already closed (last=%d) — skipping",
                self.current_epoch, self._last_closed_epoch,
            )
            return None
        self._last_closed_epoch = self.current_epoch
        epoch_result = self.orchestrator.close_epoch(
            epoch_number=self.current_epoch,
            start_block=self.epoch_start_block,
            end_block=self.epoch_start_block + EPOCH_LENGTH,
        )
        return epoch_result

    def _check_key_rotation(self):
        """Check for a pending key rotation config and execute it."""
        if not self._rotation_config.exists():
            return
        try:
            config = json.loads(self._rotation_config.read_text())
            contracts = config.get("contracts", [])
            rpc_url = config.get("rpc_url", "")
            # Read owner_key from env (never store private keys in JSON).
            # The JSON config specifies which env var holds the key.
            owner_key_env = config.get("owner_key_env", "DEPLOYER_KEY")
            if "owner_key" in config:
                logger.warning(
                    "Ignoring 'owner_key' in rotation config — private keys "
                    "must be set via environment variables, not JSON files."
                )
            owner_key = os.environ.get(owner_key_env, "")
            old_validator = config.get("old_validator", "")
            new_validator = config.get("new_validator", "")

            if not all([contracts, rpc_url, owner_key, old_validator, new_validator]):
                logger.warning("Incomplete rotation config, skipping")
                return

            from validator.utils.key_rotation import batch_rotate_validators
            results = batch_rotate_validators(
                contracts=contracts,
                rpc_url=rpc_url,
                owner_key=owner_key,
                old_validator=old_validator,
                new_validator=new_validator,
            )

            successes = sum(1 for r in results if r.get("success"))
            logger.info("Key rotation complete: %d/%d contracts rotated", successes, len(results))

            # Archive the config so it doesn't re-run
            done_path = self._rotation_config.with_suffix(".done")
            self._rotation_config.rename(done_path)
            logger.info("Rotation config archived to %s", done_path.name)

        except Exception as e:
            logger.error("Key rotation failed: %s", e, exc_info=True)

    def _set_weights(self):
        """Set miner weights on-chain via subtensor."""
        if self.mode != "bittensor" or self.subtensor is None:
            return

        try:
            import bittensor as bt
            import torch

            # Use the last closed epoch result instead of re-closing
            epochs_dir = self.orchestrator.data_dir / "epochs"
            if not epochs_dir.exists():
                return

            epoch_files = sorted(epochs_dir.glob("epoch_*.json"))
            if not epoch_files:
                return

            import json
            latest = json.loads(epoch_files[-1].read_text())
            weights_dict = latest.get("weights", {})
            if not weights_dict:
                return

            # Map hotkeys to UIDs using metagraph
            metagraph_hotkeys = list(self.metagraph.hotkeys)
            uids = []
            weights = []
            for hotkey, weight in weights_dict.items():
                if hotkey in metagraph_hotkeys:
                    uids.append(metagraph_hotkeys.index(hotkey))
                    weights.append(weight)

            if not uids:
                return

            # Normalize weights
            weight_tensor = torch.FloatTensor(weights)
            weight_tensor = weight_tensor / weight_tensor.sum()

            self.subtensor.set_weights(
                netuid=self.netuid,
                wallet=self.wallet,
                uids=torch.LongTensor(uids),
                weights=weight_tensor,
            )
            logger.info("Set weights for %d miners on block %d", len(uids), self.current_block)

        except Exception as e:
            logger.error("Failed to set weights: %s", e, exc_info=True)

    # ── Status ────────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Get current validator status."""
        info = {
            "mode": self.mode,
            "epoch": self.current_epoch,
            "block": self.current_block,
            "submissions_this_epoch": len(self.submissions_this_epoch),
            "tasks_available": len(self.orchestrator.list_tasks()),
        }
        if self.metagraph is not None:
            info["registered_miners"] = len(self.metagraph.hotkeys)
        return info


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exploit Subnet Validator Neuron",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--local", action="store_true",
                        help="Run in local simulation mode (no Bittensor)")
    parser.add_argument("--netuid", type=int, default=DEFAULT_NETUID,
                        help="Bittensor subnet UID")
    parser.add_argument("--wallet.name", dest="wallet_name", type=str,
                        default="default", help="Wallet name")
    parser.add_argument("--wallet.hotkey", dest="wallet_hotkey", type=str,
                        default="default", help="Wallet hotkey")
    parser.add_argument("--subtensor.network", dest="network", type=str,
                        default="test", help="Subtensor network (finney/test/local)")
    parser.add_argument("--anvil-port", type=int, default=18545,
                        help="Anvil RPC port for validation")

    args = parser.parse_args()

    mode = "local" if args.local else "bittensor"

    neuron = ValidatorNeuron(
        mode=mode,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
        subtensor_network=args.network,
        anvil_port=args.anvil_port,
    )

    # Graceful shutdown on SIGTERM (Docker stop / k8s pod termination)
    def _handle_sigterm(signum, frame):
        logger.info("Received SIGTERM — shutting down gracefully...")
        neuron.should_exit = True

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    neuron.run()


if __name__ == "__main__":
    main()
