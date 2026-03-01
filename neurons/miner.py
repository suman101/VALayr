"""
Bittensor Miner Neuron — Wrapper for exploit miners on the subnet.

This module connects a miner to the Bittensor network:
  1. Register on subnet via subtensor
  2. Receive tasks from validators
  3. Submit exploit solutions (commit-reveal flow)
  4. Accumulate TAO rewards based on exploit quality

Usage:
  # With Bittensor installed:
  python neurons/miner.py --netuid <NETUID> --wallet.name <WALLET> --wallet.hotkey <HOTKEY>

  # Local dev mode:
  python neurons/miner.py --local
"""

import argparse
import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validator.utils.logging import get_logger

logger = get_logger(__name__)

from miner.cli import MinerCLI
from validator.commit_reveal import CommitRevealClient, CommitRevealSimulator, CommitRecord
from neurons.protocol import ExploitSubmissionSynapse, ExploitQuerySynapse

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_NETUID = 1  # Set to actual netuid when registered on Bittensor
EPOCH_LENGTH = 360
SUBMISSION_COOLDOWN = 30  # Seconds between submissions


# ── Miner Neuron ─────────────────────────────────────────────────────────────

class MinerNeuron:
    """
    Bittensor miner neuron for exploit discovery.

    Modes:
      - 'bittensor': Full integration with Bittensor network
      - 'local':     Standalone interactive mode for development
    """

    def __init__(
        self,
        mode: str = "local",
        netuid: int = DEFAULT_NETUID,
        wallet_name: str = "default",
        wallet_hotkey: str = "default",
        subtensor_network: str = "test",
    ):
        self.mode = mode
        self.netuid = netuid
        self.miner_address = "0xLOCAL_MINER"
        self.current_block = 0
        self.should_exit = False

        # Bittensor components (lazy-loaded)
        self.wallet = None
        self.subtensor = None
        self.metagraph = None
        self.axon = None

        if mode == "bittensor":
            self._init_bittensor(wallet_name, wallet_hotkey, subtensor_network)

        # Initialize CLI for task interaction
        self.cli = MinerCLI(miner_address=self.miner_address)

    def _init_bittensor(self, wallet_name: str, hotkey: str, network: str):
        """Initialize Bittensor components."""
        try:
            import bittensor as bt

            self.wallet = bt.wallet(name=wallet_name, hotkey=hotkey)
            self.subtensor = bt.subtensor(network=network)
            self.metagraph = self.subtensor.metagraph(self.netuid)

            self.miner_address = self.wallet.hotkey.ss58_address

            # Set up axon to receive queries from validators
            self.axon = bt.axon(wallet=self.wallet)
            self.axon.attach(
                forward_fn=self._handle_query,
                synapse_type=ExploitQuerySynapse,
            )
            self.axon.serve(netuid=self.netuid, subtensor=self.subtensor)
            self.axon.start()

            uid = -1
            if self.miner_address in self.metagraph.hotkeys:
                uid = self.metagraph.hotkeys.index(self.miner_address)

            logger.info("Bittensor miner initialized")
            logger.info("  Network: %s", network)
            logger.info("  Netuid:  %d", self.netuid)
            logger.info("  Hotkey:  %s", self.miner_address)
            logger.info("  UID:     %d", uid)

        except ImportError:
            logger.warning("bittensor package not installed — pip install bittensor")
            logger.warning("Falling back to local mode.")
            self.mode = "local"
        except Exception as e:
            logger.error("Bittensor init failed: %s", e, exc_info=True)
            logger.warning("Falling back to local mode.")
            self.mode = "local"

    # ── Main Loop ─────────────────────────────────────────────────────────

    def run(self):
        """Main miner loop."""
        logger.info("Exploit Subnet Miner — %s mode", self.mode.upper())

        if self.mode == "local":
            self._run_local()
        else:
            self._run_bittensor()

    def _run_local(self):
        """Local interactive mode — list tasks, wait for manual interaction."""
        logger.info("Running in local mode.")
        logger.info("Prepared exploits dir: %s", PROJECT_ROOT / "data" / "miner" / "exploits")
        logger.info("")
        logger.info("Usage:")
        logger.info("  1. Place exploit .sol files in data/miner/exploits/<task_prefix>.sol")
        logger.info("  2. Use orchestrator CLI to submit them")
        logger.info("  3. Or call neuron.submit_with_commit_reveal() programmatically")
        logger.info("")
        logger.info("Miner is ready. Press Ctrl+C to exit.")

        try:
            while not self.should_exit:
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Miner stopped.")

    def _run_bittensor(self):
        """Bittensor mode: keep-alive loop."""
        import bittensor as bt

        logger.info("Miner is running. Waiting for validator queries...")

        while not self.should_exit:
            try:
                # Sync metagraph
                self.metagraph.sync(subtensor=self.subtensor)
                self.current_block = self.subtensor.get_current_block()

                # Check our stake/incentive
                if self.miner_address in self.metagraph.hotkeys:
                    uid = self.metagraph.hotkeys.index(self.miner_address)
                    incentive = self.metagraph.incentive[uid].item()
                    stake = self.metagraph.stake[uid].item()
                    if self.current_block % 100 == 0:  # Log every ~100 blocks
                        logger.info("Block %d | Incentive: %.4f | Stake: %.4f TAO",
                                     self.current_block, incentive, stake)

                time.sleep(12)  # ~1 block

            except KeyboardInterrupt:
                logger.info("Miner shutting down...")
                break
            except Exception as e:
                logger.error("Error: %s", e, exc_info=True)
                time.sleep(30)

        logger.info("Miner exited main loop.")

    # ── Request Handling ──────────────────────────────────────────────────

    def _handle_query(self, synapse: ExploitQuerySynapse) -> ExploitQuerySynapse:
        """
        Handle an incoming query from a validator.

        The validator may ask for:
        - Task solutions the miner has prepared
        - Heartbeat/status checks
        """
        query_type = synapse.query_type or "status"

        if query_type == "status":
            synapse.response = {"status": "active", "miner": self.miner_address}

        elif query_type == "submit":
            task_id = synapse.task_id or ""
            if not task_id:
                synapse.response = {"error": "No task_id provided"}
            else:
                exploit_path = self._find_prepared_exploit(task_id)
                if exploit_path:
                    exploit_source = exploit_path.read_text()
                    synapse.response = {"task_id": task_id, "exploit_source": exploit_source}
                else:
                    synapse.response = {"error": f"No exploit prepared for task {task_id[:16]}"}
        else:
            synapse.response = {"error": f"Unknown query type: {query_type}"}

        return synapse

    # ── Exploit Management ────────────────────────────────────────────────

    def _find_prepared_exploit(self, task_id: str) -> Optional[Path]:
        """Find a prepared exploit for the given task."""
        exploits_dir = PROJECT_ROOT / "data" / "miner" / "exploits"
        if not exploits_dir.exists():
            return None

        # Look for files matching the task ID prefix
        for f in exploits_dir.glob(f"{task_id[:16]}*.sol"):
            return f
        return None

    def prepare_exploit(self, task_id: str, exploit_source: str):
        """Save an exploit solution for later submission."""
        exploits_dir = PROJECT_ROOT / "data" / "miner" / "exploits"
        exploits_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{task_id[:16]}.sol"
        (exploits_dir / filename).write_text(exploit_source)
        logger.info("Exploit saved: %s", exploits_dir / filename)

    def submit_with_commit_reveal(
        self,
        task_id: str,
        exploit_source: str,
        commit_reveal_address: str = "",
        rpc_url: str = "http://127.0.0.1:8545",
    ) -> dict:
        """
        Full commit-reveal submission flow:
        1. Commit exploit hash
        2. Wait for reveal window
        3. Reveal and submit
        """
        if commit_reveal_address:
            # Extract private key from wallet — pass directly, don't store
            _pk = ""
            if self.wallet is not None:
                try:
                    _pk = self.wallet.hotkey.private_key.hex()
                    if not _pk.startswith("0x"):
                        _pk = "0x" + _pk
                except (AttributeError, ValueError, TypeError):
                    pass
            cr = CommitRevealClient(
                contract_address=commit_reveal_address,
                rpc_url=rpc_url,
                private_key=_pk,
                miner_address=self.miner_address,
            )
            del _pk  # Clear reference as soon as possible
        else:
            cr = CommitRevealSimulator()
            cr.open_task(task_id)

        # Phase 1: Commit
        if isinstance(cr, CommitRevealSimulator):
            record = cr.commit(task_id, self.miner_address, exploit_source)
        else:
            record = cr.prepare_commit(task_id, exploit_source)
            record = cr.submit_commit(record)

        logger.info("Committed: hash=%s...", record.commit_hash[:20])
        logger.info("Nonce saved locally (DO NOT LOSE — needed for reveal)")

        return {
            "phase": "committed",
            "commit_hash": record.commit_hash,
            "task_id": task_id,
            "nonce": record.nonce,
        }

    # ── Status ────────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Get current miner status."""
        info = {
            "mode": self.mode,
            "address": self.miner_address,
            "block": self.current_block,
        }
        if self.metagraph is not None and self.miner_address in self.metagraph.hotkeys:
            uid = self.metagraph.hotkeys.index(self.miner_address)
            info["uid"] = uid
            info["incentive"] = float(self.metagraph.incentive[uid])
            info["stake"] = float(self.metagraph.stake[uid])
        return info


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Exploit Subnet Miner Neuron",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--local", action="store_true",
                        help="Run in local development mode (no Bittensor)")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-mine mode (local only)")
    parser.add_argument("--netuid", type=int, default=DEFAULT_NETUID,
                        help="Bittensor subnet UID")
    parser.add_argument("--wallet.name", dest="wallet_name", type=str,
                        default="default", help="Wallet name")
    parser.add_argument("--wallet.hotkey", dest="wallet_hotkey", type=str,
                        default="default", help="Wallet hotkey")
    parser.add_argument("--subtensor.network", dest="network", type=str,
                        default="test", help="Subtensor network")

    args = parser.parse_args()

    mode = "local" if args.local else "bittensor"

    neuron = MinerNeuron(
        mode=mode,
        netuid=args.netuid,
        wallet_name=args.wallet_name,
        wallet_hotkey=args.wallet_hotkey,
        subtensor_network=args.network,
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
