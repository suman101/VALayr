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
import subprocess
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

    def run(self) -> None:
        """Main miner loop."""
        logger.info("Exploit Subnet Miner — %s mode", self.mode.upper())

        if self.mode == "auto":
            self._run_auto()
        elif self.mode == "local":
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

    # ── Auto-Mine Mode ────────────────────────────────────────────────────

    def _run_auto(self):
        """
        Auto-mine mode: continuously scan tasks, generate exploit scaffolds,
        attempt known exploit patterns, and submit solutions.

        This is useful for:
          - Testing the full pipeline end-to-end
          - Running a baseline miner that submits template exploits
          - Bootstrapping initial submissions on a new network
        """
        logger.info("Running in AUTO-MINE mode.")
        logger.info("Will scan for tasks and attempt known exploit patterns.")

        exploits_dir = PROJECT_ROOT / "exploits"
        submitted: set[str] = set()  # Track already-submitted task IDs
        round_num = 0

        while not self.should_exit:
            round_num += 1
            try:
                tasks = self.cli.orch.list_tasks()
                if not tasks:
                    logger.info("[Round %d] No tasks available. Waiting...", round_num)
                    time.sleep(10)
                    continue

                pending = [t for t in tasks if t["task_id"] not in submitted]
                if not pending:
                    logger.info("[Round %d] All %d tasks already attempted. Sleeping...",
                                round_num, len(tasks))
                    time.sleep(30)
                    continue

                logger.info("[Round %d] %d new tasks to attempt (of %d total)",
                            round_num, len(pending), len(tasks))

                for task_meta in pending:
                    if self.should_exit:
                        break

                    task_id = task_meta["task_id"]
                    vuln_class = task_meta.get("vulnerability_class", "unknown")
                    submitted.add(task_id)

                    # Try to find a matching example exploit
                    exploit_source = self._find_auto_exploit(vuln_class, exploits_dir)
                    if not exploit_source:
                        logger.debug("No exploit template for class '%s', skipping %s",
                                     vuln_class, task_id[:16])
                        continue

                    # Load full task to get contract details
                    full_task = self.cli.orch.load_task(task_id)
                    if full_task is None:
                        continue

                    # Adapt the exploit to the target contract if possible
                    adapted = self._adapt_exploit(exploit_source, full_task)

                    logger.info("  Submitting exploit for task %s (class: %s)",
                                task_id[:16], vuln_class)

                    try:
                        result = self.cli.orch.process_submission(
                            task_id=task_id,
                            exploit_source=adapted,
                            miner_address=self.miner_address,
                        )
                        status = result.validation_result
                        severity = result.severity_score
                        logger.info("    Result: %s  severity=%.4f", status, severity)

                        # Save for tracking
                        self.prepare_exploit(task_id, adapted)
                    except (OSError, subprocess.SubprocessError, json.JSONDecodeError,
                            ValueError, KeyError) as e:
                        logger.warning("    Submission failed: %s", e)

                    time.sleep(SUBMISSION_COOLDOWN)

            except KeyboardInterrupt:
                break
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError,
                    ValueError, KeyError) as e:
                logger.error("Auto-mine error: %s", e, exc_info=True)
                time.sleep(15)

        logger.info("Auto-mine stopped. Attempted %d tasks.", len(submitted))

    def _find_auto_exploit(self, vuln_class: str, exploits_dir: Path) -> Optional[str]:
        """
        Find a matching example exploit from the exploits/ directory.

        Maps vulnerability classes to example exploit subdirectories.
        """
        # Map vuln classes to example exploit dirs
        class_to_dir = {
            "reentrancy": "reentrancy_basic",
            "auth-bypass": "auth_bypass_missing",
            "integer-overflow": "overflow_unchecked",
            "access-control": "access_selfdestruct",
            "flash-loan": "flash_loan_oracle",
            "upgradeable": "upgradeable_vault",
            # Stage 2 classes — no pre-built exploits yet
            "cross-reentrancy": "reentrancy_basic",    # Closest match
            "governance-attack": "flash_loan_oracle",   # Closest match
        }

        dir_name = class_to_dir.get(vuln_class)
        if not dir_name:
            return None

        exploit_path = exploits_dir / dir_name / "Exploit.sol"
        if exploit_path.exists():
            return exploit_path.read_text()
        return None

    def _adapt_exploit(self, exploit_source: str, task: dict) -> str:
        """
        Minimally adapt an example exploit to the target task.

        This replaces generic contract references with the actual target
        contract name found in the task source.
        """
        source_dir = task.get("_source_dir", "")
        if not source_dir:
            return exploit_source

        # Try to extract the main contract name from the vulnerable source
        vuln_path = Path(source_dir) / "Vulnerable.sol"
        if not vuln_path.exists():
            return exploit_source

        vuln_source = vuln_path.read_text()
        target_name = None
        for line in vuln_source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("contract ") and "{" in stripped:
                target_name = stripped.split()[1].rstrip("{").strip()
                break

        if target_name and target_name != "Vulnerable":
            # Replace generic "Vulnerable" references
            exploit_source = exploit_source.replace("Vulnerable", target_name)

        return exploit_source

    def _run_bittensor(self):
        """Bittensor mode: keep-alive loop."""
        import bittensor as bt

        logger.info("Miner is running. Waiting for validator queries...")

        consecutive_errors = 0
        MAX_BACKOFF = 300  # 5 minutes cap

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

                consecutive_errors = 0
                time.sleep(12)  # ~1 block

            except KeyboardInterrupt:
                logger.info("Miner shutting down...")
                break
            except Exception as e:
                consecutive_errors += 1
                backoff = min(30 * (2 ** (consecutive_errors - 1)), MAX_BACKOFF)
                logger.error(
                    "Error (attempt %d, backoff %ds): %s",
                    consecutive_errors, backoff, e, exc_info=True,
                )
                time.sleep(backoff)

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

    def prepare_exploit(self, task_id: str, exploit_source: str) -> None:
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

def main() -> None:
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
    if args.auto:
        mode = "auto"

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
