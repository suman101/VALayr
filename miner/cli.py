"""
Miner CLI — Interface for exploit miners interacting with the subnet.

Commands:
  tasks       List available tasks from the corpus
  task        Show details for a specific task
  submit      Submit an exploit for validation
  status      Check submission status
  scores      View current epoch scores
  generate    Generate a local test exploit scaffold

This is the primary interface miners use to participate.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from validator.utils.logging import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import Orchestrator, SubmissionResult


# ── Constants ────────────────────────────────────────────────────────────────

MINER_DATA_DIR = PROJECT_ROOT / "data" / "miner"
SUBMISSIONS_DIR = MINER_DATA_DIR / "submissions"
LOCAL_CONFIG = MINER_DATA_DIR / "config.json"
MAX_EXPLOIT_SOURCE_BYTES = 64_000  # 64 KB — matches validator's limit


# ── Miner Client ─────────────────────────────────────────────────────────────

class MinerCLI:
    """Local miner client wrapping the orchestrator."""

    def __init__(self, miner_address: str = "0xMINER"):
        self.miner_address = miner_address
        self.orch = Orchestrator(mode="local")

        MINER_DATA_DIR.mkdir(parents=True, exist_ok=True)
        SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Commands ──────────────────────────────────────────────────────────

    def cmd_tasks(self, args):
        """List all available tasks in the corpus."""
        tasks = self.orch.list_tasks()
        if not tasks:
            print("[!] No tasks available. The validator needs to generate the corpus first.")
            print("    Run: python orchestrator.py generate")
            return

        print(f"\n{'#':>3s}  {'Task ID':20s}  {'Class':22s}  {'Difficulty':>10s}")
        print("-" * 60)
        for i, t in enumerate(tasks, 1):
            tid = t["task_id"][:18] + ".."
            print(f"{i:>3d}  {tid:20s}  {t['vulnerability_class']:22s}  {t['difficulty']:>10d}")
        print(f"\nTotal: {len(tasks)} tasks")

    def cmd_task(self, args):
        """Show details for a specific task."""
        task = self.orch.load_task(args.id)
        if task is None:
            print(f"[!] Task not found: {args.id}")
            return

        print(f"\n{'='*60}")
        print(f"Task ID:    {task['task_id'][:40]}...")
        print(f"Class:      {task['vulnerability_class']}")
        print(f"Difficulty: {task['difficulty']}")
        print(f"Solc:       {task['solc_version']}")

        deploy = task.get("deployment_config", {})
        print(f"Initial $:  {deploy.get('initial_balance', 0)} wei")

        inv = task.get("invariant_spec")
        if inv:
            print(f"Invariant:  {inv.get('description', 'N/A')}")
            print(f"Condition:  {inv.get('solidity_condition', 'N/A')}")

        # Show source code summary
        source_dir = task.get("_source_dir", "")
        if source_dir:
            source_path = (Path(source_dir) / "Vulnerable.sol").resolve()
            corpus_dir = (PROJECT_ROOT / "contracts" / "corpus").resolve()
            if not str(source_path).startswith(str(corpus_dir) + os.sep):
                logger.warning("Task source directory outside corpus: %s", source_dir)
            elif source_path.exists():
                source = source_path.read_text()
                lines = source.strip().split("\n")
                print(f"\nSource ({len(lines)} lines):")
                # Show first 30 lines
                for line in lines[:30]:
                    print(f"  {line}")
                if len(lines) > 30:
                    print(f"  ... ({len(lines) - 30} more lines)")
        print(f"{'='*60}")

    def cmd_submit(self, args):
        """Submit an exploit for validation."""
        exploit_path = Path(args.exploit).resolve()
        cwd = Path.cwd().resolve()

        # Prevent path traversal: exploit file must be under cwd or
        # a known project directory
        if not (exploit_path.is_relative_to(cwd)
                or exploit_path.is_relative_to(PROJECT_ROOT)):
            logger.error("Exploit file must be under %s or %s", cwd, PROJECT_ROOT)
            return

        # Reject symlinks pointing outside the allowed directories
        if exploit_path.is_symlink():
            real = exploit_path.resolve()
            if not (real.is_relative_to(cwd)
                    or real.is_relative_to(PROJECT_ROOT)):
                logger.error("Exploit symlink points outside allowed directory")
                return

        if not exploit_path.exists():
            logger.error("Exploit file not found: %s", exploit_path)
            return

        try:
            exploit_source = exploit_path.read_text()
        except (IOError, OSError) as e:
            logger.error("Failed to read exploit file: %s", e)
            return

        if len(exploit_source.encode()) > MAX_EXPLOIT_SOURCE_BYTES:
            logger.error(
                "Exploit source too large (%d bytes, max %d)",
                len(exploit_source.encode()),
                MAX_EXPLOIT_SOURCE_BYTES,
            )
            return
        logger.info("Submitting exploit for task %s...", args.task[:16])
        logger.info("File: %s (%d bytes), Miner: %s", exploit_path.name, len(exploit_source), self.miner_address)

        result = self.orch.process_submission(
            task_id=args.task,
            exploit_source=exploit_source,
            miner_address=self.miner_address,
        )

        self._print_result(result)
        self._save_submission(args.task, exploit_path, result)

    def cmd_status(self, args):
        """Check status of previous submissions."""
        if not SUBMISSIONS_DIR.exists():
            print("[!] No submissions found.")
            return

        submissions = sorted(SUBMISSIONS_DIR.glob("*.json"))
        if not submissions:
            print("[!] No submissions found.")
            return

        print(f"\n{'#':>3s}  {'Task':20s}  {'Result':24s}  {'Severity':>8s}  {'Reward':>6s}")
        print("-" * 68)
        for i, f in enumerate(submissions[-20:], 1):  # Last 20
            try:
                data = json.loads(f.read_text())
            except (json.JSONDecodeError, OSError):
                logger.warning("Skipping corrupt submission file: %s", f.name)
                continue
            tid = data.get("task_id", "?")[:18] + ".."
            result = data.get("validation_result", "?")
            severity = data.get("severity_score", 0)
            reward = data.get("reward_multiplier", 0)
            symbol = "+" if result == "VALID" else "-"
            print(f"{i:>3d}  {tid:20s}  [{symbol}] {result:20s}  {severity:>8.4f}  {reward:>6.2f}x")

    def cmd_scores(self, args):
        """Show current epoch scores."""
        epochs_dir = PROJECT_ROOT / "data" / "epochs"
        if not epochs_dir.exists():
            print("[!] No epoch data found.")
            return

        epoch_files = sorted(epochs_dir.glob("epoch_*.json"))
        if not epoch_files:
            print("[!] No epochs completed yet.")
            return

        try:
            latest = json.loads(epoch_files[-1].read_text())
        except (json.JSONDecodeError, OSError):
            logger.error("Failed to read epoch file: %s", epoch_files[-1].name)
            return
        print(f"\nEpoch {latest['epoch_number']} (blocks {latest['start_block']}-{latest['end_block']})")
        print(f"Submissions: {latest['total_submissions']} total, {latest['total_valid']} valid\n")

        scores = latest.get("miner_scores", {})
        if scores:
            print(f"{'Miner':16s}  {'Valid':>5s}  {'Unique':>6s}  {'Dup':>3s}  {'Severity':>8s}  {'Weight':>8s}")
            print("-" * 56)
            for hotkey, s in scores.items():
                weight = latest.get("weights", {}).get(hotkey, 0)
                print(f"{hotkey[:14]:16s}  {s['valid_exploits']:>5d}  {s['unique_fingerprints']:>6d}  "
                      f"{s['duplicate_fingerprints']:>3d}  {s['total_severity']:>8.4f}  {weight:>8.4f}")
        else:
            print("No miner scores recorded.")

    def cmd_scaffold(self, args):
        """Generate an exploit scaffold for a task."""
        task = self.orch.load_task(args.task)
        if task is None:
            print(f"[!] Task not found: {args.task}")
            return

        output_dir = Path(args.output).resolve() if args.output else Path(".").resolve()
        cwd = Path.cwd().resolve()
        if output_dir != cwd and cwd not in output_dir.parents:
            print(f"[!] Output directory must be under {cwd}")
            return
        output_dir.mkdir(parents=True, exist_ok=True)

        # Read the vulnerable source
        source_dir = task.get("_source_dir", "")
        contract_name = "Vulnerable"
        if source_dir:
            source_path = Path(source_dir) / "Vulnerable.sol"
            if source_path.exists():
                source = source_path.read_text()
                # Extract contract name
                for line in source.split("\n"):
                    if line.strip().startswith("contract "):
                        contract_name = line.strip().split()[1].rstrip("{").strip()
                        break

        vuln_class = task.get("vulnerability_class", "unknown")

        scaffold = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

// TODO: Import or inline the target contract here
// The validation engine will provide it as ../src/Vulnerable.sol

/// @title ExploitTest — Your exploit for {vuln_class} vulnerability
/// @dev Target contract: {contract_name}
/// @dev Task ID: {task.get('task_id', 'unknown')[:40]}...
contract ExploitTest is Test {{

    // TODO: Declare target contract instance
    // {contract_name} public target;

    function setUp() public {{
        // TODO: Deploy target with appropriate initial state
        // target = new {contract_name}();
        // vm.deal(address(target), 10 ether);
    }}

    /// @notice Entry point — the validation engine runs this function.
    /// @dev Must produce measurable state change:
    ///   - Balance drain (funds stolen)
    ///   - Storage mutation (ownership takeover)
    ///   - Contract destruction (permanent lock)
    function test_run() public {{
        // TODO: Implement your exploit here
        //
        // Hints for {vuln_class}:
{_exploit_hints(vuln_class)}
        //
        // IMPORTANT: Add assertions to prove impact
        // assertGt(attacker.balance, 0, "Attacker should profit");
    }}
}}
"""

        output_file = output_dir / "Exploit.sol"
        output_file.write_text(scaffold)
        print(f"[+] Scaffold written to {output_file}")
        print(f"    Task: {task.get('task_id', '')[:30]}...")
        print(f"    Class: {vuln_class}")
        print(f"    Edit the file, then submit with: miner submit --task {args.task[:16]} --exploit {output_file}")

    # ── Internal ──────────────────────────────────────────────────────────

    def _print_result(self, result: SubmissionResult):
        """Pretty-print a submission result."""
        ok = result.validation_result == "VALID"
        symbol = "+" if ok else "-"

        print(f"\n{'='*60}")
        print(f"  [{symbol}] {result.validation_result}")
        if ok:
            print(f"  Severity:    {result.severity_score:.4f}")
            print(f"  Detail:      {result.severity_detail}")
            print(f"  Fingerprint: {result.fingerprint[:30]}..." if result.fingerprint else "")
            print(f"  Duplicate:   {'Yes' if result.is_duplicate else 'No (FIRST!)'}")
            print(f"  Reward:      {result.reward_multiplier:.2f}x")
        else:
            print(f"  Error:       {result.error}")
        print(f"  Time:        {result.validation_time_ms}ms")
        print(f"{'='*60}")

    def _save_submission(self, task_id: str, exploit_path: Path, result: SubmissionResult):
        """Save submission record locally."""
        record = result.to_dict()
        record["exploit_file"] = str(exploit_path)
        record["submitted_at"] = time.time()

        filename = f"{task_id[:16]}_{int(time.time())}.json"
        (SUBMISSIONS_DIR / filename).write_text(json.dumps(record, indent=2))


def _exploit_hints(vuln_class: str) -> str:
    """Return exploit hints for a vulnerability class."""
    hints = {
        "reentrancy": (
            "        //   1. Deposit funds into the target\n"
            "        //   2. Call withdraw() - target sends ETH before updating state\n"
            "        //   3. In your receive(), re-enter withdraw() to drain"
        ),
        "storage-collision": (
            "        //   1. Find a proxy/delegatecall pattern\n"
            "        //   2. Craft calldata that writes to overlapping storage slots\n"
            "        //   3. Overwrite critical state (owner, implementation)"
        ),
        "auth-bypass": (
            "        //   1. Identify functions missing access control modifiers\n"
            "        //   2. Call the unprotected function as an external account\n"
            "        //   3. Escalate privilege (setOwner) then drain funds"
        ),
        "integer-overflow": (
            "        //   1. Find unchecked{} blocks with arithmetic\n"
            "        //   2. Trigger underflow (subtract from zero balance)\n"
            "        //   3. Resulting MAX_UINT balance lets you withdraw everything"
        ),
        "access-control": (
            "        //   1. Find unprotected critical functions (selfdestruct, etc.)\n"
            "        //   2. Call them as any external address\n"
            "        //   3. Destroy contract or drain via unprotected setter"
        ),
        "flash-loan": (
            "        //   1. Take a flash loan for a large amount\n"
            "        //   2. Manipulate the price oracle during the loan\n"
            "        //   3. Profit from mispriced trades, repay loan"
        ),
    }
    return hints.get(vuln_class, "        //   (No specific hints for this class)")


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="miner",
        description="Exploit Subnet Miner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workflow:
  1. miner tasks                         # Browse available tasks
  2. miner task --id 0xabc123            # Inspect a task's source code
  3. miner scaffold --task 0xabc123      # Generate exploit template
  4. # ... write your exploit ...
  5. miner submit --task 0xabc123 --exploit Exploit.sol
  6. miner status                        # Check results
  7. miner scores                        # View epoch leaderboard
        """,
    )
    parser.add_argument("--address", type=str, default="0xMINER", help="Your miner hotkey address")
    subparsers = parser.add_subparsers(dest="command")

    # tasks
    subparsers.add_parser("tasks", help="List available tasks")

    # task detail
    task_p = subparsers.add_parser("task", help="Show task details")
    task_p.add_argument("--id", type=str, required=True, help="Task ID or prefix")

    # scaffold
    scaffold_p = subparsers.add_parser("scaffold", help="Generate exploit scaffold")
    scaffold_p.add_argument("--task", type=str, required=True, help="Task ID")
    scaffold_p.add_argument("--output", type=str, default=None, help="Output directory")

    # submit
    submit_p = subparsers.add_parser("submit", help="Submit an exploit")
    submit_p.add_argument("--task", type=str, required=True, help="Task ID or prefix")
    submit_p.add_argument("--exploit", type=str, required=True, help="Path to exploit .sol")

    # status
    subparsers.add_parser("status", help="Check submission status")

    # scores
    subparsers.add_parser("scores", help="View epoch scores")

    args = parser.parse_args()
    cli = MinerCLI(miner_address=args.address)

    commands = {
        "tasks": cli.cmd_tasks,
        "task": cli.cmd_task,
        "scaffold": cli.cmd_scaffold,
        "submit": cli.cmd_submit,
        "status": cli.cmd_status,
        "scores": cli.cmd_scores,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
