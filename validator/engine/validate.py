"""
Validation Engine — The Spine of the Exploit Subnet.

Executes exploit submissions in a deterministic, sandboxed environment.
Pipeline:
  1. Rebuild environment from task hash
  2. Compile contract
  3. Deploy to fresh Anvil instance
  4. Execute exploit script
  5. Capture state diff, balance diff, event logs, call trace
  6. Compute canonical exploit fingerprint
  7. Binary outcome: VALID or REJECT

CRITICAL: Validation cost O(minutes), generation cost O(hours).
That asymmetry is the economic moat.
"""

import hashlib
import json
import logging
import os
import re
import shutil

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from validator.utils.logging import get_logger

logger = get_logger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

ANVIL_HOST = "127.0.0.1"
ANVIL_PORT_BASE = 18545  # Each validation gets a unique port
FOUNDRY_VERSION = "nightly-2024-12-01"
DOCKER_IMAGE = "ghcr.io/exploit-subnet/validator:v0.1.0"

# Anvil[0] well-known deployer key (public knowledge — used only inside sandbox).
# SECURITY: Even though this key is public, we use --unlocked + --from instead of
# passing it via CLI arg to avoid leaking patterns with real keys in production.
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil[0] address

# Deterministic Anvil config
ANVIL_CONFIG = {
    "block_timestamp": 1_700_000_000,
    "block_number": 18_000_000,
    "gas_limit": 30_000_000,
    "chain_id": 31337,
    "accounts": 10,
    "balance": 10000,  # ETH per account
    "mnemonic": "test test test test test test test test test test test junk",
    "no_mining": False,
    "hardfork": "cancun",
}

VALIDATION_TIMEOUT = 120  # seconds
MAX_GAS_EXPLOIT = 30_000_000
MIN_GAS_THRESHOLD = 21_000  # Reject if gas usage below this (spam filter)
MAX_EXPLOIT_SOURCE_BYTES = 64_000  # Reject exploits larger than 64KB (DoS guard)
ANVIL_READY_TIMEOUT = 10  # Max seconds to wait for Anvil readiness
ANVIL_READY_INTERVAL = 0.05  # Poll interval in seconds


# ── Enums & Data Structures ─────────────────────────────────────────────────

class ValidationResult(Enum):
    VALID = "VALID"
    REJECT_REVERT = "REJECT_REVERT"
    REJECT_NO_STATE_CHANGE = "REJECT_NO_STATE_CHANGE"
    REJECT_TIMEOUT = "REJECT_TIMEOUT"
    REJECT_COMPILE_FAIL = "REJECT_COMPILE_FAIL"
    REJECT_BELOW_GAS_THRESHOLD = "REJECT_BELOW_GAS_THRESHOLD"
    REJECT_INVALID_FORMAT = "REJECT_INVALID_FORMAT"
    REJECT_FINGERPRINT_ERROR = "REJECT_FINGERPRINT_ERROR"


@dataclass
class StorageSlotDiff:
    """Single storage slot change."""
    slot: str        # hex slot index
    before: str      # hex value before
    after: str       # hex value after


@dataclass
class ExecutionTrace:
    """Full execution trace from Anvil."""
    storage_diffs: list[StorageSlotDiff] = field(default_factory=list)
    balance_before: int = 0
    balance_after: int = 0
    balance_delta: int = 0
    event_logs: list[dict] = field(default_factory=list)
    call_trace: list[dict] = field(default_factory=list)
    gas_used: int = 0
    reverted: bool = False
    revert_reason: str = ""
    function_selectors: list[str] = field(default_factory=list)


@dataclass
class ExploitSubmission:
    """What a miner submits."""
    task_id: str
    exploit_source: str          # Solidity source (Foundry test format)
    entry_function: str = "test_run"  # Entry point function name (must start with test_ for Forge)
    expected_state_diff: Optional[dict] = None  # Optional expected diff JSON


@dataclass
class ValidationReport:
    """Output from validation pipeline."""
    task_id: str
    result: ValidationResult
    fingerprint: str = ""          # Canonical exploit fingerprint
    severity_score: float = 0.0    # Algorithmic severity
    execution_trace: Optional[ExecutionTrace] = None
    validation_time_ms: int = 0
    validator_id: str = ""
    error_message: str = ""

    def to_dict(self) -> dict:
        d = {
            "task_id": self.task_id,
            "result": self.result.value,
            "fingerprint": self.fingerprint,
            "severity_score": self.severity_score,
            "validation_time_ms": self.validation_time_ms,
            "validator_id": self.validator_id,
            "error_message": self.error_message,
        }
        if self.execution_trace:
            d["execution_trace"] = asdict(self.execution_trace)
        return d


# ── Validation Engine ────────────────────────────────────────────────────────

class ValidationEngine:
    """
    Deterministic exploit validation pipeline.

    Runs in Docker (production) or locally (dev) with pinned Foundry.
    """

    # Atomic counter for port allocation across concurrent validations
    _port_counter = 0
    _port_lock = threading.Lock()

    def __init__(self, validator_id: str = "validator-0",
                 work_dir: Optional[Path] = None,
                 anvil_port: int = ANVIL_PORT_BASE):
        self.validator_id = validator_id
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="exploit-val-"))
        self._owns_work_dir = work_dir is None  # Clean up only auto-created dirs
        # Allocate unique port per instance to avoid collisions (thread-safe,
        # bounded to 1000-port window so we never exceed 65535).
        with ValidationEngine._port_lock:
            ValidationEngine._port_counter = (ValidationEngine._port_counter % 1000) + 1
            self.anvil_port = anvil_port + ValidationEngine._port_counter - 1
        self._anvil_proc = None

    # ── Public API ────────────────────────────────────────────────────────

    def validate(self, task_json: dict, submission: ExploitSubmission) -> ValidationReport:
        """
        Full validation pipeline. Binary outcome.

        Args:
            task_json: Parsed task.json from task package
            submission: Miner's exploit submission

        Returns:
            ValidationReport with VALID or REJECT_*
        """
        start_time = time.monotonic()
        report = ValidationReport(
            task_id=submission.task_id,
            result=ValidationResult.REJECT_INVALID_FORMAT,
            validator_id=self.validator_id,
        )

        try:
            # Step 0: Reject oversized exploit source (DoS guard)
            if len(submission.exploit_source.encode()) > MAX_EXPLOIT_SOURCE_BYTES:
                report.error_message = (
                    f"Exploit source exceeds {MAX_EXPLOIT_SOURCE_BYTES} byte limit"
                )
                return self._finalize(report, start_time)

            # Step 0b: Sanitize exploit source (path traversal guard)
            if not self._sanitize_source(submission.exploit_source):
                report.error_message = "Exploit source contains disallowed import paths"
                return self._finalize(report, start_time)

            # Step 1: Setup workspace
            ws = self._setup_workspace(task_json, submission)
            if not ws:
                report.error_message = "Failed to setup workspace"
                return self._finalize(report, start_time)

            # Step 2: Compile
            if not self._compile(ws):
                report.result = ValidationResult.REJECT_COMPILE_FAIL
                report.error_message = "Compilation failed"
                return self._finalize(report, start_time)

            # Step 3: Start Anvil
            if not self._start_anvil():
                report.error_message = "Anvil startup failed"
                return self._finalize(report, start_time)

            # Step 4: Deploy target contract
            target_addr = self._deploy_target(ws, task_json)
            if not target_addr:
                report.error_message = "Target deployment failed"
                return self._finalize(report, start_time)

            # Step 5: Capture pre-state
            pre_state = self._capture_state(target_addr)

            # Step 6: Execute exploit
            exec_result = self._execute_exploit(ws, target_addr)

            # Step 7: Capture post-state
            post_state = self._capture_state(target_addr)

            # Step 8: Build execution trace
            trace = self._build_trace(pre_state, post_state, exec_result)
            report.execution_trace = trace

            # Step 9: Validate result (binary decision)
            if trace.reverted:
                report.result = ValidationResult.REJECT_REVERT
                report.error_message = trace.revert_reason
                return self._finalize(report, start_time)

            if trace.gas_used < MIN_GAS_THRESHOLD:
                report.result = ValidationResult.REJECT_BELOW_GAS_THRESHOLD
                return self._finalize(report, start_time)

            if not self._has_state_change(trace):
                report.result = ValidationResult.REJECT_NO_STATE_CHANGE
                return self._finalize(report, start_time)

            # Step 10: Compute fingerprint
            fingerprint = self._compute_fingerprint(trace)
            if not fingerprint:
                report.result = ValidationResult.REJECT_FINGERPRINT_ERROR
                return self._finalize(report, start_time)

            report.fingerprint = fingerprint
            report.result = ValidationResult.VALID

            # Step 11: Compute severity
            from validator.scoring.severity import SeverityScorer
            scorer = SeverityScorer()
            report.severity_score = scorer.score(trace)

        except subprocess.TimeoutExpired:
            report.result = ValidationResult.REJECT_TIMEOUT
            report.error_message = f"Execution exceeded {VALIDATION_TIMEOUT}s"
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError, KeyError) as e:
            report.error_message = f"Validation pipeline error: {type(e).__name__}: {e}"
            logger.error("Validation pipeline error for task %s: %s",
                         submission.task_id[:16], e, exc_info=True)
        except Exception as e:  # pragma: no cover — safety net for truly unexpected errors
            report.error_message = f"Unexpected error: {type(e).__name__}: {e}"
            logger.exception("Unexpected error validating task %s", submission.task_id[:16])
        finally:
            self._stop_anvil()
            self._cleanup_workspace()

        return self._finalize(report, start_time)

    # ── Private Pipeline Steps ────────────────────────────────────────────

    def _setup_workspace(self, task_json: dict, submission: ExploitSubmission) -> Optional[Path]:
        """Create isolated workspace with task contract and exploit."""
        ws = self.work_dir / f"task_{submission.task_id[:10]}"
        ws.mkdir(parents=True, exist_ok=True)

        src_dir = ws / "src"
        test_dir = ws / "test"
        src_dir.mkdir(exist_ok=True)
        test_dir.mkdir(exist_ok=True)

        # Write task contract
        task_source = task_json.get("source_code", "")
        if not task_source:
            # Load from file path
            task_dir = Path(task_json.get("_source_dir", ""))
            source_file = task_dir / "Vulnerable.sol"
            if source_file.exists():
                task_source = source_file.read_text()

        if not task_source:
            return None

        (src_dir / "Vulnerable.sol").write_text(task_source)

        # Write exploit (Foundry test format)
        exploit_wrapped = self._wrap_exploit(submission.exploit_source, submission.entry_function)
        (test_dir / "Exploit.t.sol").write_text(exploit_wrapped)

        # Write foundry.toml
        foundry_config = f"""[profile.default]
src = "src"
out = "out"
test = "test"
solc_version = "{task_json.get('solc_version', '0.8.28')}"
evm_version = "cancun"
optimizer = true
optimizer_runs = 200

[rpc_endpoints]
local = "http://{ANVIL_HOST}:{self.anvil_port}"
"""
        (ws / "foundry.toml").write_text(foundry_config)

        # Symlink forge-std so exploits can `import "forge-std/Test.sol"`
        project_forge_std = Path(__file__).resolve().parent.parent.parent / "contracts" / "lib" / "forge-std"
        if project_forge_std.is_dir():
            lib_dir = ws / "lib"
            lib_dir.mkdir(exist_ok=True)
            link = lib_dir / "forge-std"
            if not link.exists():
                try:
                    link.symlink_to(project_forge_std)
                except OSError:
                    logger.debug("Could not symlink forge-std into workspace")

        return ws

    def _wrap_exploit(self, exploit_source: str, entry_function: str) -> str:
        """Ensure exploit is in proper Foundry test format."""
        # If already has pragma and contract, use as-is
        if "pragma solidity" in exploit_source and "contract" in exploit_source:
            return exploit_source

        # Wrap raw exploit code into Foundry test
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract ExploitTest is Test {{
    function {entry_function}() public {{
        {exploit_source}
    }}
}}
"""

    def _compile(self, workspace: Path) -> bool:
        """Compile contracts in workspace. Returns True on success."""
        try:
            result = subprocess.run(
                ["forge", "build", "--root", str(workspace)],
                capture_output=True, text=True, timeout=60,
                cwd=str(workspace)
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _start_anvil(self) -> bool:
        """Start deterministic Anvil instance."""
        cmd = [
            "anvil",
            "--host", ANVIL_HOST,
            "--port", str(self.anvil_port),
            "--timestamp", str(ANVIL_CONFIG["block_timestamp"]),
            "--block-base-fee-per-gas", "0",
            "--gas-limit", str(ANVIL_CONFIG["gas_limit"]),
            "--chain-id", str(ANVIL_CONFIG["chain_id"]),
            "--accounts", str(ANVIL_CONFIG["accounts"]),
            "--balance", str(ANVIL_CONFIG["balance"]),
            "--mnemonic", ANVIL_CONFIG["mnemonic"],
            "--hardfork", ANVIL_CONFIG["hardfork"],
            "--quiet",
        ]

        try:
            self._anvil_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # Poll for readiness instead of sleeping a fixed 2 seconds
            return self._wait_anvil_ready()
        except FileNotFoundError:
            return False

    def _stop_anvil(self):
        """Terminate Anvil instance."""
        if self._anvil_proc:
            self._anvil_proc.terminate()
            try:
                self._anvil_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._anvil_proc.kill()
            self._anvil_proc = None

    def _wait_anvil_ready(self) -> bool:
        """Poll Anvil RPC until it responds or timeout is reached."""
        import urllib.error
        import urllib.request

        rpc_url = f"http://{ANVIL_HOST}:{self.anvil_port}"
        payload = json.dumps({
            "jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1
        }).encode()
        deadline = time.monotonic() + ANVIL_READY_TIMEOUT

        while time.monotonic() < deadline:
            if self._anvil_proc and self._anvil_proc.poll() is not None:
                return False  # Process exited
            try:
                req = urllib.request.Request(
                    rpc_url, data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=1) as resp:
                    data = json.loads(resp.read())
                    if "result" in data:
                        return True
            except (OSError, ConnectionError, urllib.error.URLError,
                    json.JSONDecodeError, ValueError):
                pass  # Anvil not ready yet — keep polling

        return False

    def _cleanup_workspace(self):
        """Remove temporary workspace directory to prevent disk leaks."""
        if self._owns_work_dir and self.work_dir and self.work_dir.exists():
            try:
                shutil.rmtree(self.work_dir, ignore_errors=True)
            except OSError as e:
                logger.debug("Workspace cleanup failed: %s", e)

    @staticmethod
    def _sanitize_source(source: str) -> bool:
        """Reject exploit source with dangerous patterns.

        Checks for:
          - Path traversal (.. in imports)
          - Absolute paths in imports (/etc/..., C:\\...)

        Note: The Anvil sandbox (--network=none + temp workspace) is the
        primary defense.  These checks are a belt-and-suspenders layer.
        """
        for line in source.split("\n"):
            stripped = line.strip()

            # Check import lines
            if stripped.startswith("import") or (stripped.startswith("from") and "import" in stripped):
                # Disallow path traversal
                if ".." in stripped:
                    return False
                # Disallow absolute paths (Unix + Windows)
                if re.search(r'["\']/', stripped) or re.search(r'["\'][A-Za-z]:\\\\', stripped):
                    return False

            # Reject foundry remapping directives embedded in source comments
            # (won't affect compilation, but signals malicious intent)
            if stripped.startswith("//") and "=" in stripped and ("/" in stripped):
                # Could be a remapping hint — benign in isolation but flag it
                pass

        # Source-level safety checks (belt-and-suspenders; Anvil sandbox is primary defense)
        # Reject selfdestruct/create2 in non-test contracts submitted as exploits
        # NOTE: These are valid exploit techniques, so we do NOT block them.
        # The sandbox (--network=none + temp workspace) is the real protection.
        return True

    @staticmethod
    def _extract_contract_name(source_path: Path) -> str:
        """Extract primary contract name from Solidity source for deployment.

        Returns a forge create compatible spec like 'src/Vulnerable.sol:VulnerableVault'.
        Falls back to wildcard if no contract is found.
        """
        try:
            source = source_path.read_text()
            # Match 'contract <Name>' tokens, preferring non-abstract non-interface
            contracts = re.findall(
                r"^\s*contract\s+(\w+)", source, re.MULTILINE
            )
            if contracts:
                # Use the last concrete contract (typically the main one)
                return f"src/Vulnerable.sol:{contracts[-1]}"
        except (FileNotFoundError, ValueError, IndexError) as e:
            logger.debug("Could not extract contract name: %s", e)
        # Fallback: use conventional name (forge requires exact contract name, not wildcard)
        return "src/Vulnerable.sol:Vulnerable"

    def _deploy_target(self, workspace: Path, task_json: dict) -> Optional[str]:
        """Deploy target contract to Anvil. Returns contract address."""
        deploy_config = task_json.get("deployment_config", {})
        initial_balance = deploy_config.get("initial_balance", 0)

        try:
            rpc_url = f"http://{ANVIL_HOST}:{self.anvil_port}"

            # Extract the primary contract name from the source
            contract_spec = self._extract_contract_name(workspace / "src" / "Vulnerable.sol")

            # SECURITY: Use Anvil's --unlocked accounts instead of passing
            # the private key as a CLI argument (visible in `ps aux`).
            # All Anvil accounts are pre-unlocked, so we use --from + --unlocked.
            cmd = [
                "forge", "create",
                "--root", str(workspace),
                "--rpc-url", rpc_url,
                "--unlocked",
                "--from", DEPLOYER_ADDRESS,
                "--broadcast",
                "--json",
                contract_spec,
            ]

            if initial_balance > 0:
                cmd.extend(["--value", str(initial_balance)])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                cwd=str(workspace),
            )

            if result.returncode != 0:
                return None

            # Parse deployed address from JSON output (Foundry 1.5+)
            try:
                data = json.loads(result.stdout)
                addr = data.get("deployedTo") or data.get("contractAddress")
                if addr:
                    return addr
            except json.JSONDecodeError:
                pass

            # Fallback: search for older text format
            for line in result.stdout.split("\n"):
                if "Deployed to:" in line:
                    return line.split("Deployed to:")[-1].strip()

            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _capture_state(self, target_address: str) -> dict:
        """Capture contract state via RPC.

        Captures the target contract state AND any helper contracts that were
        deployed during the exploit (flash loan providers, attacker contracts, etc.).
        The ``anvil_dumpState`` call returns the entire chain state — we extract
        every account that has code deployed (i.e. is a contract).
        """
        import urllib.request

        rpc_url = f"http://{ANVIL_HOST}:{self.anvil_port}"

        def rpc_call(method: str, params: list) -> dict:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1,
            }).encode()
            req = urllib.request.Request(rpc_url, data=payload,
                                          headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())

        state = {}
        try:
            # Get balance
            bal_resp = rpc_call("eth_getBalance", [target_address, "latest"])
            state["balance"] = int(bal_resp.get("result", "0x0"), 16)

            # Get code (to verify contract exists)
            code_resp = rpc_call("eth_getCode", [target_address, "latest"])
            state["has_code"] = len(code_resp.get("result", "0x")) > 2

            # Try Anvil's anvil_dumpState for full storage (catches mappings/dynamic arrays)
            state["storage"] = {}
            state["helper_contracts"] = {}  # addr → {balance, storage}
            full_dump_ok = False
            try:
                dump_resp = rpc_call("anvil_dumpState", [])
                raw = dump_resp.get("result")
                if raw and isinstance(raw, dict):
                    for addr, acct_data in raw.items():
                        if not isinstance(acct_data, dict):
                            continue
                        addr_lower = addr.lower()
                        storage = acct_data.get("storage", {})
                        non_zero = {
                            s: v for s, v in storage.items()
                            if v and v != "0x" + "0" * 64
                        }

                        if addr_lower == target_address.lower():
                            state["storage"] = non_zero
                            full_dump_ok = True
                        else:
                            # Capture helper contracts (non-EOA accounts with code)
                            code = acct_data.get("code", "0x")
                            if code and len(code) > 2:
                                balance = acct_data.get("balance", "0x0")
                                if isinstance(balance, str):
                                    balance = int(balance, 16) if balance.startswith("0x") else int(balance)
                                state["helper_contracts"][addr_lower] = {
                                    "balance": balance,
                                    "storage_slots": len(non_zero),
                                    "storage": non_zero if len(non_zero) <= 32 else {},
                                }
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                logger.debug("anvil_dumpState failed or returned unexpected format")

            if not full_dump_ok:
                # Fallback: poll slots 0-63 (wider than before, but still limited)
                for slot in range(64):
                    slot_hex = hex(slot)
                    stor_resp = rpc_call("eth_getStorageAt", [target_address, slot_hex, "latest"])
                    val = stor_resp.get("result", "0x0")
                    if val != "0x0000000000000000000000000000000000000000000000000000000000000000":
                        state["storage"][slot_hex] = val

            # Capture event logs emitted by ANY contract (including helpers)
            state["logs"] = []
            try:
                log_resp = rpc_call("eth_getLogs", [{
                    "fromBlock": "0x0",
                    "toBlock": "latest",
                }])
                logs = log_resp.get("result", [])
                if isinstance(logs, list):
                    state["logs"] = logs
            except (OSError, json.JSONDecodeError, KeyError, TypeError):
                logger.debug("eth_getLogs failed for state capture")

        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.debug("State capture failed: %s", e)

        return state

    def _execute_exploit(self, workspace: Path, target_address: str) -> dict:
        """Execute the exploit test via forge test."""
        rpc_url = f"http://{ANVIL_HOST}:{self.anvil_port}"

        try:
            result = subprocess.run(
                [
                    "forge", "test",
                    "--root", str(workspace),
                    "--fork-url", rpc_url,
                    "-vvvv",  # Maximum verbosity for trace
                    "--json",
                    "--gas-report",
                ],
                capture_output=True, text=True,
                timeout=VALIDATION_TIMEOUT,
                cwd=str(workspace)
            )

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"returncode": -1, "stdout": "", "stderr": "timeout", "success": False}
        except FileNotFoundError:
            return {"returncode": -1, "stdout": "", "stderr": "forge not found", "success": False}

    def _build_trace(self, pre_state: dict, post_state: dict, exec_result: dict) -> ExecutionTrace:
        """Build ExecutionTrace from before/after state snapshots."""
        trace = ExecutionTrace()

        # Balance diff
        trace.balance_before = pre_state.get("balance", 0)
        trace.balance_after = post_state.get("balance", 0)
        trace.balance_delta = trace.balance_after - trace.balance_before

        # Storage diffs
        pre_storage = pre_state.get("storage", {})
        post_storage = post_state.get("storage", {})
        all_slots = set(pre_storage.keys()) | set(post_storage.keys())

        for slot in sorted(all_slots):
            before = pre_storage.get(slot, "0x" + "0" * 64)
            after = post_storage.get(slot, "0x" + "0" * 64)
            if before != after:
                trace.storage_diffs.append(StorageSlotDiff(
                    slot=slot, before=before, after=after
                ))

        # Event logs (diff: new logs in post that weren't in pre)
        pre_logs = pre_state.get("logs", [])
        post_logs = post_state.get("logs", [])
        pre_log_set = {json.dumps(l, sort_keys=True) for l in pre_logs}
        for log in post_logs:
            log_key = json.dumps(log, sort_keys=True)
            if log_key not in pre_log_set:
                trace.event_logs.append(log)

        # Parse execution result
        trace.reverted = not exec_result.get("success", False)
        if trace.reverted:
            trace.revert_reason = exec_result.get("stderr", "")[:500]

        # Parse gas usage from forge output
        stdout = exec_result.get("stdout", "")
        try:
            if stdout.strip().startswith("{"):
                result_json = json.loads(stdout)
                # Navigate forge test JSON output
                for suite in result_json.values():
                    if isinstance(suite, dict) and "test_results" in suite:
                        for test_name, test_result in suite["test_results"].items():
                            if isinstance(test_result, dict):
                                trace.gas_used = test_result.get("gas_used", 0)
                                if test_result.get("status") == "Failure":
                                    trace.reverted = True
                                    trace.revert_reason = test_result.get("reason", "")
        except (json.JSONDecodeError, KeyError, TypeError):
            # Estimate gas from state changes
            trace.gas_used = 21_000 + len(trace.storage_diffs) * 5_000

        # Extract function selectors from call trace (if available in stderr)
        selectors = set()
        for line in exec_result.get("stderr", "").split("\n"):
            if "├─" in line or "└─" in line:
                # Parse forge trace format
                parts = line.split("::")
                if len(parts) >= 2:
                    # Use the full function signature (e.g. "withdraw(uint256)") for
                    # correct ABI selector computation, not just the bare name.
                    raw = parts[-1].strip()
                    # Strip trailing return type / whitespace after closing paren
                    paren_open = raw.find("(")
                    paren_close = raw.rfind(")")
                    if paren_open != -1 and paren_close != -1:
                        func_sig = raw[:paren_close + 1]
                    else:
                        func_sig = raw.split()[0] if raw else ""
                    if func_sig:
                        from validator.utils.hashing import keccak256
                        selector = keccak256(func_sig.encode())[2:10]  # first 4 bytes
                        selectors.add(selector)
        trace.function_selectors = sorted(selectors)

        return trace

    def _has_state_change(self, trace: ExecutionTrace) -> bool:
        """Check if exploit produced any measurable state change."""
        if trace.storage_diffs:
            return True
        if trace.balance_delta != 0:
            return True
        if trace.event_logs:
            return True
        return False

    def _compute_fingerprint(self, trace: ExecutionTrace) -> str:
        """
        Compute canonical exploit fingerprint.

        fingerprint = keccak(
            function_selectors,
            sorted_storage_slot_diffs,
            balance_delta,
            call_graph_hash
        )
        """
        components = []

        # Function selectors (sorted)
        components.append(",".join(sorted(trace.function_selectors)))

        # Sorted storage slot diffs
        slot_diffs = []
        for diff in sorted(trace.storage_diffs, key=lambda d: d.slot):
            slot_diffs.append(f"{diff.slot}:{diff.before}->{diff.after}")
        components.append("|".join(slot_diffs))

        # Balance delta
        components.append(str(trace.balance_delta))

        # Call graph hash (from selectors for now)
        call_graph_str = "->".join(trace.function_selectors)
        components.append(call_graph_str)

        canonical = "::".join(components)
        from validator.utils.hashing import keccak256
        fingerprint = keccak256(canonical.encode())
        return fingerprint

    def _finalize(self, report: ValidationReport, start_time: float) -> ValidationReport:
        """Add timing info to report."""
        report.validation_time_ms = int((time.monotonic() - start_time) * 1000)
        return report


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Validate an exploit submission")
    parser.add_argument("--task", type=str, required=True, help="Path to task directory")
    parser.add_argument("--exploit", type=str, required=True, help="Path to exploit .sol file")
    parser.add_argument("--validator-id", type=str, default="validator-0")
    parser.add_argument("--port", type=int, default=ANVIL_PORT_BASE)
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    task_dir = Path(args.task)
    task_json_path = task_dir / "task.json"
    if not task_json_path.exists():
        logger.error("task.json not found in %s", task_dir)
        return

    task_json = json.loads(task_json_path.read_text())
    task_json["_source_dir"] = str(task_dir)

    exploit_source = Path(args.exploit).read_text()
    submission = ExploitSubmission(
        task_id=task_json["task_id"],
        exploit_source=exploit_source,
    )

    engine = ValidationEngine(
        validator_id=args.validator_id,
        anvil_port=args.port,
    )

    logger.info("Validating exploit for task %s...", submission.task_id[:16])
    report = engine.validate(task_json, submission)

    logger.info("%s %s",
                "+" if report.result == ValidationResult.VALID else "-",
                report.result.value)
    if report.fingerprint:
        logger.info("Fingerprint: %s...", report.fingerprint[:20])
    if report.severity_score:
        logger.info("Severity: %.4f", report.severity_score)
    logger.info("Time: %dms", report.validation_time_ms)
    if report.error_message:
        logger.warning("Error: %s", report.error_message)

    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2))
        logger.info("Report saved to %s", args.output)

    # Always emit JSON on stdout as the LAST line so the Docker sandbox
    # orchestrator (_validate_in_docker) can parse it.
    print(json.dumps(report.to_dict(), separators=(",", ":")))


if __name__ == "__main__":
    main()
