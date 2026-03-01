# Testing Guide

Comprehensive guide to running and writing tests for the VALayr exploit subnet.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Test Suites](#test-suites)
4. [Running Tests](#running-tests)
5. [Solidity Contract Tests](#solidity-contract-tests)
6. [Python Test Suites](#python-test-suites)
7. [Determinism Verification](#determinism-verification)
8. [CI Pipeline](#ci-pipeline)
9. [Writing New Tests](#writing-new-tests)
10. [Debugging Test Failures](#debugging-test-failures)
11. [Test Coverage](#test-coverage)

---

## Overview

VALayr maintains two parallel test ecosystems:

| Ecosystem | Framework                  | Location          | Purpose                                     |
| --------- | -------------------------- | ----------------- | ------------------------------------------- |
| Solidity  | Foundry (`forge test`)     | `contracts/test/` | Smart contract correctness                  |
| Solidity  | Foundry (exploits profile) | `exploits/`       | Example exploit verification                |
| Python    | pytest                     | `tests/`          | Integration, pipeline, live Anvil, extended |

Both ecosystems are exercised in CI on every push and pull request to `main` and `develop`.

---

## Prerequisites

### Tools

| Tool    | Version                | Install                                                                           |
| ------- | ---------------------- | --------------------------------------------------------------------------------- |
| Foundry | nightly-2024-12-01     | `curl -L https://foundry.paradigm.xyz \| bash && foundryup -v nightly-2024-12-01` |
| Python  | 3.10 – 3.13            | System package manager or `pyenv`                                                 |
| Anvil   | (bundled with Foundry) | Installed with Foundry                                                            |

### Python Dependencies

```bash
pip install -r requirements.txt
pip install -e ".[dev]"          # pytest, pytest-timeout, black, ruff
```

### Module Symlinks

Hyphenated directory names need symlinks for Python imports:

```bash
ln -sf task-generator task_generator
ln -sf subnet-adapter subnet_adapter
```

The CI pipeline and `tests/conftest.py` handle this automatically.

---

## Test Suites

### Solidity Tests (`contracts/test/`)

| File                     | Tests | Description                                                     |
| ------------------------ | ----- | --------------------------------------------------------------- |
| `CommitReveal.t.sol`     | 7     | Commit/reveal lifecycle, window enforcement, nonce validation   |
| `ExploitRegistry.t.sol`  | 5     | Exploit recording, deduplication, quorum, severity, rewards     |
| `ProtocolRegistry.t.sol` | 5     | Contract registration, bounties, exploit claims, deactivation   |
| `AdversarialMode.t.sol`  | 11    | Invariant registry, adversarial scoring, multi-round challenges |

### Example Exploits (`exploits/`)

| Directory              | Vulnerability       | Technique                                     |
| ---------------------- | ------------------- | --------------------------------------------- |
| `reentrancy_basic/`    | Reentrancy          | Re-enter `withdraw()` during ETH callback     |
| `auth_bypass_missing/` | Access control      | Unprotected `setOwner()` takeover             |
| `overflow_unchecked/`  | Integer overflow    | Underflow in `unchecked` block                |
| `access_selfdestruct/` | Access control      | Unprotected `selfdestruct` permanent lock     |
| `flash_loan_oracle/`   | Oracle manipulation | AMM spot price manipulation via flash loan    |
| `upgradeable_vault/`   | Proxy vulnerability | Re-initialization of unguarded `initialize()` |

### Python Tests (`tests/`)

| File                  | Scope            | Timeout | Description                                            |
| --------------------- | ---------------- | ------- | ------------------------------------------------------ |
| `test_integration.py` | Unit/Integration | 120 s   | Core pipeline components without live blockchain       |
| `test_pipeline.py`    | End-to-end       | 120 s   | Full task → exploit → validation pipeline              |
| `test_live_anvil.py`  | Live chain       | 120 s   | Against running Anvil instance                         |
| `test_extended.py`    | Extended         | 60 s    | Edge cases, mutator verification, additional scenarios |

---

## Running Tests

### Quick: Run Everything

```bash
# Full build + all tests
./scripts/build.sh
```

### Solidity Tests Only

```bash
# Default profile (contract tests)
forge test -vvv

# Exploit profile (example exploits)
FOUNDRY_PROFILE=exploits forge test -vvv

# Specific test file
forge test --match-path contracts/test/CommitReveal.t.sol -vvv

# Specific test function
forge test --match-test test_revealAfterCommitWindow -vvv

# With gas snapshot
forge snapshot
```

### Python Tests Only

```bash
# All Python tests
PYTHONHASHSEED=0 python -m pytest tests/ -v --timeout=120

# Individual suites
PYTHONHASHSEED=0 python -m pytest tests/test_integration.py -v --timeout=120
PYTHONHASHSEED=0 python -m pytest tests/test_pipeline.py -v --timeout=120
PYTHONHASHSEED=0 python -m pytest tests/test_live_anvil.py -v --timeout=120
PYTHONHASHSEED=0 python -m pytest tests/test_extended.py -v --timeout=60

# Specific test
PYTHONHASHSEED=0 python -m pytest tests/test_pipeline.py::test_full_pipeline -v
```

> **Important:** Always set `PYTHONHASHSEED=0` for deterministic results. The CI pipeline enforces this.

### Determinism Verification

```bash
bash scripts/verify-determinism.sh
```

This script verifies 6 categories (see [Determinism Verification](#determinism-verification) section below).

---

## Solidity Contract Tests

### Test Structure

All Solidity tests use the Foundry `forge-std/Test.sol` base contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/YourContract.sol";

contract YourContractTest is Test {
    YourContract public target;

    function setUp() public {
        target = new YourContract();
        // ... setup state
    }

    function test_someFeature() public {
        // Arrange → Act → Assert
        target.doSomething();
        assertEq(target.value(), expected);
    }

    function test_revertCase() public {
        vm.expectRevert(YourContract.SomeError.selector);
        target.badCall();
    }
}
```

### Key Cheatcodes Used

| Cheatcode                   | Purpose                             | Example                                    |
| --------------------------- | ----------------------------------- | ------------------------------------------ |
| `vm.prank(addr)`            | Set `msg.sender` for next call      | `vm.prank(attacker); target.steal()`       |
| `vm.deal(addr, amount)`     | Set ETH balance                     | `vm.deal(address(target), 10 ether)`       |
| `vm.warp(timestamp)`        | Set `block.timestamp`               | `vm.warp(block.timestamp + 2 hours)`       |
| `vm.expectRevert(selector)` | Assert next call reverts            | `vm.expectRevert(Contract.Error.selector)` |
| `vm.startPrank(addr)`       | Set `msg.sender` for multiple calls | Multi-step attack sequences                |
| `makeAddr(name)`            | Create labeled address              | `address attacker = makeAddr("attacker")`  |

### CommitReveal Tests

Tests the full commit-reveal lifecycle:

- **`test_openTask`** — Task opens, commit window active
- **`test_commit`** — Hash committed, state updated
- **`test_doubleCommit_reverts`** — One commit per miner per task
- **`test_commitWithoutTask_reverts`** — Must open task first
- **`test_revealAfterCommitWindow`** — Successful reveal in correct window
- **`test_revealBeforeCommitWindowEnds_reverts`** — Cannot reveal early
- **`test_revealAfterRevealWindowCloses_reverts`** — Cannot reveal late
- **`test_revealWithWrongNonce_reverts`** — Invalid nonce rejected
- **`test_doubleReveal_reverts`** — Cannot reveal twice

### ExploitRegistry Tests

Tests deduplication and reward logic:

- **`test_recordFirstExploit`** — First submission gets full reward (1e18)
- **`test_recordDuplicateExploit`** — Duplicate gets 10% reward (1e17)
- **`test_insufficientQuorum_reverts`** — Below 5-validator quorum
- **`test_zeroSeverity_reverts`** — Zero severity rejected
- **`test_effectiveReward`** — Reward = base × multiplier × severity

### AdversarialMode Tests

Tests Stage 3 invariant writer vs. breaker system:

- **`test_submitInvariant`** — Class A miner submits invariant
- **`test_recordChallenge_hold / _broken`** — Score updates on hold/break
- **`test_processChallenge_broken / _held`** — Scoring contract awards points
- **`test_multipleRounds_scoring`** — Multi-round cumulative scoring

---

## Python Test Suites

### Shared Fixtures (`tests/conftest.py`)

The conftest provides:

- **Project root on `sys.path`** — All imports work regardless of invocation directory
- **Foundry on `PATH`** — Auto-detects `~/.foundry/bin`
- **Module aliases** — `task_generator_module` and `subnet_adapter_module` for hyphenated directories
- **`anvil` session fixture** — Shared Anvil instance for live tests (auto-skips if not installed)

### Integration Tests (`test_integration.py`)

Tests core components in isolation:

- Task generation with deterministic seeds
- Validation engine scoring
- Fingerprint extraction
- Anti-collusion detection

### Pipeline Tests (`test_pipeline.py`)

Tests the full end-to-end pipeline:

1. Generate task corpus
2. Produce exploit submission
3. Run validation engine
4. Extract fingerprint
5. Compute severity score
6. Check dedup result

### Live Anvil Tests (`test_live_anvil.py`)

Tests against a real Anvil instance:

- Deploy contracts
- Submit and validate exploits
- Verify on-chain state changes
- Test deterministic execution

### Extended Tests (`test_extended.py`)

Edge cases and advanced scenarios:

- Mutator output verification
- Boundary conditions
- Error handling paths
- Multi-template coverage

---

## Determinism Verification

The `scripts/verify-determinism.sh` script validates 6 categories:

### 1. Compiler Versions

Verifies `solc 0.8.28` is resolved by Foundry. Different compiler versions produce different bytecode, breaking validator consensus.

### 2. Python Determinism

Checks `PYTHONHASHSEED=0`. Without this, Python dict ordering is random, breaking fingerprint determinism.

### 3. Anvil Configuration

Validates canonical parameters:

| Parameter               | Required Value |
| ----------------------- | -------------- |
| `ANVIL_BLOCK_TIMESTAMP` | `1700000000`   |
| `ANVIL_BLOCK_NUMBER`    | `18000000`     |
| `ANVIL_GAS_LIMIT`       | `30000000`     |
| `ANVIL_CHAIN_ID`        | `31337`        |

All validators **must** use identical Anvil parameters. Different parameters = different execution results = failed quorum.

### 4. Bytecode Reproducibility

Compiles contracts twice with `forge build --force` and compares output hashes. If they differ, the toolchain is non-deterministic.

### 5. Task Corpus Determinism

Generates the task corpus twice with `seed=42` and compares manifest hashes. Corpus generation must be perfectly reproducible.

### 6. Docker Image

Reports the Docker image ID if available. All validators should run the same image version.

### Running

```bash
# Standalone (applies canonical defaults)
bash scripts/verify-determinism.sh

# With explicit env (CI does this)
ANVIL_BLOCK_TIMESTAMP=1700000000 \
ANVIL_BLOCK_NUMBER=18000000 \
ANVIL_GAS_LIMIT=30000000 \
ANVIL_CHAIN_ID=31337 \
PYTHONHASHSEED=0 \
bash scripts/verify-determinism.sh
```

Exit code 1 = failures detected. **Do NOT run validation until all checks pass.**

---

## CI Pipeline

The GitHub Actions CI (`.github/workflows/ci.yml`) runs on every push/PR to `main` and `develop`.

### Jobs

| Job           | Runner                                   | What it does                                                  |
| ------------- | ---------------------------------------- | ------------------------------------------------------------- |
| `foundry`     | ubuntu-latest                            | Compile, run contract tests, run exploit tests, gas snapshots |
| `python`      | ubuntu-latest × {3.10, 3.11, 3.12, 3.13} | Integration, pipeline, live Anvil, extended tests             |
| `determinism` | ubuntu-latest                            | Full determinism verification script                          |
| `lint`        | ubuntu-latest                            | `forge fmt --check`, compiler warning detection               |

### Key CI Behaviors

- **Foundry pinned** to `nightly-2024-12-01` via `foundry-rs/foundry-toolchain@v1`
- **Python matrix** tests across 4 versions (3.10 – 3.13)
- **`PYTHONHASHSEED=0`** enforced on all Python test steps
- **Submodules** checked out recursively (`submodules: recursive`)
- **Module symlinks** created before Python tests (`ln -sf task-generator task_generator`)
- **Timeouts** enforced per test suite (60 s – 120 s)

### Interpreting CI Results

```
foundry    ✓  — All contract tests pass, exploits compile + execute
python     ✓  — All 4 Python versions pass all test suites
determinism ✓ — Build is reproducible, config is canonical
lint       ✓  — Code formatted, no compiler warnings
```

If `determinism` fails but `foundry` passes, the toolchain changed. Pin Foundry version.

If `python` fails on one version but passes others, check version-specific behavior (e.g., `match` statements require 3.10+).

---

## Writing New Tests

### Adding a Solidity Test

1. Create `contracts/test/YourFeature.t.sol`
2. Import `forge-std/Test.sol` and the contract under test
3. Use `setUp()` for deployment and state initialization
4. Prefix test functions with `test_` (Forge auto-discovers them)
5. Use `vm.expectRevert` for revert assertions
6. Run: `forge test --match-path contracts/test/YourFeature.t.sol -vvv`

### Adding an Exploit Test

1. Create `exploits/your_vuln_class/Exploit.sol`
2. Include the vulnerable contract inline (self-contained)
3. Write a `test_run()` or `test_*()` function
4. Assert fund drain / state corruption with `assertLt`, `assertGt`, etc.
5. Run: `FOUNDRY_PROFILE=exploits forge test --match-path exploits/your_vuln_class/Exploit.sol -vvv`

### Adding a Python Test

1. Add test functions to existing file or create `tests/test_yourfeature.py`
2. Use fixtures from `conftest.py` (e.g., `anvil` for live tests)
3. Set `PYTHONHASHSEED=0` when running
4. Use `pytest.mark.skipIf` for conditional execution
5. Keep timeouts reasonable (< 120 s)

### Test Naming Conventions

| Convention                               | Example                        |
| ---------------------------------------- | ------------------------------ |
| Solidity: `test_<behavior>`              | `test_revealAfterCommitWindow` |
| Solidity revert: `test_<action>_reverts` | `test_doubleCommit_reverts`    |
| Python: `test_<feature>_<scenario>`      | `test_pipeline_full_cycle`     |

---

## Debugging Test Failures

### Solidity

```bash
# Maximum verbosity (shows traces)
forge test --match-test test_failing -vvvv

# Debug specific test with step-through
forge debug --match-test test_failing

# Gas report
forge test --gas-report
```

### Python

```bash
# Show print output
PYTHONHASHSEED=0 python -m pytest tests/test_pipeline.py -v -s

# Drop into debugger on failure
PYTHONHASHSEED=0 python -m pytest tests/test_pipeline.py --pdb

# Run single test
PYTHONHASHSEED=0 python -m pytest tests/test_pipeline.py::test_specific -v
```

### Anvil Issues

```bash
# Check if Anvil is running
lsof -i :8545

# Start manually with canonical config
anvil \
  --timestamp 1700000000 \
  --fork-block-number 18000000 \
  --gas-limit 30000000 \
  --chain-id 31337 \
  --block-time 1

# Test connectivity
cast block-number --rpc-url http://localhost:8545
```

### Common Issues

| Symptom                               | Cause                   | Fix                                    |
| ------------------------------------- | ----------------------- | -------------------------------------- |
| `ModuleNotFoundError: task_generator` | Missing symlinks        | `ln -sf task-generator task_generator` |
| Determinism test fails                | Wrong `PYTHONHASHSEED`  | Set `PYTHONHASHSEED=0`                 |
| Anvil tests skip                      | Foundry not installed   | Install Foundry                        |
| Bytecode hash mismatch                | Solc version drift      | Pin via `foundry.toml`                 |
| Gas snapshot fails                    | Expected values changed | Run `forge snapshot` to update         |

---

## Test Coverage

### Solidity Coverage

```bash
forge coverage
```

Generates a coverage report for all Solidity tests. Focus areas:

- All public/external functions in `CommitReveal.sol`, `ExploitRegistry.sol`, `ProtocolRegistry.sol`
- All error paths (custom errors)
- All modifier guards (onlyOwner, onlyValidator)
- Edge cases in time-window logic

### Python Coverage

```bash
pip install pytest-cov
PYTHONHASHSEED=0 python -m pytest tests/ --cov=validator --cov=task-generator --cov-report=html
```

Open `htmlcov/index.html` for a detailed coverage report.
