# VALayr — Developer Guide

> Version 1.1 · Last updated: 2026-03-03

This guide is for developers who want to contribute to VALayr's core codebase — adding features, fixing bugs, extending the validation engine, writing new mutators, or improving contracts.

For **miner participation** (writing exploits), see [MINER_GUIDE.md](MINER_GUIDE.md).
For **deployment and operations**, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Table of Contents

- [1. Development Setup](#1-development-setup)
- [2. Project Layout](#2-project-layout)
- [3. Running the System Locally](#3-running-the-system-locally)
- [4. Testing](#4-testing)
- [5. Adding a New Vulnerability Template](#5-adding-a-new-vulnerability-template)
- [6. Writing a New Mutator](#6-writing-a-new-mutator)
- [7. Extending the Validation Engine](#7-extending-the-validation-engine)
- [8. Adding a Smart Contract](#8-adding-a-smart-contract)
- [9. Modifying Scoring or Incentives](#9-modifying-scoring-or-incentives)
- [10. Code Conventions](#10-code-conventions)
- [11. Debugging Tips](#11-debugging-tips)

---

## 1. Development Setup

### 1.1 Clone & Install

```bash
git clone https://github.com/suman101/VALayr.git
cd VALayr

# Python dependencies
pip install -e ".[dev]"

# Foundry (pinned version — do NOT use latest)
curl -L https://foundry.paradigm.xyz | bash
foundryup --version nightly-2024-12-01

# Solidity dependencies
cd contracts && forge install && cd ..

# Verify
forge test --root contracts -v        # Solidity tests
python3 -m pytest tests/ -q           # Python tests
```

> **Note:** The repository uses directory symlinks for Python module imports: `task_generator → task-generator/` and `subnet_adapter → subnet-adapter/`. These are checked into Git. If they appear broken after cloning on Windows, recreate them with `mklink /D task_generator task-generator`.

> **Solidity dependencies:** The `contracts/lib/forge-std` submodule is installed by `forge install`. If you see missing import errors, run `cd contracts && forge install` again.

### 1.2 Environment Variables

```bash
# Required for determinism
export PYTHONHASHSEED=0
export PYTHONDONTWRITEBYTECODE=1

# Optional: logging
export EXPLOIT_LOG_LEVEL=DEBUG
export EXPLOIT_LOG_FILE=dev.log
```

### 1.3 IDE Setup

**VS Code** (recommended extensions):

- Python (ms-python)
- Solidity (JuanBlanco.solidity or NomicFoundation.hardhat-solidity)
- Even Better TOML

**Settings:**

```json
{
  "python.analysis.typeCheckingMode": "basic",
  "editor.rulers": [100],
  "files.trimTrailingWhitespace": true
}
```

---

## 2. Project Layout

```
valayr/
├── contracts/                 # Solidity — on-chain state
│   ├── src/                   #   CommitReveal, ExploitRegistry, ProtocolRegistry
│   │   └── stage3/            #   AdversarialMode (Stage 3)
│   ├── test/                  #   Foundry test suites
│   ├── script/                #   Deployment scripts
│   ├── lib/forge-std/         #   Forge standard library
│   ├── corpus/                #   Generated vulnerable contracts
│   └── foundry.toml           #   Compiler config (pinned)
│
├── validator/                 # Python — validator-side logic
│   ├── engine/validate.py     #   Sandboxed exploit execution
│   ├── fingerprint/dedup.py   #   State-impact fingerprinting + dedup
│   ├── scoring/severity.py    #   Algorithmic severity scoring
│   ├── anticollusion/         #   Multi-validator consensus
│   │   └── consensus.py       #   Quorum, divergence, slashing
│   ├── commit_reveal.py       #   On-chain + simulated commit-reveal
│   ├── metrics.py             #   /health + /metrics HTTP server
│   └── utils/                 #   Logging, keccak256 hashing
│
├── task-generator/            # Python — deterministic corpus generation
│   ├── generate.py            #   CorpusGenerator + TaskPackage
│   ├── mutator/               #   Pluggable mutation pipeline
│   │   ├── base.py            #   Abstract Mutator base class
│   │   ├── registry.py        #   MutationRegistry (pipeline)
│   │   ├── rename.py          #   Identifier renaming
│   │   ├── storage.py         #   Storage layout shifting
│   │   ├── balance.py         #   Ether literal rewriting
│   │   └── deadcode.py        #   Dead code injection
│   └── templates/             #   Vulnerable contract templates
│
├── subnet-adapter/            # Python — Bittensor weight computation
│   └── incentive.py           #   SubnetIncentiveAdapter
│
├── neurons/                   # Python — Bittensor neuron wrappers
│   ├── validator.py           #   ValidatorNeuron
│   ├── miner.py               #   MinerNeuron
│   └── protocol.py            #   Synapse definitions
│
├── miner/                     # Python — miner CLI
│   └── cli.py                 #   MinerCLI (tasks, scaffold, submit, scores)
│
├── orchestrator.py            # Python — central pipeline glue
├── exploits/                  # Example exploits for reference
├── tests/                     # Python test suites
├── docker/                    # Container infrastructure
├── scripts/                   # Build + verification scripts
├── docs/                      # Documentation
├── pyproject.toml             # Package config
├── foundry.toml               # Top-level Foundry config
└── requirements.txt           # Pinned dependencies
```

**Hyphenated → Underscored mapping** (Python import):

- `task-generator/` → import as `task_generator`
- `subnet-adapter/` → import as `subnet_adapter`

This is handled by `pyproject.toml` `[tool.setuptools.package-dir]` and Docker symlinks.

---

## 3. Running the System Locally

### 3.1 Generate Task Corpus

```bash
python3 task-generator/generate.py --count 2 --seed 42
```

This creates task packages in `contracts/corpus/` with a `manifest.json`.

### 3.2 Start Validator (Local Mode)

```bash
python3 neurons/validator.py --local
```

Local mode simulates 3 epochs with in-memory commit-reveal.

### 3.3 Use the Miner CLI

```bash
# List available tasks
python3 -m miner.cli tasks

# Inspect a specific task
python3 -m miner.cli task --id 0xabc123

# Generate exploit scaffolding
python3 -m miner.cli scaffold --task 0xabc123

# Submit an exploit
python3 -m miner.cli submit --task 0xabc123 --exploit Exploit.sol

# View scores
python3 -m miner.cli scores
```

### 3.4 Run the Orchestrator Directly

```bash
# Generate corpus
python3 orchestrator.py generate --count 3 --seed 42

# Process a submission
python3 orchestrator.py submit --task 0xabc123 --exploit my_exploit.sol --miner 0xMINER

# Close an epoch
python3 orchestrator.py epoch --epoch 1 --start-block 1000 --end-block 1360
```

---

## 4. Testing

### 4.1 Test Suites

| Suite              | Command                               | Requires Anvil | Coverage                                              |
| ------------------ | ------------------------------------- | -------------- | ----------------------------------------------------- |
| Unit + Integration | `pytest tests/test_integration.py -v` | No             | Task gen, fingerprint, scoring, incentives, consensus |
| Pipeline           | `pytest tests/test_pipeline.py -v`    | No             | End-to-end pipeline simulation                        |
| Extended           | `pytest tests/test_extended.py -v`    | No             | Mutators, metrics, neurons, CLI, sanitisation         |
| Live Anvil         | `pytest tests/test_live_anvil.py -v`  | Yes            | Real sandbox validation                               |
| Solidity           | `forge test --root contracts -vv`     | No             | Smart contract logic                                  |

### 4.2 Run Everything

```bash
# Python tests
python3 -m pytest tests/ -v --timeout=120

# Solidity tests
forge test --root contracts -vv

# Determinism check
PYTHONHASHSEED=0 bash scripts/verify-determinism.sh
```

### 4.3 Writing Tests

**Python:**

```python
# tests/test_my_feature.py
import pytest
from validator.scoring.severity import SeverityScorer

class TestMyFeature:
    def setup_method(self):
        self.scorer = SeverityScorer()

    def test_score_funds_drained(self):
        trace = {
            "balance_delta": -1_000_000_000_000_000_000,  # 1 ETH
            "storage_diffs": [],
            "function_selectors": ["0x12345678"],
        }
        result = self.scorer.score(trace)
        assert 0.0 < result <= 1.0

    def test_score_no_impact(self):
        trace = {"balance_delta": 0, "storage_diffs": [], "function_selectors": []}
        result = self.scorer.score(trace)
        assert result == 0.0
```

**Solidity (Foundry):**

```solidity
// contracts/test/MyContract.t.sol
import "forge-std/Test.sol";
import "../src/MyContract.sol";

contract MyContractTest is Test {
    MyContract target;

    function setUp() public {
        target = new MyContract();
    }

    function test_happyPath() public {
        target.doThing();
        assertEq(target.state(), expected);
    }

    function test_revert_unauthorised() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(MyContract.Unauthorized.selector);
        target.adminFunction();
    }
}
```

### 4.4 Test Fixtures

Shared fixtures are in `tests/conftest.py`. Use them to avoid repeating setup:

```python
@pytest.fixture
def orchestrator():
    return Orchestrator(mode="local")

@pytest.fixture
def sample_task(orchestrator):
    orchestrator.generate_corpus(count_per_class=1, seed=42)
    tasks = orchestrator.list_tasks()
    return tasks[0]
```

---

## 5. Adding a New Vulnerability Template

Templates live in `task-generator/templates/`. Each template is a `.sol` file with a deliberately vulnerable contract.

### 5.1 Create the Template

```solidity
// task-generator/templates/my_vuln_type.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MyVulnType — Template for <vulnerability description>
/// @dev VULNERABILITY: <brief description of the flaw>
contract Vulnerable {
    mapping(address => uint256) public balances;

    // ... vulnerable logic here ...
}
```

**Requirements:**

- Contract must be named `Vulnerable` (the validation engine expects this)
- Must be exploitable — someone should be able to write Solidity that changes state
- Include a comment describing the intended vulnerability
- Use `pragma solidity ^0.8.28`

### 5.2 Register the Template

In `task-generator/generate.py`, add the template to the vulnerability class mapping:

```python
VULNERABILITY_CLASSES = {
    "reentrancy": ["reentrancy_basic.sol", "reentrancy_cross.sol", ...],
    "my-vuln-type": ["my_vuln_type.sol"],  # ← add here
}
```

### 5.3 Create an Example Exploit

Add a reference exploit in `exploits/my_vuln_type/Exploit.sol`:

```solidity
// exploits/my_vuln_type/Exploit.sol
contract ExploitTest is Test {
    function test_run() public {
        // Deploy target, execute exploit, verify state change
    }
}
```

### 5.4 Add Scaffold Hints

In `miner/cli.py`, add hints for the new vulnerability class:

```python
def _exploit_hints(self, vuln_class: str) -> str:
    hints = {
        # ...existing...
        "my-vuln-type": "Hint: Look for <specific pattern>. Consider <strategy>.",
    }
    return hints.get(vuln_class, "Analyse the contract for vulnerabilities.")
```

### 5.5 Test

```bash
# Generate corpus including new templates
python3 task-generator/generate.py --count 1 --seed 42

# Verify the template is included
python3 -m miner.cli tasks

# Submit the reference exploit
python3 orchestrator.py submit --task <ID> --exploit exploits/my_vuln_type/Exploit.sol --miner 0x1234
```

---

## 6. Writing a New Mutator

Mutators are pluggable source transformations that change a contract's surface form without altering its vulnerability semantics.

### 6.1 Create the Mutator

```python
# task-generator/mutator/my_mutator.py
from .base import Mutator

class MyMutator(Mutator):
    """Brief description of what this mutator does."""

    name = "my_mutator"

    def apply(self, source: str, params: dict, seed: int) -> str:
        """
        Apply mutation to Solidity source code.

        Args:
            source: Raw Solidity source
            params: Mutation parameters (from task config)
            seed: Deterministic seed — MUST use for any randomness

        Returns:
            Mutated Solidity source
        """
        import random
        rng = random.Random(seed)  # NEVER use random.random() directly

        # ... transformation logic ...

        return mutated_source
```

**Rules:**

1. **Deterministic** — same `(source, params, seed)` → same output. Always.
2. **Semantics-preserving** — the vulnerability must survive the mutation.
3. **Composable** — the mutator may receive already-mutated source from a prior mutator.

### 6.2 Register the Mutator

In `task-generator/mutator/registry.py`:

```python
from .my_mutator import MyMutator

class MutationRegistry:
    def __init__(self):
        self._mutators = [
            RenameMutator(),
            StorageLayoutMutator(),
            BalanceMutator(),
            DeadCodeMutator(),
            MyMutator(),  # ← add to pipeline
        ]
```

### 6.3 Test

```python
# tests/test_extended.py (or a new file)
from task_generator.mutator.my_mutator import MyMutator

def test_my_mutator_deterministic():
    mutator = MyMutator()
    source = "contract Vulnerable { uint public x; }"
    result1 = mutator.apply(source, {}, seed=42)
    result2 = mutator.apply(source, {}, seed=42)
    assert result1 == result2

def test_my_mutator_changes_source():
    mutator = MyMutator()
    source = "contract Vulnerable { uint public x; }"
    result = mutator.apply(source, {}, seed=42)
    assert result != source

def test_my_mutator_preserves_vulnerability():
    # Compile and validate that the mutated contract is still exploitable
    pass
```

---

## 7. Extending the Validation Engine

### 7.1 Adding a New Rejection Reason

In `validator/engine/validate.py`:

```python
class ValidationResult(Enum):
    # ... existing ...
    REJECT_MY_REASON = "reject_my_reason"  # ← add here
```

Update the validation pipeline to check for the new condition:

```python
def _validate_binary(self, trace: ExecutionTrace) -> ValidationResult:
    # ... existing checks ...
    if my_condition(trace):
        return ValidationResult.REJECT_MY_REASON
    return ValidationResult.VALID
```

### 7.2 Adding a New Fingerprint Component

In `validator/fingerprint/dedup.py`:

```python
@dataclass
class FingerprintComponents:
    # ... existing ...
    my_component: str  # ← add field

    def canonical_string(self) -> str:
        # MUST include the new component deterministically
        parts = [
            # ... existing parts ...
            f"my_component:{self.my_component}",
        ]
        return "|".join(parts)
```

> **Warning:** Adding a fingerprint component changes ALL fingerprints. Existing dedup records will no longer match. Plan migration accordingly.

### 7.3 Modifying Severity Weights

Severity weights are intentionally fixed. To change them:

1. Update constants in `validator/scoring/severity.py`
2. Verify weights still sum to 1.0 (the constructor asserts this)
3. Document the change in CHANGELOG.md with rationale
4. Coordinate with all validators for simultaneous deployment

---

## 8. Adding a Smart Contract

### 8.1 Create the Contract

```solidity
// contracts/src/MyContract.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract MyContract {
    error ZeroAddress();
    event OwnershipTransferred(address indexed prev, address indexed next);

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }
}
```

**Checklist:**

- [ ] Custom errors (not `require` strings) for gas efficiency
- [ ] Events for all state-changing functions
- [ ] Access control modifiers on all mutating functions
- [ ] Zero-address checks where applicable
- [ ] `OwnershipTransferred` event on ownership changes

### 8.2 Write Tests

```solidity
// contracts/test/MyContract.t.sol
import "forge-std/Test.sol";
import "../src/MyContract.sol";

contract MyContractTest is Test {
    // Test happy path, reverts, edge cases, events
}
```

### 8.3 Add to Deploy Script

```solidity
// contracts/script/Deploy.s.sol
import "../src/MyContract.sol";

// In the run() function:
MyContract myContract = new MyContract();
```

### 8.4 Test

```bash
forge test --root contracts -vv --match-contract MyContractTest
```

---

## 9. Modifying Scoring or Incentives

### 9.1 Severity Scoring

Weights are in `validator/scoring/severity.py`. The system enforces:

```python
assert W_FUNDS + W_PRIVILEGE + W_INVARIANT + W_LOCK == 1.0
```

Changing weights affects ALL miners' scores. Coordinate with the validator community.

### 9.2 Incentive Formula

The raw score formula is in `subnet-adapter/incentive.py`:

```python
raw = (unique * avg_sev) + (dupes * avg_sev * 0.1) + (earlies * 0.05) - (invalid * 0.05)
```

Changes here directly affect TAO distribution. Must be:

- Deterministic
- Published (adversarial environment — no hidden rules)
- Coordinated across all validators simultaneously

---

## 10. Code Conventions

### Python

| Rule                                             | Enforcement      |
| ------------------------------------------------ | ---------------- |
| PEP 8, 100-char limit                            | `ruff` / `black` |
| Type hints on all public functions               | Manual review    |
| Imports: stdlib → third-party → local            | `ruff` (isort)   |
| Logging via `get_logger(__name__)`               | Convention       |
| Atomic file I/O (`os.replace` + `fcntl.LOCK_EX`) | Convention       |
| No bare `except`                                 | `ruff`           |

### Solidity

| Rule                                   | Enforcement    |
| -------------------------------------- | -------------- |
| `pragma solidity ^0.8.28`              | `foundry.toml` |
| Custom errors over `require` strings   | Code review    |
| Events for state changes               | Code review    |
| Access modifiers on mutating functions | Code review    |
| UPPER_CASE constants                   | Convention     |

### Git

| Prefix      | Type                  |
| ----------- | --------------------- |
| `feat:`     | New feature           |
| `fix:`      | Bug fix               |
| `security:` | Security hardening    |
| `docs:`     | Documentation         |
| `refactor:` | Non-functional change |
| `test:`     | Test-only change      |
| `ci:`       | CI/CD change          |

---

## 11. Debugging Tips

### Python Debugging

```bash
# Run with debug logging
EXPLOIT_LOG_LEVEL=DEBUG python3 orchestrator.py submit --task 0xabc ...

# Debug a specific test
python3 -m pytest tests/test_integration.py::TestScoring -v -s

# Interactive debugger
python3 -m pytest tests/test_pipeline.py --pdb
```

### Solidity Debugging

```bash
# Verbose trace
forge test --root contracts -vvvv --match-test test_myFunction

# Gas report
forge test --root contracts --gas-report

# Debug in Anvil
anvil --timestamp 1700000000 --block-number 18000000
# In another terminal:
forge test --fork-url http://localhost:8545 -vvvv
```

### Anvil Debug Script

There's a helper at `tests/_debug_anvil.py` for inspecting Anvil state during development.

### Common Gotchas

1. **PYTHONHASHSEED** — If not set to `0`, Python's `hash()` is non-deterministic. The `StorageLayoutMutator` uses `hashlib.sha256` instead, but other code might accidentally use `hash()`.

2. **keccak256 vs SHA-3** — `hashlib.sha3_256` is NIST SHA-3, NOT Ethereum keccak256. Always use `validator.utils.hashing.keccak256`.

3. **Forge test format** — Exploit submissions must have a `test_run()` function (or the configured `entry_function`). The validation engine wraps raw code if needed, but explicit test format is more reliable.

4. **Port conflicts** — Each Anvil instance uses a unique port (thread-safe counter). If tests fail with port errors, check for orphaned Anvil processes: `pkill -f anvil`.

5. **File locking on macOS** — `fcntl.LOCK_EX` works differently on macOS vs Linux. The code handles this, but be aware when testing concurrency.

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture, component interactions, data flow
- [API_REFERENCE.md](API_REFERENCE.md) — Complete API documentation
- [CONTRACT_REFERENCE.md](CONTRACT_REFERENCE.md) — Solidity contract ABIs, events, and errors
- [TESTING.md](TESTING.md) — Test suites, CI pipeline, determinism verification
- [THREAT_MODEL.md](THREAT_MODEL.md) — Security analysis and risk matrix
- [DATA_SCHEMA.md](DATA_SCHEMA.md) — JSON schemas for persistent state files
- [DEPLOYMENT.md](DEPLOYMENT.md) — Production deployment guide
- [MINER_GUIDE.md](MINER_GUIDE.md) — Guide for exploit miners
- [VALIDATOR_GUIDE.md](VALIDATOR_GUIDE.md) — Guide for validator operators
- [EXPLOIT_WRITING_GUIDE.md](EXPLOIT_WRITING_GUIDE.md) — Annotated exploit examples
- [GLOSSARY.md](GLOSSARY.md) — Definitions of all key terms
- [CONTRIBUTING.md](../CONTRIBUTING.md) — PR process and standards

---

_Questions? Open a discussion on GitHub or reach out to the maintainers._
