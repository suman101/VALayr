# Contributing to VALayr

Thank you for your interest in contributing to VALayr! This guide covers the development setup, coding standards, and PR process.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

---

## Development Setup

### Prerequisites

| Tool    | Version            | Install                                                                                  |
| ------- | ------------------ | ---------------------------------------------------------------------------------------- |
| Python  | ≥ 3.10             | [python.org](https://www.python.org/)                                                    |
| Foundry | nightly-2024-12-01 | `curl -L https://foundry.paradigm.xyz \| bash && foundryup --version nightly-2024-12-01` |
| Docker  | ≥ 24.0             | [docker.com](https://www.docker.com/)                                                    |
| Git     | ≥ 2.30             | System package manager                                                                   |

### Quick Start

```bash
# Clone the repository
git clone https://github.com/suman101/VALayr.git
cd VALayr

# Install Python dependencies
pip install -r requirements.txt

# Install Foundry (pinned to nightly-2024-12-01 for deterministic builds)
curl -L https://foundry.paradigm.xyz | bash
foundryup --version nightly-2024-12-01

# Install Solidity dependencies
cd contracts && forge install && cd ..

# Verify setup
forge test --root contracts          # 81 Solidity tests
python3 -m pytest tests/ -q          # 198 Python tests
```

### Environment Variables

```bash
export PYTHONHASHSEED=0              # Required for deterministic builds
# export ETH_PRIVATE_KEY=0x...      # Only for on-chain operations (never commit)
```

---

## Project Structure

```
├── contracts/              # Solidity contracts + Foundry tests
│   ├── src/                #   Production contracts
│   ├── test/               #   Foundry test suites
│   └── foundry.toml        #   Foundry configuration
├── validator/              # Validator-side Python modules
│   ├── engine/             #   Deterministic validation engine
│   ├── fingerprint/        #   Fingerprint + dedup engine
│   ├── anticollusion/      #   Multi-validator consensus
│   ├── scoring/            #   Severity scoring

│   ├── metrics.py          #   Health/metrics HTTP server
│   └── utils/              #   Logging, helpers
├── neurons/                # Bittensor neuron wrappers
│   ├── validator.py        #   Validator neuron
│   ├── miner.py            #   Miner neuron
│   └── protocol.py         #   Synapse definitions
├── miner/                  # Miner CLI tool
├── task-generator/         # Vulnerable contract corpus generator
├── subnet-adapter/         # Bittensor incentive adapter
├── orchestrator.py         # Central pipeline orchestrator
├── docker/                 # Docker infrastructure
├── scripts/                # Build + verification scripts
├── tests/                  # Python test suites
└── docs/                   # Documentation (threat model, etc.)
```

---

## Coding Standards

### Python

- **Style**: PEP 8 with 100-character line limit
- **Type hints**: Required on all public function signatures
- **Imports**: stdlib → third-party → local, separated by blank lines
- **Logging**: Use `from validator.utils.logging import get_logger; logger = get_logger(__name__)`
- **Exceptions**: Always narrow — never `except Exception:` without a specific reason
- **File I/O**: Use atomic writes (`tempfile` + `os.replace`) and file locking (`fcntl.LOCK_EX`) for shared state

```python
# Good
try:
    result = parse_data(raw)
except json.JSONDecodeError as exc:
    logger.warning("Malformed JSON: %s", exc)
    return None

# Bad
try:
    result = parse_data(raw)
except:
    pass
```

### Solidity

- **Version**: `pragma solidity ^0.8.28;`
- **Gas efficiency**: Prefer custom errors (`error ZeroAddress()`) over `require()` with strings
- **Events**: Emit an event for every state-changing external function
- **Access control**: All mutating functions must use `onlyOwner`, `onlyValidator`, or `onlyProtocol`
- **Naming**: CamelCase for contracts/events/errors, camelCase for functions/variables, UPPER_CASE for constants

```solidity
// Good
error ZeroAddress();
event OwnershipTransferred(address indexed prev, address indexed next);

function transferOwnership(address newOwner) external onlyOwner {
    if (newOwner == address(0)) revert ZeroAddress();
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
}

// Bad
function transferOwnership(address newOwner) external {
    require(newOwner != address(0), "zero address");
    owner = newOwner;
}
```

### Docker

- Use non-root users (`appuser`)
- Pin base image digests or exact tags
- Keep `--network=none` for validation containers
- Minimise layer count; combine `RUN` statements

---

## Testing

### Running Tests

```bash
# All Solidity tests
forge test --root contracts -v

# All Python tests (quick)
python3 -m pytest tests/ -q

# Specific test file
python3 -m pytest tests/test_extended.py -v

# With timeout enforcement
python3 -m pytest tests/ --timeout=120

# Determinism verification
PYTHONHASHSEED=0 bash scripts/verify-determinism.sh
```

### Writing Tests

**Solidity** (Foundry):

- Place in `contracts/test/`
- Inherit from `forge-std/Test.sol`
- Use `vm.expectRevert(CustomError.selector)` for error assertions
- Test both happy path and revert cases

**Python** (pytest):

- Place in `tests/`
- Use `conftest.py` fixtures for shared setup
- Mock external services (Anvil, Bittensor) rather than requiring live instances
- Target ≥ 80 % coverage on new code

### CI Pipeline

Every PR triggers:

1. Foundry tests (`forge test`)
2. Python tests across 4 versions (3.10, 3.11, 3.12, 3.13)
3. Determinism verification
4. Solidity lint check

---

## Pull Request Process

1. **Branch** from `main`: `git checkout -b feat/my-feature`
2. **Implement** with tests — no PR without corresponding test coverage
3. **Run locally**: `forge test --root contracts && python3 -m pytest tests/ -q`
4. **Commit** with conventional prefixes:
   - `feat:` new feature
   - `fix:` bug fix
   - `security:` security hardening
   - `docs:` documentation only
   - `refactor:` non-functional change
   - `test:` test-only change
   - `ci:` CI/CD change
5. **Open PR** against `main` with:
   - Description of what and why
   - Link to related issue (if any)
   - Test results screenshot/output
6. **Review** — at least one approval required
7. **Merge** — squash merge preferred

---

## Security

- **Never commit secrets** — use environment variables
- **Read** [SECURITY.md](SECURITY.md) before contributing security-sensitive code
- **Read** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) to understand trust boundaries
- Follow the **Security Checklist** in SECURITY.md for every PR
- Report vulnerabilities via the process in SECURITY.md — not via public issues

---

## Further Reading

- [Developer Guide](docs/DEVELOPER_GUIDE.md) — Detailed development setup, adding templates/mutators/contracts
- [Testing Guide](docs/TESTING.md) — Test suites, CI pipeline, writing tests
- [Architecture](docs/ARCHITECTURE.md) — System architecture and design decisions
- [Glossary](docs/GLOSSARY.md) — Definitions of key terms
