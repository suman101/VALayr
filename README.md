# VALayr

> **v0.1.0** · Bittensor subnet for deterministic, adversarial smart-contract exploit discovery.

VALayr incentivises miners to discover vulnerabilities in opt-in smart contracts. Miners craft Solidity exploits, validators execute them in deterministic sandboxes, and the results are fingerprinted, scored, de-duplicated, and rewarded with TAO.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│ Task Generator   │────▶│  Miners           │────▶│ Validation Engine  │
│ (Deterministic   │     │  (Exploit craft)  │     │ (Docker/Anvil)     │
│  Corpus)         │     └──────────────────┘     └────────┬───────────┘
└─────────────────┘                                        │
                                                           ▼
                         ┌──────────────────┐     ┌────────────────────┐
                         │ Subnet Incentive  │◀────│ Fingerprint/Dedup  │
                         │ Adapter (TAO)     │     │ + Severity Scoring │
                         └──────────────────┘     └────────────────────┘
```

## Hard Constraints

1. **Incentives are on-chain and adversarial.** Every scoring rule is deterministic and published.
2. **Validation must be cheaper than generation.** O(minutes) vs O(hours).
3. **Deterministic reproducibility.** Any observer can re-run validation and reach the same result.

## Getting Started

| I want to…                  | Start here                                 |
| --------------------------- | ------------------------------------------ |
| **Mine** (find exploits)    | [Miner Guide](docs/MINER_GUIDE.md)         |
| **Validate** (run a node)   | [Validator Guide](docs/VALIDATOR_GUIDE.md) |
| **Develop** (contribute)    | [Developer Guide](docs/DEVELOPER_GUIDE.md) |
| **Deploy** (production)     | [Deployment Guide](docs/DEPLOYMENT.md)     |
| **Audit** (security review) | [Threat Model](docs/THREAT_MODEL.md)       |

## Documentation

| Document                                               | Description                                                                              |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| [Architecture](docs/ARCHITECTURE.md)                   | System architecture, component interactions, data flow diagrams, design decisions        |
| [API Reference](docs/API_REFERENCE.md)                 | Complete API documentation: Python modules, synapses, contract ABIs, CLI, HTTP endpoints |
| [Deployment Guide](docs/DEPLOYMENT.md)                 | Production deployment, Docker configuration, monitoring, troubleshooting                 |
| [Developer Guide](docs/DEVELOPER_GUIDE.md)             | Contributing code: setup, testing, adding templates/mutators/contracts                   |
| [Miner Guide](docs/MINER_GUIDE.md)                     | Miner onboarding: writing exploits, submission workflow, scoring, strategies             |
| [Validator Guide](docs/VALIDATOR_GUIDE.md)             | Validator setup, epoch lifecycle, weight setting, monitoring, determinism                |
| [Testing Guide](docs/TESTING.md)                       | Test suites, CI pipeline, determinism verification, writing tests                        |
| [Contract Reference](docs/CONTRACT_REFERENCE.md)       | Solidity contract documentation: ExploitRegistry, ProtocolRegistry, Treasury, Stage 3    |
| [Exploit Writing Guide](docs/EXPLOIT_WRITING_GUIDE.md) | Annotated exploit examples for every vulnerability class, scoring strategies             |
| [Glossary](docs/GLOSSARY.md)                           | Definitions of all key terms and concepts used in the project                            |
| [Threat Model](docs/THREAT_MODEL.md)                   | STRIDE analysis, risk matrix, attack surfaces, security controls                         |
| [Data Schema](docs/DATA_SCHEMA.md)                     | JSON schemas for all persistent state files (fingerprints, epochs, commits)              |
| [Contributing](CONTRIBUTING.md)                        | PR process, coding standards, development setup                                          |
| [Security Policy](SECURITY.md)                         | Vulnerability reporting, scope, disclosure policy                                        |
| [Changelog](CHANGELOG.md)                              | Release history and notable changes                                                      |

## Components

| Component             | Location                           | Status |
| --------------------- | ---------------------------------- | ------ |
| On-chain Contracts    | `contracts/src/`                   | v1     |
| Treasury              | `contracts/src/Treasury.sol`       | v1     |
| Vulnerable Corpus     | `contracts/corpus/`                | v1     |
| Task Generator        | `task-generator/`                  | v1     |
| Mainnet Discovery     | `task-generator/discovery.py`      | v1     |
| Mainnet Source Fetch  | `task-generator/mainnet.py`        | v1     |
| Mutator Framework     | `task-generator/mutator/`          | v1     |
| Validation Engine     | `validator/engine/`                | v1     |
| Fingerprint / Dedup   | `validator/fingerprint/`           | v1     |
| Severity Scoring      | `validator/scoring/`               | v1     |
| Anti-Collusion        | `validator/anticollusion/`         | v1     |
| Bounty System         | `validator/bounty/`                | v1     |
| Reward Splitting      | `validator/bounty/reward_split.py` | v1     |
| Anti-Bypass Detection | `validator/bounty/anti_bypass.py`  | v1     |
| Metrics / Health      | `validator/metrics.py`             | v1     |
| Structured Logging    | `validator/utils/logging.py`       | v1     |
| Subnet Adapter        | `subnet-adapter/`                  | v1     |
| Orchestrator          | `orchestrator.py`                  | v1     |
| Validator Neuron      | `neurons/validator.py`             | v1     |
| Miner Neuron          | `neurons/miner.py`                 | v1     |
| Miner CLI             | `miner/cli.py`                     | v1     |
| Docker Infra          | `docker/`                          | v1     |
| CI / CD               | `.github/workflows/ci.yml`         | v1     |

---

## Quickstart

### Prerequisites

- Python 3.10+
- [Foundry](https://book.getfoundry.sh/) (pinned to `nightly-2024-12-01`)

### Install

```bash
# 1. Clone
git clone https://github.com/suman101/VALayr.git && cd VALayr

# 2. Install Foundry (pinned)
curl -L https://foundry.paradigm.xyz | bash
foundryup --version nightly-2024-12-01

# 3. Install Python deps
pip install -e ".[dev]"

# 4. Build contracts
forge build
```

### Run Locally

```bash
# Generate task corpus
python3 task-generator/generate.py --count 2 --seed 42

# Start validator in local mode
python3 neurons/validator.py --local

# In another terminal — use the miner CLI
python3 -m miner.cli tasks
python3 -m miner.cli scaffold --task 0xabc123
# ... write your exploit ...
python3 -m miner.cli submit --task 0xabc123 --exploit Exploit.sol
python3 -m miner.cli scores
```

### Run Tests

```bash
# All tests
python3 -m pytest tests/ -v

# Contract tests only
forge test -vv

# Live Anvil integration tests (starts/stops Anvil)
python3 -m pytest tests/test_live_anvil.py -v
```

---

## Miner CLI

The `miner/cli.py` module provides a complete workflow for miners:

| Command    | Description                       |
| ---------- | --------------------------------- |
| `tasks`    | List available tasks              |
| `task`     | Inspect a specific task           |
| `scaffold` | Generate an exploit template      |
| `submit`   | Submit an exploit for validation  |
| `status`   | Check previous submission results |
| `scores`   | View current epoch leaderboard    |

```bash
python3 -m miner.cli --address 0xYOUR_HOTKEY tasks
python3 -m miner.cli submit --task 0xdeadbeef --exploit Exploit.sol
```

---

## Orchestrator

The orchestrator (`orchestrator.py`) is the central pipeline glue:

```
task-generator → validation → fingerprint → scoring → incentive → epoch weights
```

It also wires anti-collusion into the validation flow.

### Key Methods

- `generate_corpus(count_per_class, seed)` — generate / refresh the task corpus
- `process_submission(task_id, exploit_source, miner_address)` — full validation pipeline
- `close_epoch(epoch_number, start_block, end_block)` — compute & record epoch weights

---

## Anti-Collusion Engine

Located in `validator/anticollusion/consensus.py`.

- **Random validator assignment** per task (weighted by reliability)
- **Minimum quorum** of 5 validators
- **66% agreement threshold** for consensus
- **Divergence tracking**: rolling window, slash if >20% divergence

All execution traces are public and replayable — anyone can re-run
validation and verify consensus was reached honestly.

The consensus relay runs as a separate Docker service with its own
health endpoint on port 9946.

---

## Mutator Framework

The `task-generator/mutator/` module provides pluggable mutation strategies:

| Mutator                | Effect                                       |
| ---------------------- | -------------------------------------------- |
| `RenameMutator`        | Deterministic variable / function renaming   |
| `StorageLayoutMutator` | Shifts storage slot layout with padding vars |
| `BalanceMutator`       | Rewrites `ether/wei` literals                |
| `DeadCodeMutator`      | Injects inert functions / variables          |

Mutators are composed by `MutationRegistry` and applied in order.
Custom mutators can be added by subclassing `Mutator`.

---

## Metrics & Health

A lightweight HTTP server (no external deps) exposes:

| Endpoint   | Response                                    |
| ---------- | ------------------------------------------- |
| `/health`  | `{"status": "ok"}`                          |
| `/metrics` | JSON: counters, gauges, histogram summaries |

Tracked metrics: `validations_total`, `validations_valid`, `duplicates_total`,
`validation_latency_ms` (p50/p99), `severity_score`, `uptime_seconds`.

```bash
# Standalone
python3 -m validator.metrics --port 9946

# Programmatic
from validator.metrics import MetricsServer, inc, observe
srv = MetricsServer(port=9946)
srv.start()
```

---

## Docker Deployment

### Build

```bash
docker build -t ghcr.io/exploit-subnet/validator:v0.1.0 -f docker/Dockerfile.validator .
docker build -t ghcr.io/exploit-subnet/miner:v0.1.0 -f docker/Dockerfile.miner .
```

### Run with Compose

```bash
cd docker && docker compose up -d
```

Services:

- **validator**: runs with `--network=none` for deterministic isolation
- **consensus-relay**: exposes port 9946 for health/metrics
- **miner**: lightweight miner container

### Verify

```bash
curl http://localhost:9946/health
curl http://localhost:9946/metrics
```

---

## Neurons (Bittensor Integration)

### Validator Neuron (`neurons/validator.py`)

```bash
# Bittensor mode
python3 neurons/validator.py --netuid 1 --wallet.name default --wallet.hotkey default

# Local simulation
python3 neurons/validator.py --local
```

Features: per-miner rate limiting (50/epoch), automatic corpus refresh,
structured logging.

### Miner Neuron (`neurons/miner.py`)

```bash
# Bittensor mode
python3 neurons/miner.py --netuid 1 --wallet.name default --wallet.hotkey default

# Local mode
python3 neurons/miner.py --local
```

---

## Environment Variables

| Variable                            | Default      | Description                              |
| ----------------------------------- | ------------ | ---------------------------------------- |
| `EXPLOIT_LOG_LEVEL`                 | `INFO`       | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `EXPLOIT_LOG_FILE`                  | _(none)_     | Optional log file path                   |
| `ANVIL_BLOCK_TIMESTAMP`             | `1700000000` | Fixed block timestamp for determinism    |
| `ANVIL_BLOCK_NUMBER`                | `18000000`   | Fixed block number                       |
| `ANVIL_GAS_LIMIT`                   | `30000000`   | Block gas limit                          |
| `ANVIL_CHAIN_ID`                    | `31337`      | Chain ID                                 |
| `PYTHONHASHSEED`                    | `0`          | Must be 0 for deterministic Python       |
| `VALAYR_REQUIRE_SANDBOX`            | `true`       | Require Docker sandbox for validation    |
| `VALAYR_EPOCH_COMPUTE_BUDGET`       | `10000`      | Max compute units per epoch              |
| `VALAYR_INVALID_SUBMISSION_PENALTY` | `0.05`       | Penalty for invalid submissions          |
| `VALAYR_DIFFICULTY_MULTIPLIER`      | `1.0`        | Task difficulty scaling factor           |
| `VALAYR_DISCOVERY_ENABLED`          | `false`      | Enable mainnet contract discovery        |
| `VALAYR_DISCOVERY_INTERVAL`         | `3600`       | Discovery scan interval (seconds)        |
| `VALAYR_BOUNTY_ENABLED`             | `false`      | Enable bounty platform integration       |
| `VALAYR_REWARD_SPLIT_PROTOCOL_FEE`  | `0.10`       | Protocol fee on bounty payouts (10%)     |
| `VALAYR_TREASURY_ADDRESS`           | _(none)_     | Treasury contract address                |
| `VALAYR_ANTI_BYPASS_ENABLED`        | `true`       | Enable anti-bypass violation detection   |

See [Deployment Guide](docs/DEPLOYMENT.md) for the full consolidated environment variable reference.

---

## Testing

```bash
# Unit + integration (no Anvil needed)
python3 -m pytest tests/ -v

# Contract tests only (125 Solidity tests)
forge test --root contracts -vv

# Live Anvil integration tests (requires Foundry)
python3 -m pytest tests/test_live_anvil.py -v

# All tests (125 Solidity + 477 Python)
forge test --root contracts -vv && python3 -m pytest tests/ -v

# Determinism verification
PYTHONHASHSEED=0 bash scripts/verify-determinism.sh
```

Test suites:

- `test_integration.py` — task generation, fingerprinting, scoring, incentives, consensus
- `test_pipeline.py` — end-to-end pipeline simulation
- `test_live_anvil.py` — real Anvil sandbox validation
- `test_extended.py` — mutators, metrics, neurons, miner CLI, input sanitization
- `test_adversarial.py` — Stage 3 adversarial invariant system (35 tests)
- `test_bounty.py` — bounty platform, reward splitting, anti-bypass
- `test_multi_tx.py` — multi-transaction exploit sequences
- `test_security.py` — security regression tests (path traversal, injection, etc.)
- `test_reward_split.py` — reward-split engine unit tests
- `test_mainnet_source.py` — mainnet contract source fetching
- `test_difficulty_discovery.py` — difficulty scaling and discovery engine

---

## Project Structure

```
├── .github/workflows/ci.yml    # CI: Forge + Python tests, lint, type-check
├── contracts/
│   ├── src/                    # On-chain contracts
│   │   ├── ExploitRegistry.sol
│   │   ├── ProtocolRegistry.sol
│   │   ├── Treasury.sol
│   │   ├── Ownable2Step.sol
│   │   ├── Pausable.sol
│   │   └── stage3/            # Adversarial mode contracts
│   ├── corpus/                 # Generated vulnerable contract corpus
│   └── test/                   # Foundry Solidity tests (125 tests)
├── task-generator/
│   ├── generate.py             # Deterministic corpus generator
│   ├── discovery.py            # Mainnet contract discovery engine
│   ├── mainnet.py              # Live mainnet contract source fetcher
│   ├── mutator/                # Pluggable mutation framework
│   │   ├── base.py / registry.py
│   │   ├── rename.py / storage.py / balance.py / deadcode.py
│   └── templates/              # Vulnerable contract templates
├── validator/
│   ├── engine/validate.py      # Anvil sandbox validation engine
│   ├── fingerprint/dedup.py    # Fingerprint engine + dedup
│   ├── scoring/severity.py     # Severity scorer
│   ├── anticollusion/          # Anti-collusion consensus engine
│   ├── bounty/                 # Bounty system
│   │   ├── anti_bypass.py      #   Anti-bypass violation detection
│   │   ├── identity.py         #   Miner identity claims
│   │   ├── platform.py         #   Bounty platform integration
│   │   └── reward_split.py     #   Reward splitting engine
│   ├── metrics.py              # Health/metrics HTTP server
│   └── utils/                  # Logging, hashing utilities
├── subnet-adapter/
│   └── incentive.py            # Bittensor weight computation
├── neurons/
│   ├── validator.py            # Bittensor validator neuron
│   ├── miner.py                # Bittensor miner neuron
│   └── protocol.py             # Synapse message definitions
├── miner/
│   └── cli.py                  # Miner CLI interface
├── orchestrator.py             # Central pipeline glue
├── docker/
│   ├── Dockerfile.validator / Dockerfile.miner
│   ├── docker-compose.yml
│   └── prometheus.yml / alertmanager.yml / alerts.yml
├── scripts/                    # Build, deploy, backup, health-check
├── exploits/                   # Reference exploit examples
├── docs/                       # Full documentation suite
│   └── runbooks/               # Operational runbooks (8 files)
├── tests/                      # Python test suites (477 tests)
│   ├── test_integration.py     #   Core unit + integration
│   ├── test_pipeline.py        #   End-to-end pipeline
│   ├── test_live_anvil.py      #   Real Anvil sandbox
│   ├── test_extended.py        #   Mutators, metrics, neurons, CLI
│   ├── test_adversarial.py     #   Stage 3 adversarial subsystem
│   ├── test_bounty.py          #   Bounty / reward-split system
│   ├── test_multi_tx.py        #   Multi-transaction exploits
│   ├── test_security.py        #   Security regression tests
│   └── ... (25 test files)
└── pyproject.toml
```

---

## Legal

Only opt-in protocol contracts are targeted. 72-hour disclosure window enforced on-chain.
See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full risk analysis.
