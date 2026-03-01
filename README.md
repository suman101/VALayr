# VALayr

A Bittensor subnet for deterministic, adversarial smart contract exploit discovery.

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

## Documentation

| Document                                               | Description                                                                               |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| [Architecture](docs/ARCHITECTURE.md)                   | System architecture, component interactions, data flow diagrams, design decisions         |
| [API Reference](docs/API_REFERENCE.md)                 | Complete API documentation: Python modules, synapses, contract ABIs, CLI, HTTP endpoints  |
| [Deployment Guide](docs/DEPLOYMENT.md)                 | Production deployment, Docker configuration, monitoring, troubleshooting                  |
| [Developer Guide](docs/DEVELOPER_GUIDE.md)             | Contributing code: setup, testing, adding templates/mutators/contracts                    |
| [Miner Guide](docs/MINER_GUIDE.md)                     | Miner onboarding: writing exploits, submission workflow, scoring, strategies              |
| [Validator Guide](docs/VALIDATOR_GUIDE.md)             | Validator setup, epoch lifecycle, weight setting, monitoring, determinism                 |
| [Testing Guide](docs/TESTING.md)                       | Test suites, CI pipeline, determinism verification, writing tests                         |
| [Contract Reference](docs/CONTRACT_REFERENCE.md)       | Solidity contract documentation: CommitReveal, ExploitRegistry, ProtocolRegistry, Stage 3 |
| [Exploit Writing Guide](docs/EXPLOIT_WRITING_GUIDE.md) | Annotated exploit examples for every vulnerability class, scoring strategies              |
| [Glossary](docs/GLOSSARY.md)                           | Definitions of all key terms and concepts used in the project                             |
| [Threat Model](docs/THREAT_MODEL.md)                   | STRIDE analysis, risk matrix, attack surfaces, security controls                          |
| [Contributing](CONTRIBUTING.md)                        | PR process, coding standards, development setup                                           |
| [Security Policy](SECURITY.md)                         | Vulnerability reporting, scope, disclosure policy                                         |
| [Changelog](CHANGELOG.md)                              | Release history and notable changes                                                       |

## Components

| Component           | Location                     | Status |
| ------------------- | ---------------------------- | ------ |
| On-chain Contracts  | `contracts/src/`             | v1     |
| Vulnerable Corpus   | `contracts/corpus/`          | v1     |
| Task Generator      | `task-generator/`            | v1     |
| Mutator Framework   | `task-generator/mutator/`    | v1     |
| Validation Engine   | `validator/engine/`          | v1     |
| Fingerprint / Dedup | `validator/fingerprint/`     | v1     |
| Severity Scoring    | `validator/scoring/`         | v1     |
| Anti-Collusion      | `validator/anticollusion/`   | v1     |
| Commit-Reveal       | `validator/commit_reveal.py` | v1     |
| Metrics / Health    | `validator/metrics.py`       | v1     |
| Structured Logging  | `validator/utils/logging.py` | v1     |
| Subnet Adapter      | `subnet-adapter/`            | v1     |
| Orchestrator        | `orchestrator.py`            | v1     |
| Validator Neuron    | `neurons/validator.py`       | v1     |
| Miner Neuron        | `neurons/miner.py`           | v1     |
| Miner CLI           | `miner/cli.py`               | v1     |
| Docker Infra        | `docker/`                    | v1     |
| CI / CD             | `.github/workflows/ci.yml`   | v1     |

---

## Quickstart

### Prerequisites

- Python 3.10+
- [Foundry](https://book.getfoundry.sh/) (pinned to `nightly-2024-12-01`)

### Install

```bash
# 1. Clone
git clone <REPO_URL> && cd XYZ

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

It also wires commit-reveal and anti-collusion into the validation flow.

### Key Methods

- `generate_corpus(count_per_class, seed)` — generate / refresh the task corpus
- `process_submission(task_id, exploit_source, miner_address)` — full validation pipeline
- `commit_exploit(task_id, exploit_source, miner_address)` — commit-reveal phase 1
- `reveal_and_process(...)` — commit-reveal phase 2 + validation
- `close_epoch(epoch_number, start_block, end_block)` — compute & record epoch weights

---

## Commit-Reveal Flow

Prevents front-running of exploit submissions.

1. **Commit**: miner hashes `(task_id, exploit_source, nonce)` and submits the hash on-chain.
2. **Reveal window**: after N blocks, the miner reveals the plaintext.
3. **Validation**: the revealed exploit is validated only if the hash matches the commit.

Two implementations:

- `CommitRevealClient` — on-chain via the `CommitReveal.sol` contract
- `CommitRevealSimulator` — in-memory for local development and testing

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
commit-reveal integration, structured logging.

### Miner Neuron (`neurons/miner.py`)

```bash
# Bittensor mode
python3 neurons/miner.py --netuid 1 --wallet.name default --wallet.hotkey default

# Local mode
python3 neurons/miner.py --local
```

---

## Environment Variables

| Variable                | Default      | Description                              |
| ----------------------- | ------------ | ---------------------------------------- |
| `EXPLOIT_LOG_LEVEL`     | `INFO`       | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `EXPLOIT_LOG_FILE`      | _(none)_     | Optional log file path                   |
| `ANVIL_BLOCK_TIMESTAMP` | `1700000000` | Fixed block timestamp for determinism    |
| `ANVIL_BLOCK_NUMBER`    | `18000000`   | Fixed block number                       |
| `ANVIL_GAS_LIMIT`       | `30000000`   | Block gas limit                          |
| `ANVIL_CHAIN_ID`        | `31337`      | Chain ID                                 |
| `PYTHONHASHSEED`        | `0`          | Must be 0 for deterministic Python       |
| `ETH_PRIVATE_KEY`       | _(none)_     | Private key for on-chain commit-reveal   |

---

## Testing

```bash
# Unit + integration (no Anvil needed)
python3 -m pytest tests/test_integration.py tests/test_pipeline.py tests/test_extended.py -v

# Live Anvil tests (requires Foundry)
python3 -m pytest tests/test_live_anvil.py -v

# Contract tests
forge test -vv

# All tests
python3 -m pytest tests/ -v && forge test -vv
```

Test suites:

- `test_integration.py` — task generation, fingerprinting, scoring, incentives, consensus
- `test_pipeline.py` — end-to-end pipeline simulation
- `test_live_anvil.py` — real Anvil sandbox validation
- `test_extended.py` — mutators, metrics, neurons, miner CLI, input sanitization

---

## Project Structure

```
├── .github/workflows/ci.yml    # CI: Forge tests + Python tests
├── contracts/
│   ├── src/                    # On-chain contracts (CommitReveal, ExploitRegistry)
│   ├── corpus/                 # Generated vulnerable contract corpus
│   └── test/                   # Foundry Solidity tests
├── task-generator/
│   ├── generate.py             # Deterministic corpus generator
│   ├── mutator/                # Pluggable mutation framework
│   └── templates/              # Vulnerable contract templates
├── validator/
│   ├── engine/validate.py      # Anvil sandbox validation engine
│   ├── fingerprint/dedup.py    # Fingerprint engine + dedup
│   ├── scoring/severity.py     # Severity scorer
│   ├── anticollusion/          # Anti-collusion consensus engine
│   ├── commit_reveal.py        # Commit-reveal mechanism
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
│   ├── Dockerfile.validator
│   ├── Dockerfile.miner
│   └── docker-compose.yml
├── tests/
│   ├── test_integration.py
│   ├── test_pipeline.py
│   ├── test_live_anvil.py
│   └── test_extended.py
└── pyproject.toml
```

---

## Legal

Only opt-in protocol contracts. 72-hour disclosure window enforced on-chain.
