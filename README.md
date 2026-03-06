<p align="center">
  <h1 align="center">VALayr</h1>
  <p align="center">
    <strong>Adversarial smart-contract exploit discovery on Bittensor</strong>
  </p>
  <p align="center">
    <a href="docs/VALIDATOR_GUIDE.md">Validator Guide</a> ·
    <a href="docs/MINER_GUIDE.md">Miner Guide</a> ·
    <a href="docs/ARCHITECTURE.md">Architecture</a> ·
    <a href="docs/THREAT_MODEL.md">Threat Model</a>
  </p>
</p>

---

VALayr is a Bittensor subnet that pays miners to **find real vulnerabilities** in smart contracts. Miners craft Solidity exploits, validators execute them inside deterministic sandboxes, and successful discoveries are fingerprinted, scored, de-duplicated, and rewarded — on-chain.

## Why VALayr?

- **Adversarial by design** — miners compete to find the deepest exploits; scoring rules are deterministic and public.
- **Deterministic validation** — pinned toolchain (solc 0.8.28, Foundry nightly-2024-12-01, Anvil), `PYTHONHASHSEED=0`, Docker `--network=none`. Any observer can reproduce any result.
- **Real-world targets** — mainnet discovery engine fetches live contracts from Ethereum; bounty system integrates with Immunefi / Code4rena.
- **Anti-collusion** — multi-validator consensus (≥ 5 quorum, ≥ 66% agreement), divergence-based slashing, fingerprint deduplication.
- **Multi-transaction exploits** — governance attacks, oracle manipulation, timelock bypasses — not just single-tx reentrancy.
- **Progressive difficulty** — three-phase epoch system ramps from synthetic corpus to 60% mainnet-sourced tasks.

## How It Works

```
                    ┌──────────────┐
                    │ Task Generator│ ─── Mainnet Discovery
                    │  + Mutators   │ ─── Synthetic Corpus
                    └──────┬───────┘
                           │ vulnerable contracts
                           ▼
┌──────────┐  exploit  ┌──────────────────────────────┐  weights  ┌──────────┐
│  Miners  │ ────────▶ │       Validator Pipeline      │ ────────▶ │ Bittensor│
│(Solidity)│           │ Sandbox → Score → Fingerprint │           │   (TAO)  │
└──────────┘           │ → Dedup → Consensus → Record  │           └──────────┘
                       └──────────────┬───────────────┘
                                      │ on-chain
                                      ▼
                       ┌──────────────────────────────┐
                       │  ExploitRegistry · Treasury   │
                       │  ProtocolRegistry (bounties)  │
                       └──────────────────────────────┘
```

1. **Task Generator** produces vulnerable Solidity contracts — from templates + mutators or live mainnet discovery.
2. **Miners** craft exploits (`forge-std/Test.sol` tests) that drain, escalate, or break target invariants.
3. **Validators** execute exploits in an isolated Anvil sandbox, compute severity scores (0–1), fingerprint state diffs, and deduplicate.
4. **Anti-collusion consensus** across ≥ 5 validators confirms results; divergent validators are slashed.
5. **Epoch close** aggregates scores into Bittensor weight vectors; bounty-eligible exploits trigger on-chain reward splits.

## Quick Start

### Prerequisites

| Tool    | Version              | Notes                                  |
| ------- | -------------------- | -------------------------------------- |
| Python  | ≥ 3.10               | `python3` required                     |
| Foundry | `nightly-2024-12-01` | [Install](https://book.getfoundry.sh/) |
| Docker  | ≥ 24.0               | Production only                        |

### Install & Run

```bash
# Clone
git clone https://github.com/suman101/VALayr.git && cd VALayr

# Install Foundry (pinned)
curl -L https://foundry.paradigm.xyz | bash
foundryup --version nightly-2024-12-01

# Install Python deps
pip install -e ".[dev]"

# Build contracts
forge build

# Generate tasks & start local validator
python3 task-generator/generate.py --count 2 --seed 42
python3 neurons/validator.py --local
```

```bash
# In another terminal — mine
python3 -m miner.cli tasks
python3 -m miner.cli scaffold --task 0xabc123
# ... write your exploit ...
python3 -m miner.cli submit --task 0xabc123 --exploit Exploit.sol
python3 -m miner.cli scores
```

### Bittensor Network

```bash
# Validator
python3 neurons/validator.py --netuid 1 --wallet.name default --wallet.hotkey default

# Miner
python3 neurons/miner.py --netuid 1 --wallet.name default --wallet.hotkey default
```

### Docker (Production)

```bash
cd docker && docker compose up -d
curl http://localhost:9946/health   # → {"status": "ok"}
```

## Testing

**134 Solidity tests** + **569 Python tests** across 24 test files:

```bash
forge test --root contracts -vv                    # Solidity (134 tests)
python3 -m pytest tests/ -v                        # Python   (569 tests)
PYTHONHASHSEED=0 bash scripts/verify-determinism.sh # Determinism check
```

<details>
<summary><strong>Full test suite breakdown</strong></summary>

| File                               | Tests | Coverage Area                                       |
| ---------------------------------- | ----: | --------------------------------------------------- |
| `test_extended.py`                 |    64 | Mutators, metrics, neurons, CLI, input sanitisation |
| `test_adversarial.py`              |    58 | Stage 3 adversarial invariant system                |
| `test_bounty.py`                   |    47 | Bounty platform, reward splitting, anti-bypass      |
| `test_security.py`                 |    39 | Security regression tests                           |
| `test_round2.py`                   |    37 | Deploy pipeline, auto-mine, key rotation            |
| `test_validate_engine_unit.py`     |    36 | Validation engine unit tests                        |
| `test_e2e_pipeline.py`             |    32 | Full end-to-end pipeline with weight blending       |
| `test_schemas_hashing.py`          |    29 | Schema validation and keccak256 hashing             |
| `test_difficulty_discovery.py`     |    27 | Difficulty scaling and discovery engine             |
| `test_multi_tx.py`                 |    21 | Multi-transaction exploit sequences                 |
| `test_mutator_extended.py`         |    19 | Extended mutator coverage                           |
| `test_integration.py`              |    19 | Task generation, fingerprinting, scoring, consensus |
| `test_uniqueness.py`               |    18 | Uniqueness scoring                                  |
| `test_mainnet_source.py`           |    17 | Mainnet contract source fetching                    |
| `test_key_rotation.py`             |    17 | Key rotation                                        |
| `test_consensus_edge.py`           |    16 | Consensus edge cases                                |
| `test_orchestrator_integration.py` |    15 | Orchestrator integration                            |
| `test_protocol_roundtrip.py`       |    11 | Protocol round-trip                                 |
| `test_reward_split.py`             |    10 | Reward-split engine                                 |
| `test_validator_neuron.py`         |     8 | Validator neuron lifecycle                          |
| `test_pipeline.py`                 |     8 | End-to-end pipeline simulation                      |
| `test_fingerprint_recovery.py`     |     8 | Fingerprint DB recovery                             |
| `test_live_anvil.py`               |     7 | Real Anvil sandbox validation                       |
| `test_logging_utils.py`            |     6 | Logging utilities                                   |

Solidity: `ExploitRegistry` (14), `ProtocolRegistry` (26), `AdversarialMode` (26), `Treasury` (29), `Ownable2Step` (19), `Pausable` (12), `ReentrancyGuard` (3), Invariants (5).

</details>

## Architecture Overview

| Component             | Location                   | Description                                                                   |
| --------------------- | -------------------------- | ----------------------------------------------------------------------------- |
| **Smart Contracts**   | `contracts/src/`           | ExploitRegistry, ProtocolRegistry, Treasury, Ownable2Step, Pausable           |
| **Task Generator**    | `task-generator/`          | Deterministic corpus generation, mainnet discovery, mutation framework        |
| **Validation Engine** | `validator/engine/`        | Anvil sandbox execution, state-diff capture                                   |
| **Scoring**           | `validator/scoring/`       | Severity scoring (funds drained 40%, escalation 25%, invariant 20%, lock 15%) |
| **Fingerprinting**    | `validator/fingerprint/`   | State-diff fingerprinting, deduplication                                      |
| **Anti-Collusion**    | `validator/anticollusion/` | Multi-validator consensus, divergence slashing                                |
| **Bounty System**     | `validator/bounty/`        | Reward splitting (70/20/10), anti-bypass detection, platform integration      |
| **Subnet Adapter**    | `subnet-adapter/`          | Bittensor weight computation                                                  |
| **Orchestrator**      | `orchestrator.py`          | Central pipeline: task → validate → fingerprint → score → record              |
| **Neurons**           | `neurons/`                 | Bittensor validator/miner neuron wrappers                                     |
| **Miner CLI**         | `miner/cli.py`             | `tasks`, `scaffold`, `submit`, `status`, `scores`                             |
| **Docker**            | `docker/`                  | Compose stack with `--network=none` sandbox isolation                         |

See [Architecture docs](docs/ARCHITECTURE.md) for detailed data flow diagrams, design decisions, and component deep dives.

## Configuration

<details>
<summary><strong>Environment variables</strong></summary>

| Variable                            | Default                 | Description                            |
| ----------------------------------- | ----------------------- | -------------------------------------- |
| **Determinism**                     |                         |                                        |
| `ANVIL_BLOCK_TIMESTAMP`             | `1700000000`            | Fixed block timestamp                  |
| `ANVIL_BLOCK_NUMBER`                | `18000000`              | Fixed block number                     |
| `ANVIL_GAS_LIMIT`                   | `30000000`              | Block gas limit                        |
| `ANVIL_CHAIN_ID`                    | `31337`                 | Chain ID                               |
| `PYTHONHASHSEED`                    | `0`                     | **Must be 0** for deterministic Python |
| **Orchestrator**                    |                         |                                        |
| `VALAYR_MAX_CONCURRENT_VALIDATIONS` | `4`                     | Max parallel validations per epoch     |
| `VALAYR_EPOCH_COMPUTE_BUDGET`       | `10000`                 | CPU-seconds budget per epoch           |
| `VALAYR_SUBMISSION_TIMEOUT`         | `300`                   | Per-submission timeout (seconds)       |
| `VALAYR_REQUIRE_SANDBOX`            | auto                    | Force Docker sandbox                   |
| **Difficulty Phasing**              |                         |                                        |
| `VALAYR_EPOCH_DIFFICULTY_2`         | `51`                    | Phase 2 start epoch                    |
| `VALAYR_EPOCH_DIFFICULTY_3`         | `201`                   | Phase 3 start epoch                    |
| `VALAYR_MAINNET_RATIO_{1,2,3}`      | `0.0 / 0.3 / 0.6`       | Mainnet task ratio per phase           |
| `VALAYR_MIN_SEVERITY_{1,2,3}`       | `0.0 / 0.1 / 0.2`       | Severity floor per phase               |
| **Bounty**                          |                         |                                        |
| `VALAYR_MINER_SHARE`                | `0.70`                  | Miner reward share                     |
| `VALAYR_VALIDATOR_SHARE`            | `0.20`                  | Validator reward share                 |
| `VALAYR_TREASURY_SHARE`             | `0.10`                  | Treasury reward share                  |
| `VALAYR_TREASURY_ADDRESS`           | —                       | Treasury contract address              |
| `VALAYR_RECEIPT_HMAC_KEY`           | _(auto)_                | 32+ byte hex key for receipt integrity |
| **On-Chain**                        |                         |                                        |
| `VALAYR_RPC_URL`                    | `http://127.0.0.1:8545` | RPC endpoint                           |
| `VALAYR_PROTOCOL_REGISTRY`          | —                       | ProtocolRegistry address               |
| `VALAYR_EXPLOIT_REGISTRY`           | —                       | ExploitRegistry address                |
| `VALAYR_ADVERSARIAL_SCORING`        | —                       | AdversarialScoring address             |
| **Logging**                         |                         |                                        |
| `EXPLOIT_LOG_LEVEL`                 | `INFO`                  | DEBUG / INFO / WARNING / ERROR         |
| `EXPLOIT_LOG_FILE`                  | —                       | Optional log file path                 |

Copy `.env.example` to `.env` and fill in your values. See [Deployment Guide](docs/DEPLOYMENT.md) for the full reference.

</details>

## Documentation

| Document                                               | Description                                                         |
| ------------------------------------------------------ | ------------------------------------------------------------------- |
| [Architecture](docs/ARCHITECTURE.md)                   | System design, component interactions, data flow diagrams           |
| [API Reference](docs/API_REFERENCE.md)                 | Python modules, synapses, contract ABIs, CLI, HTTP endpoints        |
| [Contract Reference](docs/CONTRACT_REFERENCE.md)       | Solidity contract docs: ExploitRegistry, ProtocolRegistry, Treasury |
| [Deployment Guide](docs/DEPLOYMENT.md)                 | Production deployment, Docker, monitoring, troubleshooting          |
| [Developer Guide](docs/DEVELOPER_GUIDE.md)             | Contributing code, setup, adding templates/mutators/contracts       |
| [Exploit Writing Guide](docs/EXPLOIT_WRITING_GUIDE.md) | Annotated exploits for every vulnerability class                    |
| [Miner Guide](docs/MINER_GUIDE.md)                     | Writing exploits, submission workflow, scoring strategies           |
| [Validator Guide](docs/VALIDATOR_GUIDE.md)             | Validator setup, epoch lifecycle, weight setting, monitoring        |
| [Testing Guide](docs/TESTING.md)                       | Test suites, CI pipeline, determinism verification                  |
| [Threat Model](docs/THREAT_MODEL.md)                   | STRIDE analysis, risk matrix, attack surfaces, security controls    |
| [Data Schema](docs/DATA_SCHEMA.md)                     | JSON schemas for all persistent state files                         |
| [Glossary](docs/GLOSSARY.md)                           | Key terms and concepts                                              |
| [Changelog](CHANGELOG.md)                              | Release history                                                     |
| [Runbooks](docs/runbooks/)                             | 10 operational runbooks (key rotation, incident response, etc.)     |

## Project Structure

```
VALayr/
├── contracts/
│   ├── src/                        # ExploitRegistry, ProtocolRegistry, Treasury, Ownable2Step, Pausable
│   ├── test/                       # Foundry tests (134 tests, 8 files)
│   └── corpus/                     # Generated vulnerable contract corpus
├── task-generator/
│   ├── generate.py                 # Deterministic corpus generator
│   ├── discovery.py                # Mainnet contract discovery engine
│   ├── mainnet.py                  # Live source fetcher
│   ├── mutator/                    # Rename, Storage, Balance, DeadCode mutators
│   └── templates/                  # 9 vulnerability class templates
├── validator/
│   ├── engine/validate.py          # Anvil sandbox validation
│   ├── scoring/severity.py         # Severity scoring
│   ├── fingerprint/dedup.py        # Fingerprint engine + dedup
│   ├── anticollusion/              # Multi-validator consensus
│   ├── bounty/                     # Reward splits, anti-bypass, platform integration
│   ├── metrics.py                  # Health/metrics HTTP server (port 9946)
│   └── utils/                      # Logging, hashing, difficulty, secrets
├── neurons/                        # Bittensor validator + miner neurons
├── subnet-adapter/                 # Bittensor weight computation
├── miner/cli.py                    # Miner CLI
├── orchestrator.py                 # Central pipeline
├── exploits/                       # 9 reference exploit examples
├── docker/                         # Compose stack, Prometheus, Grafana, alerting
├── scripts/                        # Build, deploy, backup, health-check, verify
├── tests/                          # 569 Python tests across 24 files
├── docs/                           # Full documentation suite + 10 runbooks
├── .env.example                    # Environment variable template
└── pyproject.toml                  # Python project config
```

## Security

VALayr treats all miner-submitted code as adversarial. Key security controls:

- **Sandbox isolation** — Docker `--network=none`, ephemeral workspace, non-root user
- **Path-traversal sanitiser** — rejects `..` and absolute paths in imports
- **Rate limiting** — 50 submissions/miner/epoch, 1000 global cap, 30s cooldown
- **On-chain access control** — `onlyValidator`, `onlyOwner`, `Ownable2Step`, `ReentrancyGuard`
- **Disclosure window** — 72-hour on-chain enforcement before bounty payout

Report vulnerabilities responsibly — see [SECURITY.md](SECURITY.md). Full risk analysis in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contributing

```bash
pip install -e ".[dev]"
pre-commit install
python3 -m pytest tests/ -x -q   # 569 tests, must pass
forge test --root contracts       # 134 tests, must pass
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for PR process, coding standards, and CI pipeline details.

## Legal

Only opt-in protocol contracts are targeted. 72-hour disclosure window enforced on-chain. See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.
