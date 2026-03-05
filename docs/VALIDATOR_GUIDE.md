# Validator Guide

> Version 1.1 · Last updated: 2026-03-03

Complete guide for running and operating a VALayr validator node.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Validator Architecture](#validator-architecture)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Validation Pipeline](#validation-pipeline)
7. [Epoch Lifecycle](#epoch-lifecycle)
8. [Weight Setting](#weight-setting)
9. [Monitoring & Metrics](#monitoring--metrics)
10. [Docker Deployment](#docker-deployment)
11. [Determinism Requirements](#determinism-requirements)
12. [Validator Onboarding Checklist](#validator-onboarding-checklist)
13. [Security Hardening](#security-hardening)
14. [Troubleshooting](#troubleshooting)
15. [FAQ](#faq)

---

## Overview

Validators are the backbone of the VALayr subnet. They:

1. **Generate task corpora** — Deterministic vulnerable Solidity contracts miners must exploit
2. **Receive exploit submissions** — From miners via Bittensor axon
3. **Validate exploits** — In sandboxed Anvil instances with `--network=none`
4. **Compute fingerprints** — Canonical state-impact fingerprints for deduplication
5. **Score severity** — Algorithmic scoring with fixed weights (no subjectivity)
6. **Set weights on-chain** — Determine miner rewards via `subtensor.set_weights()`
7. **Participate in consensus** — Multi-validator agreement (≥5 quorum, ≥66% match)

**Economic guarantee:** Validation cost is O(minutes), exploit generation cost is O(hours). This asymmetry is the economic moat.

---

## Prerequisites

### Hardware

| Requirement | Minimum    | Recommended |
| ----------- | ---------- | ----------- |
| CPU         | 4 cores    | 8+ cores    |
| RAM         | 8 GB       | 16 GB       |
| Disk        | 100 GB SSD | 250 GB NVMe |
| Network     | 100 Mbps   | 1 Gbps      |

### Software

| Tool         | Version            | Install                                                                           |
| ------------ | ------------------ | --------------------------------------------------------------------------------- |
| Python       | 3.10+              | System package manager or `pyenv`                                                 |
| Foundry      | nightly-2024-12-01 | `curl -L https://foundry.paradigm.xyz \| bash && foundryup -v nightly-2024-12-01` |
| Bittensor    | 7.3.1              | `pip install bittensor==7.3.1`                                                    |
| pycryptodome | 3.21.0             | `pip install pycryptodome==3.21.0`                                                |
| Docker       | 24+                | (recommended for production)                                                      |

### Bittensor Wallet

```bash
# Create a wallet (if you don't have one)
btcli wallet create --wallet.name validator --wallet.hotkey default

# Register on the subnet
btcli subnet register --netuid <NETUID> --wallet.name validator --wallet.hotkey default
```

---

## Validator Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ValidatorNeuron                              │
│                                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────────────┐│
│  │ Bittensor │  │  Orchestrator │  │    Submission Handler      ││
│  │  Axon     │──│              │──│  (rate limiting, routing)   ││
│  └──────────┘  └──────┬───────┘  └────────────────────────────┘│
│                        │                                         │
│  ┌─────────────────────▼───────────────────────────────────────┐│
│  │              Validation Pipeline                              ││
│  │  ┌─────────┐  ┌────────┐  ┌──────────┐  ┌───────────────┐  ││
│  │  │ Compile  │→ │ Deploy │→ │  Execute │→ │  Fingerprint  │  ││
│  │  │ (forge)  │  │(Anvil) │  │ (forge)  │  │  + Severity   │  ││
│  │  └─────────┘  └────────┘  └──────────┘  └───────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
│                        │                                         │
│  ┌─────────────────────▼───────────────────────────────────────┐│
│  │  Anti-Collusion  │  Weight Setting                          ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component              | Module                           | Purpose                                     |
| ---------------------- | -------------------------------- | ------------------------------------------- |
| ValidatorNeuron        | `neurons/validator.py`           | Bittensor integration, epoch loop           |
| Orchestrator           | `orchestrator.py`                | Coordinates task gen → validation → scoring |
| ValidationEngine       | `validator/engine/validate.py`   | Sandboxed exploit execution                 |
| FingerprintEngine      | `validator/fingerprint/dedup.py` | Canonical fingerprints, dedup               |
| SeverityScorer         | `validator/scoring/severity.py`  | Algorithmic severity scoring                |
| AntiCollusionEngine    | `validator/anticollusion/`       | Cross-validator consensus                   |
| MetricsServer          | `validator/metrics.py`           | Health checks and observability             |
| SubnetIncentiveAdapter | `subnet-adapter/incentive.py`    | Weight vector computation                   |

---

## Quick Start

### Local Mode (Development)

```bash
# Clone and install
git clone <repo-url> && cd VALayr
pip install -r requirements.txt
pip install -e ".[dev]"
ln -sf task-generator task_generator
ln -sf subnet-adapter subnet_adapter

# Verify determinism
bash scripts/verify-determinism.sh

# Run in local mode (no Bittensor)
python neurons/validator.py --local
```

### Bittensor Mode (Production)

```bash
# Install with Bittensor support
pip install -r requirements.txt
pip install -e ".[bittensor]"

# Run on testnet
python neurons/validator.py \
  --netuid <NETUID> \
  --wallet.name validator \
  --wallet.hotkey default \
  --subtensor.network test

# Run on mainnet (finney)
python neurons/validator.py \
  --netuid <NETUID> \
  --wallet.name validator \
  --wallet.hotkey default \
  --subtensor.network finney
```

### CLI Options

| Flag                  | Default   | Description                         |
| --------------------- | --------- | ----------------------------------- |
| `--local`             | off       | Run without Bittensor (dev/testing) |
| `--netuid`            | 1         | Bittensor subnet UID                |
| `--wallet.name`       | `default` | Wallet name                         |
| `--wallet.hotkey`     | `default` | Wallet hotkey                       |
| `--subtensor.network` | `test`    | Network: `finney`, `test`, `local`  |
| `--anvil-port`        | 18545     | Base Anvil RPC port                 |

---

## Configuration

### Environment Variables

| Variable                | Default       | Description                   |
| ----------------------- | ------------- | ----------------------------- |
| `ANVIL_BLOCK_TIMESTAMP` | `1700000000`  | Pinned block timestamp        |
| `ANVIL_BLOCK_NUMBER`    | `18000000`    | Pinned block number           |
| `ANVIL_GAS_LIMIT`       | `30000000`    | Gas limit per block           |
| `ANVIL_CHAIN_ID`        | `31337`       | Chain ID                      |
| `PYTHONHASHSEED`        | `0`           | **Must be 0** for determinism |
| `VALIDATOR_ID`          | `validator-0` | Unique validator identifier   |
| `EXPLOIT_LOG_LEVEL`     | `INFO`        | Logging level                 |
| `EXPLOIT_LOG_FILE`      | (none)        | Log file path (optional)      |

### Anvil Configuration

All validators **must** use identical Anvil parameters. The canonical config:

```python
ANVIL_CONFIG = {
    "block_timestamp": 1_700_000_000,
    "block_number": 18_000_000,
    "gas_limit": 30_000_000,
    "chain_id": 31337,
    "accounts": 10,
    "balance": 10000,        # ETH per account
    "mnemonic": "test test test test test test test test test test test junk",
    "hardfork": "cancun",
}
```

> **Critical:** Different Anvil parameters between validators = different execution results = failed quorum = lost rewards. Run `bash scripts/verify-determinism.sh` to validate your configuration automatically.

---

## Validation Pipeline

Each exploit submission goes through an 11-step pipeline:

### Step-by-Step

| Step | Action                         | Reject If                                    |
| ---- | ------------------------------ | -------------------------------------------- |
| 0a   | Size check                     | Source > 64 KB                               |
| 0b   | Sanitize source                | Path traversal / absolute imports            |
| 1    | Setup workspace                | Task contract missing                        |
| 2    | Compile (`forge build`)        | Compilation errors                           |
| 3    | Start Anvil                    | Port conflict / binary missing               |
| 4    | Deploy target contract         | Deployment fails                             |
| 5    | Capture pre-state              | —                                            |
| 6    | Execute exploit (`forge test`) | Timeout (120s)                               |
| 7    | Capture post-state             | —                                            |
| 8    | Build execution trace          | —                                            |
| 9    | Validate result                | Revert, no state change, below gas threshold |
| 10   | Compute fingerprint            | Fingerprint error                            |
| 11   | Score severity                 | —                                            |

### Validation Results

| Result                       | Meaning                                         |
| ---------------------------- | ----------------------------------------------- |
| `VALID`                      | Exploit successfully demonstrates vulnerability |
| `REJECT_REVERT`              | Exploit transaction reverted                    |
| `REJECT_NO_STATE_CHANGE`     | No measurable impact on contract state          |
| `REJECT_TIMEOUT`             | Execution exceeded 120s timeout                 |
| `REJECT_COMPILE_FAIL`        | Solidity compilation failed                     |
| `REJECT_BELOW_GAS_THRESHOLD` | Gas < 21,000 (spam filter)                      |
| `REJECT_INVALID_FORMAT`      | Malformed submission                            |
| `REJECT_FINGERPRINT_ERROR`   | Could not compute canonical fingerprint         |

### State Capture

The engine captures contract state via Anvil RPC:

- **`eth_getBalance`** — Contract ETH balance
- **`eth_getCode`** — Verify contract exists
- **`anvil_dumpState`** — Full storage dump (primary)
- **`eth_getStorageAt`** — Fallback: poll slots 0–63
- **`eth_getLogs`** — Event logs from all contracts

State diff = post-state minus pre-state. The diff feeds into fingerprinting and severity scoring.

---

## Epoch Lifecycle

### Constants

| Parameter                             | Value      | Description                   |
| ------------------------------------- | ---------- | ----------------------------- |
| `EPOCH_LENGTH`                        | 360 blocks | ~60 minutes at ~10s/block     |
| `TASK_REFRESH_EPOCHS`                 | 6          | Refresh corpus every 6 epochs |
| `WEIGHT_SET_INTERVAL`                 | 100 blocks | Set weights every ~17 minutes |
| `MAX_SUBMISSIONS_PER_EPOCH`           | 1000       | Global cap per epoch          |
| `MAX_SUBMISSIONS_PER_MINER_PER_EPOCH` | 50         | Per-miner cap                 |

### Epoch Flow

```
┌─ Epoch N ──────────────────────────────────────────────────┐
│                                                             │
│  1. Sync metagraph                                          │
│  2. Check for epoch transition                              │
│  3. Receive submissions via axon                            │
│     └─ Rate limit: 50/miner, 1000/total                    │
│  4. Validate each submission (pipeline above)               │
│  5. Close epoch → compute weights                           │
│  6. Set weights on-chain                                     │
│  7. Refresh corpus (every 6 epochs)                         │
│                                                             │
│  Sleep 12s (≈1 block) between iterations                    │
└─────────────────────────────────────────────────────────────┘
```

### Epoch Transition

When a new epoch is detected:

1. Close the current epoch: `orchestrator.close_epoch()`
2. Reset per-epoch state (submissions list, miner counters)
3. Generate new task corpus if `TASK_REFRESH_EPOCHS` elapsed

An epoch overlap guard prevents closing the same epoch twice.

---

## Weight Setting

Weights determine how TAO rewards are distributed to miners.

### Weight Computation

The `SubnetIncentiveAdapter` computes a weight vector from epoch results:

1. Collect all `VALID` submissions for the epoch
2. For each miner: `weight = severity_score × reward_multiplier`
   - First submission of a fingerprint: `reward_multiplier = 1.0`
   - Duplicate fingerprint: `reward_multiplier = 0.10`
3. Normalize weights to sum to 1.0
4. Map miner hotkeys to UIDs via the metagraph

### On-Chain Weight Setting

```python
subtensor.set_weights(
    netuid=self.netuid,
    wallet=self.wallet,
    uids=torch.LongTensor(uids),
    weights=weight_tensor,  # Normalized FloatTensor
)
```

Weights are set every `WEIGHT_SET_INTERVAL` blocks (~100 blocks).

---

## Monitoring & Metrics

### Built-in Metrics Server

The validator includes a lightweight HTTP metrics server:

```bash
# Start standalone
python -m validator.metrics --port 9946 --host 0.0.0.0
```

### Endpoints

| Endpoint   | Method | Response                     |
| ---------- | ------ | ---------------------------- |
| `/health`  | GET    | `{"status": "ok"}`           |
| `/metrics` | GET    | Full metrics snapshot (JSON) |

### Metric Types

| Type      | Method                                          | Example                                 |
| --------- | ----------------------------------------------- | --------------------------------------- |
| Counter   | `metrics.inc("validations_total")`              | Monotonically increasing count          |
| Gauge     | `metrics.set_gauge("epoch", 42)`                | Point-in-time value                     |
| Histogram | `metrics.observe("validation_latency_ms", 142)` | Rolling 1000-sample buffer with p50/p99 |

### Key Metrics

| Metric                   | Type      | Description                  |
| ------------------------ | --------- | ---------------------------- |
| `validations_total`      | Counter   | Total exploits validated     |
| `validations_valid`      | Counter   | Successful validations       |
| `validations_rejected`   | Counter   | Rejected submissions         |
| `validation_latency_ms`  | Histogram | Validation pipeline duration |
| `epoch`                  | Gauge     | Current epoch number         |
| `submissions_this_epoch` | Gauge     | Submissions in current epoch |
| `uptime_seconds`         | Auto      | Time since server start      |

### Prometheus Integration

Export metrics to Prometheus by scraping the `/metrics` endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: exploit-validator
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:9946"]
```

### Validator Status

Programmatically check validator status:

```python
neuron = ValidatorNeuron(mode="local")
status = neuron.status()
# {
#   "mode": "local",
#   "epoch": 3,
#   "block": 1080,
#   "submissions_this_epoch": 12,
#   "tasks_available": 26,
# }
```

---

## Docker Deployment

### Build

```bash
docker build -t ghcr.io/exploit-subnet/validator:v0.1.0 \
  -f docker/Dockerfile.validator .
```

### Run with Docker Compose

```bash
cd docker
docker compose up -d validator consensus-relay
```

### Services

| Service              | Network          | Purpose                                   |
| -------------------- | ---------------- | ----------------------------------------- |
| `validator`          | bridge (default) | Bittensor neuron, receives submissions    |
| `consensus-relay`    | bridge           | Anti-collusion engine, metrics on `:9946` |
| `validation-sandbox` | **none**         | Isolated exploit execution                |
| `miner`              | bridge           | Miner node                                |

### Resource Limits

| Service            | CPU                           | Memory                        |
| ------------------ | ----------------------------- | ----------------------------- |
| validator          | 4 cores (limit), 2 (reserved) | 8 GB (limit), 4 GB (reserved) |
| validation-sandbox | 2 cores                       | 4 GB                          |

### Volumes

| Volume           | Mount                   | Purpose                              |
| ---------------- | ----------------------- | ------------------------------------ |
| `validator-data` | `/app/data`             | Fingerprint DB, commit records, logs |
| `task-corpus`    | `/app/contracts/corpus` | Generated task corpus (read-only)    |

### Network Isolation

The validation sandbox runs with `network_mode: "none"`. The entrypoint script verifies this:

```bash
# If this succeeds, the sandbox is NOT properly isolated
if curl -s --connect-timeout 2 https://1.1.1.1 > /dev/null 2>&1; then
    echo "FATAL: Network access detected"
    exit 1
fi
```

---

## Determinism Requirements

**If two validators produce different results for the same exploit, consensus fails and no one gets rewards.**

### Checklist

- [ ] Foundry pinned to `nightly-2024-12-01`
- [ ] `solc` version resolved as `0.8.28`
- [ ] `PYTHONHASHSEED=0`
- [ ] Anvil config uses canonical values (timestamp, block, gas, chain ID)
- [ ] Anvil mnemonic: `test test test test test test test test test test test junk`
- [ ] EVM hardfork: `cancun`
- [ ] Docker image tag matches across all validators
- [ ] `forge build --force` produces identical bytecode on consecutive runs

### Verification

```bash
bash scripts/verify-determinism.sh
```

All 6 categories must pass. If any fail, **do not run validation**.

---

## Security Hardening

### Source Sanitization

The engine rejects exploit sources that contain:

- Path traversal (`..` in imports)
- Absolute paths (`/etc/...`, `C:\\...`)

### Execution Sandbox

- Anvil runs locally (loopback only)
- Docker sandbox: `--network=none`
- Temporary workspace cleaned up after each validation
- Unique port per concurrent validation (thread-safe allocation)

### Rate Limiting

- Global: 1000 submissions per epoch
- Per-miner: 50 submissions per epoch
- Miner blacklist: unregistered hotkeys are rejected

### Key Management

- Private keys are passed via `ETH_PRIVATE_KEY` environment variable (never CLI args)
- Anvil deployer key is public knowledge (used only inside sandbox)
- `--unlocked` + `--from` preferred over raw key passing

---

## Troubleshooting

### Validator Won't Start

| Symptom                         | Cause                | Fix                                 |
| ------------------------------- | -------------------- | ----------------------------------- |
| `bittensor not installed`       | Missing package      | `pip install bittensor==7.3.1`      |
| Falls back to local mode        | Bittensor init fails | Check wallet, network, registration |
| `Foundry (anvil) not installed` | Missing Foundry      | Install and pin version             |

### Validation Failures

| Symptom                                  | Likely Cause                  | Fix                              |
| ---------------------------------------- | ----------------------------- | -------------------------------- |
| All submissions `REJECT_COMPILE_FAIL`    | Wrong solc version            | Pin `0.8.28` in `foundry.toml`   |
| `REJECT_TIMEOUT` everywhere              | Anvil too slow                | Check CPU, increase timeout      |
| No state changes detected                | Target not deployed correctly | Check `_extract_contract_name()` |
| Fingerprint mismatches across validators | Non-deterministic config      | Run `verify-determinism.sh`      |

### Weight Setting Issues

| Symptom                 | Cause                 | Fix                              |
| ----------------------- | --------------------- | -------------------------------- |
| `Failed to set weights` | Wallet not registered | Register on subnet               |
| Weights all zero        | No valid submissions  | Check task corpus generation     |
| Epoch already closed    | Double-close race     | Epoch overlap guard handles this |

### Docker Issues

| Symptom                          | Cause                | Fix                            |
| -------------------------------- | -------------------- | ------------------------------ |
| `FATAL: Network access detected` | Sandbox not isolated | Use `--network=none`           |
| Container OOM killed             | Insufficient memory  | Increase memory limit to 8 GB+ |
| Port conflict                    | Anvil port in use    | Change `--anvil-port`          |

---

## FAQ

**Q: How many validators does the subnet need?**
A: Minimum 5 for quorum. At least 66% must agree for a submission to be accepted. More validators = more robust consensus.

**Q: How long does validation take?**
A: Typically 5–30 seconds per submission, depending on exploit complexity. The 120-second timeout is a hard cap.

**Q: Can I run validator and miner on the same machine?**
A: Yes, but use different wallets and ensure sufficient resources (16 GB+ RAM, 8+ cores).

**Q: What happens if my validator disagrees with consensus?**
A: If you consistently disagree, your validator weight is reduced. Run `verify-determinism.sh` to ensure your environment matches.

**Q: How often should I update the Docker image?**
A: Only when a new version is released in CHANGELOG. All validators must update together to maintain consensus.

**Q: What if Foundry releases a new nightly?**
A: Do NOT upgrade unless the project announces it. The pinned version (`nightly-2024-12-01`) is the canonical version. Upgrading independently breaks determinism.

**Q: How do I monitor validator health?**
A: Hit `http://localhost:9946/health` for a readiness check and `/metrics` for full metrics. Set up Prometheus scraping for dashboards.

---

## Stage 3: Adversarial Validation

Stage 3 adds the adversarial invariant challenge pipeline. Validators now process two types of submissions:

### Challenge Processing

When a Class B miner submits an exploit targeting a Class A invariant, the validator:

1. Loads the invariant from `InvariantRegistry`
2. Deploys the target contract in a sandboxed Anvil instance
3. Executes the Class B exploit
4. Evaluates whether the invariant holds or is broken
5. Calls `AdversarialScoring.processChallenge()` to update scores on-chain

### Validator Requirements for Stage 3

- Your validator address must be registered via `setValidator()` on both `InvariantRegistry` and `AdversarialScoring`
- The `Deploy.s.sol` script handles this automatically for fresh deployments
- For existing deployments, the contract owner must call `setValidator(yourAddress, true)`

---

## Validator Onboarding Checklist

Use this checklist to ensure your validator is correctly configured before going live:

### Infrastructure

- [ ] **Hardware**: 16 GB+ RAM, 8+ CPU cores, 100 GB+ SSD
- [ ] **OS**: Linux (recommended) or macOS — Docker required for production
- [ ] **Network**: Stable connection, low latency to Bittensor finney network

### Software

- [ ] **Python 3.10+** installed — `python3 --version`
- [ ] **Foundry nightly-2024-12-01** — `forge --version` (do NOT use newer versions)
- [ ] **Docker 24.0+** — `docker --version`
- [ ] **Repository cloned** — `git clone https://github.com/suman101/VALayr.git`
- [ ] **Dependencies installed** — `pip install -e ".[dev]"`

### Determinism Verification

- [ ] **Run `bash scripts/verify-determinism.sh`** — all 6 checks must PASS
- [ ] `PYTHONHASHSEED=0` set in environment
- [ ] Anvil parameters match canonical values (see [config](#configuration))
- [ ] `solc 0.8.28` resolved by Foundry

### Bittensor

- [ ] **Wallet created** — `btcli wallet new_hotkey --wallet.name validator`
- [ ] **Subnet registered** — `btcli subnet register --netuid <NETUID> --wallet.name validator`
- [ ] **Sufficient stake** — check with `btcli wallet overview`

### Monitoring

- [ ] **Health endpoint accessible** — `curl http://localhost:9946/health`
- [ ] **Prometheus scraping configured** (optional but recommended)
- [ ] **Alertmanager rules loaded** — `docker/alerts.yml`

### Go-Live

- [ ] Run a local test epoch: `python3 neurons/validator.py --local`
- [ ] Verify weight-setting works: check logs for `set_weights` calls
- [ ] Switch to production: `python3 neurons/validator.py --netuid <NETUID> --subtensor.network finney`

---

## Cross-References

| Document                                                    | Relevance                              |
| ----------------------------------------------------------- | -------------------------------------- |
| [ARCHITECTURE.md](ARCHITECTURE.md)                          | Full system architecture and data flow |
| [DEPLOYMENT.md](DEPLOYMENT.md)                              | Docker deployment and monitoring setup |
| [TESTING.md](TESTING.md)                                    | Test suites and determinism checks     |
| [THREAT_MODEL.md](THREAT_MODEL.md)                          | Security controls and risk mitigations |
| [CONTRACT_REFERENCE.md](CONTRACT_REFERENCE.md)              | Smart contract ABI reference           |
| [DATA_SCHEMA.md](DATA_SCHEMA.md)                            | JSON schemas for state files           |
| [Runbook: Epoch Stall](runbooks/epoch-stall.md)             | Recovering from stalled epochs         |
| [Runbook: Consensus Failure](runbooks/consensus-failure.md) | Handling consensus failures            |
| [Runbook: Validator Drift](runbooks/validator-drift.md)     | Diagnosing determinism drift           |
| [Runbook: Key Rotation](runbooks/key-rotation.md)           | Rotating compromised validator keys    |

### Emergency Pause

All contracts support an emergency `pause()` mechanism callable by the contract owner. When paused, all state-changing functions revert. Use this for incident response. See `docs/runbooks/incident-response.md` for the full procedure.
