# VALayr — Deployment & Operations Guide

> Version 0.1.0 · Last updated: 2026-03-06

This guide covers production deployment, Docker configuration, monitoring, troubleshooting, and operational procedures for running VALayr validator and miner nodes.

---

## Table of Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Deployment Modes](#2-deployment-modes)
- [3. Docker Deployment](#3-docker-deployment)
- [4. Bare-Metal Deployment](#4-bare-metal-deployment)
- [5. Smart Contract Deployment](#5-smart-contract-deployment)
- [6. Monitoring & Observability](#6-monitoring--observability)
- [7. Security Hardening](#7-security-hardening)
- [8. Backup & Recovery](#8-backup--recovery)
- [9. Upgrading](#9-upgrading)
- [10. Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

### Hardware Requirements

| Component | Validator           | Miner        |
| --------- | ------------------- | ------------ |
| CPU       | 4+ cores            | 2+ cores     |
| RAM       | 8 GB minimum        | 4 GB minimum |
| Disk      | 50 GB SSD           | 20 GB SSD    |
| Network   | Stable, low-latency | Stable       |

### Software Requirements

| Tool           | Version              | Required By           |
| -------------- | -------------------- | --------------------- |
| Docker         | ≥ 24.0               | All (Docker mode)     |
| Docker Compose | v2+                  | All (Docker mode)     |
| Python         | ≥ 3.10               | All (bare-metal mode) |
| Foundry        | `nightly-2024-12-01` | Validator only        |
| solc           | `0.8.28`             | Validator only        |
| Git            | ≥ 2.30               | All                   |

### Network Requirements

| Port          | Direction          | Service               | Required By       |
| ------------- | ------------------ | --------------------- | ----------------- |
| Bittensor p2p | Inbound + Outbound | Axon communication    | Validator + Miner |
| 9946          | Outbound (or LAN)  | Metrics/Health        | Validator         |
| 18545+        | Localhost only     | Anvil RPC (ephemeral) | Validator         |

### Credentials

| Credential                          | Purpose                             | Storage                 |
| ----------------------------------- | ----------------------------------- | ----------------------- |
| Bittensor wallet (coldkey + hotkey) | Subnet registration, weight setting | `~/.bittensor/wallets/` |

---

## 2. Deployment Modes

### Local Mode (Development)

No Bittensor, no Docker, no on-chain transactions. Everything runs in-process.

```bash
python3 neurons/validator.py --local
python3 neurons/miner.py --local
```

### Docker Mode (Recommended for Production)

Full isolation with network-disabled validation sandbox.

```bash
cd docker && docker compose up -d
```

### Bare-Metal Mode

Direct execution with Bittensor network integration.

```bash
python3 neurons/validator.py --netuid 1 --wallet.name default --wallet.hotkey default
```

---

## 3. Docker Deployment

### 3.1 Build Images

```bash
# Validator image (includes Foundry, Anvil, solc)
docker build -t ghcr.io/exploit-subnet/validator:v0.1.0 \
  -f docker/Dockerfile.validator .

# Miner image (lightweight Python only)
docker build -t ghcr.io/exploit-subnet/miner:v0.1.0 \
  -f docker/Dockerfile.miner .
```

### 3.2 Verify Image Integrity

```bash
# Check image hash (pin in production)
docker inspect --format='{{.Id}}' ghcr.io/exploit-subnet/validator:v0.1.0

# Verify tool versions inside the image
docker run --rm ghcr.io/exploit-subnet/validator:v0.1.0 shell -c \
  "forge --version && solc --version && python3 --version"
```

### 3.3 Service Architecture

```
docker-compose.yml
├── validator          # Bittensor neuron (network-enabled)
├── consensus-relay    # Anti-collusion engine + metrics (port 9946)
├── miner              # Exploit discovery (network-enabled)
└── validation-sandbox # Anvil sandbox (network=none, on-demand)
```

### 3.4 Configure Environment

Create a `.env` file alongside `docker-compose.yml`:

```bash
# .env
BITTENSOR_NETWORK=finney
WALLET_NAME=default
WALLET_HOTKEY=default
NETUID=1

# NEVER commit this file
ETH_PRIVATE_KEY=0x<your-key-here>

# Deterministic config (do not change)
ANVIL_BLOCK_TIMESTAMP=1700000000
ANVIL_BLOCK_NUMBER=18000000
ANVIL_GAS_LIMIT=30000000
ANVIL_CHAIN_ID=31337
PYTHONHASHSEED=0
```

#### Complete VALAYR\_\* Environment Variable Reference

All `VALAYR_*` variables are optional unless marked **required**. See [VALIDATOR_GUIDE.md](VALIDATOR_GUIDE.md#configuration) for detailed descriptions.

| Variable                            | Default       | Category     | Description                                       |
| ----------------------------------- | ------------- | ------------ | ------------------------------------------------- |
| `ANVIL_BLOCK_TIMESTAMP`             | `1700000000`  | Determinism  | Pinned block timestamp                            |
| `ANVIL_BLOCK_NUMBER`                | `18000000`    | Determinism  | Pinned block number                               |
| `ANVIL_GAS_LIMIT`                   | `30000000`    | Determinism  | Gas limit per block                               |
| `ANVIL_CHAIN_ID`                    | `31337`       | Determinism  | Chain ID                                          |
| `PYTHONHASHSEED`                    | `0`           | Determinism  | **Must be 0**                                     |
| `VALIDATOR_ID`                      | `validator-0` | Identity     | Unique validator identifier                       |
| `EXPLOIT_LOG_LEVEL`                 | `INFO`        | Logging      | Logging level                                     |
| `EXPLOIT_LOG_FILE`                  | (none)        | Logging      | Log file path                                     |
| `VALAYR_MAX_CONCURRENT_VALIDATIONS` | `4`           | Orchestrator | Max parallel validations per epoch                |
| `VALAYR_EPOCH_COMPUTE_BUDGET`       | `10000`       | Orchestrator | CPU-seconds budget per epoch                      |
| `VALAYR_SUBMISSION_TIMEOUT`         | `300`         | Orchestrator | Per-submission timeout (seconds)                  |
| `VALAYR_REQUIRE_SANDBOX`            | auto          | Security     | Force Docker sandbox; auto-enabled in Docker mode |
| `VALAYR_EPOCH_DIFFICULTY_2`         | `51`          | Difficulty   | Epoch where phase 2 begins                        |
| `VALAYR_EPOCH_DIFFICULTY_3`         | `201`         | Difficulty   | Epoch where phase 3 begins                        |
| `VALAYR_MAINNET_RATIO_1`            | `0.0`         | Difficulty   | Mainnet task ratio — phase 1                      |
| `VALAYR_MAINNET_RATIO_2`            | `0.3`         | Difficulty   | Mainnet task ratio — phase 2                      |
| `VALAYR_MAINNET_RATIO_3`            | `0.6`         | Difficulty   | Mainnet task ratio — phase 3                      |
| `VALAYR_MIN_SEVERITY_1`             | `0.0`         | Difficulty   | Min severity threshold — phase 1                  |
| `VALAYR_MIN_SEVERITY_2`             | `0.1`         | Difficulty   | Min severity threshold — phase 2                  |
| `VALAYR_MIN_SEVERITY_3`             | `0.2`         | Difficulty   | Min severity threshold — phase 3                  |
| `VALAYR_MINER_SHARE`                | `0.70`        | Bounty       | Miner reward share                                |
| `VALAYR_VALIDATOR_SHARE`            | `0.20`        | Bounty       | Validator reward share                            |
| `VALAYR_TREASURY_SHARE`             | `0.10`        | Bounty       | Treasury reward share                             |
| `VALAYR_TREASURY_ADDRESS`           | (none)        | Bounty       | Treasury contract address                         |
| `VALAYR_RECEIPT_HMAC_KEY`           | —             | Security     | **Required.** 32+ byte hex key for receipt HMAC   |
| `ETH_PRIVATE_KEY`                   | —             | On-chain     | Validator/deployer private key (never commit)     |

### 3.5 Start Services

```bash
cd docker

# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f validator
docker compose logs -f consensus-relay
```

### 3.6 Volumes

| Volume           | Mounted To                          | Purpose                                       |
| ---------------- | ----------------------------------- | --------------------------------------------- |
| `validator-data` | `/app/data`                         | Fingerprint DB, reports, anti-collusion state |
| `task-corpus`    | `/app/contracts/corpus` (read-only) | Task corpus (shared)                          |
| `miner-data`     | `/app/data`                         | Miner exploits, submissions                   |

### 3.7 Resource Limits

| Service            | CPU                      | Memory                         |
| ------------------ | ------------------------ | ------------------------------ |
| Validator          | 4 (limit) / 2 (reserved) | 8 GB (limit) / 4 GB (reserved) |
| Validation Sandbox | 2 (limit) / 1 (reserved) | 4 GB (limit) / 2 GB (reserved) |
| Consensus Relay    | Default                  | Default                        |
| Miner              | Default                  | Default                        |

### 3.8 Network Isolation

The validation sandbox runs with `network_mode: "none"`. The entrypoint script verifies this:

```bash
# This MUST fail inside the sandbox:
curl -s --connect-timeout 2 https://1.1.1.1
# If it succeeds, the entrypoint exits with error
```

> **CRITICAL:** If network isolation fails, validation results become non-deterministic. Never disable network isolation in production.

---

## 4. Bare-Metal Deployment

### 4.1 Install Dependencies

```bash
# Python
pip install -e ".[dev]"

# Foundry (pinned)
curl -L https://foundry.paradigm.xyz | bash
foundryup --version nightly-2024-12-01

# solc (pinned)
# Linux:
curl -L "https://github.com/ethereum/solidity/releases/download/v0.8.28/solc-static-linux" \
  -o /usr/local/bin/solc && chmod +x /usr/local/bin/solc
# macOS:
brew install solidity
```

### 4.2 Set Environment

```bash
export PYTHONHASHSEED=0
export PYTHONDONTWRITEBYTECODE=1
export EXPLOIT_LOG_LEVEL=INFO
export EXPLOIT_LOG_FILE=/var/log/valayr/validator.log

# For on-chain operations only:
export ETH_PRIVATE_KEY=0x<your-key>
```

### 4.3 Register on Bittensor

```bash
# Create wallet (if needed)
btcli wallet create --wallet.name default --wallet.hotkey default

# Register on subnet
btcli subnet register --netuid <NETUID> --wallet.name default --wallet.hotkey default
```

### 4.4 Run Validator

```bash
python3 neurons/validator.py \
  --netuid <NETUID> \
  --wallet.name default \
  --wallet.hotkey default
```

### 4.5 Run Miner

```bash
python3 neurons/miner.py \
  --netuid <NETUID> \
  --wallet.name default \
  --wallet.hotkey default
```

### 4.6 Systemd Service (Linux)

Create `/etc/systemd/system/valayr-validator.service`:

```ini
[Unit]
Description=VALayr Validator Neuron
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=valayr
Group=valayr
WorkingDirectory=/opt/valayr
ExecStart=/usr/bin/python3 neurons/validator.py --netuid 1 --wallet.name default --wallet.hotkey default
Restart=on-failure
RestartSec=10
Environment=PYTHONHASHSEED=0
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=EXPLOIT_LOG_LEVEL=INFO
Environment=EXPLOIT_LOG_FILE=/var/log/valayr/validator.log

# Security hardening
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/valayr/data /var/log/valayr
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now valayr-validator
```

---

## 5. Smart Contract Deployment

### 5.1 Deploy Contracts

```bash
cd contracts

# Deploy to testnet
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --private-key $DEPLOY_KEY \
  --broadcast \
  --verify

# Deploy to mainnet (use multi-sig in production)
forge script script/Deploy.s.sol \
  --rpc-url $MAINNET_RPC \
  --private-key $DEPLOY_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_KEY
```

### 5.2 Post-Deployment Configuration

```bash
# Add validators to ExploitRegistry
cast send $EXPLOIT_REGISTRY "addValidator(address)" $VALIDATOR_ADDRESS \
  --rpc-url $RPC_URL --private-key $OWNER_KEY
```

### 5.3 Ownership Transfer Delay

All VALayr contracts inherit `Ownable2Step` with a configurable `TRANSFER_DELAY`.

| Environment | Recommended Delay | Seconds  |
| ----------- | ----------------- | -------- |
| Local/Test  | 0 (instant)       | `0`      |
| Testnet     | 1 hour            | `3600`   |
| Mainnet     | 48 hours          | `172800` |

The delay is set as a constructor argument and is **immutable** after deployment.
Modify your deploy script to pass the appropriate value:

```solidity
// In Deploy.s.sol — change the constructor arg for production
new ExploitRegistry(172_800);   // 48 hours
new ProtocolRegistry(172_800);
new Treasury(validatorAddr, 172_800);
```

> **WARNING**: Deploying with `TRANSFER_DELAY=0` on mainnet allows instant
> ownership transfers with no cooling-off period. Always use ≥ 48 hours for
> production contracts.

### 5.4 Mainnet Contract Address Strategy

After deploying contracts to mainnet, wire the on-chain addresses into the
subnet configuration so the validator can interact with them.

| Contract         | Env Variable                  | Usage                              |
| ---------------- | ----------------------------- | ---------------------------------- |
| ExploitRegistry  | `VALAYR_EXPLOIT_REGISTRY`     | Record validated exploits on-chain |
| ProtocolRegistry | `VALAYR_PROTOCOL_REGISTRY`    | Register protocol bounties         |
| Treasury         | `VALAYR_TREASURY_ADDRESS`     | Competition prize escrow           |
| AdversarialMode  | `VALAYR_ADVERSARIAL_REGISTRY` | Stage 3 invariant scoring          |

**Recommended deployment chain**: Ethereum L2 (Base, Arbitrum, or Optimism) for
low gas costs. The contracts are chain-agnostic — deploy to any EVM-compatible
chain and set `VALAYR_CHAIN_ID` accordingly.

```bash
# After deployment, update .env with contract addresses
VALAYR_EXPLOIT_REGISTRY=0x...
VALAYR_PROTOCOL_REGISTRY=0x...
VALAYR_TREASURY_ADDRESS=0x...
VALAYR_ADVERSARIAL_REGISTRY=0x...
VALAYR_CHAIN_ID=8453          # Base mainnet
VALAYR_RPC_URL=https://mainnet.base.org
```

Store the deploy artifact (`deployments/deploy_*.json`) in version control
so all validators reference the same addresses.

### 5.5 Verify Determinism

```bash
# Build contracts and check bytecode hash
scripts/verify-determinism.sh

# Compare bytecode across machines
forge build --root contracts
sha256sum contracts/out/**/*.json
```

---

## 6. Monitoring & Observability

### 6.1 Health Check

```bash
# Docker
curl -sf http://localhost:9946/health
# Expected: {"status": "ok"}

# Docker Compose built-in
docker compose ps   # Check "healthy" status
```

### 6.2 Metrics

```bash
curl -s http://localhost:9946/metrics | python3 -m json.tool
```

Key metrics to monitor:

| Metric                        | Type      | Alert Threshold             |
| ----------------------------- | --------- | --------------------------- |
| `validations_total`           | Counter   | No increase in 30 min       |
| `validations_valid`           | Counter   | Valid rate < 10%            |
| `duplicates_total`            | Counter   | Duplicate rate > 80%        |
| `validation_latency_ms` (p99) | Histogram | > 60,000 ms                 |
| `uptime_seconds`              | Gauge     | Resets (unexpected restart) |

### 6.3 Log Monitoring

```bash
# Docker
docker compose logs -f --tail 100 validator

# Bare-metal with log file
tail -f /var/log/valayr/validator.log

# Search for errors
grep -i "error\|critical\|fatal" /var/log/valayr/validator.log
```

Log levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

### 6.4 Prometheus Integration (Optional)

The JSON metrics endpoint can be scraped by a custom exporter:

```python
# Example: convert /metrics to Prometheus format
import requests
from prometheus_client import Counter, Histogram, Gauge

metrics = requests.get("http://localhost:9946/metrics").json()
# Map to Prometheus types...
```

### 6.5 Alert Examples

| Condition                 | Severity | Action                       |
| ------------------------- | -------- | ---------------------------- |
| `/health` returns non-200 | Critical | Restart service              |
| No validations in 30 min  | Warning  | Check miner connectivity     |
| p99 latency > 60s         | Warning  | Check resource limits        |
| Valid rate < 10%          | Warning  | Check corpus / miner quality |
| Disk usage > 80%          | Warning  | Prune fingerprint DB         |

---

## 7. Security Hardening

### 7.1 Network Isolation Checklist

- [ ] Validation sandbox runs with `--network=none`
- [ ] Entrypoint verifies network isolation (curl test)
- [ ] Metrics port (9946) is not exposed to the public internet
- [ ] Anvil RPC ports are localhost-only and ephemeral

### 7.2 Secret Management

- [ ] `ETH_PRIVATE_KEY` stored in environment variable, not files
- [ ] Docker `.env` file has `chmod 0600` permissions
- [ ] `.env` is in `.gitignore`
- [ ] Private key is deleted from memory after use (`del _pk`)
- [ ] Bittensor wallet keys have restricted file permissions

### 7.3 Container Hardening

- [ ] Base images pinned by SHA digest (not `:latest`)
- [ ] Non-root user (`appuser`) in all containers
- [ ] Read-only filesystem where possible
- [ ] CPU and memory limits set
- [ ] No privileged containers
- [ ] `.dockerignore` excludes build artefacts

### 7.4 File Permissions

```bash
# Secure data directories
chmod 0700 data/
chmod 0644 data/fingerprints.json
chmod 0600 .env
```

### 7.5 Firewall Rules

```bash
# Allow Bittensor p2p (adjust port as needed)
ufw allow 8091/tcp

# Allow metrics access from monitoring subnet only
ufw allow from 10.0.0.0/24 to any port 9946

# Deny all other inbound
ufw default deny incoming
```

---

## 8. Backup & Recovery

### 8.1 Critical Data

| Data                 | Path                     | Backup Frequency | Recovery Priority |
| -------------------- | ------------------------ | ---------------- | ----------------- |
| Fingerprint DB       | `data/fingerprints.json` | Every epoch      | High              |
| Anti-collusion state | `data/anticollusion/`    | Every epoch      | Medium            |
| Validation reports   | `data/reports/`          | Daily            | Low               |
| Bittensor wallet     | `~/.bittensor/wallets/`  | Once (offline)   | Critical          |

### 8.2 Backup Script

```bash
#!/bin/bash
# backup-valayr.sh
BACKUP_DIR="/backup/valayr/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Critical data
cp -r data/fingerprints.json "$BACKUP_DIR/"
cp -r data/anticollusion/ "$BACKUP_DIR/"

# Compress
tar czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

echo "Backup saved to $BACKUP_DIR.tar.gz"
```

### 8.3 Recovery Procedure

1. Stop the validator: `docker compose stop validator`
2. Restore data: `tar xzf backup.tar.gz -C data/`
3. Verify fingerprint DB integrity: `python3 -c "import json; json.load(open('data/fingerprints.json'))"`
4. Restart: `docker compose start validator`
5. Verify health: `curl http://localhost:9946/health`

---

## 9. Upgrading

### 9.1 Version Upgrade Procedure

```bash
# 1. Pull latest code
git pull origin main

# 2. Rebuild images
docker build -t ghcr.io/exploit-subnet/validator:v0.2.0 -f docker/Dockerfile.validator .
docker build -t ghcr.io/exploit-subnet/miner:v0.2.0 -f docker/Dockerfile.miner .

# 3. Update image tags in docker-compose.yml
# Edit: image: ghcr.io/exploit-subnet/validator:v0.2.0

# 4. Rolling restart
docker compose up -d --no-deps validator
docker compose up -d --no-deps consensus-relay
docker compose up -d --no-deps miner

# 5. Verify
docker compose ps
curl http://localhost:9946/health
```

### 9.2 Contract Upgrade

Smart contracts are **immutable** once deployed. To upgrade:

1. Deploy new contract version
2. Update validator configuration to point to new addresses
3. Migrate any relevant on-chain state
4. Update validators via coordinated rollout

### 9.3 Rollback

```bash
# Revert to previous image
docker compose down
# Edit docker-compose.yml to previous version tag
docker compose up -d
```

---

## 10. Troubleshooting

### 10.1 Common Issues

#### Validator not receiving submissions

```bash
# Check Bittensor registration
btcli subnet list --netuid <NETUID>

# Check axon is reachable
btcli wallet overview --wallet.name default

# Check logs for errors
docker compose logs validator | grep -i error
```

#### Validation timeouts

```bash
# Check Anvil is working
docker compose exec validator forge --version
docker compose exec validator anvil --version

# Check resource availability
docker stats --no-stream

# Increase timeout if needed (env var)
VALIDATION_TIMEOUT=180
```

#### Network isolation failure

```bash
# Verify sandbox has no network
docker compose run --rm validation-sandbox curl -s https://1.1.1.1
# Expected: connection error

# If it succeeds, check docker-compose.yml:
# validation-sandbox must have: network_mode: "none"
```

#### Fingerprint DB corruption

```bash
# Validate JSON
python3 -c "import json; json.load(open('data/fingerprints.json'))"

# If corrupt, restore from backup
cp /backup/valayr/latest/fingerprints.json data/fingerprints.json

# If no backup, reset (loses dedup history)
echo '{}' > data/fingerprints.json
```

#### High duplicate rate

This is normal if many miners are targeting the same vulnerability. Check:

```bash
# View fingerprint stats
python3 -c "
import json
db = json.load(open('data/fingerprints.json'))
for task_id, records in db.items():
    print(f'{task_id}: {len(records)} unique fingerprints')
"
```

#### Memory issues

```bash
# Check container memory usage
docker stats --no-stream

# Prune old data
python3 -c "
from validator.fingerprint.dedup import FingerprintEngine
engine = FingerprintEngine()
pruned = engine.prune(max_age_days=30)
print(f'Pruned {pruned} records')
"
```

### 10.2 Diagnostic Commands

```bash
# Full system check
docker compose ps && \
curl -sf http://localhost:9946/health && \
curl -s http://localhost:9946/metrics | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Validations: {d[\"counters\"].get(\"validations_total\",0)}')"

# Check determinism
docker compose exec validator bash -c '
echo "PYTHONHASHSEED=$PYTHONHASHSEED"
echo "ANVIL_BLOCK_TIMESTAMP=$ANVIL_BLOCK_TIMESTAMP"
forge --version | head -1
solc --version | tail -1
'

# Test sandbox isolation
docker compose run --rm validation-sandbox /app/entrypoint.sh validate --dry-run

# View recent reports
ls -lt data/reports/ | head -10
```

---

## Appendix: Checklist for Production Launch

- [ ] Bittensor wallet created and registered on subnet
- [ ] Docker images built and tagged with version
- [ ] `.env` configured with correct network/wallet/key
- [ ] Network isolation verified (sandbox curl test fails)
- [ ] Health endpoint returns 200
- [ ] Metrics endpoint returns valid JSON
- [ ] Monitoring alerts configured
- [ ] Backup schedule set up
- [ ] Firewall rules applied
- [ ] Log rotation configured
- [ ] Resource limits set in `docker-compose.yml`
- [ ] Deterministic config verified (PYTHONHASHSEED, Anvil params)
- [ ] Smart contracts deployed and validators whitelisted
- [ ] Test submission validated end-to-end

---

_For security-related concerns, see [SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md)._

---

## Operational Runbooks

For incident response and operational procedures, see:

| Runbook                                            | When to Use                                                  |
| -------------------------------------------------- | ------------------------------------------------------------ |
| [Key Rotation](runbooks/key-rotation.md)           | Compromised or expired validator/deployer keys               |
| [Epoch Stall](runbooks/epoch-stall.md)             | Epoch fails to close or weight-setting stalls                |
| [Consensus Failure](runbooks/consensus-failure.md) | Validators cannot reach quorum on submissions                |
| [Validator Drift](runbooks/validator-drift.md)     | Determinism check fails or validators give different results |
| [Treasury](runbooks/treasury.md)                   | Creating, settling, or debugging Treasury competitions       |
| [Incident Response](runbooks/incident-response.md) | Security incidents, exploit leaks, emergency procedures      |
| [Validator Recovery](runbooks/validator-recovery.md) | Recovering a failed or corrupted validator node            |
| [Backup & Recovery](runbooks/backup-recovery.md)   | Data backup procedures and disaster recovery                 |
| [Mainnet Deploy](runbooks/mainnet-deploy.md)       | Step-by-step mainnet contract deployment                     |
