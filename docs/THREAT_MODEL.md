# VALayr — Threat Model

> Version 1.0 · Last updated: 2025-07

## 1. Overview

VALayr is a Bittensor subnet (SN-XX) that incentivises discovery of smart-contract exploits through an adversarial mining process. Miners submit Solidity exploit code, validators execute it in a deterministic sandbox, and the results are scored, fingerprinted, de-duplicated, and recorded on-chain for optional bounty payout.

This document describes the system's **threat actors**, **trust boundaries**, **attack surfaces**, **assets at risk**, and **mitigations** in the current design.

---

## 2. Threat Actors

| Actor                      | Capability                                                                                | Motivation                                                                 |
| -------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Malicious Miner**        | Submits arbitrary Solidity to validators; registered on Bittensor with a hotkey           | Inflate rewards, front-run other miners, steal exploit IP, disrupt scoring |
| **Colluding Validators**   | Operate ≥1 validator node; can produce false validation results                           | Inflate ally miners' scores, suppress competitors, drain bounty pools      |
| **External Attacker**      | Network access to exposed services (metrics endpoint, Docker host, Bittensor p2p)         | Denial of service, data exfiltration, code injection                       |
| **Compromised Dependency** | Supply-chain poisoning of Foundry toolchain, Solidity compiler, Python packages           | Sandbox escape, backdoor exploit validation                                |
| **Rug-Pull Protocol**      | A registered protocol owner that tries to withdraw bounty before valid claims are settled | Avoid paying legitimate exploit bounties                                   |

---

## 3. Trust Boundaries

```
┌───────────────────────────────────────────────────────┐
│                    PUBLIC INTERNET                     │
│   (Bittensor p2p, EVM RPC, metrics port 9946)        │
└──────────┬────────────────────────┬───────────────────┘
           │ Synapse / axon          │ HTTP
           ▼                         ▼
┌─────────────────────┐   ┌──────────────────────┐
│  VALIDATOR NEURON   │   │  CONSENSUS RELAY     │
│  (neurons/          │   │  (validator/          │
│   validator.py)     │   │   anticollusion/      │
│                     │   │   consensus.py)       │
│  ┌───────────────┐  │   │  Port 9946            │
│  │ Orchestrator  │  │   └──────────────────────┘
│  └──────┬────────┘  │
│         │           │
│  ┌──────▼────────┐  │
│  │ SANDBOX       │  │  ◀── network = none (Docker)
│  │ (Anvil +      │  │
│  │  forge build) │  │
│  └───────────────┘  │
└─────────────────────┘
           │
           ▼  (on-chain tx)
┌─────────────────────┐
│  EVM CHAIN          │
│  CommitReveal.sol   │
│  ExploitRegistry.sol│
│  ProtocolRegistry.sol│
└─────────────────────┘
```

### Boundary Descriptions

| #   | Boundary                    | From → To                                   | Enforcement                                                                                   |
| --- | --------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------- |
| B-1 | **Miner → Validator**       | Untrusted Solidity enters validator process | Size limit (64 KB), path-traversal sanitiser, sandbox (Docker `--network=none`, ephemeral fs) |
| B-2 | **Off-chain → On-chain**    | Validation results written to EVM contracts | `onlyValidator` modifier on `recordExploit()`, commit-reveal prevents front-running           |
| B-3 | **Docker isolation**        | Validator container has zero internet       | `network_mode: "none"` + entrypoint guard (`curl 1.1.1.1 → fatal exit`)                       |
| B-4 | **Commit → Reveal window**  | Time-locked secret disclosure               | 2-hour commit window, 4-hour reveal window enforced by `block.timestamp`                      |
| B-5 | **Protocol owner → Subnet** | External protocols opt-in with bounties     | `MIN_BOUNTY = 0.01 ETH`, `extcodehash` verification, 72-hour disclosure window                |
| B-6 | **Validator ↔ Validator**   | Multi-validator consensus                   | ≥ 5 quorum, ≥ 66 % agreement threshold, divergence tracking with auto-slashing                |

---

## 4. Attack Surface Analysis

### 4.1 Smart Contract Entry Points

| Function                                | Access                | Threat                         | Mitigation                                                                  |
| --------------------------------------- | --------------------- | ------------------------------ | --------------------------------------------------------------------------- |
| `CommitReveal.commit()`                 | Any sender            | Spam commits (DoS)             | `MAX_COMMITS_PER_TASK = 256`                                                |
| `CommitReveal.reveal()`                 | Committed miners only | Hash pre-image race            | Time window enforced on-chain; nonce generated with `secrets.token_hex(32)` |
| `ExploitRegistry.recordExploit()`       | `onlyValidator`       | Fake exploit injection         | Validator whitelist + multi-quorum check (`MIN_QUORUM = 5`)                 |
| `ProtocolRegistry.registerContract()`   | Any (with ETH)        | Registration spam              | Minimum bounty requirement (0.01 ETH), `extcodehash` check                  |
| `ProtocolRegistry.recordExploit()`      | `onlyValidator`       | False claim to drain bounty    | Validator whitelist, 90 % max reward cap (`MAX_REWARD_BPS = 9000`)          |
| `ProtocolRegistry.withdrawBounty()`     | `onlyProtocol`        | Withdraw before claims settled | Disclosure window enforcement loop (72 h)                                   |
| `ProtocolRegistry.payExploitReward()`   | Any (after window)    | Reentrancy                     | Checks-effects-interactions pattern; reward computed once and immutable     |
| `AdversarialScoring.processChallenge()` | `onlyOwner`           | Centralised scoring            | Designed as validator-only in Stage 3; decentralisation planned             |

### 4.2 Network Interfaces

| Interface                  | Port          | Exposure                                                      | Mitigation                                                                 |
| -------------------------- | ------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Bittensor axon (validator) | Bittensor p2p | Receives `ExploitSubmissionSynapse` from any registered miner | Hotkey blacklist, per-miner rate limit (50/epoch), global epoch cap (1000) |
| Bittensor axon (miner)     | Bittensor p2p | Receives `ExploitQuerySynapse` from validators                | Bittensor synapse auth                                                     |
| Metrics HTTP               | 9946          | JSON health / metrics                                         | Read-only, no auth (bind `0.0.0.0` when in Docker, `127.0.0.1` otherwise)  |
| Anvil RPC                  | 18545+        | localhost only, ephemeral per validation                      | Killed after each run; never exposed externally                            |

### 4.3 File I/O

| Path                                          | R/W | Risk                                       | Mitigation                                          |
| --------------------------------------------- | --- | ------------------------------------------ | --------------------------------------------------- |
| `data/fingerprints.json`                      | R/W | Dedup corruption → duplicate rewards       | `fcntl.LOCK_EX` + atomic `os.replace`               |
| `data/anticollusion/anticollusion_state.json` | R/W | False slashing decisions                   | Bounded history (10 K entries), periodic pruning    |
| `data/commit-reveal/commit_*.json`            | R/W | Loss = can't reveal; theft = front-running | File-system ACLs, `chmod 0600`                      |
| `data/reports/*.json`                         | W   | Exploit IP leakage                         | Written inside secure validator container           |
| `data/miner/exploits/*.sol`                   | R/W | Pre-disclosure vulnerability details       | Miner-local, never transmitted after validation     |
| `/tmp/exploit-val-*`                          | R/W | Sandbox escape artefacts                   | Auto-cleaned in `finally` block; `tempfile.mkdtemp` |

---

## 5. Asset Inventory

### 5.1 Financial

| Asset               | Location                                                | CIA Impact                                |
| ------------------- | ------------------------------------------------------- | ----------------------------------------- |
| Bounty pools        | `ProtocolRegistry.registry[hash].bountyPool` (on-chain) | Loss of funds if fake exploit is recorded |
| TAO stake/incentive | Bittensor metagraph                                     | Weight manipulation = TAO misallocation   |
| Exploit rewards     | `ProtocolRegistry.claims[hash][fp].rewardAmount`        | Over-payment via duplicate fingerprints   |

### 5.2 Intellectual Property

| Asset                   | Location                                | CIA Impact                                 |
| ----------------------- | --------------------------------------- | ------------------------------------------ |
| Exploit source code     | Synapse payloads, `data/reports/*.json` | Pre-disclosure leakage to competitors      |
| Commit nonces           | `data/commit-reveal/commit_*.json`      | Theft = front-running; loss = can't reveal |
| Vulnerability templates | `task-generator/templates/*.sol`        | Low — public after generation              |

### 5.3 Cryptographic Material

| Asset                 | Location                | CIA Impact                                     |
| --------------------- | ----------------------- | ---------------------------------------------- |
| `ETH_PRIVATE_KEY`     | Runtime env var, memory | On-chain tx signing (commit-reveal, recording) |
| Bittensor wallet keys | `bt.wallet()` keystore  | Staking, weight-setting authority              |
| Anvil deployer key    | Hardcoded (`0xac09…`)   | LOW — well-known test key, sandbox only        |

---

## 6. STRIDE Analysis

### 6.1 Spoofing

| Threat                                    | Impact                   | Mitigation                                                                        |
| ----------------------------------------- | ------------------------ | --------------------------------------------------------------------------------- |
| Miner impersonates another miner's hotkey | Steal credit for exploit | Bittensor cryptographic identity (hotkey/coldkey); commit-reveal on-chain binding |
| Fake validator records exploit            | Drain bounty pool        | `onlyValidator` modifier; validators added only by contract owner                 |

### 6.2 Tampering

| Threat                                  | Impact                                | Mitigation                                                                    |
| --------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------- |
| Miner submits code that escapes sandbox | Arbitrary code execution on validator | Docker `--network=none`, ephemeral workspace, entrypoint guard, non-root user |
| Fingerprint DB corruption               | Duplicates paid as originals          | `fcntl.LOCK_EX` exclusive file locking, atomic `os.replace()`                 |
| Validator manipulates scoring           | Inflated/deflated miner weights       | Multi-validator consensus (≥ 5 quorum, ≥ 66 % agreement)                      |

### 6.3 Repudiation

| Threat                             | Impact                        | Mitigation                                                                             |
| ---------------------------------- | ----------------------------- | -------------------------------------------------------------------------------------- |
| Validator denies validation result | Dispute resolution impossible | On-chain commit-reveal provides immutable audit trail; consensus relay logs exportable |
| Miner denies submission            | Weight disputes               | Bittensor synapse provides signed message trail                                        |

### 6.4 Information Disclosure

| Threat                                       | Impact                    | Mitigation                                                                               |
| -------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------- |
| Exploit code leaked before disclosure window | Front-running by attacker | Commit-reveal: hash published on-chain first, code revealed only after window            |
| Private key in process listing               | Key theft                 | `ETH_PRIVATE_KEY` passed via env var (not CLI args); `del _pk` after use in miner neuron |
| Metrics endpoint leaks sensitive data        | Operational intelligence  | Read-only JSON; no exploit data; bind `127.0.0.1` outside Docker                         |

### 6.5 Denial of Service

| Threat                        | Impact                  | Mitigation                                                                           |
| ----------------------------- | ----------------------- | ------------------------------------------------------------------------------------ |
| Commit spam on-chain          | Block legitimate miners | `MAX_COMMITS_PER_TASK = 256`; requires gas                                           |
| Submission flood to validator | Resource exhaustion     | Per-miner rate limit (50/epoch), global cap (1000/epoch), submission cooldown (30 s) |
| Contract registration spam    | Registry bloat          | `MIN_BOUNTY = 0.01 ETH`                                                              |
| Large exploit source          | Memory/disk exhaustion  | 64 KB size limit                                                                     |

### 6.6 Elevation of Privilege

| Threat                                  | Impact                       | Mitigation                                                                   |
| --------------------------------------- | ---------------------------- | ---------------------------------------------------------------------------- |
| Exploit code gains shell access         | Full validator compromise    | Solidity runs in Anvil EVM — no host syscall access; Docker isolation        |
| `transferOwnership` called by non-owner | Contract takeover            | `onlyOwner` modifier + `ZeroAddress` custom error on all ownership transfers |
| Path traversal in exploit imports       | Read/write outside workspace | `_sanitize_source()` rejects `..` and absolute paths                         |

---

## 7. Data Flow Diagram

```
MINER                        VALIDATOR                         EVM CHAIN
  │                              │                                │
  │  1. prepare_commit()         │                                │
  │     keccak256(task+hash+nonce)│                               │
  │                              │                                │
  │  2. submit_commit(hash) ─────────────────────────────────────▶ CommitReveal
  │                              │                                │  .commit()
  │     [2-hour commit window]   │                                │
  │                              │                                │
  │  3. ExploitSubmissionSynapse ▶ _handle_submission()           │
  │     (task_id, source,        │  ├─ blacklist_check            │
  │      commit_hash, nonce)     │  ├─ rate_limit_check           │
  │                              │  │                             │
  │                              │  4. reveal_and_process()       │
  │                              │     ├─ reveal() ──────────────▶ CommitReveal
  │                              │     │                          │  .reveal()
  │                              │  5. process_submission()       │
  │                              │     ├─ sanitize_source()       │
  │                              │     ├─ ValidationEngine        │
  │                              │     │  ├─ forge build          │
  │                              │     │  ├─ start_anvil()        │
  │                              │     │  ├─ deploy + execute     │
  │                              │     │  ├─ capture state diff   │
  │                              │     │  └─ compute fingerprint  │
  │                              │     ├─ SeverityScorer          │
  │                              │     ├─ FingerprintEngine       │
  │                              │     │  (check_duplicate)       │
  │                              │     ├─ AntiCollusionEngine     │
  │                              │     │  (consensus vote)        │
  │                              │     └─ save_report()           │
  │                              │                                │
  │                              │  6. close_epoch()              │
  │                              │     ├─ compute_weights()       │
  │                              │     └─ set_weights() ─────────▶ subtensor
  │                              │                                │
  │                              │  7. (optional)                 │
  │                              │     ├─ recordExploit() ───────▶ ExploitRegistry
  │                              │     └─ recordExploit() ───────▶ ProtocolRegistry
  │                              │                                │
  │                              │     [72-hour disclosure]       │
  │                              │                                │
  │◀──── payExploitReward() ─────────────────────────────────────── ProtocolRegistry
```

---

## 8. Risk Matrix

| ID   | Threat                               | Likelihood | Impact   | Risk       | Status                                                                      |
| ---- | ------------------------------------ | ---------- | -------- | ---------- | --------------------------------------------------------------------------- |
| T-1  | Sandbox escape via Solidity imports  | Low        | Critical | **High**   | Mitigated (path sanitiser + Docker `--network=none`)                        |
| T-2  | Validator collusion (< 5 validators) | Medium     | High     | **High**   | Mitigated (quorum ≥ 5, consensus ≥ 66 %, divergence slashing)               |
| T-3  | Front-running exploit submissions    | Medium     | High     | **High**   | Mitigated (on-chain commit-reveal, 2 h commit window)                       |
| T-4  | Bounty pool drain via fake exploit   | Low        | Critical | **High**   | Mitigated (`onlyValidator`, disclosure window, 90 % reward cap)             |
| T-5  | Fingerprint DB corruption            | Low        | Medium   | **Medium** | Mitigated (file locking, atomic writes, on-chain mirror)                    |
| T-6  | Private key leakage                  | Low        | Critical | **Medium** | Mitigated (env-var only, `del _pk`, never in CLI args/ps)                   |
| T-7  | Exploit IP leaked before disclosure  | Medium     | Medium   | **Medium** | Mitigated (commit-reveal, validator sandbox isolation)                      |
| T-8  | DoS via submission flood             | Medium     | Low      | **Low**    | Mitigated (rate limits, size limits, gas costs)                             |
| T-9  | Ownership transfer to zero address   | Low        | Medium   | **Low**    | Mitigated (`ZeroAddress` custom error on all contracts)                     |
| T-10 | Supply-chain compromise (tooling)    | Low        | Critical | **Medium** | Partially mitigated (pinned Foundry nightly, solc version, Docker base SHA) |

---

## 9. Residual Risks & Recommendations

| #   | Residual Risk                                                                                         | Recommendation                                                     | Priority |
| --- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | -------- |
| R-1 | **Reentrancy in `payExploitReward` / `withdrawBounty`** — uses `call{value}` without reentrancy guard | Add OpenZeppelin `ReentrancyGuard` or move to pull-payment pattern | High     |
| R-2 | **Centralised ownership** — all contracts have a single `owner`                                       | Migrate to multi-sig or governance timelock before mainnet         | High     |
| R-3 | **Solidity compiler pinning** — contracts compile with `0.8.28` but `foundry.toml` may auto-update    | Pin `solc_version = "0.8.28"` explicitly in `foundry.toml`         | Medium   |
| R-4 | **Validator key rotation** — no mechanism to rotate compromised validator keys                        | Implement key rotation with grace period                           | Medium   |
| R-5 | **Fingerprint DB pruning** — unbounded growth over time                                               | Implement time-based or size-based pruning with archival           | Low      |
| R-6 | **Epoch overlap race** — new epoch can start before prior epoch's weights are set                     | Add epoch overlap guard in orchestrator                            | Low      |

---

## 10. Security Controls Summary

| Control                            | Type                   | Location                                         |
| ---------------------------------- | ---------------------- | ------------------------------------------------ |
| Commit-reveal scheme               | Preventive             | `CommitReveal.sol`, `validator/commit_reveal.py` |
| Docker network isolation           | Preventive             | `docker-compose.yml`, `entrypoint.sh`            |
| Path-traversal sanitiser           | Preventive             | `validator/engine/validate.py`                   |
| Multi-validator consensus          | Detective + Corrective | `validator/anticollusion/consensus.py`           |
| Fingerprint deduplication          | Detective              | `validator/fingerprint/dedup.py`                 |
| Rate limiting (per-miner + global) | Preventive             | `neurons/validator.py`                           |
| Disclosure window enforcement      | Preventive             | `ProtocolRegistry.sol`                           |
| Divergence-based slashing          | Corrective             | `validator/anticollusion/consensus.py`           |
| Private key hygiene                | Preventive             | `neurons/miner.py`, `validator/commit_reveal.py` |
| Deterministic build toolchain      | Preventive             | Dockerfiles, CI, `PYTHONHASHSEED=0`              |
| Non-root container user            | Preventive             | `Dockerfile.validator`, `Dockerfile.miner`       |
| OwnershipTransferred events        | Detective              | All four contracts                               |

---

_This document should be updated when new components are added or trust boundaries change._
