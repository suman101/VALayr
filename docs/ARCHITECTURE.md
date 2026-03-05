# VALayr — System Architecture

> Version 1.1 · Last updated: 2026-03-03

## 1. Executive Summary

VALayr is a **Bittensor subnet (SN-XX)** that incentivises the deterministic, adversarial discovery of smart-contract exploits. Miners craft Solidity exploit code targeting vulnerable contracts; validators execute it in sandboxed Anvil instances, fingerprint the results, score severity, de-duplicate submissions, and produce on-chain weight vectors that distribute TAO rewards.

The system is designed around three hard constraints:

1. **Adversarial incentives** — every scoring rule is deterministic and published.
2. **Cheap verification** — validation is O(minutes) while exploit generation is O(hours).
3. **Deterministic reproducibility** — any observer can re-run validation and reach the same result.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              VALayr Subnet                                       │
│                                                                                  │
│  ┌─────────────────┐     ┌──────────────────┐     ┌────────────────────────┐    │
│  │ Task Generator   │────▶│  Miners           │────▶│  Validation Engine     │    │
│  │ (Deterministic   │     │  (Exploit craft)  │     │  (Docker + Anvil       │    │
│  │  Corpus)         │     │                   │     │   --network=none)      │    │
│  └─────────────────┘     └──────────────────┘     └────────┬───────────────┘    │
│                                                             │                    │
│                                                             ▼                    │
│  ┌─────────────────┐     ┌──────────────────┐     ┌────────────────────────┐    │
│  │ Bittensor Chain  │◀────│ Subnet Incentive  │◀────│ Fingerprint / Dedup    │    │
│  │ (TAO weights)    │     │ Adapter           │     │ + Severity Scoring     │    │
│  └─────────────────┘     └──────────────────┘     └────────┬───────────────┘    │
│                                                             │                    │
│                                                             ▼                    │
│  ┌─────────────────┐     ┌──────────────────┐     ┌────────────────────────┐    │
│  │ EVM Chain        │◀────│ Commit-Reveal     │     │ Anti-Collusion         │    │
│  │ (Contracts)      │     │ (On-chain)        │     │ Consensus Engine       │    │
│  └─────────────────┘     └──────────────────┘     └────────────────────────┘    │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

### 3.1 Component Map

```
                    ┌───────────────────────────────┐
                    │        orchestrator.py         │
                    │    (Central Pipeline Glue)     │
                    └──────┬────────────────────────┘
                           │
        ┌──────────────────┼──────────────────────────────────┐
        │                  │                                   │
        ▼                  ▼                                   ▼
┌───────────────┐  ┌───────────────┐                 ┌───────────────────┐
│ task-generator │  │   validator   │                 │  subnet-adapter   │
│               │  │               │                 │                   │
│ generate.py   │  │ engine/       │                 │ incentive.py      │
│ mutator/      │  │   validate.py │                 │ (weight vectors)  │
│  base.py      │  │ fingerprint/  │                 └───────────────────┘
│  registry.py  │  │   dedup.py    │
│  rename.py    │  │ scoring/      │                 ┌───────────────────┐
│  storage.py   │  │   severity.py │                 │     neurons       │
│  balance.py   │  │ anticollusion/│                 │                   │
│  deadcode.py  │  │   consensus.py│◄────────────────│ validator.py      │
│ templates/    │  │ commit_reveal │                 │ miner.py          │
└───────────────┘  │   .py         │                 │ protocol.py       │
                   │ metrics.py    │                 └───────────────────┘
                   │ utils/        │
                   │   logging.py  │                 ┌───────────────────┐
                   │   hashing.py  │                 │      miner        │
                   └───────────────┘                 │   cli.py          │
                                                     └───────────────────┘
                   ┌───────────────┐
                   │  contracts/   │
                   │ CommitReveal  │
                   │ ExploitReg    │
                   │ ProtocolReg   │
                   │ stage3/       │
                   │  Adversarial  │
                   └───────────────┘
```

### 3.2 Component Responsibilities

| Component                 | Location                     | Responsibility                                                                                                                             |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Orchestrator**          | `orchestrator.py`            | Central integration point; wires task generation → validation → fingerprinting → scoring → incentive computation → epoch weight production |
| **Task Generator**        | `task-generator/`            | Produces deterministic vulnerable Solidity contract packages from templates + mutations                                                    |
| **Mutator Framework**     | `task-generator/mutator/`    | Pluggable source-level transformations that preserve vulnerability semantics while changing bytecode fingerprints                          |
| **Validation Engine**     | `validator/engine/`          | Executes exploit submissions in deterministic, sandboxed Anvil instances; binary outcome (VALID / REJECT)                                  |
| **Fingerprint Engine**    | `validator/fingerprint/`     | Computes state-impact fingerprints and deduplicates submissions; first submitter gets full reward                                          |
| **Severity Scorer**       | `validator/scoring/`         | Algorithmic severity scoring (funds drained, privilege escalation, invariant breakage, permanent lock)                                     |
| **Anti-Collusion Engine** | `validator/anticollusion/`   | Multi-validator consensus with quorum, agreement thresholds, divergence tracking, and slashing                                             |
| **Commit-Reveal**         | `validator/commit_reveal.py` | Two-phase anti-front-running: hash commitment on-chain → timed reveal window                                                               |
| **Metrics Server**        | `validator/metrics.py`       | Lightweight HTTP `/health` + `/metrics` endpoint for monitoring                                                                            |
| **Subnet Adapter**        | `subnet-adapter/`            | Translates validation results into Bittensor-compatible weight vectors                                                                     |
| **Validator Neuron**      | `neurons/validator.py`       | Bridges Orchestrator ↔ Bittensor network (axon, metagraph, weight setting)                                                                 |
| **Miner Neuron**          | `neurons/miner.py`           | Receives task queries, manages exploit preparation and commit-reveal submission                                                            |
| **Miner CLI**             | `miner/cli.py`               | Interactive command-line workflow: list tasks → scaffold → submit → check scores                                                           |
| **Smart Contracts**       | `contracts/src/`             | On-chain state: commit-reveal registry, exploit registry, protocol bounty registry, adversarial scoring                                    |

---

## 4. Data Flow

### 4.1 End-to-End Pipeline

```
     ┌─────────┐         ┌────────────┐         ┌───────────┐
     │  MINER  │         │ VALIDATOR  │         │ EVM CHAIN │
     └────┬────┘         └─────┬──────┘         └─────┬─────┘
          │                    │                       │
          │  ─── 1. List tasks (ExploitQuerySynapse) ──▶
          │  ◀── Task corpus list ─────────────────────│
          │                    │                       │
          │  ─── 2. prepare_commit() ──────────────────│
          │       keccak256(task + exploit + nonce)     │
          │                    │                       │
          │  ─── 3. submit_commit(hash) ───────────────────────▶ CommitReveal.commit()
          │                    │                       │
          │     [2-hour commit window elapses]         │
          │                    │                       │
          │  ─── 4. ExploitSubmissionSynapse ─────────▶│
          │       (task_id, source, hash, nonce)       │
          │                    │                       │
          │                    │── 5. reveal() ────────────────▶ CommitReveal.reveal()
          │                    │                       │
          │                    │── 6. Validate in sandbox ─┐   │
          │                    │   ├─ forge build           │   │
          │                    │   ├─ start Anvil           │   │
          │                    │   ├─ deploy + execute      │   │
          │                    │   ├─ capture state diff    │   │
          │                    │   └─ compute fingerprint   │   │
          │                    │                       ◀───┘   │
          │                    │                       │
          │                    │── 7. Score severity           │
          │                    │── 8. Check duplicates         │
          │                    │── 9. Anti-collusion vote      │
          │                    │── 10. Record metrics          │
          │                    │                       │
          │  ◀── SubmissionResult ─────────────────────│
          │                    │                       │
          │                    │── 11. close_epoch()           │
          │                    │   ├─ compute_weights()        │
          │                    │   └─ set_weights() ──────────▶ Bittensor subtensor
          │                    │                       │
          │                    │── 12. (optional) ─────────────▶ ExploitRegistry
          │                    │       recordExploit() ────────▶ ProtocolRegistry
          │                    │                       │
          │                    │   [72-hour disclosure]        │
          │                    │                       │
          │  ◀── payExploitReward() ───────────────────────── ProtocolRegistry
          │                    │                       │
```

### 4.2 Validation Engine Pipeline (11 Steps)

```
ExploitSubmission
       │
       ▼
 ┌─ Step 0: Input Validation ─────────────────────────────────┐
 │  • Source size check (≤ 64 KB)                             │
 │  • Path-traversal sanitisation (reject ".." and abs paths) │
 └────────────────────────────────┬────────────────────────────┘
                                  │
       ▼                          │
 ┌─ Step 1: Workspace Setup ──────┤
 │  • tempfile.mkdtemp()          │
 │  • Write Vulnerable.sol        │
 │  • Write Exploit.t.sol         │
 │  • Generate foundry.toml       │
 │  • Symlink forge-std            │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Step 2: Compile ──────────────┤
 │  • forge build (120s timeout)  │
 │  • Parse compiler errors       │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Step 3: Start Anvil ──────────┤
 │  • Deterministic config:       │
 │    timestamp=1700000000        │
 │    block=18000000              │
 │    gas=30000000                │
 │    chain=31337                 │
 │  • Poll eth_chainId readiness  │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Steps 4–5: Deploy + Pre-State ┤
 │  • forge create (deploy target)│
 │  • anvil_dumpState             │
 │  • eth_getLogs                 │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Step 6: Execute Exploit ──────┤
 │  • forge test --fork-url ...   │
 │    -vvvv --json --gas-report   │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Steps 7–8: Post-State + Trace ┤
 │  • anvil_dumpState (post)      │
 │  • Diff pre/post storage       │
 │  • Parse gas from JSON         │
 │  • Extract function selectors  │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Step 9: Binary Validation ────┤
 │  • State must have changed     │
 │  • Exploit must not revert     │
 │  • Gas ≥ MIN_GAS_THRESHOLD     │
 └────────────────────────────────┤
                                  │
       ▼                          │
 ┌─ Steps 10–11: Fingerprint      │
 │  + Severity ───────────────────┘
 │  • keccak256 of canonical
 │    state-impact components
 │  • Weighted severity score
 └────────────────────────────────▶ ValidationReport
```

---

## 5. Module Deep Dives

### 5.1 Orchestrator (`orchestrator.py`)

The orchestrator is the central integration point. It initialises every sub-component and exposes the pipeline through a single-class API.

**Modes:**

- `local` — in-process validation (development / testing)
- `docker` — network-disabled container (`--network=none`, read-only data volume, CPU/RAM limits)

**Key Methods:**

| Method                                                    | Description                                               |
| --------------------------------------------------------- | --------------------------------------------------------- |
| `generate_corpus(count_per_class, seed)`                  | Generate or refresh the task corpus via `CorpusGenerator` |
| `load_task(task_id)`                                      | Load task by ID or unambiguous prefix                     |
| `commit_exploit(task_id, source, miner, nonce)`           | Phase 1 of commit-reveal                                  |
| `reveal_and_process(task_id, source, miner, hash, nonce)` | Phase 2 + full validation pipeline                        |
| `process_submission(task_id, source, miner)`              | Direct validation (bypasses commit-reveal)                |
| `close_epoch(epoch, start_block, end_block)`              | Compute weights, prune state, persist results             |

**Output:** `SubmissionResult` dataclass containing validation result, fingerprint, duplicate status, severity score, reward multiplier, timing, and commit hash.

### 5.2 Task Generator (`task-generator/`)

Produces byte-for-byte reproducible vulnerable contract packages.

**Pipeline:**

```
Templates (*.sol)  ──▶  MutationRegistry  ──▶  TaskPackage  ──▶  Corpus Directory
                        ├─ RenameMutator
                        ├─ StorageLayoutMutator
                        ├─ BalanceMutator
                        └─ DeadCodeMutator
```

**Vulnerability Classes:**

| Class                       | Templates | Difficulty  |
| --------------------------- | --------- | ----------- |
| Reentrancy                  | 3         | Medium      |
| Storage Collision           | 2         | Hard        |
| Auth Bypass                 | 3         | Easy–Medium |
| Integer Overflow            | 2         | Easy        |
| Access Control              | 2         | Medium      |
| Flash Loan                  | 1         | Hard        |
| Flash Loan System (Stage 2) | 1         | Expert      |
| Upgradeable Vault (Stage 2) | 1         | Expert      |

**Determinism:** All mutations are seeded with `PYTHONHASHSEED=0` and explicit `random.Random(seed)` instances. The same seed produces the same corpus across all validators.

### 5.3 Validation Engine (`validator/engine/validate.py`)

The validation engine is the security-critical core. It executes untrusted Solidity in a deterministic sandbox and produces a binary result.

**Deterministic Anvil Configuration:**

| Parameter       | Value        | Purpose              |
| --------------- | ------------ | -------------------- |
| Block Timestamp | `1700000000` | Fixed timestamp      |
| Block Number    | `18000000`   | Fixed block height   |
| Gas Limit       | `30000000`   | Consistent gas       |
| Chain ID        | `31337`      | Standard test chain  |
| Mnemonic        | Hardcoded    | Repeatable addresses |

**Security Layers:**

1. Source size limit (64 KB)
2. Path-traversal sanitiser (rejects `..` and absolute paths)
3. Docker `--network=none` isolation
4. Ephemeral workspace (`tempfile.mkdtemp`, cleaned in `finally`)
5. Non-root container user
6. Per-validation Anvil instance (killed after each run)

**Result Types:**

| Result                       | Meaning                                     |
| ---------------------------- | ------------------------------------------- |
| `VALID`                      | Exploit successfully changed contract state |
| `REJECT_REVERT`              | Exploit transaction reverted                |
| `REJECT_NO_STATE_CHANGE`     | No storage / balance changes detected       |
| `REJECT_TIMEOUT`             | Exceeded 120s validation timeout            |
| `REJECT_COMPILE_FAIL`        | Solidity compilation failed                 |
| `REJECT_BELOW_GAS_THRESHOLD` | Gas used below 21,000 (trivial)             |
| `REJECT_INVALID_FORMAT`      | Source failed sanitisation                  |
| `REJECT_FINGERPRINT_ERROR`   | Fingerprint computation failed              |

### 5.4 Fingerprint & Dedup Engine (`validator/fingerprint/dedup.py`)

Deduplication is by **state impact**, not vulnerability class. Two exploits that drain the same funds via different code paths produce the same fingerprint.

**Fingerprint Components:**

| Component            | Source                                                |
| -------------------- | ----------------------------------------------------- |
| Function selectors   | Sorted list of 4-byte selectors called during exploit |
| Storage slot diffs   | Sorted list of `(slot, old_value, new_value)` tuples  |
| Balance delta        | Net wei change of the target contract                 |
| Ownership mutation   | Boolean: ownership storage slot changed               |
| Proxy admin mutation | Boolean: EIP-1967 admin/impl slot changed             |
| Call graph hash      | Hash of the inter-contract call sequence              |

**Canonical Fingerprint:** `keccak256(canonical_string(components))`

**Reward Policy:**

- First submission: `1.0×` multiplier (full reward)
- Duplicate submissions: `0.1×` multiplier (10%)

### 5.5 Severity Scoring (`validator/scoring/severity.py`)

Purely algorithmic — no human grading. Weights are fixed in v1 to prevent manipulation.

**Scoring Formula:**

$$\text{severity} = 0.40 \cdot S_{\text{funds}} + 0.25 \cdot S_{\text{privilege}} + 0.20 \cdot S_{\text{invariant}} + 0.15 \cdot S_{\text{lock}}$$

| Component            | Weight | Calculation                                                     |
| -------------------- | ------ | --------------------------------------------------------------- |
| Funds Drained        | 0.40   | $\min\left(\frac{\log_{10}(\text{wei} + 1)}{24}, \; 1.0\right)$ |
| Privilege Escalation | 0.25   | 1.0 if ownership or admin slot changed                          |
| Invariant Broken     | 0.20   | 1.0 if proxy impl changed, funds drained, or ≥3 slots changed   |
| Permanent Lock       | 0.15   | 1.0 if critical slot zeroed out                                 |

### 5.6 Anti-Collusion Engine (`validator/anticollusion/consensus.py`)

Multi-validator consensus prevents single-validator score manipulation.

**Parameters:**

| Parameter           | Value                     |
| ------------------- | ------------------------- |
| Minimum Quorum      | 5 validators              |
| Consensus Threshold | 66% agreement             |
| Divergence Window   | 100 validations (rolling) |
| Slash Threshold     | > 20% divergence rate     |
| Slash Amount        | 5% of stake (500 bps)     |
| Slash Cooldown      | 24 hours                  |
| Max Validators/Task | 11                        |

**Validator Selection:** Deterministic random assignment weighted by reliability score (`0.6 × lifetime_agreement + 0.4 × recent_agreement`), seeded by `keccak256(task_id)`.

**Slashing Flow:**

```
validator divergence > 20% over last 100 validations
             │
             ▼
   cooldown elapsed? (24h) ─── No ──▶ Skip
             │
            Yes
             │
             ▼
   Slash 5% stake + emit SlashEvent
             │
             ▼
   Auto-recovery when rate improves below threshold
```

### 5.7 Commit-Reveal (`validator/commit_reveal.py`)

Prevents exploit front-running — miners prove knowledge before revealing code.

**Protocol:**

```
Phase 1 — Commit (2-hour window)
   hash = keccak256(abi.encodePacked(taskId, artifactHash, nonce))
   CommitReveal.commit(taskId, hash) → on-chain

Phase 2 — Reveal (4-hour window, after commit closes)
   CommitReveal.reveal(taskId, artifactHash, nonce)
   Contract verifies: keccak256(taskId, artifactHash, nonce) == stored hash
```

**Dual-Mode Implementation:**

- `CommitRevealClient` — on-chain via `cast send`/`cast call`; private key via `ETH_PRIVATE_KEY` env var (never CLI)
- `CommitRevealSimulator` — in-memory Python mirror for local development/testing

### 5.8 Subnet Incentive Adapter (`subnet-adapter/incentive.py`)

Translates validation results into Bittensor weight vectors.

**Raw Score Formula:**

$$\text{score} = (\text{unique} \times \overline{S}) + (\text{duplicates} \times \overline{S} \times 0.1) + (\text{earliest\_commits} \times 0.05) - (\text{invalid} \times 0.05)$$

Where $\overline{S}$ is the average severity of a miner's submissions.

**Weight Normalisation:** Raw scores are normalised to sum to 1.0 across all miners in the epoch. Miners with zero raw score receive equal share (prevents starvation).

### 5.9 Metrics & Health (`validator/metrics.py`)

Zero-dependency HTTP server on port 9946.

| Endpoint       | Response                                       |
| -------------- | ---------------------------------------------- |
| `GET /health`  | `{"status": "ok"}`                             |
| `GET /metrics` | JSON: counters, gauges, histogram p50/p99/mean |

**Tracked Metrics:**

| Metric                  | Type      |
| ----------------------- | --------- |
| `validations_total`     | Counter   |
| `validations_valid`     | Counter   |
| `duplicates_total`      | Counter   |
| `validation_latency_ms` | Histogram |
| `severity_score`        | Histogram |
| `uptime_seconds`        | Gauge     |

---

## 6. Smart Contract Architecture

### 6.1 Contract Map

```
┌─────────────────────────────────────────────────────────┐
│                    EVM Chain (L1 / L2)                   │
│                                                          │
│  ┌──────────────────┐     ┌────────────────────────┐    │
│  │  CommitReveal.sol │     │ ExploitRegistry.sol     │    │
│  │                   │     │                         │    │
│  │  openTask()       │     │ recordExploit()         │    │
│  │  commit()         │     │ getExploitRecord()      │    │
│  │  reveal()         │     │ getEffectiveReward()    │    │
│  │  getEarliest      │     │                         │    │
│  │    Reveal()       │     │ FULL_REWARD = 1e18      │    │
│  │                   │     │ DUPLICATE = 1e17        │    │
│  │  COMMIT_WINDOW=2h │     │ MIN_QUORUM = 5          │    │
│  │  REVEAL_WINDOW=4h │     └────────────────────────┘    │
│  │  MAX_COMMITS=256  │                                    │
│  └──────────────────┘     ┌────────────────────────┐    │
│                            │ ProtocolRegistry.sol    │    │
│  ┌──────────────────┐     │                         │    │
│  │ stage3/           │     │ registerContract()      │    │
│  │ AdversarialMode   │     │ recordExploit()         │    │
│  │  .sol             │     │ payExploitReward()      │    │
│  │                   │     │ withdrawBounty()        │    │
│  │ InvariantRegistry │     │                         │    │
│  │ AdversarialScoring│     │ DISCLOSURE_WINDOW=72h   │    │
│  └──────────────────┘     │ MAX_REWARD_BPS=9000     │    │
│                            │ MIN_BOUNTY=0.01 ETH     │    │
│                            └────────────────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 6.2 Contract Interactions

| Contract             | Access Control                                                                                            | Key Invariants                                                                                          |
| -------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **CommitReveal**     | `owner` opens tasks; anyone commits/reveals                                                               | Hash must match on reveal; time windows enforced by `block.timestamp`                                   |
| **ExploitRegistry**  | `onlyValidator` records exploits                                                                          | Minimum quorum of 5 validators; duplicate detection via fingerprint                                     |
| **ProtocolRegistry** | Protocols register with bounty; `onlyValidator` records exploits; anyone triggers payout after disclosure | 72-hour disclosure window; 90% max reward cap; bounty withdrawal blocked during active claims           |
| **AdversarialMode**  | `onlyValidator` on InvariantRegistry + AdversarialScoring; `onlyOwner` for admin                          | Invariant writers vs. breakers — evolutionary pressure; score floor at MIN_SCORE; Pausable in emergency |

### 6.3 Stage 3 Pipeline — Adversarial Invariant Discovery

Stage 3 introduces a two-class miner system where Class A miners write invariants and Class B miners try to break them.

```
┌────────────────────┐         ┌─────────────────────────┐
│  Class A Miner     │         │  Class B Miner          │
│  (Invariant Writer)│         │  (Exploit Writer)       │
│                    │         │                         │
│  submitInvariant() │         │  Submits exploit that   │
│  → InvariantRegistry        │  targets invariant      │
└────────┬───────────┘         └──────────┬──────────────┘
         │                                │
         ▼                                ▼
┌─────────────────────────────────────────────────────────┐
│               Validator (processChallenge)               │
│                                                          │
│  1. Deploys target contract in Anvil sandbox             │
│  2. Executes Class B exploit against invariant           │
│  3. Checks if invariant holds or is broken               │
│  4. Calls AdversarialScoring.processChallenge()          │
│     which updates scores and records on InvariantRegistry│
└─────────────────────────────────────────────────────────┘

Scoring Constants (AdversarialScoring):
  W_HOLD_REWARD      = 100    Class A reward when invariant holds
  W_BREACH_PENALTY   = 500    Class A penalty when invariant is broken
  W_BREACH_REWARD    = 1000   Class B reward for breaking invariant
  W_FAILED_CHALLENGE = 10     Class B consolation for trying
  MIN_SCORE = type(int256).min / 2   Floor to prevent overflow
```

---

## 7. Security Architecture

### 7.1 Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│                        PUBLIC INTERNET                        │
│   (Bittensor p2p, EVM RPC, metrics port 9946)               │
└───────────┬──────────────────────────┬───────────────────────┘
            │ Synapse / Axon            │ HTTP
            ▼                           ▼
┌──────────────────────┐    ┌───────────────────────────┐
│  VALIDATOR NEURON    │    │   CONSENSUS RELAY          │
│                      │    │   (anticollusion engine)   │
│  ┌────────────────┐  │    │   Port 9946                │
│  │  Orchestrator  │  │    └───────────────────────────┘
│  └───────┬────────┘  │
│          │           │
│  ┌───────▼────────┐  │
│  │   SANDBOX      │  │   ◀── network = none (Docker)
│  │   (Anvil +     │  │       read-only filesystem
│  │    forge)      │  │       CPU/RAM limits
│  └────────────────┘  │       non-root user
└──────────────────────┘
            │
            ▼ (on-chain tx)
┌──────────────────────┐
│      EVM CHAIN       │
│  CommitReveal.sol    │
│  ExploitRegistry.sol │
│  ProtocolRegistry.sol│
└──────────────────────┘
```

### 7.2 Defence Layers

| Layer                         | Mechanism                                            | Protects Against                     |
| ----------------------------- | ---------------------------------------------------- | ------------------------------------ |
| **Input Validation**          | 64 KB size limit, path sanitisation                  | Oversized payloads, path traversal   |
| **Sandbox Isolation**         | Docker `--network=none`, ephemeral workspace         | Sandbox escape, network exfiltration |
| **Deterministic Execution**   | Pinned Anvil config, pinned solc, `PYTHONHASHSEED=0` | Non-reproducible validation          |
| **Commit-Reveal**             | On-chain hash commitment + timed reveal              | Front-running, exploit theft         |
| **Multi-Validator Consensus** | ≥5 quorum, ≥66% agreement                            | Single-validator manipulation        |
| **Divergence Slashing**       | 20% threshold, 5% stake slash                        | Systematic dishonest validation      |
| **Rate Limiting**             | 50/miner/epoch, 1000/epoch global                    | Submission flooding                  |
| **Fingerprint Dedup**         | State-impact hashing                                 | Duplicate reward farming             |
| **Disclosure Window**         | 72-hour on-chain enforcement                         | Bounty rug-pulls                     |
| **Key Hygiene**               | Env vars only, `del _pk` after use                   | Private key leakage                  |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full STRIDE analysis and risk matrix.

---

## 8. Infrastructure Architecture

### 8.1 Docker Services

```
┌─────────────────────────────────────────────────────────────────────┐
│                     docker-compose.yml                              │
│                                                                     │
│  ┌─────────────────────────┐     ┌──────────────────────────────┐  │
│  │      validator           │     │    consensus-relay            │  │
│  │  neurons/validator.py    │     │  anticollusion/consensus.py   │  │
│  │  4 CPU / 8 GB RAM        │     │  Port 9946 (health/metrics)  │  │
│  │  Network: enabled         │     │  Network: enabled             │  │
│  │  Vols: validator-data,   │     └──────────────────────────────┘  │
│  │        task-corpus       │                                       │
│  └────────────┬─────────────┘     ┌──────────────────────────────┐  │
│               │ spawns on-demand  │         miner                 │  │
│               ▼                   │  neurons/miner.py              │  │
│  ┌─────────────────────────┐     │  Network: enabled              │  │
│  │  validation-sandbox      │     │  Vol: miner-data               │  │
│  │  network_mode: "none"    │     └──────────────────────────────┘  │
│  │  2 CPU / 4 GB RAM        │                                       │
│  │  read-only data volume   │                                       │
│  │  profile: [sandbox]      │                                       │
│  └─────────────────────────┘                                        │
│                                                                     │
│  Volumes: validator-data, task-corpus, miner-data                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Build Toolchain

| Tool         | Version              | Purpose                              |
| ------------ | -------------------- | ------------------------------------ |
| Foundry      | `nightly-2024-12-01` | Solidity compilation + Anvil sandbox |
| solc         | `0.8.28`             | Solidity compiler (pinned)           |
| Python       | `3.10+`              | Validator logic, orchestration       |
| pycryptodome | `3.21.0`             | Ethereum keccak256 hashing           |
| Docker       | `≥ 24.0`             | Container isolation                  |
| Ubuntu       | `22.04` (SHA-pinned) | Validator base image                 |

### 8.3 Determinism Guarantees

All of the following are pinned for byte-for-byte reproducibility:

- Foundry nightly version
- Solidity compiler version
- Python hash seed (`PYTHONHASHSEED=0`)
- Anvil configuration (block, timestamp, gas, chain, mnemonic)
- Docker base image (SHA digest)
- Mutator seeds (explicit `random.Random(seed)`)
- Fuzz seed in `foundry.toml`

---

## 9. Execution Phases

### Phase 1: Single Contract (Weeks 0–4)

- Single EVM target contract per task
- Solidity-only exploits
- Deterministic exploit validation
- Core vulnerability classes: reentrancy, overflow, auth bypass, access control

### Phase 2: Multi-Contract Systems (Months 3–4)

- Proxy patterns (transparent proxy, UUPS)
- Flash loan + oracle manipulation
- Upgradeable vault attacks
- Multi-contract deployment in sandbox

### Phase 3: Adversarial Mode (Months 5–6)

- **Class A Miners**: Submit invariants (contract properties that should hold)
- **Class B Miners**: Attempt to break submitted invariants
- Dual scoring: invariant quality (hold rate) + breaking ability (challenge success)
- `InvariantRegistry` + `AdversarialScoring` contracts
- "The actual moat — evolutionary pressure"

---

## 10. Key Design Decisions

### 10.1 Determinism Over Flexibility

Every scoring rule is published, every validation is reproducible, and every weight computation is auditable. This sacrifices adaptive scoring (which could game-theoretically be stronger) for transparency (which prevents hidden manipulation).

### 10.2 State-Impact Fingerprinting

Deduplication is based on what the exploit _does_ (state changes), not how it does it (source code). This means two syntactically different exploits that drain the same funds via different paths correctly share a fingerprint.

### 10.3 Cheap Verification, Expensive Generation

Validation runs in minutes (compile + execute in Anvil). Exploit generation requires hours of analysis. This asymmetry ensures validators can process submissions at scale without becoming a bottleneck.

### 10.4 Fixed Scoring Weights

Severity weights are constants, not parameters. This eliminates an attack vector where validators could manipulate weights to favour specific miners. The trade-off is reduced adaptability.

### 10.5 Dual-Mode Everything

Every component supports local (in-memory) and production (on-chain/Docker) modes. This enables rapid development and comprehensive testing without network dependencies.

---

## 11. Sequence Diagrams

### 11.1 Miner Submission (Happy Path)

```
Miner                    Validator                  Anvil         Chain
  │                         │                         │             │
  │── list tasks ──────────▶│                         │             │
  │◀── task list ───────────│                         │             │
  │                         │                         │             │
  │── prepare_commit() ─────│                         │             │
  │── submit_commit(hash) ──│─────────────────────────│────────────▶│
  │                         │                         │             │
  │   [2h commit window]    │                         │             │
  │                         │                         │             │
  │── submit exploit ──────▶│                         │             │
  │                         │── reveal() ─────────────│────────────▶│
  │                         │                         │             │
  │                         │── setup workspace ─────▶│             │
  │                         │── forge build ─────────▶│             │
  │                         │── start Anvil ─────────▶│             │
  │                         │── deploy target ───────▶│             │
  │                         │── capture pre-state ───▶│             │
  │                         │── execute exploit ─────▶│             │
  │                         │── capture post-state ──▶│             │
  │                         │── kill Anvil ──────────▶│             │
  │                         │                         │             │
  │                         │── fingerprint + dedup   │             │
  │                         │── severity score        │             │
  │                         │── consensus vote        │             │
  │                         │                         │             │
  │◀── SubmissionResult ────│                         │             │
  │                         │                         │             │
```

### 11.2 Epoch Close

```
Validator                SubnetAdapter           AntiCollusion        Chain
  │                         │                         │               │
  │── close_epoch() ───────▶│                         │               │
  │                         │── compute weights ──────│               │
  │                         │   for each submission:  │               │
  │                         │   ├─ achieve_consensus()│               │
  │                         │   ├─ compute_raw_score()│               │
  │                         │   └─ normalize_weights()│               │
  │                         │                         │               │
  │◀── weight_vector ───────│                         │               │
  │                         │                         │               │
  │── set_weights() ────────│─────────────────────────│──────────────▶│
  │                         │                         │               │
  │── prune fingerprints    │                         │               │
  │── persist epoch result  │                         │               │
  │                         │                         │               │
```

---

## 12. Cross-References

| Document                                               | Coverage                                               |
| ------------------------------------------------------ | ------------------------------------------------------ |
| [README.md](../README.md)                              | Quickstart, component overview, CLI usage              |
| [THREAT_MODEL.md](THREAT_MODEL.md)                     | STRIDE analysis, risk matrix, attack surfaces          |
| [API_REFERENCE.md](API_REFERENCE.md)                   | Module APIs, synapse formats, contract ABIs            |
| [CONTRACT_REFERENCE.md](CONTRACT_REFERENCE.md)         | Solidity contract ABIs, storage layout, events         |
| [DEPLOYMENT.md](DEPLOYMENT.md)                         | Production deployment, Docker, monitoring              |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)               | Development setup, testing, adding components          |
| [MINER_GUIDE.md](MINER_GUIDE.md)                       | Miner onboarding, exploit writing, submission workflow |
| [VALIDATOR_GUIDE.md](VALIDATOR_GUIDE.md)               | Validator setup, epoch lifecycle, weight setting       |
| [EXPLOIT_WRITING_GUIDE.md](EXPLOIT_WRITING_GUIDE.md)   | Annotated exploit examples for every vuln class        |
| [TESTING.md](TESTING.md)                               | Test suites, CI pipeline, determinism verification     |
| [DATA_SCHEMA.md](DATA_SCHEMA.md)                       | JSON schemas for persistent state files                |
| [GLOSSARY.md](GLOSSARY.md)                             | Definitions of all key terms                           |
| [CONTRIBUTING.md](../CONTRIBUTING.md)                  | PR process, coding standards                           |
| [SECURITY.md](../SECURITY.md)                          | Vulnerability reporting, scope                         |
| [CHANGELOG.md](../CHANGELOG.md)                        | Release history                                        |

---

_This document should be updated when new components are added or architectural decisions change._
