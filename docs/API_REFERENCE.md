# VALayr — API Reference

> Version 1.2 · Last updated: 2026-03-06

This document covers the public APIs of every VALayr module: Python classes and functions, Bittensor synapse formats, smart contract interfaces, CLI commands, and HTTP endpoints.

---

## Table of Contents

- [1. Python Modules](#1-python-modules)
  - [1.1 Orchestrator](#11-orchestrator)
  - [1.2 Validation Engine](#12-validation-engine)
  - [1.3 Fingerprint Engine](#13-fingerprint-engine)
  - [1.4 Severity Scorer](#14-severity-scorer)
  - [1.5 Anti-Collusion Engine](#15-anti-collusion-engine)
  - [1.6 Subnet Incentive Adapter](#16-subnet-incentive-adapter)
  - [1.7 Bounty System](#17-bounty-system)
  - [1.8 Task Generator](#18-task-generator)
  - [1.9 Metrics Server](#19-metrics-server)
  - [1.10 Utilities](#110-utilities)
- [2. Bittensor Synapses](#2-bittensor-synapses)
- [3. Smart Contracts](#3-smart-contracts)
- [4. CLI Commands](#4-cli-commands)
- [5. HTTP Endpoints](#5-http-endpoints)

---

## 1. Python Modules

### 1.1 Orchestrator

**Module:** `orchestrator.py`

#### Class: `Orchestrator`

The central pipeline that wires all sub-components together.

```python
Orchestrator(mode: str = "local")
```

| Parameter | Type  | Default   | Description                                                         |
| --------- | ----- | --------- | ------------------------------------------------------------------- |
| `mode`    | `str` | `"local"` | `"local"` for in-process, `"docker"` for container-based validation |

**Methods:**

```python
def generate_corpus(count_per_class: int = 2, seed: int = 42) -> dict
```

Generate or refresh the task corpus. Returns manifest dict.

```python
def load_task(task_id: str) -> TaskPackage
```

Load a task by ID or unambiguous prefix match. Raises `ValueError` if not found or ambiguous.

```python
def process_submission(
    task_id: str,
    exploit_source: str,
    miner_address: str
) -> SubmissionResult
```

Full validation pipeline (sandbox execution, fingerprinting, severity scoring).

```python
def close_epoch(
    epoch_number: int,
    start_block: int,
    end_block: int
) -> EpochResult
```

Compute epoch weights, prune stale fingerprints, persist results.

#### Dataclass: `SubmissionResult`

```python
@dataclass
class SubmissionResult:
    task_id: str
    miner_address: str
    validation_result: str          # "valid" or "reject_*"
    fingerprint: str                # keccak256 hex or ""
    is_duplicate: bool
    reward_multiplier: float        # 1.0 (original) or 0.0 (rejected)
    severity_score: float           # [0.0, 1.0]
    severity_detail: str
    validation_time_ms: int
    error: str
```

---

### 1.2 Validation Engine

**Module:** `validator.engine.validate`

#### Enum: `ValidationResult`

```python
class ValidationResult(Enum):
    VALID = "valid"
    REJECT_REVERT = "reject_revert"
    REJECT_NO_STATE_CHANGE = "reject_no_state_change"
    REJECT_TIMEOUT = "reject_timeout"
    REJECT_COMPILE_FAIL = "reject_compile_fail"
    REJECT_BELOW_GAS_THRESHOLD = "reject_below_gas_threshold"
    REJECT_INVALID_FORMAT = "reject_invalid_format"
    REJECT_FINGERPRINT_ERROR = "reject_fingerprint_error"
```

#### Dataclass: `ExploitSubmission`

```python
@dataclass
class ExploitSubmission:
    task_id: str                    # hex task identifier
    exploit_source: str             # raw Solidity source code
    entry_function: str = "test_run"  # function to execute
```

#### Dataclass: `ExecutionTrace`

```python
@dataclass
class ExecutionTrace:
    storage_diffs: list[dict]       # [{"slot": "0x...", "old": "0x...", "new": "0x..."}]
    balance_before: int             # wei
    balance_after: int              # wei
    balance_delta: int              # wei (can be negative)
    event_logs: list[dict]          # decoded event log entries
    call_trace: list[dict]          # inter-contract call sequence
    gas_used: int
    reverted: bool
    function_selectors: list[str]   # sorted 4-byte selectors ["0x12345678", ...]
```

#### Dataclass: `ValidationReport`

```python
@dataclass
class ValidationReport:
    result: ValidationResult
    fingerprint: str | None
    severity: float
    trace: ExecutionTrace | None
    execution_time_ms: float
    error: str | None
```

#### Class: `ValidationEngine`

```python
ValidationEngine()
```

**Methods:**

```python
def validate(
    submission: ExploitSubmission,
    task: TaskPackage
) -> ValidationReport
```

Execute the full 11-step validation pipeline. Thread-safe (atomic port counter).

**Constants:**

| Constant                   | Value        | Description                         |
| -------------------------- | ------------ | ----------------------------------- |
| `VALIDATION_TIMEOUT`       | `120`        | Max seconds for validation          |
| `MAX_GAS_EXPLOIT`          | `30_000_000` | Block gas limit                     |
| `MIN_GAS_THRESHOLD`        | `21_000`     | Minimum gas for non-trivial exploit |
| `MAX_EXPLOIT_SOURCE_BYTES` | `64_000`     | Max source size (64 KB)             |
| `ANVIL_READY_TIMEOUT`      | `10`         | Seconds to wait for Anvil RPC       |

---

### 1.3 Fingerprint Engine

**Module:** `validator.fingerprint.dedup`

#### Dataclass: `FingerprintComponents`

```python
@dataclass
class FingerprintComponents:
    function_selectors: list[str]   # sorted 4-byte selectors
    storage_slot_diffs: list[tuple] # [(slot, old, new), ...]
    balance_delta: int              # net wei change
    ownership_mutation: bool        # owner slot changed
    proxy_admin_mutation: bool      # EIP-1967 admin/impl slot changed
    call_graph_hash: str            # hash of call sequence
```

Methods:

```python
def canonical_string(self) -> str
```

Deterministic string representation for hashing.

#### Dataclass: `DedupResult`

```python
@dataclass
class DedupResult:
    is_duplicate: bool
    reward_multiplier: float        # 1.0 or 0.1
    first_miner: str | None         # address of first submitter
    first_timestamp: float | None
    submission_count: int           # total submissions with this fingerprint
```

#### Class: `FingerprintEngine`

```python
FingerprintEngine(db_path: str = "data/fingerprints.json")
```

**Methods:**

```python
def extract_components(trace: ExecutionTrace) -> FingerprintComponents
```

Extract fingerprint components from an execution trace. Static method.

```python
def compute_fingerprint(components: FingerprintComponents) -> str
```

Returns `keccak256(canonical_string)` as `0x`-prefixed hex.

```python
def check_duplicate(
    task_id: str,
    fingerprint: str,
    miner_address: str
) -> DedupResult
```

Check dedup and register the submission. Thread-safe (file locking).

```python
def prune(max_age_days: int = 30) -> int
```

Remove records older than threshold. Returns count of pruned records.

**Constants:**

| Constant                      | Value  |
| ----------------------------- | ------ |
| `FULL_REWARD_MULTIPLIER`      | `1.0`  |
| `DUPLICATE_REWARD_MULTIPLIER` | `0.10` |

---

### 1.4 Severity Scorer

**Module:** `validator.scoring.severity`

#### Dataclass: `SeverityBreakdown`

```python
@dataclass
class SeverityBreakdown:
    funds_drained_score: float      # [0.0, 1.0]
    privilege_escalation_score: float
    invariant_broken_score: float
    permanent_lock_score: float
    final_severity: float           # weighted sum
    wei_drained: int
```

#### Class: `SeverityScorer`

```python
SeverityScorer()
```

**Methods:**

```python
def score(trace: ExecutionTrace | dict) -> float
```

Returns final severity score in `[0.0, 1.0]`.

```python
def score_detailed(trace: ExecutionTrace | dict) -> SeverityBreakdown
```

Returns full breakdown with per-component scores.

**Fixed Weights:**

| Weight                   | Value  | Component                 |
| ------------------------ | ------ | ------------------------- |
| `W_FUNDS_DRAINED`        | `0.40` | Funds drained             |
| `W_PRIVILEGE_ESCALATION` | `0.25` | Privilege escalation      |
| `W_INVARIANT_BROKEN`     | `0.20` | Invariant broken          |
| `W_PERMANENT_LOCK`       | `0.15` | Permanent lock            |
| `MAX_LOG_DRAIN`          | `24.0` | ≈1M ETH cap for log scale |

---

### 1.5 Anti-Collusion Engine

**Module:** `validator.anticollusion.consensus`

#### Dataclass: `ValidatorState`

```python
@dataclass
class ValidatorState:
    validator_id: str
    stake: float
    total_validations: int
    agreements: int
    divergences: int
    recent_results: list[bool]      # rolling window (last 100)
    last_slash_time: float | None
```

Properties:

```python
@property
def divergence_rate(self) -> float   # divergences / len(recent_results)
@property
def reliability_score(self) -> float # 0.6 * lifetime + 0.4 * recent
```

#### Dataclass: `ConsensusResult`

```python
@dataclass
class ConsensusResult:
    task_id: str
    consensus_result: ValidationResult | None  # None if no consensus
    consensus_fingerprint: str | None
    consensus_severity: float | None
    agreement_ratio: float
    agreeing_validators: list[str]
    diverging_validators: list[str]
```

#### Dataclass: `SlashEvent`

```python
@dataclass
class SlashEvent:
    validator_id: str
    reason: str
    divergence_rate: float
    slash_amount_bps: int
    evidence_hashes: list[str]
    timestamp: float
```

#### Class: `AntiCollusionEngine`

```python
AntiCollusionEngine()
```

**Methods:**

```python
def register_validator(validator_id: str, stake: float) -> None
```

Register a new validator with initial stake.

```python
def assign_validators(task_id: str, count: int = None) -> list[str]
```

Deterministic random assignment weighted by reliability. Returns list of validator IDs.

```python
def compute_consensus(
    task_id: str,
    votes: dict[str, dict]
) -> ConsensusResult
```

Tally votes, find majority (≥66%), update histories, check slash conditions. `votes` maps validator IDs to `{"result": ValidationResult, "fingerprint": str, "severity": float}`.

```python
def export_consensus_log() -> list[dict]
```

Full consensus history for public re-verification.

```python
def export_validator_stats() -> dict[str, dict]
```

Reliability stats per validator.

**Constants:**

| Constant                     | Value   |
| ---------------------------- | ------- |
| `MIN_QUORUM`                 | `5`     |
| `CONSENSUS_THRESHOLD`        | `0.66`  |
| `DIVERGENCE_WINDOW`          | `100`   |
| `DIVERGENCE_SLASH_THRESHOLD` | `0.20`  |
| `SLASH_AMOUNT_BPS`           | `500`   |
| `SLASH_COOLDOWN_SECONDS`     | `86400` |
| `MAX_VALIDATORS_PER_TASK`    | `11`    |

---

### 1.6 Subnet Incentive Adapter

**Module:** `subnet_adapter.incentive`

#### Dataclass: `MinerScore`

```python
@dataclass
class MinerScore:
    miner_hotkey: str
    valid_count: int
    invalid_count: int
    unique_fingerprints: int
    duplicate_fingerprints: int
    average_severity: float
    raw_score: float
    normalized_weight: float
```

#### Dataclass: `EpochResult`

```python
@dataclass
class EpochResult:
    epoch_number: int
    miner_scores: dict[str, MinerScore]
    weights: dict[str, float]       # hotkey → normalized weight
    total_submissions: int
    valid_submissions: int
```

#### Dataclass: `ValidatorVote`

```python
@dataclass
class ValidatorVote:
    validator_id: str
    result: ValidationResult
    fingerprint: str | None
    severity: float
    timestamp: float
    miner_hotkey: str
```

#### Class: `SubnetIncentiveAdapter`

```python
SubnetIncentiveAdapter()
```

**Methods:**

```python
def record_vote(vote: ValidatorVote) -> None
```

Record a single validator's vote for a submission.

```python
def compute_epoch_weights(
    epoch: int,
    start_block: int,
    end_block: int
) -> EpochResult
```

Compute weights from collected votes for the epoch.

```python
def get_weight_vector(
    weights: dict[str, float],
    metagraph: object | None = None
) -> tuple[list[int], list[float]]
```

Convert hotkey→weight map to `(uids, weights)` tuple for `subtensor.set_weights()`.

**Score Formula:**

```
raw_score = (unique × avg_severity)
          + (duplicates × avg_severity × 0.1)
          - (invalid × 0.05)
```

**Constants:**

| Constant                     | Value  |
| ---------------------------- | ------ |
| `BASE_REWARD_PER_TASK`       | `1.0`  |
| `DUPLICATE_PENALTY`          | `0.90` |
| `MIN_SUBMISSIONS_FOR_WEIGHT` | `1`    |
| `MAX_SUBMISSIONS_PER_EPOCH`  | `50`   |

---

### 1.7 Bounty System

**Modules:** `validator.bounty.reward_split`, `validator.bounty.anti_bypass`, `validator.bounty.platform`, `validator.bounty.identity`

#### Dataclass: `RewardSplit`

```python
@dataclass
class RewardSplit:
    report_id: str
    platform: str
    total_amount: float           # Total payout (USD or token units)
    currency: str                 # e.g. "USD", "USDC", "ETH"
    miner_hotkey: str
    validator_id: str
    miner_amount: float = 0.0
    validator_amount: float = 0.0
    treasury_amount: float = 0.0
    miner_share: float = 0.70
    validator_share: float = 0.20
    treasury_share: float = 0.10
    computed_at: float = 0.0
```

#### Dataclass: `PayoutRecord`

```python
@dataclass
class PayoutRecord:
    report_id: str
    platform: str
    task_id: str
    fingerprint: str
    miner_hotkey: str
    validator_id: str
    bounty_amount: float = 0.0
    currency: str = "USD"
    split: Optional[RewardSplit] = None
    status: str = "pending"       # pending | computed | distributed | failed
    detected_at: float = 0.0
    distributed_at: float = 0.0
```

#### Class: `RewardSplitEngine`

```python
RewardSplitEngine(data_dir: Path, treasury_address: str = "")
```

**Methods:**

```python
def compute_split(
    report_id: str,
    platform: str,
    task_id: str,
    fingerprint: str,
    miner_hotkey: str,
    validator_id: str,
    bounty_amount: float,
    currency: str = "USD",
) -> RewardSplit
```

Compute the reward split for a bounty payout. Miner and validator amounts are computed first; treasury receives the remainder to avoid floating-point rounding loss.

```python
def mark_distributed(report_id: str) -> bool
def mark_failed(report_id: str, reason: str = "") -> bool
def get_payout(report_id: str) -> Optional[PayoutRecord]
def list_payouts(miner_hotkey: str | None, status: str | None) -> list[PayoutRecord]
def total_distributed(miner_hotkey: str | None = None) -> float
```

**Constants:**

| Constant                  | Value  |
| ------------------------- | ------ |
| `DEFAULT_MINER_SHARE`     | `0.70` |
| `DEFAULT_VALIDATOR_SHARE` | `0.20` |
| `DEFAULT_TREASURY_SHARE`  | `0.10` |

#### Dataclass: `SubnetReceipt`

```python
@dataclass
class SubnetReceipt:
    task_id: str
    miner_hotkey: str
    fingerprint: str
    subnet_timestamp: int
    bittensor_block: int = 0
    hmac_tag: str = ""
```

**Methods:**

```python
def compute_hmac() -> str       # HMAC-SHA256 over canonical fields
def verify_hmac() -> bool       # Verify tag integrity
```

#### Dataclass: `BypassViolation`

```python
@dataclass
class BypassViolation:
    miner_hotkey: str
    task_id: str
    fingerprint: str
    subnet_timestamp: int
    platform_timestamp: int
    platform: str
    delta_seconds: int         # platform_ts - subnet_ts (negative = bypass)
    severity: str              # "warning" | "violation" | "critical"
```

#### Class: `AntiBypassEngine`

```python
AntiBypassEngine(data_dir: Path)
```

Monitors for miner bypass attempts — detects when miners submit to bounty platforms before routing through the subnet.

**Constants:**

| Constant                   | Value | Description                                    |
| -------------------------- | ----- | ---------------------------------------------- |
| `RELAY_GRACE_SECONDS`      | `300` | Platform submission within 5 min is legitimate |
| `BYPASS_THRESHOLD_SECONDS` | `60`  | Pre-dating subnet by >60s = bypass             |

---

### 1.8 Task Generator

**Module:** `task_generator.generate`

#### Dataclass: `DeploymentConfig`

```python
@dataclass
class DeploymentConfig:
    constructor_args: list
    initial_balance: int            # wei
    deployer_address: str           # Anvil[0]
    block_timestamp: int            # 1_700_000_000
    block_number: int               # 18_000_000
    gas_limit: int                  # 30_000_000
    chain_id: int                   # 31337
```

#### Dataclass: `TaskPackage`

```python
@dataclass
class TaskPackage:
    source_code: str                # Solidity source
    solc_version: str               # "0.8.28"
    deployment_config: DeploymentConfig
    vulnerability_class: str        # e.g. "reentrancy"
    difficulty: str                 # "easy" | "medium" | "hard" | "expert"
    invariant: InvariantSpec | None
```

Methods:

```python
def compute_task_id(self) -> str    # keccak256 of canonical JSON
def to_json(self) -> dict
```

#### Class: `CorpusGenerator`

```python
CorpusGenerator(templates_dir: str = "task-generator/templates")
```

**Methods:**

```python
def generate_from_template(
    template_name: str,
    seed: int,
    mutations: dict | None = None
) -> TaskPackage
```

```python
def generate_batch(
    count_per_class: int = 2,
    seed: int = 42
) -> list[TaskPackage]
```

```python
def save_batch(
    packages: list[TaskPackage],
    output_dir: str = "contracts/corpus"
) -> dict
```

Save packages to disk and generate manifest. Returns manifest dict.

---

### 1.9 Metrics Server

**Module:** `validator.metrics`

#### Module-Level Functions

```python
def inc(name: str, amount: int = 1) -> None
```

Increment a counter.

```python
def set_gauge(name: str, value: float) -> None
```

Set a gauge value.

```python
def observe(name: str, value: float) -> None
```

Record a histogram observation.

```python
def snapshot() -> dict
```

Returns all current metrics as a dict:

```json
{
  "counters": {"validations_total": 42, ...},
  "gauges": {"uptime_seconds": 3600.5, ...},
  "histograms": {
    "validation_latency_ms": {
      "count": 42, "mean": 1500.0, "p50": 1200.0, "p99": 4500.0
    }
  }
}
```

#### Class: `MetricsServer`

```python
MetricsServer(port: int = 9946, bind: str = "0.0.0.0")
```

**Methods:**

```python
def start() -> None       # start as daemon thread
def stop() -> None        # shutdown the HTTP server
```

---

### 1.10 Utilities

#### `validator.utils.logging`

```python
def get_logger(name: str) -> logging.Logger
```

Returns a logger under the `exploit_subnet` namespace. Configured once on first call.

**Environment Variables:**

| Variable            | Default  | Description                                                          |
| ------------------- | -------- | -------------------------------------------------------------------- |
| `EXPLOIT_LOG_LEVEL` | `INFO`   | Log level (DEBUG/INFO/WARNING/ERROR)                                 |
| `EXPLOIT_LOG_FILE`  | _(none)_ | Optional file path; enables `RotatingFileHandler` (50 MB, 5 backups) |

#### `validator.utils.hashing`

```python
def keccak256(data: bytes | str) -> str
```

Returns `0x`-prefixed 64-char hex string.

**Backend resolution order:**

1. `pycryptodome` (`Crypto.Hash.keccak`) — primary, fast
2. `pysha3` (`sha3.keccak_256`) — fallback if pycryptodome unavailable
3. `cast keccak` (Foundry CLI) — last resort, subprocess-based

If `data` is a `str`, it is UTF-8 encoded before hashing.

> **Warning:** This is Ethereum keccak256, NOT NIST SHA-3 (`hashlib.sha3_256`). Using `hashlib.sha3_256` will produce different hashes and break determinism.

---

## 2. Bittensor Synapses

### `ExploitSubmissionSynapse`

**Direction:** Miner → Validator

| Field            | Type           | Direction | Description                      |
| ---------------- | -------------- | --------- | -------------------------------- |
| `task_id`        | `str`          | Request   | Hex task identifier              |
| `exploit_source` | `str`          | Request   | Raw Solidity exploit source      |
| `result`         | `dict \| None` | Response  | Validation result from validator |

### `ExploitQuerySynapse`

**Direction:** Validator → Miner

| Field        | Type           | Direction | Description                              |
| ------------ | -------------- | --------- | ---------------------------------------- |
| `query_type` | `str`          | Request   | `"status"`, `"submit"`, or `"heartbeat"` |
| `task_id`    | `str \| None`  | Request   | Task ID (for `submit` queries)           |
| `response`   | `dict \| None` | Response  | Miner response                           |

**Fallback:** When `bittensor` is not installed, synapses use a lightweight `_SynapseBase` shim for local/CI usage.

---

## 3. Smart Contracts

### 3.1 ExploitRegistry.sol

#### Functions

| Function                                                                                                | Access          | Description                                         |
| ------------------------------------------------------------------------------------------------------- | --------------- | --------------------------------------------------- |
| `recordExploit(bytes32 taskId, address miner, bytes32 fingerprint, uint256 severity, bool isDuplicate)` | `onlyValidator` | Record a validated exploit                          |
| `getExploitRecord(bytes32 taskId, bytes32 fingerprint) → ExploitRecord`                                 | View            | Retrieve exploit record                             |
| `getEffectiveReward(bytes32 taskId, bytes32 fingerprint) → uint256`                                     | View            | Compute `baseReward × multiplier × severity / 1e36` |
| `addValidator(address validator)`                                                                       | `onlyOwner`     | Whitelist a validator                               |
| `removeValidator(address validator)`                                                                    | `onlyOwner`     | Remove a validator                                  |

#### Structs

```solidity
struct ExploitRecord {
    address miner;
    bytes32 fingerprint;
    uint256 severity;       // 1e18 fixed-point
    bool isDuplicate;
    uint256 rewardMultiplier;
    uint256 recordedAt;
    uint256 validatorCount;
}
```

#### Constants

| Constant           | Value        |
| ------------------ | ------------ |
| `FULL_REWARD`      | `1e18`       |
| `DUPLICATE_REWARD` | `1e17` (10%) |
| `MIN_QUORUM`       | `5`          |

---

### 3.3 ProtocolRegistry.sol

#### Functions

| Function                                                                                    | Access                 | Description                                           |
| ------------------------------------------------------------------------------------------- | ---------------------- | ----------------------------------------------------- |
| `registerContract(address target)`                                                          | Any (payable)          | Register contract + deposit bounty (min 0.01 ETH)     |
| `recordExploit(bytes32 contractHash, address miner, bytes32 fingerprint, uint256 severity)` | `onlyValidator`        | Record exploit against registered contract            |
| `payExploitReward(bytes32 contractHash, bytes32 fingerprint)`                               | Any (after disclosure) | Trigger reward payout                                 |
| `withdrawBounty(bytes32 contractHash)`                                                      | `onlyProtocol`         | Withdraw remaining bounty (blocked during disclosure) |

#### Constants

| Constant                  | Value               |
| ------------------------- | ------------------- |
| `MIN_BOUNTY`              | `0.01 ether`        |
| `DISCLOSURE_WINDOW`       | `259200` (72 hours) |
| `MAX_REWARD_BPS`          | `9000` (90%)        |
| `MAX_CLAIMS_PER_CONTRACT` | `100`               |

---

### 3.4 AdversarialMode.sol (Stage 3)

#### Contracts

**`InvariantRegistry`** — Class A miners submit invariants.

| Function                                                          | Access | Description                   |
| ----------------------------------------------------------------- | ------ | ----------------------------- |
| `submitInvariant(bytes32 taskId, string source, string property)` | Any    | Submit an invariant assertion |
| `getInvariant(bytes32 invariantId) → Invariant`                   | View   | Retrieve invariant details    |

**`AdversarialScoring`** — Class B miners challenge invariants.

| Function                                                                 | Access      | Description              |
| ------------------------------------------------------------------------ | ----------- | ------------------------ |
| `processChallenge(bytes32 invariantId, address challenger, bool broken)` | `onlyOwner` | Record challenge result  |
| `getScores(bytes32 invariantId) → (uint256 holdRate, uint256 breakRate)` | View        | Challenge and hold rates |

---

## 4. CLI Commands

### 4.1 Miner CLI (`miner.cli`)

```bash
python3 -m miner.cli [--address ADDRESS] COMMAND [OPTIONS]
```

| Command    | Options                         | Description                                                 |
| ---------- | ------------------------------- | ----------------------------------------------------------- |
| `tasks`    |                                 | List all available tasks in the corpus                      |
| `task`     | `--id TASK_ID`                  | Inspect a specific task (show source, metadata)             |
| `scaffold` | `--task TASK_ID`                | Generate exploit template with vulnerability-specific hints |
| `submit`   | `--task TASK_ID --exploit FILE` | Submit an exploit for validation                            |
| `status`   | `--task TASK_ID` (optional)     | Check previous submission results                           |
| `scores`   |                                 | View current epoch leaderboard                              |

### 4.2 Orchestrator CLI

```bash
python3 orchestrator.py COMMAND [OPTIONS]
```

| Command    | Options                                   | Description                 |
| ---------- | ----------------------------------------- | --------------------------- |
| `generate` | `--count N --seed S`                      | Generate task corpus        |
| `submit`   | `--task ID --exploit FILE --miner ADDR`   | Submit and validate exploit |
| `epoch`    | `--epoch N --start-block B --end-block E` | Close an epoch              |
| `list`     |                                           | List corpus tasks           |

### 4.3 Neuron Commands

```bash
# Validator
python3 neurons/validator.py [--local | --netuid N --wallet.name W --wallet.hotkey H]

# Miner
python3 neurons/miner.py [--local | --netuid N --wallet.name W --wallet.hotkey H]
```

### 4.4 Docker Entrypoint

```bash
docker run <image> COMMAND
```

| Command    | Description            |
| ---------- | ---------------------- |
| `validate` | Run validation engine  |
| `generate` | Run task generator     |
| `score`    | Run severity scorer    |
| `shell`    | Interactive bash shell |

---

## 5. HTTP Endpoints

### Metrics Server (Port 9946)

| Method | Path       | Response           | Description     |
| ------ | ---------- | ------------------ | --------------- |
| `GET`  | `/health`  | `{"status": "ok"}` | Readiness probe |
| `GET`  | `/metrics` | JSON (see below)   | All metrics     |

**Metrics Response Schema:**

```json
{
  "counters": {
    "validations_total": 142,
    "validations_valid": 87,
    "duplicates_total": 23
  },
  "gauges": {
    "uptime_seconds": 14523.7
  },
  "histograms": {
    "validation_latency_ms": {
      "count": 142,
      "mean": 1523.4,
      "p50": 1200.0,
      "p99": 4800.0
    },
    "severity_score": {
      "count": 87,
      "mean": 0.45,
      "p50": 0.4,
      "p99": 0.92
    }
  }
}
```

---

## 6. Environment Variables

| Variable                  | Default      | Description                      |
| ------------------------- | ------------ | -------------------------------- |
| `EXPLOIT_LOG_LEVEL`       | `INFO`       | Logging level                    |
| `EXPLOIT_LOG_FILE`        | _(none)_     | Log file path (enables rotation) |
| `ANVIL_BLOCK_TIMESTAMP`   | `1700000000` | Fixed Anvil timestamp            |
| `ANVIL_BLOCK_NUMBER`      | `18000000`   | Fixed Anvil block                |
| `ANVIL_GAS_LIMIT`         | `30000000`   | Anvil gas limit                  |
| `ANVIL_CHAIN_ID`          | `31337`      | Anvil chain ID                   |
| `PYTHONHASHSEED`          | `0`          | **Must be 0** for determinism    |
| `PYTHONDONTWRITEBYTECODE` | `1`          | Skip `.pyc` generation           |
| `ETH_PRIVATE_KEY`         | _(none)_     | Private key for on-chain ops     |

---

## Cross-References

- [CONTRACT_REFERENCE.md](CONTRACT_REFERENCE.md) — Solidity contract ABIs and custom errors
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture and component interactions
- [DATA_SCHEMA.md](DATA_SCHEMA.md) — JSON schemas for files produced by these APIs
- [GLOSSARY.md](GLOSSARY.md) — Term definitions

---

_This reference is auto-generated from code inspection. If a method signature changes, update this document._
