# Smart Contract Reference

> Version 1.1 · Last updated: 2026-03-03

Complete reference for all Solidity contracts in the VALayr exploit subnet.

---

## Table of Contents

1. [Overview](#overview)
2. [Deployment](#deployment)
3. [CommitReveal](#commitreveal)
4. [ExploitRegistry](#exploitregistry)
5. [ProtocolRegistry](#protocolregistry)
6. [InvariantRegistry (Stage 3)](#invariantregistry-stage-3)
7. [AdversarialScoring (Stage 3)](#adversarialscoring-stage-3)
8. [Custom Errors Reference](#custom-errors-reference)
8. [Build & Test](#build--test)
9. [Foundry Configuration](#foundry-configuration)

---

## Overview

| Contract           | File                                       | Purpose                           | Stage   |
| ------------------ | ------------------------------------------ | --------------------------------- | ------- |
| CommitReveal       | `contracts/src/CommitReveal.sol`           | Anti-theft commit-reveal scheme   | v1      |
| ExploitRegistry    | `contracts/src/ExploitRegistry.sol`        | On-chain exploit records + dedup  | v1      |
| ProtocolRegistry   | `contracts/src/ProtocolRegistry.sol`       | Protocol opt-in + bounty escrow   | v1      |
| InvariantRegistry  | `contracts/src/stage3/AdversarialMode.sol` | Invariant submission + challenges | Stage 3 |
| AdversarialScoring | `contracts/src/stage3/AdversarialMode.sol` | Class A/B miner scoring           | Stage 3 |

All contracts use:

- **Solidity 0.8.28** with Cancun EVM target
- **Optimizer** enabled with 200 runs
- **Custom errors** instead of `require()` strings (gas-efficient)

---

## Deployment

Deploy all contracts with the Foundry script:

```bash
# Local (Anvil)
anvil --block-time 1 &
forge script contracts/script/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast

# With custom deployer key
DEPLOYER_KEY=0xYOUR_PRIVATE_KEY \
forge script contracts/script/Deploy.s.sol \
  --rpc-url <RPC_URL> \
  --broadcast
```

### Deploy.s.sol Output

The deploy script deploys all 5 contracts and wires them together:

```
=== Deployed Addresses ===
ProtocolRegistry:    0x...
CommitReveal:        0x...
ExploitRegistry:     0x...
InvariantRegistry:   0x...
AdversarialScoring:  0x...
Deployer/Validator:  0x...
```

The deployer is automatically registered as a validator on both `ProtocolRegistry` and `ExploitRegistry`.

---

## CommitReveal

**File:** `contracts/src/CommitReveal.sol`

Prevents exploit theft by forcing miners to commit a hash before revealing the exploit. Earliest valid commitment wins priority.

### Constants

| Name                   | Value   | Description                                |
| ---------------------- | ------- | ------------------------------------------ |
| `COMMIT_WINDOW`        | 2 hours | Duration for submitting commit hashes      |
| `REVEAL_WINDOW`        | 4 hours | Duration for revealing after commit closes |
| `MAX_COMMITS_PER_TASK` | 256     | Maximum commitments per task               |

### Timeline

```
[openTask] ─── 2 hours ──→ [commit window closes] ─── 4 hours ──→ [reveal window closes]
```

### Structs

#### Commitment

```solidity
struct Commitment {
    address miner;
    bytes32 commitHash;          // keccak256(taskId || exploitArtifactHash || nonce)
    uint256 committedAt;         // block.timestamp
    bool revealed;
    bytes32 exploitArtifactHash; // Filled on reveal
    uint256 revealedAt;
}
```

### Functions

#### `openTask(bytes32 taskId)` — Owner only

Opens a task for commit submissions. Emits `TaskOpened`.

```solidity
function openTask(bytes32 taskId) external onlyOwner
```

| Error             | Condition               |
| ----------------- | ----------------------- |
| `Unauthorized`    | Caller is not owner     |
| `TaskAlreadyOpen` | Task was already opened |

#### `commit(bytes32 taskId, bytes32 commitHash)` — Any miner

Submit a blinded commitment hash. The hash must equal `keccak256(abi.encodePacked(taskId, exploitArtifactHash, nonce))`.

```solidity
function commit(bytes32 taskId, bytes32 commitHash) external
```

| Error                | Condition                             |
| -------------------- | ------------------------------------- |
| `TaskNotOpen`        | Task has not been opened              |
| `CommitWindowClosed` | Past the 2-hour commit window         |
| `AlreadyCommitted`   | Miner already committed for this task |
| `MaxCommitsReached`  | 256 commitments already               |

#### `reveal(bytes32 taskId, bytes32 exploitArtifactHash, bytes32 nonce)` — Committed miners

Reveal the exploit artifact hash and nonce. Must match the prior commitment.

```solidity
function reveal(bytes32 taskId, bytes32 exploitArtifactHash, bytes32 nonce) external
```

| Error                 | Condition                     |
| --------------------- | ----------------------------- |
| `NoCommitment`        | Caller never committed        |
| `RevealWindowNotOpen` | Still in commit window        |
| `RevealWindowClosed`  | Past the 4-hour reveal window |
| `AlreadyRevealed`     | Already revealed              |
| `InvalidReveal`       | Hash doesn't match commitment |

#### View Functions

```solidity
function getEarliestReveal(bytes32 taskId, bytes32 exploitArtifactHash)
    external view returns (address miner, uint256 committedAt)

function isRevealWindowOpen(bytes32 taskId) external view returns (bool)
function isCommitWindowOpen(bytes32 taskId) external view returns (bool)
```

### Events

```solidity
event TaskOpened(bytes32 indexed taskId, uint256 openTime);
event CommitSubmitted(bytes32 indexed taskId, address indexed miner, uint256 index, uint256 timestamp);
event ExploitRevealed(bytes32 indexed taskId, address indexed miner, bytes32 exploitArtifactHash, uint256 timestamp);
```

---

## ExploitRegistry

**File:** `contracts/src/ExploitRegistry.sol`

On-chain record of validated exploits. Stores canonical fingerprints, handles deduplication, and tracks severity scores.

### Constants

| Name               | Value | Description                      |
| ------------------ | ----- | -------------------------------- |
| `FULL_REWARD`      | 1e18  | 100% reward multiplier           |
| `DUPLICATE_REWARD` | 1e17  | 10% reward for duplicates        |
| `MIN_QUORUM`       | 5     | Minimum validators for recording |

### Structs

#### ExploitRecord

```solidity
struct ExploitRecord {
    bytes32 taskId;
    bytes32 fingerprint;         // Canonical state-impact fingerprint
    address miner;
    uint256 severityScore;       // 1e18 fixed-point
    uint256 validatedAt;
    uint256 validatorQuorum;     // Number of agreeing validators
    bool isDuplicate;
    uint256 rewardMultiplier;    // 1e18 = full, 1e17 = 10%
}
```

### Functions

#### `recordExploit(...)` — Validators only

Record a validated exploit. Handles dedup automatically.

```solidity
function recordExploit(
    bytes32 taskId,
    bytes32 fingerprint,
    address miner,
    uint256 severityScore,
    uint256 quorumCount
) external onlyValidator returns (uint256 exploitId)
```

**Dedup logic:**

- If `fingerprint` is new for `taskId` → `isDuplicate = false`, `rewardMultiplier = FULL_REWARD`
- If `fingerprint` already exists → `isDuplicate = true`, `rewardMultiplier = DUPLICATE_REWARD`

| Error                | Condition                            |
| -------------------- | ------------------------------------ |
| `Unauthorized`       | Caller is not a registered validator |
| `InsufficientQuorum` | `quorumCount` < 5                    |
| `ZeroAddress`        | Miner address is zero                |
| `ZeroSeverity`       | Severity score is zero               |

#### `getEffectiveReward(uint256 exploitId, uint256 baseReward)` — View

Compute effective reward: `baseReward × rewardMultiplier × severityScore / 1e36`

#### Admin

```solidity
function setValidator(address validator, bool status) external onlyOwner
function transferOwnership(address newOwner) external onlyOwner
```

### Events

```solidity
event ExploitRecorded(uint256 indexed exploitId, bytes32 indexed taskId,
    bytes32 fingerprint, address miner, uint256 severity, bool isDuplicate);
event ValidatorUpdated(address indexed validator, bool status);
```

---

## ProtocolRegistry

**File:** `contracts/src/ProtocolRegistry.sol`

Opt-in registry for protocols submitting their contracts for adversarial testing. Includes bounty escrow and disclosure windows.

### Constants

| Name                      | Value      | Description                              |
| ------------------------- | ---------- | ---------------------------------------- |
| `DISCLOSURE_WINDOW`       | 72 hours   | Mandatory disclosure delay before payout |
| `MIN_BOUNTY`              | 0.01 ETH   | Minimum bounty deposit                   |
| `MAX_REWARD_BPS`          | 9000 (90%) | Maximum reward as basis points of bounty |
| `MAX_CLAIMS_PER_CONTRACT` | 100        | Prevents unbounded exploit history       |

### Structs

#### RegisteredContract

```solidity
struct RegisteredContract {
    address protocol;       // Protocol owner
    address target;         // Contract being tested
    bytes32 codeHash;       // keccak256(runtime bytecode) at registration
    uint256 bountyPool;     // Wei deposited as bounty
    uint256 registeredAt;
    uint256 expiresAt;      // 0 = no expiry
    bool active;
}
```

#### ExploitClaim

```solidity
struct ExploitClaim {
    address miner;
    bytes32 taskId;
    bytes32 exploitFingerprint;
    uint256 severityScore;   // 1e18 fixed-point
    uint256 rewardAmount;
    uint256 claimedAt;
    bool paid;
}
```

### Protocol Functions

#### `registerContract(address target, uint256 expiresAt)` — Payable

Register a contract for testing. Must deposit at least `MIN_BOUNTY` (0.01 ETH).

```solidity
function registerContract(address target, uint256 expiresAt) external payable
```

The `contractHash` is computed as `keccak256(abi.encodePacked(target, extcodehash(target)))`.

#### `addBounty(bytes32 contractHash)` — Protocol owner, payable

Add more bounty to an existing registration.

#### `deactivateContract(bytes32 contractHash)` — Protocol owner

Mark a contract as inactive. Cannot withdraw bounty until all disclosure windows close.

#### `withdrawBounty(bytes32 contractHash)` — Protocol owner

Withdraw remaining bounty after deactivation. Protected by reentrancy guard. Enforces that all existing claims are paid or their disclosure windows have expired.

### Validator Functions

#### `recordExploit(...)` — Validators only

Record a validated exploit and compute reward.

```solidity
function recordExploit(
    bytes32 contractHash,
    bytes32 exploitFingerprint,
    address miner,
    uint256 severityScore
) external onlyValidator
```

**Reward formula:** `reward = (bountyPool × severityScore × MAX_REWARD_BPS) / (1e18 × 10000)`

Capped at `bountyPool`. First-claim priority enforced (same fingerprint cannot be claimed twice).

#### `payExploitReward(...)` — Anyone (after disclosure window)

```solidity
function payExploitReward(bytes32 contractHash, bytes32 exploitFingerprint) external
```

Can only be called after the 72-hour disclosure window. Protected by reentrancy guard.

### View Functions

```solidity
function isRegistered(bytes32 contractHash) external view returns (bool)
function getExploitCount(bytes32 contractHash) external view returns (uint256)
function getContractHash(address target) external view returns (bytes32)
```

### Events

```solidity
event ContractRegistered(bytes32 indexed contractHash, address indexed protocol, address target, uint256 bounty);
event ContractDeactivated(bytes32 indexed contractHash);
event BountyAdded(bytes32 indexed contractHash, uint256 amount);
event ExploitClaimed(bytes32 indexed contractHash, bytes32 indexed exploitFingerprint, address miner, uint256 reward);
event ExploitRewardPaid(bytes32 indexed contractHash, bytes32 indexed exploitFingerprint, address miner, uint256 amount);
event BountyWithdrawn(bytes32 indexed contractHash, uint256 amount);
```

---

## InvariantRegistry (Stage 3)

**File:** `contracts/src/stage3/AdversarialMode.sol`

Stage 3 (Month 5–6) introduces an adversarial invariant system with two miner classes:

- **Class A (Invariant Writers):** Submit formal properties about contracts
- **Class B (Exploit Writers):** Attempt to break those invariants

### Structs

#### Invariant

```solidity
struct Invariant {
    address submitter;             // Class A miner
    bytes32 targetContractHash;
    string description;            // Human-readable
    string solidityCondition;      // Solidity boolean expression
    bytes compiledCheck;           // ABI-encoded check function
    uint256 submittedAt;
    uint256 challengeCount;
    uint256 breachCount;
    uint256 holdCount;
    bool active;
}
```

### Functions

#### `submitInvariant(...)` — Any miner (Class A)

```solidity
function submitInvariant(
    bytes32 targetContractHash,
    string calldata description,
    string calldata solidityCondition,
    bytes calldata compiledCheck
) external returns (uint256 id)
```

#### `recordChallenge(uint256 id, bool broken)` — Validators only

Record the result of a challenge attempt. `broken = true` means Class B's exploit broke the invariant.

#### `getInvariantScore(uint256 id)` — View

Returns `holdCount / challengeCount` (1e18 fixed-point). Untested invariants return 1e18 (neutral).

#### `deactivateInvariant(uint256 id)` — Validators only

Deactivate a trivially-true or invalid invariant.

---

## AdversarialScoring (Stage 3)

**File:** `contracts/src/stage3/AdversarialMode.sol`

Computes rewards for both miner classes in the adversarial game.

### Scoring Weights

| Constant             | Value | When                                           |
| -------------------- | ----- | ---------------------------------------------- |
| `W_HOLD_REWARD`      | +100  | Invariant holds under challenge (Class A wins) |
| `W_BREACH_PENALTY`   | -500  | Invariant broken (Class A loses)               |
| `W_BREACH_REWARD`    | +1000 | Exploit breaks invariant (Class B wins)        |
| `W_FAILED_CHALLENGE` | +10   | Class B tried but invariant held (consolation) |

### `processChallenge(...)` — Owner only

```solidity
function processChallenge(
    uint256 invariantId,
    address classAMiner,
    address classBMiner,
    bool broken
) external onlyOwner
```

**If `broken = true` (Class B wins):**

- Class B: `+1000`
- Class A: `-500`

**If `broken = false` (Class A wins):**

- Class A: `+100`
- Class B: `+10`

### Score Storage

```solidity
mapping(address => int256) public classAScores;
mapping(address => int256) public classBScores;
```

Scores can go negative (Class A loses 500 points when their invariant is broken).

---

## Build & Test

### Compile

```bash
forge build --sizes    # Show contract sizes
```

### Run Tests

```bash
# All contract tests
forge test -vvv

# Specific test file
forge test --match-path contracts/test/CommitReveal.t.sol -vvv

# Example exploits
FOUNDRY_PROFILE=exploits forge test -vvv

# Gas snapshot
forge snapshot
```

### Coverage

```bash
forge coverage
```

### Format

```bash
forge fmt           # Format all Solidity files
forge fmt --check   # Check formatting (CI)
```

---

## Foundry Configuration

**File:** `foundry.toml`

### Default Profile

```toml
[profile.default]
src = "contracts/src"
out = "contracts/out"
libs = ["contracts/lib"]
test = "contracts/test"
script = "contracts/script"
solc_version = "0.8.28"
evm_version = "cancun"
optimizer = true
optimizer_runs = 200
bytecode_hash = "ipfs"
cbor_metadata = true
extra_output = ["storageLayout", "abi", "evm.bytecode", "evm.deployedBytecode"]
```

### Fuzz Settings

```toml
[profile.default.fuzz]
runs = 256
seed = "0x000000000000000000000000000000000000000000000000000000000000002a"
```

The fixed seed ensures fuzz tests are reproducible across validators.

### Exploits Profile

```toml
[profile.exploits]
test = "exploits"
```

Used for running example exploit submissions: `FOUNDRY_PROFILE=exploits forge test -vvv`

---

## Pausable Emergency Mechanism

All contracts inherit from `Pausable.sol` which provides:

| Function    | Access      | Description                                                |
| ----------- | ----------- | ---------------------------------------------------------- |
| `pause()`   | `onlyOwner` | Pauses the contract — all `whenNotPaused` functions revert |
| `unpause()` | `onlyOwner` | Resumes normal operation                                   |
| `paused()`  | `view`      | Returns current pause state                                |

Critical state-changing functions (`commit`, `reveal`, `openTask`, `recordExploit`, `submitInvariant`, `processChallenge`, `registerContract`, `payExploitReward`) are guarded by `whenNotPaused`.

Administrative functions (`transferOwnership`, `acceptOwnership`, `setValidator`, `pause`, `unpause`) remain callable when paused.

## Convenience View Functions

### ExploitRegistry

- `getExploit(uint256 exploitId) → ExploitRecord` — Full exploit record by ID

### ProtocolRegistry

- `getRemainingBounty(bytes32 contractHash) → uint256` — Remaining bounty pool for a contract

### AdversarialScoring

- `getClassAScore(address miner) → int256` — Class A miner score
- `getClassBScore(address miner) → int256` — Class B miner score

---

## Custom Errors Reference

All contracts use custom errors (gas-efficient) instead of `require()` strings.

| Error                    | Contract(s)                    | Trigger                                                |
| ------------------------ | ------------------------------ | ------------------------------------------------------ |
| `ZeroAddress()`          | All five contracts             | Null address passed for miner, owner, or validator     |
| `NotOwner()`             | All five contracts             | Caller is not `owner`                                  |
| `NotValidator()`         | InvariantRegistry, AdversarialScoring | Caller is not a registered validator            |
| `TaskNotOpen()`          | CommitReveal                   | Attempting commit/reveal on a non-open task            |
| `CommitWindowClosed()`   | CommitReveal                   | Commit submitted after the 2-hour window               |
| `RevealWindowClosed()`   | CommitReveal                   | Reveal submitted after the 4-hour window               |
| `RevealTooEarly()`       | CommitReveal                   | Reveal attempted during commit window                  |
| `InvalidHash()`          | CommitReveal                   | Revealed hash doesn't match committed hash             |
| `AlreadyCommitted()`     | CommitReveal                   | Same miner committed twice for same task               |
| `AlreadyRevealed()`      | CommitReveal                   | Same miner revealed twice for same task                |
| `ContractStillActive()`  | ProtocolRegistry               | Attempting to close a contract that still has active claims |
| `ContractInactive()`     | ProtocolRegistry               | Attempting operations on an inactive contract          |
| `InvalidSeverity()`      | ProtocolRegistry               | Severity score > 1e18 (must be in [0, 1e18])          |
| `InvalidStartIndex()`    | ProtocolRegistry               | `withdrawBounty()` called with startIndex > history length |
| `ContractPaused()`       | All five contracts             | Function called while contract is paused               |

---

## Cross-References

- [API_REFERENCE.md](API_REFERENCE.md) — Python APIs that interact with these contracts
- [DEPLOYMENT.md](DEPLOYMENT.md) — How to deploy these contracts
- [ARCHITECTURE.md](ARCHITECTURE.md) — Where contracts fit in the system
- [GLOSSARY.md](GLOSSARY.md) — Term definitions

### CommitReveal

- `getEarliestReveal(bytes32 taskId, bytes32 artifactHash) → (address, uint256)` — O(1) cached lookup of earliest reveal
