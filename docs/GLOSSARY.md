# Glossary

Terminology used throughout the VALayr exploit subnet documentation and codebase.

---

## A

### AdversarialMode

Stage 3 system (Month 5–6) where two miner classes compete: Class A writes invariants, Class B tries to break them. See `contracts/src/stage3/AdversarialMode.sol`.

### AntiCollusionEngine

Validator component that detects coordinated submission patterns between miners. Enforces multi-validator consensus (≥5 quorum, ≥66% agreement).

### Anvil

Foundry's local Ethereum node, used as the deterministic execution sandbox for exploit validation. All validators use identical Anvil configuration to ensure reproducible results.

### Axon

Bittensor component that receives incoming network requests. The validator's axon receives exploit submissions from miners.

---

## B

### Bittensor

Decentralized machine intelligence network. VALayr operates as a subnet within Bittensor, using its incentive mechanism for TAO distribution.

### Bytecode Determinism

The requirement that compiling the same Solidity source with the same compiler version and settings always produces identical EVM bytecode. Critical for multi-validator consensus.

---

## C

### Cancun

The EVM hardfork version targeted by all contracts (`evm_version = "cancun"` in `foundry.toml`). Notably changes `SELFDESTRUCT` behavior.

### Class A Miner

Stage 3 miner role: writes formal invariants (properties that contracts should satisfy). Gains score when invariants hold, loses score when they're broken.

### Class B Miner

Stage 3 miner role: writes exploits that attempt to break Class A's invariants. Earns score when an invariant is broken.

### Commit Hash

`H = keccak256(abi.encodePacked(taskId, exploitArtifactHash, nonce))` — the blinded hash submitted during the commit phase to prevent exploit theft.

### Commit-Reveal

Two-phase protocol preventing exploit theft. Miners first commit a hash of their exploit (commit phase, 2 hours), then reveal the actual exploit (reveal phase, 4 hours). See `CommitReveal.sol`.

### Commit Window

The 2-hour period after a task opens during which miners can submit commit hashes.

### Corpus

The set of generated vulnerable Solidity contracts that miners must exploit. Generated deterministically by the Task Generator with a fixed seed.

---

## D

### Deduplication (Dedup)

The process of identifying whether two exploit submissions have the same state impact. Performed by comparing canonical fingerprints. First submission: 100% reward. Duplicates: 10%.

### Dendrite

Bittensor component for making outgoing network requests. Used by miners to send submissions to validators.

### Deploy Script

`contracts/script/Deploy.s.sol` — Foundry script that deploys all on-chain contracts.

### Determinism

The property that the same inputs always produce the same outputs. Essential for validator consensus. Enforced via pinned tool versions (`solc 0.8.28`, `Foundry nightly-2024-12-01`), fixed Anvil config, and `PYTHONHASHSEED=0`.

### Disclosure Window

72-hour mandatory delay between recording an exploit claim and paying out the bounty reward. Defined in `ProtocolRegistry.sol`.

---

## E

### Epoch

A fixed-length validation cycle (360 blocks ≈ 60 minutes). Each epoch: receive submissions → validate → set weights.

### Execution Trace

The complete record of state changes produced by running an exploit: storage diffs, balance changes, event logs, call traces, gas used. Used for fingerprinting and scoring.

### Exploit

A Solidity test file that demonstrates a vulnerability in a target contract by producing measurable state changes (fund drain, privilege escalation, etc.).

### Exploit Artifact Hash

`keccak256(exploit_source_code)` — the hash of the raw exploit Solidity source, used in the commit-reveal protocol.

### ExploitRegistry

On-chain contract that records validated exploits with their fingerprints, severity scores, and dedup status. See `contracts/src/ExploitRegistry.sol`.

---

## F

### Fingerprint

A canonical hash representing an exploit's state impact: `keccak256(function_selectors, sorted_storage_diffs, balance_delta, call_graph_hash)`. Two exploits with identical state effects share the same fingerprint.

### FingerprintEngine

Python component (`validator/fingerprint/dedup.py`) that computes canonical fingerprints and manages deduplication state.

### Forge

Foundry's testing framework for Solidity. Discovers and runs `test_*()` functions. Used both for contract tests and exploit execution.

### Foundry

Ethereum development toolkit including `forge` (build/test), `anvil` (local node), and `cast` (CLI interaction). Pinned to `nightly-2024-12-01`.

### Finney

A Bittensor network environment. `finney` is the production mainnet where real TAO rewards are distributed. Other networks: `test` (testnet), `local` (development).

---

## G

### Gas Threshold

Minimum gas usage (21,000) required for an exploit to be considered valid. Below this threshold, the submission is rejected as spam.

---

## H

### Hotkey

A Bittensor wallet key used for on-chain operations. Each miner and validator has a unique hotkey registered on the subnet.

---

## I

### Invariant

A formal property that a smart contract should satisfy (e.g., "total supply equals sum of all balances"). In Stage 3, Class A miners write invariants for Class B miners to break.

### Invariant Registry

Smart contract that stores submitted invariants and tracks their challenge history. See `InvariantRegistry` in `contracts/src/stage3/AdversarialMode.sol`.

---

## K

### keccak256

Ethereum's hash function. **Not** the same as NIST SHA-3. Used for commit hashes, fingerprints, and all on-chain hashing. VALayr uses `pycryptodome` for Python-side keccak256 to match Solidity exactly.

---

## M

### Metagraph

Bittensor's graph of all registered neurons (miners and validators) in a subnet. Synced periodically to know which hotkeys are active.

### Miner

A Bittensor neuron that discovers and submits exploit proofs for vulnerable contracts. Scored based on exploit severity and novelty.

### Mutator

A transformation applied to vulnerability templates to generate unique task variants. Types: `rename` (identifiers), `balance` (ETH amounts), `storage` (initial state), `deadcode` (noise insertion). Located in `task-generator/mutator/`.

---

## N

### Netuid

The numerical identifier for a Bittensor subnet. VALayr operates on a specific netuid.

### Nonce

A random 32-byte value used in the commit-reveal scheme to blind the commit hash. Must be kept secret until the reveal phase.

---

## O

### Orchestrator

Central coordination module (`orchestrator.py`) that ties together task generation, validation, scoring, and weight setting.

---

## P

### Privilege Escalation

A severity category: the exploit changes ownership or admin control of the target contract (detected by monitoring known ownership storage slots).

### ProtocolRegistry

On-chain contract where protocols opt in to adversarial testing by registering contracts and depositing bounties. See `contracts/src/ProtocolRegistry.sol`.

### Proxy

An upgradeable contract pattern where a proxy contract delegates calls to an implementation contract. Vulnerabilities arise from unguarded `initialize()` functions and storage slot collisions.

---

## Q

### Quorum

The minimum number of validators (5) that must agree on a validation result for it to be recorded. With ≥66% agreement required.

---

## R

### Reentrancy

A vulnerability class where an external call allows the callee to call back into the vulnerable function before the first invocation completes, typically draining funds.

### Reveal Window

The 4-hour period after the commit window closes during which miners can reveal their exploit source and nonce.

### Reward Multiplier

The fraction of base reward a miner receives: 1.0 (100%) for first-of-fingerprint, 0.10 (10%) for duplicates, 0.0 for invalid submissions.

---

## S

### Sandbox

The isolated execution environment for exploit validation. Uses a fresh Anvil instance, temporary workspace, and Docker `--network=none` in production.

### Severity Score

Algorithmic score in [0, 1] computed from four weighted components: funds drained (40%), privilege escalation (25%), invariant broken (20%), permanent lock (15%). All weights are fixed in v1.

### SeverityScorer

Python component (`validator/scoring/severity.py`) that computes severity scores from execution traces.

### Slashing

Penality mechanism where a validator's stake or reputation is reduced for misbehaviour. In VALayr, validators with >20% divergence from consensus trigger divergence-based slashing via the anti-collusion engine.

### State Impact

The measurable changes an exploit produces on the target contract: storage slot diffs, balance changes, event logs. The basis for fingerprinting and deduplication.

### Storage Collision

A vulnerability where two contracts (e.g., proxy and implementation) use the same storage slots for different purposes, causing data corruption via `delegatecall`.

### Subtensor

Bittensor's blockchain. Validators set weights on subtensor via `subtensor.set_weights()`.

### SubnetIncentiveAdapter

Python component (`subnet-adapter/incentive.py`) that maps exploit scores to Bittensor weight vectors for on-chain reward distribution.

### Synapse

A Bittensor message type for communication between neurons. VALayr defines `ExploitSubmissionSynapse` and `ExploitQuerySynapse` in `neurons/protocol.py`.

### Subnet UID

See **Netuid**.

---

## T

### TAO

The native token of the Bittensor network. Miners earn TAO rewards proportional to their weight vector scores. Validators distribute TAO by setting weights on subtensor each epoch.

### Task

A vulnerable Solidity contract generated by the Task Generator, packaged with metadata (`task.json`). Each task has a unique `task_id` and belongs to a vulnerability class.

### Task Generator

Component (`task-generator/generate.py`) that creates deterministic vulnerable Solidity contracts by applying mutators to vulnerability templates.

### Template

A base vulnerable Solidity contract that serves as the starting point for task generation. Located in `task-generator/templates/`. Examples: `reentrancy_basic.sol`, `overflow_unchecked.sol`.

---

## V

### Validation Engine

Core component (`validator/engine/validate.py`) that executes exploit submissions in a sandboxed Anvil instance and produces binary VALID/REJECT results.

### Validation Result

One of: `VALID`, `REJECT_REVERT`, `REJECT_NO_STATE_CHANGE`, `REJECT_TIMEOUT`, `REJECT_COMPILE_FAIL`, `REJECT_BELOW_GAS_THRESHOLD`, `REJECT_INVALID_FORMAT`, `REJECT_FINGERPRINT_ERROR`.

### Validator

A Bittensor neuron that generates tasks, validates exploit submissions, computes fingerprints and scores, and sets miner weights on-chain.

---

## W

### Weight Vector

The array of weights set by validators on-chain via `subtensor.set_weights()`. Determines the fraction of TAO each miner receives each epoch.

### Weight Setting

The process of computing and submitting miner reward weights based on exploit severity, uniqueness, and reward multiplier. Occurs every ~100 blocks.
