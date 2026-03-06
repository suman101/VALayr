# VALayr — Miner Guide

> Version 0.1.0 · Last updated: 2026-03-06

This guide is for **miners** who want to participate in the VALayr subnet by discovering and submitting smart contract exploits. You do not need to understand the validator internals — this guide covers everything you need to earn TAO.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Getting Started](#2-getting-started)
- [3. Understanding Tasks](#3-understanding-tasks)
- [4. Writing Exploits](#4-writing-exploits)
- [5. Submission Workflow](#5-submission-workflow)
- [6. Scoring & Rewards](#6-scoring--rewards)
- [7. Exploit Strategies by Vulnerability Class](#7-exploit-strategies-by-vulnerability-class)
- [8. Tips for Maximising Rewards](#8-tips-for-maximising-rewards)
- [9. Treasury Competitions](#9-treasury-competitions)
- [10. FAQ](#10-faq)
- [11. First-Time Miner Checklist](#11-first-time-miner-checklist)

---

## 1. Overview

VALayr is a Bittensor subnet where **miners compete to find exploits in vulnerable Solidity smart contracts**. Here's how it works:

1. **Validators publish tasks** — each task is a vulnerable Solidity contract
2. **You write an exploit** — Solidity code that exploits the vulnerability
3. **You submit the exploit** — via CLI or Bittensor synapse
4. **Validators verify it** — in a sandboxed Anvil instance
5. **You earn TAO** — based on severity, uniqueness, and speed

**Key principle:** The first miner to submit a unique exploit gets full reward. Duplicates receive only 10%.

---

## 2. Getting Started

### 2.1 Prerequisites

| Tool      | Version              | Required                        |
| --------- | -------------------- | ------------------------------- |
| Python    | ≥ 3.10               | Yes                             |
| Foundry   | `nightly-2024-12-01` | Recommended (for local testing) |
| Bittensor | 7.3.1                | For on-chain mining             |

### 2.2 Install

```bash
# Clone the repository
git clone https://github.com/suman101/VALayr.git
cd VALayr

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install Foundry for local exploit testing
curl -L https://foundry.paradigm.xyz | bash
foundryup --version nightly-2024-12-01
```

### 2.3 Register on Bittensor

```bash
# Create a wallet
btcli wallet create --wallet.name miner --wallet.hotkey miner_hot

# Register on the subnet
btcli subnet register --netuid <NETUID> --wallet.name miner --wallet.hotkey miner_hot
```

### 2.4 Run the Miner

```bash
# Local mode (no Bittensor — for practice)
python3 neurons/miner.py --local

# Bittensor mode (production)
python3 neurons/miner.py --netuid <NETUID> --wallet.name miner --wallet.hotkey miner_hot
```

---

## 3. Understanding Tasks

Each task is a vulnerable Solidity contract packaged with deployment configuration.

### 3.1 List Available Tasks

```bash
python3 -m miner.cli tasks
```

Output:

```
Task ID              | Class            | Difficulty | Templates
---------------------|------------------|------------|----------
0x08fbc301...        | reentrancy       | medium     | 1
0x099287f6...        | auth-bypass      | easy       | 1
0x0c2f8b0d...        | storage-collision| hard       | 1
...
```

### 3.2 Inspect a Task

```bash
python3 -m miner.cli task --id 0x08fbc301
```

This shows:

- **Source code** of the vulnerable contract
- **Vulnerability class** (reentrancy, overflow, auth-bypass, etc.)
- **Difficulty rating**
- **Deployment config** (constructor args, initial balance, etc.)

### 3.3 Task Package Contents

Each task directory contains:

```
contracts/corpus/0x08fbc301/
├── Vulnerable.sol       # The contract to exploit
├── task.json            # Metadata (class, difficulty, deployment config)
└── foundry.toml         # Compiler config
```

---

## 4. Writing Exploits

### 4.1 Exploit Format

Your exploit must be a Foundry test contract with a `test_run()` function:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

interface IVulnerable {
    // Interface for the target contract
}

contract ExploitTest is Test {
    IVulnerable target;

    function setUp() public {
        // Target is already deployed by the validation engine
        // You can deploy auxiliary contracts here
    }

    function test_run() public {
        // YOUR EXPLOIT CODE HERE
        // Must change the target contract's state
    }
}
```

**Requirements:**

- Must be valid Solidity (`^0.8.28`)
- Must have a `test_run()` function (or configure `entry_function`)
- Must cause a **state change** in the target contract
- Must NOT revert
- Must be under **64 KB** in size
- Must NOT use `..` path traversal or absolute imports

### 4.2 Generate a Scaffold

```bash
python3 -m miner.cli scaffold --task 0x08fbc301
```

This generates a template exploit with:

- The target contract's interface
- Vulnerability-specific hints
- Boilerplate test structure

### 4.3 Test Locally

Before submitting, test your exploit locally:

```bash
# Start a local Anvil instance
anvil --timestamp 1700000000 --block-number 18000000 --gas-limit 30000000 --chain-id 31337

# In another terminal, run your exploit
forge test --fork-url http://localhost:8545 -vvvv
```

Or use the orchestrator for full pipeline testing:

```bash
python3 orchestrator.py submit \
  --task 0x08fbc301 \
  --exploit my_exploit.sol \
  --miner 0xYOUR_ADDRESS
```

---

## 5. Submission Workflow

### 5.1 Quick Submit

```bash
python3 -m miner.cli submit --task 0x08fbc301 --exploit Exploit.sol
```

### 5.2 Check Submission Status

```bash
# Check a specific submission
python3 -m miner.cli status --task 0x08fbc301

# Check all recent submissions
python3 -m miner.cli status
```

### 5.3 View Scores

```bash
python3 -m miner.cli scores
```

Output:

```
Epoch 42 Leaderboard
Rank | Miner         | Valid | Unique | Severity | Weight
-----|---------------|-------|--------|----------|-------
  1  | 0xabcd...1234 |    8  |    6   |   0.72   | 0.341
  2  | 0xdead...beef |    5  |    4   |   0.58   | 0.224
  3  | 0x1234...5678 |    3  |    2   |   0.45   | 0.118
...
```

---

## 6. Scoring & Rewards

### 6.1 How Scoring Works

Your score is determined by four factors:

1. **Validity** — Does your exploit actually work? (binary: yes/no)
2. **Uniqueness** — Is this a new exploit? (first submitter gets 10× more)
3. **Severity** — How impactful is the exploit? (0.0 to 1.0)
4. **Speed** — Did you submit first? (small bonus)

### 6.2 Severity Score Breakdown

| Component                | Weight | How to Maximise                                              |
| ------------------------ | ------ | ------------------------------------------------------------ |
| **Funds Drained**        | 40%    | Drain as much ETH/tokens as possible                         |
| **Privilege Escalation** | 25%    | Take ownership of the contract                               |
| **Invariant Broken**     | 20%    | Change proxy implementation, modify ≥3 storage slots         |
| **Permanent Lock**       | 15%    | Zero out critical storage slots (e.g., destroy the contract) |

### 6.3 Reward Formula

```
raw_score = (unique_exploits × avg_severity)
          + (duplicate_exploits × avg_severity × 0.1)
          - (invalid_submissions × 0.05)
```

Weights are normalised across all miners each epoch to produce TAO rewards.

### 6.4 Duplicate Policy

**First unique submission**: `1.0×` reward multiplier
**Subsequent duplicates**: `0.1×` reward multiplier (10%)

Deduplication is based on **state impact**, not source code. Two different exploits that drain the same funds via different paths produce the same fingerprint and are considered duplicates.

### 6.5 Penalties

| Infraction                                    | Penalty                  |
| --------------------------------------------- | ------------------------ |
| Invalid submission (reverts, no state change) | `-0.05` per submission   |
| Submissions exceeding rate limit              | Silently dropped         |
| Blacklisted hotkey                            | All submissions rejected |

---

## 7. Exploit Strategies by Vulnerability Class

### 7.1 Reentrancy

**Pattern:** The vulnerable contract sends ETH before updating state.

**Strategy:**

1. Deploy an attacker contract with a `receive()` or `fallback()` function
2. Call the vulnerable `withdraw()` function
3. In `receive()`, re-enter `withdraw()` before the balance is updated
4. Repeat until funds are drained

```solidity
contract Attacker {
    IVulnerable target;
    uint256 reentryCount;

    constructor(address _target) { target = IVulnerable(_target); }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (reentryCount < 5) {
            reentryCount++;
            target.withdraw(msg.value);
        }
    }
}
```

### 7.2 Integer Overflow/Underflow

**Pattern:** Arithmetic operations wrap around without checks in `unchecked` blocks.

**Strategy:**

1. Find `unchecked` blocks or pre-0.8.0 patterns
2. Craft inputs that cause overflow (large values) or underflow (subtract from zero)
3. Exploit the resulting incorrect state

### 7.3 Auth Bypass / Missing Access Control

**Pattern:** Critical functions lack proper access control modifiers.

**Strategy:**

1. Call admin/owner functions directly from your attacker address
2. Transfer ownership to yourself
3. Drain funds or modify state

### 7.4 Storage Collision

**Pattern:** Proxy contracts where implementation and proxy share overlapping storage slots.

**Strategy:**

1. Identify the proxy's admin/implementation storage slots
2. Find functions that write to the same slots in the implementation
3. Overwrite the proxy admin with your address

### 7.5 Flash Loan + Oracle Manipulation

**Pattern:** A lending protocol uses an AMM's spot price as an oracle.

**Strategy:**

1. Flash loan a large amount of tokens
2. Dump tokens into the AMM → crash the spot price
3. Borrow against inflated collateral from the lending protocol
4. Repay the flash loan, keep the profit

### 7.6 Upgradeable Proxy

**Pattern:** An upgradeable proxy has a missing or unprotected initialiser.

**Strategy:**

1. Call `initialize()` if it's unprotected
2. Take ownership
3. Upgrade to a malicious implementation
4. Drain all funds

---

## 8. Tips for Maximising Rewards

### 8.1 Speed Matters

- First unique submission gets full reward
- Submit as early as possible, even before your exploit is perfect

### 8.2 Maximise Severity

The severity score directly multiplies your reward:

- **Drain funds** (40% weight) — always try to extract ETH
- **Take ownership** (25% weight) — `transferOwnership()` or overwrite the owner slot
- **Break invariants** (20% weight) — change proxy implementation, modify multiple storage slots
- **Permanent damage** (15% weight) — zero out critical slots

### 8.3 Target Unique State Changes

Dedup is based on state impact. To avoid duplicates:

- Find **different vulnerabilities** in the same contract
- Exploit **different entry points** that produce different storage diffs
- Target different aspects: funds drain vs. ownership vs. proxy upgrade

### 8.4 Avoid Invalid Submissions

Each invalid submission costs you `-0.05` points. Before submitting:

```bash
# Always test locally first
forge test --fork-url http://localhost:8545 -vvvv

# Check that state actually changes
# Look for non-zero storage diffs and balance changes
```

### 8.5 Study the Templates

The vulnerability templates in `task-generator/templates/` are based on real-world patterns. Study them to understand what the validators are looking for.

### 8.6 Rate Limits

| Limit               | Value            |
| ------------------- | ---------------- |
| Per-miner per-epoch | 50 submissions   |
| Global per-epoch    | 1000 submissions |
| Submission cooldown | 30 seconds       |

Don't waste submissions on untested exploits.

---

## 9. Treasury Competitions

Treasury competitions are on-chain, winner-takes-all events funded via the `Treasury` smart contract. They offer an additional reward path beyond standard epoch-based TAO earnings.

### How It Works

1. **Competition created** — The contract owner (or any funder) creates a competition targeting a specific task, with an ETH prize pool and a deadline.
2. **Miners submit exploits** — Standard submissions via the Bittensor axon. The validator automatically forwards qualifying exploit scores to the on-chain `Treasury.submitScore()` function.
3. **Highest severity wins** — The miner whose exploit scores the highest severity when the deadline passes wins the entire prize pool (minus a 5% protocol fee).
4. **Winner withdraws** — After the competition is settled on-chain, the winning miner calls `withdrawPrize()` to claim their ETH.

### Key Parameters

| Parameter    | Value    | Description                                 |
| ------------ | -------- | ------------------------------------------- |
| Min duration | 1 hour   | Shortest allowed competition                |
| Max duration | 30 days  | Longest allowed competition                 |
| Min prize    | 0.01 ETH | Minimum funded prize pool                   |
| Protocol fee | 5%       | Deducted on settlement, goes to subnet fund |

### Tips for Competitions

- **Check active competitions** — Monitor the `CompetitionCreated` events or query `Treasury.isActive(id)`.
- **Target high-severity bugs** — The winning metric is severity score, not speed.
- **Deduplicate locally** — If your exploit fingerprint matches another miner's, only the first submission counts. Aim for novel attack vectors.
- **Watch the deadline** — Submissions after `comp.deadline` revert on-chain.

### Reward Split (Bounty Payouts)

When a validated exploit is matched to a real-world bug bounty, the payout is split:

| Recipient | Default Share | Configurable Via         |
| --------- | ------------- | ------------------------ |
| Miner     | 70%           | `VALAYR_MINER_SHARE`     |
| Validator | 20%           | `VALAYR_VALIDATOR_SHARE` |
| Treasury  | 10%           | `VALAYR_TREASURY_SHARE`  |

Shares must sum to 1.0. The split is computed by `RewardSplitEngine` and recorded in `data/rewards/payouts.json`.

---

## 10. FAQ

### Q: Do I need Foundry installed to mine?

**A:** Not strictly — you can write Solidity and submit via the CLI. But Foundry is strongly recommended for **testing your exploits locally** before submitting. Invalid submissions cost you points.

### Q: How long is an epoch?

**A:** Approximately 60 minutes (~360 blocks). Scores reset each epoch.

### Q: What happens if two miners find the same exploit?

**A:** The first miner (by submission time) gets the full reward (1.0× multiplier). All subsequent miners with the same state-impact fingerprint receive only 10% (0.1× multiplier).

### Q: Can I submit exploits for the same task multiple times?

**A:** Yes, but only unique fingerprints earn full reward. If you find a different vulnerability in the same contract (different state impact), it counts as a new unique exploit.

### Q: What's the maximum exploit size?

**A:** 64 KB of Solidity source code.

### Q: Will my exploit source code be visible to others?

**A:** Not during the discovery phase. After validation, your exploit is part of the validation record. Bittensor's built-in time-locked commitments protect your submission priority.

### Q: What if the validator is down?

**A:** If the validator times out or is unreachable, your submission will not be processed. You can re-submit to another validator.

### Q: How do I check if Bittensor is working?

```bash
btcli wallet overview --wallet.name miner
btcli subnet metagraph --netuid <NETUID>
```

### Q: What Solidity version should I use?

**A:** `pragma solidity ^0.8.28` — this matches the pinned compiler version.

### Q: Can I import external libraries?

**A:** Only `forge-std` is available in the sandbox. You cannot import OpenZeppelin or other external libraries. Write self-contained exploits.

---

## Quick Reference

```bash
# List tasks
python3 -m miner.cli tasks

# Inspect a task
python3 -m miner.cli task --id <TASK_ID>

# Generate exploit scaffold
python3 -m miner.cli scaffold --task <TASK_ID>

# Test locally
forge test --fork-url http://localhost:8545 -vvvv

# Submit exploit
python3 -m miner.cli submit --task <TASK_ID> --exploit Exploit.sol

# Check status
python3 -m miner.cli status

# View leaderboard
python3 -m miner.cli scores
```

---

_For developer documentation (contributing code to VALayr itself), see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)._

---

## Stage 3: Adversarial Invariant Discovery

Stage 3 introduces a two-class miner system. Miners can participate as **Class A** (invariant writers) or **Class B** (exploit writers).

### Class A — Invariant Writers

Class A miners write safety invariants for target contracts. An invariant is a property that should always hold (e.g., "total supply never decreases"). Invariants are submitted on-chain via `InvariantRegistry.submitInvariant()`.

**Scoring:**

- If your invariant **holds** against a Class B challenge: **+100 points** (W_HOLD_REWARD)
- If your invariant is **broken**: **-500 points** (W_BREACH_PENALTY)
- Score has a floor of `MIN_SCORE` to prevent unbounded negatives

**Strategy:** Write invariants that are true and hard to break. Trivially true invariants (e.g., "1 == 1") earn zero challenges and no score.

### Class B — Exploit Writers (Traditional)

Class B miners write exploits targeting submitted invariants. The goal is to break as many invariants as possible.

**Scoring:**

- Breaking an invariant: **+1000 points** (W_BREACH_REWARD)
- Failed challenge (invariant holds): **+10 points** (W_FAILED_CHALLENGE) — small consolation

### Workflow

1. Class A submits an invariant via `InvariantRegistry.submitInvariant()`
2. Class B submits an exploit targeting that invariant
3. Validator runs `AdversarialScoring.processChallenge()`:
   - Deploys the target contract in a sandboxed Anvil instance
   - Executes the Class B exploit
   - Checks if the invariant holds or is broken
   - Updates scores for both miners
4. Both classes earn TAO based on their accumulated scores

---

## 11. First-Time Miner Checklist

Use this checklist to verify your setup before your first submission:

- [ ] **Python 3.10+** installed — `python3 --version`
- [ ] **Foundry** installed and pinned — `forge --version` shows `nightly-2024-12-01`
- [ ] **Repository cloned** — `git clone https://github.com/suman101/VALayr.git`
- [ ] **Dependencies installed** — `pip install -e ".[dev]"`
- [ ] **Contracts compile** — `forge build` succeeds in `contracts/`
- [ ] **Bittensor wallet created** — `btcli wallet new_hotkey --wallet.name miner`
- [ ] **Subnet registered** — `btcli subnet register --netuid <NETUID> --wallet.name miner`
- [ ] **Can list tasks** — `python3 -m miner.cli tasks` returns task list
- [ ] **Can scaffold** — `python3 -m miner.cli scaffold --task <TASK_ID>` generates template
- [ ] **Local test passes** — `forge test` with your exploit succeeds
- [ ] **Can submit** — `python3 -m miner.cli submit --task <TASK_ID> --exploit Exploit.sol`

**Common gotchas:**

- Use `pragma solidity ^0.8.28;` — other versions will fail compilation
- Only `forge-std` is available — no OpenZeppelin or other imports
- Maximum exploit size is 64 KB
- Rate limit: 50 submissions per epoch per miner

---

_For the full exploit writing tutorial with annotated examples, see [EXPLOIT_WRITING_GUIDE.md](EXPLOIT_WRITING_GUIDE.md)._
_For developer documentation (contributing code to VALayr itself), see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)._
