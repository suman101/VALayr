# VALayr — Miner Guide

> Version 1.0 · Last updated: 2026-03

This guide is for **miners** who want to participate in the VALayr subnet by discovering and submitting smart contract exploits. You do not need to understand the validator internals — this guide covers everything you need to earn TAO.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Getting Started](#2-getting-started)
- [3. Understanding Tasks](#3-understanding-tasks)
- [4. Writing Exploits](#4-writing-exploits)
- [5. Submission Workflow](#5-submission-workflow)
- [6. Scoring & Rewards](#6-scoring--rewards)
- [7. Commit-Reveal Protocol](#7-commit-reveal-protocol)
- [8. Exploit Strategies by Vulnerability Class](#8-exploit-strategies-by-vulnerability-class)
- [9. Tips for Maximising Rewards](#9-tips-for-maximising-rewards)
- [10. FAQ](#10-faq)

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
git clone https://github.com/<org>/valayr.git
cd valayr

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

### 5.1 Quick Submit (Local/Development)

```bash
python3 -m miner.cli submit --task 0x08fbc301 --exploit Exploit.sol
```

### 5.2 Full Commit-Reveal Submit (Production)

The commit-reveal protocol prevents other miners from stealing your exploit:

```bash
# Step 1: Commit (sends hash on-chain, hides your exploit)
python3 -m miner.cli commit --task 0x08fbc301 --exploit Exploit.sol

# Step 2: Wait for commit window to close (~2 hours)

# Step 3: Reveal (sends actual exploit after window)
python3 -m miner.cli reveal --task 0x08fbc301
```

### 5.3 Check Submission Status

```bash
# Check a specific submission
python3 -m miner.cli status --task 0x08fbc301

# Check all recent submissions
python3 -m miner.cli status
```

### 5.4 View Scores

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
4. **Speed** — Did you commit first? (small bonus)

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
          + (earliest_commits × 0.05)
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

## 7. Commit-Reveal Protocol

The commit-reveal protocol prevents front-running — it ensures no one can steal your exploit by seeing it before you get credit.

### 7.1 How It Works

```
You                                               Chain
 │                                                  │
 │── 1. Hash your exploit + random nonce            │
 │── 2. Submit hash on-chain (commit) ─────────────▶│
 │                                                  │
 │   [Wait 2 hours — commit window]                 │
 │                                                  │
 │── 3. Reveal exploit + nonce ────────────────────▶│
 │      Chain verifies: hash(exploit + nonce) == commit
 │                                                  │
 │   [Validator runs validation]                    │
 │                                                  │
 │◀── 4. Receive score ────────────────────────────│
```

### 7.2 Timing

| Phase             | Duration | What Happens                                             |
| ----------------- | -------- | -------------------------------------------------------- |
| **Commit Window** | 2 hours  | Submit your hash. Others cannot see your exploit.        |
| **Reveal Window** | 4 hours  | Reveal your exploit code. Validator verifies hash match. |

### 7.3 Important

- **Do NOT share your exploit** during the commit window
- **Save your nonce** — you need it for the reveal step
- If you miss the reveal window, your commit is **void** (no credit)
- The commit-reveal client stores records locally in `data/commit-reveal/`

---

## 8. Exploit Strategies by Vulnerability Class

### 8.1 Reentrancy

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

### 8.2 Integer Overflow/Underflow

**Pattern:** Arithmetic operations wrap around without checks in `unchecked` blocks.

**Strategy:**

1. Find `unchecked` blocks or pre-0.8.0 patterns
2. Craft inputs that cause overflow (large values) or underflow (subtract from zero)
3. Exploit the resulting incorrect state

### 8.3 Auth Bypass / Missing Access Control

**Pattern:** Critical functions lack proper access control modifiers.

**Strategy:**

1. Call admin/owner functions directly from your attacker address
2. Transfer ownership to yourself
3. Drain funds or modify state

### 8.4 Storage Collision

**Pattern:** Proxy contracts where implementation and proxy share overlapping storage slots.

**Strategy:**

1. Identify the proxy's admin/implementation storage slots
2. Find functions that write to the same slots in the implementation
3. Overwrite the proxy admin with your address

### 8.5 Flash Loan + Oracle Manipulation

**Pattern:** A lending protocol uses an AMM's spot price as an oracle.

**Strategy:**

1. Flash loan a large amount of tokens
2. Dump tokens into the AMM → crash the spot price
3. Borrow against inflated collateral from the lending protocol
4. Repay the flash loan, keep the profit

### 8.6 Upgradeable Proxy

**Pattern:** An upgradeable proxy has a missing or unprotected initialiser.

**Strategy:**

1. Call `initialize()` if it's unprotected
2. Take ownership
3. Upgrade to a malicious implementation
4. Drain all funds

---

## 9. Tips for Maximising Rewards

### 9.1 Speed Matters

- Use commit-reveal to lock in your discovery time
- First unique submission gets full reward
- Commit as early as possible, even before your exploit is perfect

### 9.2 Maximise Severity

The severity score directly multiplies your reward:

- **Drain funds** (40% weight) — always try to extract ETH
- **Take ownership** (25% weight) — `transferOwnership()` or overwrite the owner slot
- **Break invariants** (20% weight) — change proxy implementation, modify multiple storage slots
- **Permanent damage** (15% weight) — zero out critical slots

### 9.3 Target Unique State Changes

Dedup is based on state impact. To avoid duplicates:

- Find **different vulnerabilities** in the same contract
- Exploit **different entry points** that produce different storage diffs
- Target different aspects: funds drain vs. ownership vs. proxy upgrade

### 9.4 Avoid Invalid Submissions

Each invalid submission costs you `-0.05` points. Before submitting:

```bash
# Always test locally first
forge test --fork-url http://localhost:8545 -vvvv

# Check that state actually changes
# Look for non-zero storage diffs and balance changes
```

### 9.5 Study the Templates

The vulnerability templates in `task-generator/templates/` are based on real-world patterns. Study them to understand what the validators are looking for.

### 9.6 Rate Limits

| Limit               | Value            |
| ------------------- | ---------------- |
| Per-miner per-epoch | 50 submissions   |
| Global per-epoch    | 1000 submissions |
| Submission cooldown | 30 seconds       |

Don't waste submissions on untested exploits.

---

## 10. FAQ

### Q: Do I need Foundry installed to mine?

**A:** Not strictly — you can write Solidity and submit via the CLI. But Foundry is strongly recommended for **testing your exploits locally** before submitting. Invalid submissions cost you points.

### Q: How long is an epoch?

**A:** Approximately 60 minutes (~360 blocks). Scores reset each epoch.

### Q: What happens if two miners find the same exploit?

**A:** The first miner (by commit time) gets the full reward (1.0× multiplier). All subsequent miners with the same state-impact fingerprint receive only 10% (0.1× multiplier).

### Q: Can I submit exploits for the same task multiple times?

**A:** Yes, but only unique fingerprints earn full reward. If you find a different vulnerability in the same contract (different state impact), it counts as a new unique exploit.

### Q: What's the maximum exploit size?

**A:** 64 KB of Solidity source code.

### Q: Will my exploit source code be visible to others?

**A:** Not during the commit window. After reveal, your exploit is part of the validation record. The commit-reveal protocol protects you during the discovery phase.

### Q: What if the validator is down?

**A:** If the validator times out or is unreachable, your submission will not be processed. The commit-reveal hash is on-chain, so you can re-submit to another validator during the reveal window.

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
