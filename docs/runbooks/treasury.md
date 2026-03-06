# Runbook: Treasury Competition Operations

> Version 1.2 · Last updated: 2026-03-06

## When to Use

- Creating, monitoring, settling, or debugging Treasury competitions.
- Investigating failed score submissions or stuck settlements.
- Withdrawing protocol fees or winner prizes.

---

## Prerequisites

- `cast` (Foundry) installed and available on PATH.
- `RPC_URL` set to the target chain RPC endpoint.
- `TREASURY` set to the deployed Treasury contract address.
- Deployer/owner private key available for admin operations.
- Validator private key available for score submission.

---

## 1. Create a Competition

```bash
# Parameters: taskId (bytes32), duration (seconds), prize (ETH value)
TASK_ID=$(cast --to-bytes32 "reentrancy_basic")
DURATION=86400  # 24 hours

cast send $TREASURY \
  "createCompetition(bytes32,uint256)" $TASK_ID $DURATION \
  --value 1ether \
  --rpc-url $RPC_URL \
  --private-key $OWNER_KEY
```

**Constraints:**

| Parameter | Requirement         |
| --------- | ------------------- |
| Duration  | ≥ 1 hour, ≤ 30 days |
| Prize     | ≥ 0.01 ETH          |
| Contract  | Must not be paused  |

---

## 2. Check Competition Status

```bash
# Is competition still accepting submissions?
cast call $TREASURY "isActive(uint256)" $COMP_ID --rpc-url $RPC_URL

# Get full details (returns Competition struct)
cast call $TREASURY "getCompetition(uint256)" $COMP_ID --rpc-url $RPC_URL

# Time remaining (seconds, 0 if ended)
cast call $TREASURY "timeRemaining(uint256)" $COMP_ID --rpc-url $RPC_URL
```

---

## 3. Settle a Competition

After the deadline passes, anyone can settle:

```bash
cast send $TREASURY "settle(uint256)" $COMP_ID \
  --rpc-url $RPC_URL \
  --private-key $CALLER_KEY
```

**What happens on settlement:**

- If there is a winner: 5% protocol fee deducted, remainder earmarked for winner.
- If no submissions: full prize pool moved to `accumulatedFees` (returned to owner via `withdrawFees`).

---

## 4. Winner Prize Withdrawal

The winning miner calls this from their own wallet:

```bash
cast send $TREASURY "withdrawPrize(uint256)" $COMP_ID \
  --rpc-url $RPC_URL \
  --private-key $WINNER_KEY
```

**Requirements:** Competition must be settled, not already withdrawn, caller must be the recorded winner.

---

## 5. Withdraw Protocol Fees (Admin)

```bash
cast send $TREASURY "withdrawFees(address)" $RECIPIENT_ADDRESS \
  --rpc-url $RPC_URL \
  --private-key $OWNER_KEY
```

---

## 6. Update Validator Address (Admin)

If the authorized validator address changes:

```bash
cast send $TREASURY "setValidator(address)" $NEW_VALIDATOR \
  --rpc-url $RPC_URL \
  --private-key $OWNER_KEY
```

---

## Troubleshooting

### Score submission reverts with `CompetitionNotActive`

- Competition deadline has passed, or `startTime == 0` (invalid ID).
- Fix: Check `isActive(id)` and `timeRemaining(id)`.

### Settlement reverts with `CompetitionNotEnded`

- Deadline hasn't passed yet.
- Fix: Wait until `block.timestamp > deadline`.

### Settlement reverts with `AlreadySettled`

- Competition was already settled.
- Fix: Check `competitions[id].settled`.

### Winner withdrawal reverts with `NotWinner`

- Caller address doesn't match `competitions[id].winner`.
- Fix: Verify the winning miner's address with `getCompetition(id)`.

### `withdrawFees` reverts with `Transfer failed`

- Recipient address cannot receive ETH (e.g., contract without `receive()`/`fallback()`).
- Fix: Use an EOA or a contract that accepts ETH.

---

## Emergency Procedures

### Pause All Operations

```bash
cast send $TREASURY "pause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
```

All state-changing functions (`createCompetition`, `submitScore`, `settle`) will revert while paused. `withdrawPrize` and `withdrawFees` are **not** blocked by pause (uses `nonReentrant` only).

### Unpause

```bash
cast send $TREASURY "unpause()" --rpc-url $RPC_URL --private-key $OWNER_KEY
```

---

## Monitoring

| Event                | What It Means                             |
| -------------------- | ----------------------------------------- |
| `CompetitionCreated` | New competition funded and started        |
| `ScoreSubmitted`     | Validator forwarded a miner's score       |
| `CompetitionSettled` | Deadline passed, winner determined        |
| `PrizeWithdrawn`     | Winner claimed their ETH                  |
| `FeesWithdrawn`      | Owner collected accumulated protocol fees |
| `ValidatorUpdated`   | Authorized validator address changed      |
