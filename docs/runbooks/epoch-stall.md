# Epoch Stall Runbook

> Version 1.2 · Last updated: 2026-03-06

## Symptoms

- Epoch number stops incrementing in metrics
- `close_epoch()` throws exceptions or times out
- Weight-setting calls to subtensor fail
- Miner scores stop updating

## Diagnosis

### 1. Check Validator Logs

```bash
grep -i "epoch\|close_epoch\|set_weights" /path/to/validator.log | tail -20
```

### 2. Check Epoch State

```bash
ls -lt data/epochs/ | head -5
# Verify the latest epoch file was written recently
```

### 3. Check Subtensor Connectivity

```bash
btcli subnet metagraph --netuid <NETUID>
```

## Root Causes

| Cause                       | Indicator                         | Fix                                     |
| --------------------------- | --------------------------------- | --------------------------------------- |
| Subtensor RPC timeout       | `ConnectionError` in logs         | Restart validator, check network        |
| Epoch overlap guard tripped | "Epoch overlap" warning in logs   | Wait for previous epoch to close        |
| No submissions in epoch     | `total_submissions: 0` in metrics | Normal — epoch closes with zero weights |
| Fingerprint DB lock held    | `LOCK_EX` timeout in logs         | Kill orphaned processes, restart        |

## Recovery Steps

1. **Check for orphaned processes**: `ps aux | grep -E 'anvil|validator'`
2. **Kill orphans if found**: `pkill -f anvil`
3. **Verify state files**: `python3 -c "import json; json.load(open('data/anticollusion_state.json'))"`
4. **Restart validator**: `python3 neurons/validator.py --netuid <NETUID>`
5. **Monitor**: Wait one full epoch (~60 min) and verify epoch number increments

## Prevention

- Set up Prometheus alerting on `epoch_number` metric (alert if no change in 90 minutes)
- Configure `docker/alerts.yml` with epoch stall rule
