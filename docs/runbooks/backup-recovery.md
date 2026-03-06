# Backup & Recovery Runbook

> Version 1.2 · Last updated: 2026-03-06

## What to Back Up

| Data                 | Location                        | Frequency        | Method          |
| -------------------- | ------------------------------- | ---------------- | --------------- |
| Fingerprint DB       | `data/fingerprints.json`        | Every epoch      | File copy       |
| Anti-collusion state | `data/anticollusion_state.json` | Every epoch      | File copy       |
| Epoch history        | `data/epochs/epoch_*.json`      | After each epoch | File copy       |
| Deployment addresses | `deployments/*.json`            | After deploy     | Git + off-site  |
| Validator config     | Environment variables / config  | On change        | Encrypted vault |

## Backup Procedure

```bash
#!/bin/bash
# Run after each epoch or on cron schedule
BACKUP_DIR="/backups/valayr/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

cp data/fingerprints.json "$BACKUP_DIR/"
cp data/anticollusion_state.json "$BACKUP_DIR/"
cp -r data/epochs/ "$BACKUP_DIR/epochs/"
cp -r deployments/ "$BACKUP_DIR/deployments/"

# Compress
tar -czf "${BACKUP_DIR}.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

# Retain last 30 days
find /backups/valayr/ -name "*.tar.gz" -mtime +30 -delete
```

## Recovery Procedure

1. Stop the validator: `systemctl stop valayr-validator`
2. Extract backup: `tar -xzf /backups/valayr/<latest>.tar.gz -C /tmp/restore/`
3. Restore data files:
   ```bash
   cp /tmp/restore/fingerprints.json data/
   cp /tmp/restore/anticollusion_state.json data/
   cp -r /tmp/restore/epochs/ data/
   ```
4. Verify data integrity: `python3 -c "import json; json.load(open('data/fingerprints.json'))"`
5. Restart validator: `systemctl start valayr-validator`
6. Monitor metrics for normal operation

## RTO / RPO Targets

| Metric                         | Target            | Notes                             |
| ------------------------------ | ----------------- | --------------------------------- |
| Recovery Time Objective (RTO)  | 1 hour            | Time from incident to operational |
| Recovery Point Objective (RPO) | 1 epoch (~1 hour) | Maximum data loss window          |

## Smart Contract State

On-chain state (exploit records, bounties, scores) is inherently backed up by the blockchain. No separate backup needed. Deployment addresses in `deployments/*.json` should be version-controlled and stored off-site.
