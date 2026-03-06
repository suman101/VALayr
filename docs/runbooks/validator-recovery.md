# Validator Crash Recovery Runbook — v1.2

## When to Use

- Validator process crashes mid-epoch
- Fingerprint database file corrupted
- Anti-collusion state lost or unreadable
- Docker container OOM-killed or restarted

---

## 1. Assess the Damage

```bash
# Check container status
docker ps -a --filter name=exploit-validator

# Check last logs
docker logs --tail 100 exploit-validator

# Check data directory integrity
ls -la data/
python3 -c "import json; json.load(open('data/fingerprints.json'))" && echo "OK" || echo "CORRUPT"
python3 -c "import json; json.load(open('data/anticollusion_state.json'))" && echo "OK" || echo "CORRUPT"
python3 -c "import json; json.load(open('data/anti_bypass/subnet_receipts.json'))" && echo "OK" || echo "CORRUPT"
```

---

## 2. Corrupt Fingerprint DB

**Symptom**: `WARNING  Failed to load fingerprint DB from data/fingerprints.json`

**Resolution**:

1. The validator auto-recovers by starting with an empty DB.
2. Historical duplicates will not be detected until the DB rebuilds.
3. If a backup exists:
   ```bash
   scripts/restore.sh --component fingerprints --timestamp LATEST
   ```
4. If no backup, the DB will rebuild over the next epoch as miners resubmit.

---

## 3. Corrupt Anti-Collusion State

**Symptom**: `WARNING  Failed to load anticollusion state`

**Resolution**:

1. Auto-recovers with empty state (all validators reset to clean slate).
2. Historical divergence records are lost — validators with prior infractions start fresh.
3. Restore from backup if available:
   ```bash
   scripts/restore.sh --component anticollusion --timestamp LATEST
   ```

---

## 4. Mid-Epoch Crash Recovery

**Steps**:

1. Restart the validator:
   ```bash
   docker-compose up -d validator
   ```
2. The validator loads persisted state (atomic writes ensure consistency).
3. Submissions processed before the crash are preserved.
4. Submissions in-flight at crash time are lost — miners must resubmit.
5. Check epoch progress:
   ```bash
   curl -s http://localhost:9946/health | python3 -m json.tool
   ```

---

## 5. OOM Kill Recovery

**Symptom**: `docker inspect` shows `OOMKilled: true`

**Resolution**:

1. Increase memory limit in `docker-compose.yml`:
   ```yaml
   deploy:
     resources:
       limits:
         memory: 12G # was 8G
   ```
2. Check if VALAYR_MAX_CONCURRENT_VALIDATIONS is too high.
3. Restart: `docker-compose up -d validator`

---

## 6. Full Data Restore from Backup

```bash
# List available backups
ls /var/backups/valayr/

# Restore specific backup
scripts/restore.sh --backup /var/backups/valayr/backup_20260301.tar.gz

# Verify restored data
scripts/health-check.sh
```

---

## 7. Prevention

- **Backups**: Run `scripts/backup.sh` via cron (hourly recommended).
- **Monitoring**: Prometheus alerts fire on `valayr_validator_up == 0`.
- **Atomic Writes**: All persistence uses temp+rename — partial writes cannot corrupt files.
- **Logging**: All `_load()` methods log warnings on corruption (never silent).

---

## Cross-References

- [backup-recovery.md](backup-recovery.md) — Backup/restore procedures
- [incident-response.md](incident-response.md) — Incident escalation
- [DEPLOYMENT.md](../DEPLOYMENT.md) — Full deployment guide
