# Validator Drift Runbook

> Version 1.2 · Last updated: 2026-03-06

## Symptoms

- `verify-determinism.sh` fails one or more checks
- Your validator's results diverge from consensus
- Divergence rate exceeds 20% (slashing threshold)
- Miner exploits that other validators accept are rejected by yours (or vice versa)

## Diagnosis

### 1. Run Determinism Checks

```bash
PYTHONHASHSEED=0 bash scripts/verify-determinism.sh
```

Expected output: all 6 categories PASS.

### 2. Identify the Failing Category

| Category                 | Common Cause                | Fix                                      |
| ------------------------ | --------------------------- | ---------------------------------------- |
| Compiler Versions        | `solc` auto-updated         | `foundryup --version nightly-2024-12-01` |
| Python Determinism       | PYTHONHASHSEED not 0        | `export PYTHONHASHSEED=0`                |
| Anvil Configuration      | Env vars not set            | Set all `ANVIL_*` variables              |
| Bytecode Reproducibility | Cache corruption            | `forge clean && forge build --force`     |
| Task Corpus Determinism  | Mutator or template changed | Regenerate with `seed=42`                |
| Docker Image             | Running outdated image      | Pull latest tagged image                 |

### 3. Check for Orphaned State

```bash
# Check for corrupted fingerprint DB
python3 -c "import json; db = json.load(open('data/fingerprints.json')); print(f'{len(db)} tasks')"

# Check for stale lock files
ls -la data/*.lock 2>/dev/null
```

## Recovery Steps

1. **Fix the determinism check failure** (see table above)
2. **Clean and rebuild**:
   ```bash
   cd contracts && forge clean && forge build --force && cd ..
   ```
3. **Regenerate corpus**:
   ```bash
   PYTHONHASHSEED=0 python3 task-generator/generate.py --count 2 --seed 42
   ```
4. **Verify fix**: `bash scripts/verify-determinism.sh` — all PASS
5. **Restart validator**: `python3 neurons/validator.py --netuid <NETUID>`
6. **Monitor divergence**: Watch logs for `divergence_rate` over next epoch

## Prevention

- Use Docker with pinned base images and tool versions
- Never run `foundryup` without specifying the pinned version
- Always set `PYTHONHASHSEED=0` in your environment/Dockerfile
- Run `verify-determinism.sh` as part of Docker entrypoint
- Set Prometheus alert on `divergence_rate > 0.1` (warn at 10%, critical at 20%)
