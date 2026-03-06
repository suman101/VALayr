# Consensus Failure Runbook

> Version 1.2 · Last updated: 2026-03-06

## Symptoms

- Submissions rejected with "quorum not reached" in logs
- `achieve_consensus()` returns `False` consistently
- Miner scores are 0 despite valid exploits
- Divergence warnings across multiple validators

## Diagnosis

### 1. Check Consensus Logs

```bash
grep -i "consensus\|quorum\|divergence\|agreement" /path/to/validator.log | tail -30
```

### 2. Verify Validator Count

```bash
btcli subnet metagraph --netuid <NETUID>
# Need ≥5 active validators for quorum
```

### 3. Compare Determinism Across Validators

Each validator should run:

```bash
PYTHONHASHSEED=0 bash scripts/verify-determinism.sh
```

All 6 checks must PASS and produce identical hashes across all validators.

## Root Causes

| Cause                    | Indicator                    | Fix                                           |
| ------------------------ | ---------------------------- | --------------------------------------------- |
| Foundry version mismatch | Different bytecode hashes    | Pin to `nightly-2024-12-01`                   |
| PYTHONHASHSEED not set   | Different fingerprint hashes | Set `PYTHONHASHSEED=0`                        |
| Anvil config mismatch    | Different execution traces   | Standardize Anvil parameters                  |
| Fewer than 5 validators  | `quorum not reached` in logs | Wait for more validators to join              |
| Network partition        | Some validators unreachable  | Check connectivity between validators         |
| solc version drift       | Compiler output differs      | Pin `solc_version = "0.8.28"` in foundry.toml |

## Recovery Steps

1. **Verify your determinism**: `bash scripts/verify-determinism.sh`
2. **Compare with other validators**: Share the output hashes (not keys) to identify drift
3. **Update to canonical versions**: `foundryup --version nightly-2024-12-01`
4. **Rebuild contracts**: `forge build --force` in `contracts/`
5. **Regenerate corpus**: `PYTHONHASHSEED=0 python3 task-generator/generate.py --count 2 --seed 42`
6. **Restart validator**: Fresh start with clean state
7. **Monitor**: Verify consensus succeeds on next epoch

## Prevention

- Always use Docker images with pinned toolchain versions
- Run `verify-determinism.sh` on every startup
- Monitor `divergence_rate` metric in Prometheus
