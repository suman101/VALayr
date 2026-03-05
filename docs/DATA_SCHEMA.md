# Data Schema Reference

> Last updated: 2026-03-03

This document describes the JSON schemas for all persistent state files used by VALayr.

**Concurrency note**: All state files use `fcntl.LOCK_EX` file locking and atomic writes (temp file + `os.replace`) to prevent corruption under concurrent access.

---

## fingerprints.json

**Location**: `data/fingerprints.json`
**Written by**: `validator/fingerprint/dedup.py` (FingerprintEngine)
**Concurrency**: File-locked (`fcntl.LOCK_EX`), atomic writes via temp+rename.

```json
{
  "<task_id_hex>": {
    "<fingerprint_hex>": {
      "fingerprint": "0xabcdef...",
      "task_id": "0x123456...",
      "miner_address": "0xAAAA...",
      "first_seen_at": 1700000000.0,
      "components": {},
      "submission_count": 3
    }
  }
}
```

| Field              | Type   | Description                                           |
| ------------------ | ------ | ----------------------------------------------------- |
| `fingerprint`      | string | keccak256 hex of canonical fingerprint components     |
| `task_id`          | string | Task identifier (hex)                                 |
| `miner_address`    | string | Address of the first miner to submit this fingerprint |
| `first_seen_at`    | float  | Unix timestamp of first submission                    |
| `components`       | object | Raw fingerprint components (optional, for debugging)  |
| `submission_count` | int    | Total submissions with this fingerprint               |

---

## anticollusion_state.json

**Location**: `data/anticollusion_state.json`
**Written by**: `validator/anticollusion/` module

```json
{
  "epoch": 42,
  "similarity_matrix": {
    "<miner_a>": {
      "<miner_b>": 0.85
    }
  },
  "flagged_pairs": [["0xAAAA...", "0xBBBB..."]],
  "last_updated": 1700000000.0
}
```

| Field               | Type   | Description                                 |
| ------------------- | ------ | ------------------------------------------- |
| `epoch`             | int    | Epoch number when state was computed        |
| `similarity_matrix` | object | Pairwise similarity scores between miners   |
| `flagged_pairs`     | array  | Miner pairs flagged for potential collusion |
| `last_updated`      | float  | Unix timestamp                              |

---

## epoch\_\*.json

**Location**: `data/epochs/epoch_<number>.json`
**Written by**: `neurons/validator.py` at epoch close

```json
{
  "epoch_number": 42,
  "start_block": 18000000,
  "end_block": 18000100,
  "total_submissions": 150,
  "total_valid": 80,
  "miner_scores": {
    "<hotkey>": {
      "valid_exploits": 5,
      "unique_fingerprints": 3,
      "duplicate_fingerprints": 2,
      "total_severity": 2.5
    }
  },
  "weights": {
    "<hotkey>": 0.125
  },
  "timestamp": 1700000000.0
}
```

---

## deployments/deploy\_\*.json

**Location**: `deployments/deploy_<network>_<timestamp>.json`
**Written by**: `scripts/deploy.sh` or Foundry broadcast

```json
{
  "network": "local",
  "chain_id": 31337,
  "deployer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "timestamp": "2026-03-03T06:11:32Z",
  "contracts": {
    "ExploitRegistry": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    "ProtocolRegistry": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    "InvariantRegistry": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
    "AdversarialScoring": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
  }
}
```

---

## data/reports/report\_\*.json

**Location**: `data/reports/report_<task_id>_<timestamp_ns>.json`
**Written by**: `validator/engine/validate.py` after each validation run

```json
{
  "task_id": "0x123456...",
  "miner_address": "0xAAAA...",
  "result": "VALID",
  "severity_score": 0.85,
  "fingerprint": "0xabcdef...",
  "is_duplicate": false,
  "reward_multiplier": 1.0,
  "execution_trace": {
    "gas_used": 150000,
    "storage_diffs": { "0x0": { "before": "0x0", "after": "0x1" } },
    "balance_delta": "-1000000000000000000",
    "events": [],
    "call_graph_hash": "0x..."
  },
  "timestamp": 1700000000.123456789,
  "epoch": 42
}
```

| Field               | Type   | Description                                                                                                                                                                            |
| ------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `result`            | string | One of: `VALID`, `REJECT_REVERT`, `REJECT_NO_STATE_CHANGE`, `REJECT_TIMEOUT`, `REJECT_COMPILE_FAIL`, `REJECT_BELOW_GAS_THRESHOLD`, `REJECT_INVALID_FORMAT`, `REJECT_FINGERPRINT_ERROR` |
| `severity_score`    | float  | Score in [0, 1] computed by `SeverityScorer`                                                                                                                                           |
| `is_duplicate`      | bool   | Whether the fingerprint was seen before for this task                                                                                                                                  |
| `reward_multiplier` | float  | 1.0 for unique, 0.1 for duplicate, 0.0 for invalid                                                                                                                                     |
| `execution_trace`   | object | Full execution trace (storage diffs, balances, events, gas)                                                                                                                            |

---

## data/miner/submissions/\*.json

**Location**: `data/miner/submissions/<task_id>_<timestamp>.json`
**Written by**: `miner/cli.py` upon exploit submission

```json
{
  "task_id": "0x123456...",
  "exploit_path": "Exploit.sol",
  "submitted_at": 1700000000.0,
  "status": "pending"
}
```

---

## corpus/manifest.json

**Location**: `contracts/corpus/manifest.json`
**Written by**: `task-generator/generate.py`
**Determinism**: Generated with `PYTHONHASHSEED=0` and `seed=42`

```json
{
  "version": 1,
  "seed": 42,
  "generated_at": "2026-03-03T00:00:00Z",
  "tasks": [
    {
      "task_id": "0x08fbc301...",
      "template": "reentrancy_basic",
      "vulnerability_class": "reentrancy",
      "difficulty": "medium",
      "mutators_applied": ["rename", "balance", "storage"]
    }
  ]
}
```

---

## Cross-References

- [ARCHITECTURE.md](ARCHITECTURE.md) — system data flow diagrams
- [API_REFERENCE.md](API_REFERENCE.md) — Python APIs that produce/consume these files
- [VALIDATOR_GUIDE.md](VALIDATOR_GUIDE.md) — operational data management
- [GLOSSARY.md](GLOSSARY.md) — term definitions
