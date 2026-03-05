# Data Schema Reference

This document describes the JSON schemas for all persistent state files used by VALayr.

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

## commit\_\*.json

**Location**: `data/commit-reveal/commit_<task_id>.json`
**Written by**: `validator/commit_reveal.py`

```json
{
  "task_id": "0x123456...",
  "commitments": [
    {
      "miner": "0xAAAA...",
      "commit_hash": "0xdef...",
      "committed_at": 1700000000,
      "revealed": true,
      "artifact_hash": "0xabc...",
      "revealed_at": 1700007200
    }
  ],
  "task_opened_at": 1700000000,
  "commit_window_ends": 1700007200,
  "reveal_window_ends": 1700021600
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
    "CommitReveal": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "ExploitRegistry": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    "ProtocolRegistry": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    "InvariantRegistry": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
    "AdversarialScoring": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
  }
}
```
