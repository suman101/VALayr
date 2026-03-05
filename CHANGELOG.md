# Changelog

All notable changes to VALayr are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Stage 3 Python integration** — `validator/engine/adversarial.py`: AdversarialEngine for Class A/B miner flows (invariant submission, challenge processing, scoring, weight computation)
- Orchestrator Stage 3 methods: `submit_invariant()`, `submit_challenge()`, `get_adversarial_weights()`
- Orchestrator CLI commands: `invariant` and `challenge`
- Adversarial weight blending in `close_epoch()` (70% exploit + 30% adversarial)
- `tests/test_adversarial.py` — 35 tests for Stage 3 subsystem
- **Python lint & type-check CI job** — ruff, black, mypy in `lint-python` workflow job
- `[tool.mypy]` configuration in `pyproject.toml`
- Example data files in `data/reports/`, `data/anticollusion/`, `data/commit-reveal/`
- `Pausable` modifier on `ProtocolRegistry.sol` — owner can pause/unpause contract in emergencies
- Paginated `withdrawBounty()` with `startIndex` parameter and `InvalidStartIndex` guard
- `getEarliestReveal()` convenience getter on `CommitReveal.sol` — O(1) lookup via cached earliest timestamp
- Severity-score validation on `recordExploit()` — reverts with `InvalidSeverity` if score > 1e18
- `ContractStillActive` error for clearer revert messages in `ProtocolRegistry`
- `DATA_SCHEMA.md` — JSON schemas for all persistent state files
- Operational runbooks: `docs/runbooks/key-rotation.md`, `epoch-stall.md`, `consensus-failure.md`, `validator-drift.md`
- Type annotations across Python codebase (`orchestrator.py`, `validate.py`, `severity.py`, `incentive.py`)

### Changed

- Consolidated keccak256 utility — `commit_reveal.py` and `generate.py` now delegate to `validator/utils/hashing.keccak256` (removed ~60 lines of duplicate code)
- Repository URL placeholders replaced with `https://github.com/suman101/VALayr.git`
- CI lint job split into `lint-solidity` and `lint-python`
- Pinned `ruff==0.8.6`, `black==24.10.0`, `mypy==1.14.1` in `requirements.txt`
- Epoch overlap guard uses `<` instead of `<=` in `orchestrator.py` and `validator.py`
- Consensus iteration sorted for deterministic tie-breaking (lexicographic on miner address)
- Severity scores clamped to [0, 1] in `incentive.py`
- Storage slot normalization (int → hex) in `severity.py`

### Fixed

- **CRITICAL**: `withdrawBounty()` pagination bypass — `startIndex > history.length` skipped validation checks but still transferred bounty
- **CRITICAL**: Deadlock in `FingerprintEngine` — `prune()`/`check_duplicate()` calling `_save_db()` inside `_lock` (split into `_save_db()` and `_save_db_unlocked()`)
- **CRITICAL**: Race condition in validator submission rate limiting — check-and-increment was not atomic
- Path traversal vulnerabilities in task-generator template loading and miner CLI source lookup
- TOCTOU race in file size check — now checks size after read
- Regex injection in `RenameMutator` and `BalanceMutator` — switched to lambda replacement
- Windows path regex bypass in `validate.py` — fixed `_sanitize_source()` pattern
- `retry_subprocess` now re-raises `FileNotFoundError` immediately instead of retrying
- Private key CLI arg exposure removed from `key_rotation.py` — requires `--private-key-stdin`

### Security

- 19 bugs/vulnerabilities fixed across two security audit rounds
- See `docs/THREAT_MODEL.md` for updated residual risk status (R-3 through R-6 resolved)

## [0.1.0] — 2026-03-03

### Added

- **Threat model** (`docs/THREAT_MODEL.md`) — STRIDE analysis, risk matrix, data-flow diagrams, asset inventory
- **Security policy** (`SECURITY.md`) — responsible disclosure, scope, contributor checklist
- **Contributing guide** (`CONTRIBUTING.md`) — dev setup, PR process, coding standards
- **Changelog** (this file)
- `OwnershipTransferred` events on all five contracts (`CommitReveal`, `ExploitRegistry`, `ProtocolRegistry`, `InvariantRegistry`, `AdversarialMode`)
- `ValidatorUpdated` event on `InvariantRegistry`
- `ZeroAddress` custom errors on `InvariantRegistry` and `AdversarialScoring`
- Disclosure window enforcement in `ProtocolRegistry.withdrawBounty()` — loops through unpaid claims within `DISCLOSURE_WINDOW`
- Zero-address validation on `recordExploit()` in both `ExploitRegistry` and `ProtocolRegistry`
- `AdversarialMode.t.sol` — 14 Foundry tests for `InvariantRegistry` + `AdversarialScoring`
- `CommitReveal.t.sol` — reveal-window-close revert test
- Graceful `SIGTERM` shutdown handlers on both validator and miner neurons
- `RotatingFileHandler` for structured logging (10 MB, 5 backups)
- Bounded `consensus_history` (10 K entries) and `recent_results` pruning
- Non-root `appuser` in both Dockerfiles
- `.dockerignore` to exclude build artefacts from images
- `MetricsServer` health+metrics HTTP endpoint (port 9946)
- Mutator framework for task corpus diversification (`RenameMutator`, `StorageLayoutMutator`, etc.)
- CI: Python 3.10 / 3.11 added to test matrix
- CI: all test scripts now run via `pytest` with `--timeout` flags

### Changed

- `AdversarialMode.sol` — migrated `require()` strings to custom errors (`ZeroAddress`) for gas efficiency and consistency
- `dedup.py` — `_load_db` now locks the `.lock` file (same target as `_save_db`), fixing lock inconsistency
- `miner.py` — private key variable renamed to `_pk` and deleted after use (`del _pk`)
- `docker-compose.yml` — consensus relay binds `0.0.0.0` (reachable from Docker network)
- `requirements.txt` — bittensor version comment updated to `7.3.1`
- `scripts/build.sh` — corpus generation now uses `PYTHONHASHSEED=0`
- CI: integration/pipeline/live-anvil tests now run through `pytest` instead of raw `python`

### Fixed

- `ProtocolRegistry.withdrawBounty()` — could withdraw while active exploit claims were pending (disclosure window not enforced)
- `ExploitRegistry.recordExploit()` — accepted `address(0)` as miner
- `ProtocolRegistry.recordExploit()` — accepted `address(0)` as miner
- `dedup.py` — `_load_db` locked the data file while `_save_db` locked `.lock` file (deadlock risk)
- `severity.py` — unclosed file handle in `from_file()`, dead `struct` import
- `StorageLayoutMutator` — non-deterministic `hash()` for storage allocation (replaced with `hashlib.sha256`)
- `RenameMutator` — substring false-positives on renames (added word-boundary matching)
- Port counter in `validate.py` — race condition on `_next_port` (replaced with `threading.Lock`)
- `AdversarialMode.t.sol` — `vm.expectRevert` now uses custom error selectors instead of string matching
- `consensus.py` — below-quorum threshold changed from `> quorum` to `>= quorum` (`0.51` fix)
- `miner.py` / `commit_reveal.py` — private key no longer visible in `ps` output
- Function selector hashing — replaced Python `sha3` with `keccak256` across codebase
- Report filenames — added `time.time_ns()` to prevent collisions
- `fcntl` — conditional import with `msvcrt` fallback for non-POSIX platforms

### Security

- See `docs/THREAT_MODEL.md` for full STRIDE analysis and risk matrix
- All `transferOwnership` functions now emit `OwnershipTransferred` for audit trail
- Disclosure window enforcement prevents bounty rug-pulls
- Zero-address guards prevent miner address confusion on-chain
- File-lock consistency prevents fingerprint DB corruption under concurrent access
