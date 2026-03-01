# Changelog

All notable changes to VALayr are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Threat model** (`docs/THREAT_MODEL.md`) — STRIDE analysis, risk matrix, data-flow diagrams, asset inventory
- **Security policy** (`SECURITY.md`) — responsible disclosure, scope, contributor checklist
- **Contributing guide** (`CONTRIBUTING.md`) — dev setup, PR process, coding standards
- **Changelog** (this file)
- `OwnershipTransferred` events on all four contracts (`CommitReveal`, `ExploitRegistry`, `ProtocolRegistry`, `AdversarialMode`)
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
