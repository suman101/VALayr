# Security Policy — VALayr

## Supported Versions

| Version          | Supported |
| ---------------- | --------- |
| main (HEAD)      | ✅        |
| Pre-release tags | ✅        |
| Older commits    | ❌        |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in VALayr, please report it responsibly:

1. **Email**: Send a detailed report to **security@valamandir.io** (or the project maintainer's email).
2. **Subject line**: `[VALayr Security] <brief description>`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected component(s) and file(s)
   - Potential impact assessment
   - Suggested fix (if any)

We will acknowledge receipt within **48 hours** and aim to release a patch within **7 days** for critical issues.

### Response SLAs

| Severity | Acknowledgement | Patch Target | Disclosure Window |
| -------- | --------------- | ------------ | ----------------- |
| Critical | 24 hours        | 3 days       | 7 days            |
| High     | 48 hours        | 7 days       | 14 days           |
| Medium   | 72 hours        | 14 days      | 30 days           |
| Low      | 1 week          | Next release | 90 days           |

## Scope

The following components are in scope for security reports:

| Component             | Path                          | Priority |
| --------------------- | ----------------------------- | -------- |
| Smart contracts       | `contracts/src/`              | Critical |
| Validation engine     | `validator/engine/`           | Critical |
| Scoring engine        | `validator/scoring/`          | Critical |
| Treasury contract     | `contracts/src/Treasury.sol`  | Critical |
| Anti-collusion engine | `validator/anticollusion/`    | High     |
| Fingerprint dedup     | `validator/fingerprint/`      | High     |
| Bounty system         | `validator/bounty/`           | High     |
| Neuron wrappers       | `neurons/`                    | High     |
| Orchestrator          | `orchestrator.py`             | High     |
| Subnet adapter        | `subnet-adapter/`             | Medium   |
| Docker infrastructure | `docker/`                     | Medium   |
| Discovery engine      | `task-generator/discovery.py` | Medium   |
| Task generator        | `task-generator/`             | Low      |
| CI / scripts          | `.github/`, `scripts/`        | Low      |

## Out of Scope

- Bittensor framework vulnerabilities (report to [OpenTensor](https://github.com/opentensor/bittensor))
- Foundry / Anvil vulnerabilities (report to [Foundry](https://github.com/foundry-rs/foundry))
- Denial-of-service via Bittensor p2p layer (inherent to the network)

## Disclosure Policy

- We follow **coordinated disclosure**: please allow us reasonable time to patch before public disclosure.
- Credit will be given in the CHANGELOG and release notes (unless you prefer anonymity).
- If a bounty programme is active, eligible reports will be rewarded per programme terms.

## Security Design Principles

VALayr follows these security principles (detailed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)):

1. **Defence in depth** — multiple independent controls at each trust boundary
2. **Least privilege** — non-root containers, `onlyValidator`/`onlyOwner` modifiers, minimal Docker capabilities
3. **Determinism** — pinned toolchain versions, `PYTHONHASHSEED=0`, fixed Anvil config
4. **Zero-trust miner input** — all miner-submitted code is treated as adversarial
5. **On-chain verifiability** — exploit registry provides an immutable audit log
6. **Fail-closed** — network guard exits fatally if isolation is breached; unknown errors rejected

## Security Checklist for Contributors

Before submitting a PR, ensure:

- [ ] No secrets (private keys, API tokens) in code or commits
- [ ] All new file I/O uses atomic writes and appropriate locking
- [ ] New Solidity functions have correct access control modifiers
- [ ] Exception handlers are narrowed (no bare `except:` or `except Exception`)
- [ ] Path inputs are sanitised against traversal (`..`, absolute paths)
- [ ] Docker containers remain `--network=none` for validation
- [ ] `PYTHONHASHSEED=0` is set in any new execution context
- [ ] New dependencies are version-pinned in `requirements.txt`
