#!/bin/bash
set -euo pipefail

# ── Validator Entrypoint ──────────────────────────────────────────────────────
# Enforces determinism and network isolation before running validation.

echo "=== Exploit Subnet Validator ==="
echo "Image version: v0.1.0"
echo "Foundry: $(forge --version 2>&1 | head -1)"
echo "solc: $(solc --version 2>&1 | tail -1)"
echo "Python: $(python3 --version 2>&1)"

# ── Verify Network Isolation ──────────────────────────────────────────────────
echo "[*] Checking network isolation..."
if curl -s --connect-timeout 2 https://1.1.1.1 > /dev/null 2>&1; then
    echo "[!] FATAL: Network access detected. Validation results may be non-deterministic."
    echo "[!] Run with: docker run --network=none ..."
    exit 1
fi

# ── Verify Tool Versions ─────────────────────────────────────────────────────
echo "[*] Verifying tool versions..."
FORGE_VERSION=$(forge --version 2>&1 | head -1)
SOLC_VERSION_ACTUAL=$(solc --version 2>&1 | tail -1)

echo "    forge: $FORGE_VERSION"
echo "    solc:  $SOLC_VERSION_ACTUAL"

# ── Verify Deterministic Config ───────────────────────────────────────────────
echo "[*] Deterministic config:"
echo "    ANVIL_BLOCK_TIMESTAMP=$ANVIL_BLOCK_TIMESTAMP"
echo "    ANVIL_BLOCK_NUMBER=$ANVIL_BLOCK_NUMBER"
echo "    ANVIL_GAS_LIMIT=$ANVIL_GAS_LIMIT"
echo "    ANVIL_CHAIN_ID=$ANVIL_CHAIN_ID"
echo "    PYTHONHASHSEED=$PYTHONHASHSEED"

# ── Run Command ──────────────────────────────────────────────────────────────
# Trap EXIT to clean up any background processes (e.g. Anvil) on crash
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null' EXIT INT TERM

case "${1:-validate}" in
    validate)
        echo "[*] Starting validation engine..."
        exec python3 -m validator.engine.validate "${@:2}"
        ;;
    generate)
        echo "[*] Running task generator..."
        exec python3 -m task_generator.generate "${@:2}"
        ;;
    score)
        echo "[*] Running severity scorer..."
        exec python3 -m validator.scoring.severity "${@:2}"
        ;;
    shell)
        echo "[*] Dropping to shell..."
        exec /bin/bash
        ;;
    *)
        echo "[!] Unknown command: $1"
        echo "Usage: $0 {validate|generate|score|shell} [args...]"
        exit 1
        ;;
esac
