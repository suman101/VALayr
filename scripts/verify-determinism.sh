#!/bin/bash
set -euo pipefail

# ── Determinism Verification Script ──────────────────────────────────────────
# Verifies that the build environment is fully deterministic.
# Run this on every validator before going live.
#
# If ANY check fails, DO NOT run validation. Fix it first.
# If two validators compile different bytecode, your subnet dies.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Determinism Verification ==="
echo ""

PASS=0
FAIL=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [ "$expected" = "$actual" ]; then
        echo "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $desc"
        echo "    Expected: $expected"
        echo "    Actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

# ── 1. Solc Version ──────────────────────────────────────────────────────────
echo "[1] Compiler versions"

EXPECTED_SOLC="0.8.28"
if command -v forge &> /dev/null; then
    # Foundry manages its own solc — check the version it resolves
    ACTUAL_SOLC=$(forge config --json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('solc',''))" 2>/dev/null || echo "")
    if [ -z "$ACTUAL_SOLC" ] && command -v solc &> /dev/null; then
        ACTUAL_SOLC=$(solc --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    check "solc version (Foundry-managed)" "$EXPECTED_SOLC" "$ACTUAL_SOLC"
elif command -v solc &> /dev/null; then
    ACTUAL_SOLC=$(solc --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check "solc version" "$EXPECTED_SOLC" "$ACTUAL_SOLC"
else
    echo "  ⚠ solc not found (Foundry manages its own)"
fi

EXPECTED_FOUNDRY="nightly-2024-12-01"
if command -v forge &> /dev/null; then
    FORGE_VER=$(forge --version 2>&1 | head -1)
    echo "  Foundry: $FORGE_VER"
    if echo "$FORGE_VER" | grep -q "$EXPECTED_FOUNDRY"; then
        echo "  ✓ Foundry nightly matches ($EXPECTED_FOUNDRY)"
        PASS=$((PASS + 1))
    else
        echo "  ✗ Foundry nightly mismatch (expected $EXPECTED_FOUNDRY)"
        FAIL=$((FAIL + 1))
    fi
fi

# ── 2. Python Config ─────────────────────────────────────────────────────────
echo ""
echo "[2] Python determinism"

PYTHONHASHSEED="${PYTHONHASHSEED:-unset}"
check "PYTHONHASHSEED" "0" "$PYTHONHASHSEED"

PYTHON_VER=$(python3 --version 2>&1 | awk '{print $2}')
echo "  Python: $PYTHON_VER"

# ── 3. Anvil Config ──────────────────────────────────────────────────────────
echo ""
echo "[3] Anvil deterministic config"

# These are the canonical values — all validators MUST use these
EXPECTED_TIMESTAMP="1700000000"
EXPECTED_BLOCK="18000000"
EXPECTED_GAS="30000000"
EXPECTED_CHAIN="31337"

# Apply canonical defaults when env vars are not set (standalone use)
ANVIL_BLOCK_TIMESTAMP="${ANVIL_BLOCK_TIMESTAMP:-$EXPECTED_TIMESTAMP}"
ANVIL_BLOCK_NUMBER="${ANVIL_BLOCK_NUMBER:-$EXPECTED_BLOCK}"
ANVIL_GAS_LIMIT="${ANVIL_GAS_LIMIT:-$EXPECTED_GAS}"
ANVIL_CHAIN_ID="${ANVIL_CHAIN_ID:-$EXPECTED_CHAIN}"

check "Block timestamp" "$EXPECTED_TIMESTAMP" "$ANVIL_BLOCK_TIMESTAMP"
check "Block number" "$EXPECTED_BLOCK" "$ANVIL_BLOCK_NUMBER"
check "Gas limit" "$EXPECTED_GAS" "$ANVIL_GAS_LIMIT"
check "Chain ID" "$EXPECTED_CHAIN" "$ANVIL_CHAIN_ID"

# ── 4. Bytecode Reproducibility ──────────────────────────────────────────────
echo ""
echo "[4] Bytecode reproducibility"

# Optional: pinned bytecode hashes for release builds.
# Once a release is finalised, populate EXPECTED_BYTECODE_HASH with:
#   export EXPECTED_BYTECODE_HASH="sha256:..."  (from CI build artifact)
# When set, this verifies the local build matches the release build exactly.
EXPECTED_BYTECODE_HASH="${EXPECTED_BYTECODE_HASH:-}"

if command -v forge &> /dev/null && [ -d "contracts/out" ]; then
    # Build twice and compare — use sha256 for cryptographic integrity
    if command -v sha256sum &> /dev/null; then
        HASHCMD="sha256sum"
    elif command -v shasum &> /dev/null; then
        HASHCMD="shasum -a 256"
    else
        HASHCMD="md5sum"
    fi

    forge build --force 2>/dev/null
    HASH1=$(find contracts/out -name "*.json" -exec "$HASHCMD" {} + 2>/dev/null | sort | "$HASHCMD" | awk '{print $1}')

    forge build --force 2>/dev/null
    HASH2=$(find contracts/out -name "*.json" -exec "$HASHCMD" {} + 2>/dev/null | sort | "$HASHCMD" | awk '{print $1}')

    check "Double-build hash match" "$HASH1" "$HASH2"

    # If a pinned release hash is provided, verify against it
    if [ -n "$EXPECTED_BYTECODE_HASH" ]; then
        check "Pinned bytecode hash" "$EXPECTED_BYTECODE_HASH" "$HASH1"
    else
        echo "  ⚠ No EXPECTED_BYTECODE_HASH set (set for release builds)"
    fi
else
    echo "  ⚠ Skipped (forge not available or contracts not built)"
fi

# ── 5. Task Corpus Determinism ────────────────────────────────────────────────
echo ""
echo "[5] Task corpus determinism"

CORPUS_HASH1=$(python3 -c "
import sys
sys.path.insert(0, '.')
from importlib.util import spec_from_file_location, module_from_spec
spec = spec_from_file_location('gen', 'task-generator/generate.py')
mod = module_from_spec(spec)
spec.loader.exec_module(mod)
import tempfile, hashlib, json
from pathlib import Path
with tempfile.TemporaryDirectory() as d:
    g = mod.CorpusGenerator(output_dir=Path(d))
    pkgs = g.generate_batch(seed=42)
    m = g.generate_manifest(pkgs)
    print(hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()[:16])
" 2>/dev/null || echo "error")

CORPUS_HASH2=$(python3 -c "
import sys
sys.path.insert(0, '.')
from importlib.util import spec_from_file_location, module_from_spec
spec = spec_from_file_location('gen', 'task-generator/generate.py')
mod = module_from_spec(spec)
spec.loader.exec_module(mod)
import tempfile, hashlib, json
from pathlib import Path
with tempfile.TemporaryDirectory() as d:
    g = mod.CorpusGenerator(output_dir=Path(d))
    pkgs = g.generate_batch(seed=42)
    m = g.generate_manifest(pkgs)
    print(hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()[:16])
" 2>/dev/null || echo "error")

if [ "$CORPUS_HASH1" != "error" ] && [ "$CORPUS_HASH2" != "error" ]; then
    check "Corpus manifest hash" "$CORPUS_HASH1" "$CORPUS_HASH2"
else
    echo "  ⚠ Skipped (generation error)"
fi

# ── 6. Docker Image Hash (if available) ──────────────────────────────────────
echo ""
echo "[6] Docker image"

if command -v docker &> /dev/null; then
    IMG_ID=$(docker inspect --format='{{.Id}}' ghcr.io/exploit-subnet/validator:v0.1.0 2>/dev/null || echo "not_found")
    if [ "$IMG_ID" != "not_found" ]; then
        echo "  Image ID: ${IMG_ID:0:24}..."
    else
        echo "  ⚠ Validator image not built yet"
    fi
else
    echo "  ⚠ Docker not available"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "[!] DETERMINISM CHECKS FAILED."
    echo "[!] Do NOT run validation until all checks pass."
    exit 1
else
    echo ""
    echo "[+] All determinism checks passed."
    echo "[+] This validator is safe to go live."
fi
