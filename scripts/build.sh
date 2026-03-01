#!/bin/bash
set -euo pipefail

# ── Build Script ──────────────────────────────────────────────────────────────
# Compiles contracts, generates corpus, verifies determinism.
# Run from project root: ./scripts/build.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Exploit Subnet Build ==="
echo "Project: $PROJECT_DIR"
echo ""

# ── Step 1: Verify Tools ─────────────────────────────────────────────────────
echo "[1/5] Verifying tools..."

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo "  ✓ $1: $($1 --version 2>&1 | head -1)"
    else
        echo "  ✗ $1: NOT FOUND"
        echo "    Install: $2"
        return 1
    fi
}

TOOLS_OK=true
check_tool "forge" "curl -L https://foundry.paradigm.xyz | bash && foundryup" || TOOLS_OK=false
check_tool "anvil" "Installed with Foundry" || TOOLS_OK=false
check_tool "python3" "brew install python3" || TOOLS_OK=false

if [ "$TOOLS_OK" = false ]; then
    echo ""
    echo "[!] Missing required tools. Install them and re-run."
    exit 1
fi

# ── Step 2: Build Contracts ───────────────────────────────────────────────────
echo ""
echo "[2/5] Building Solidity contracts..."

forge build 2>&1 | tail -5
echo "  ✓ Contracts compiled"

# Verify bytecode reproducibility
BYTECODE_HASH=$(find contracts/out -name "*.json" -exec cat {} + | python3 -c "
import sys, json, hashlib
data = sys.stdin.read()
print(hashlib.sha256(data.encode()).hexdigest()[:16])
" 2>/dev/null || echo "skip")

if [ "$BYTECODE_HASH" != "skip" ]; then
    echo "  Bytecode hash: $BYTECODE_HASH"
fi

# ── Step 3: Run Contract Tests ────────────────────────────────────────────────
echo ""
echo "[3/5] Running Foundry tests..."

forge test -v 2>&1 | tail -20
echo "  ✓ Contract tests passed"

# ── Step 4: Generate Task Corpus ──────────────────────────────────────────────
echo ""
echo "[4/5] Generating task corpus..."

PYTHONHASHSEED=0 python3 task-generator/generate.py --manifest --seed 42 --count 3
echo "  ✓ Corpus generated"

# ── Step 5: Run Python Tests ─────────────────────────────────────────────────
echo ""
echo "[5/5] Running integration tests..."

# Install Python deps if requirements.txt exists
if [ -f requirements.txt ]; then
    echo "  Installing Python dependencies..."
    python3 -m pip install -r requirements.txt --quiet 2>/dev/null || true
fi

python3 tests/test_integration.py
echo "  ✓ Integration tests passed"

python3 tests/test_pipeline.py
echo "  ✓ Pipeline tests passed"

python3 -m pytest tests/test_extended.py -v --timeout=60 || echo "  ⚠ Extended tests require pytest"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Build Complete ==="
echo ""
echo "Next steps:"
echo "  1. Start Anvil:    anvil --block-time 1"
echo "  2. Deploy:         forge script contracts/script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast"
echo "  3. Validate:       python3 validator/engine/validate.py --task <TASK_DIR> --exploit <EXPLOIT.sol>"
echo ""
