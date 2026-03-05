#!/usr/bin/env bash
# ── VALayr Health Check Script ───────────────────────────────────────────────
# Checks system health: processes, endpoints, Docker containers.
#
# Usage:
#   ./scripts/health-check.sh           # Check all components
#   ./scripts/health-check.sh --docker  # Check Docker containers only
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }

FAILURES=0

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                 VALayr Health Check                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Check Foundry tools ────────────────────────────────────────────────
echo "Foundry:"
if command -v forge &>/dev/null; then
    pass "forge available: $(forge --version 2>/dev/null | head -1)"
else
    fail "forge not found"
fi

if command -v anvil &>/dev/null; then
    pass "anvil available: $(anvil --version 2>/dev/null | head -1)"
else
    fail "anvil not found"
fi

if command -v cast &>/dev/null; then
    pass "cast available"
else
    fail "cast not found"
fi

echo ""

# ── 2. Check Python ──────────────────────────────────────────────────────
echo "Python:"
if command -v python3 &>/dev/null; then
    pass "python3: $(python3 --version)"
else
    fail "python3 not found"
fi

python3 -c "import validator.engine.validate" 2>/dev/null && \
    pass "validator module importable" || fail "validator module import failed"

python3 -c "import miner.cli" 2>/dev/null && \
    pass "miner module importable" || fail "miner module import failed"

echo ""

# ── 3. Check local Anvil (if running) ────────────────────────────────────
echo "Anvil RPC:"
ANVIL_URL="${ANVIL_URL:-http://127.0.0.1:8545}"
if curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    "$ANVIL_URL" >/dev/null 2>&1; then
    CHAIN_ID=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
        "$ANVIL_URL" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "?")
    pass "Anvil responding at $ANVIL_URL (chainId=$CHAIN_ID)"
else
    warn "Anvil not running at $ANVIL_URL (expected if not in dev mode)"
fi

echo ""

# ── 4. Check metrics endpoint ────────────────────────────────────────────
echo "Metrics:"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9946/metrics}"
if curl -sf "$METRICS_URL" >/dev/null 2>&1; then
    pass "Metrics endpoint responding at $METRICS_URL"
else
    warn "Metrics endpoint not responding at $METRICS_URL"
fi

echo ""

# ── 5. Check Docker containers (if Docker is available) ──────────────────
echo "Docker:"
if command -v docker &>/dev/null; then
    pass "Docker available"
    for container in exploit-validator exploit-consensus exploit-miner; do
        status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
        if [ "$status" = "running" ]; then
            pass "$container: running"
        elif [ "$status" = "not found" ]; then
            warn "$container: not deployed"
        else
            fail "$container: $status"
        fi
    done
else
    warn "Docker not available"
fi

echo ""

# ── 6. Check disk space ──────────────────────────────────────────────────
echo "Disk:"
DISK_USAGE=$(df -h . | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -lt 80 ]; then
    pass "Disk usage: ${DISK_USAGE}%"
elif [ "$DISK_USAGE" -lt 90 ]; then
    warn "Disk usage: ${DISK_USAGE}% (consider cleanup)"
else
    fail "Disk usage: ${DISK_USAGE}% (critical)"
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────────
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}All health checks passed.${NC}"
    exit 0
else
    echo -e "${RED}${FAILURES} health check(s) failed.${NC}"
    exit 1
fi
