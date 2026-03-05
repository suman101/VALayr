#!/usr/bin/env bash
# ── VALayr Rollback Script ───────────────────────────────────────────────────
# Rolls back to a previous deployment state using deployment records.
#
# Usage:
#   ./scripts/rollback.sh                          # Show available deployments
#   ./scripts/rollback.sh <deployment_file.json>    # Rollback to specific deploy
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deployments"

if [ ! -d "$DEPLOY_DIR" ]; then
    echo "ERROR: No deployments directory found at $DEPLOY_DIR"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                VALayr Rollback Utility                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# No arguments = list available deployments
if [ $# -lt 1 ]; then
    echo "  Available deployment records:"
    echo ""
    for f in "$DEPLOY_DIR"/deploy_*.json; do
        [ -f "$f" ] || continue
        timestamp="$(basename "$f" .json | sed 's/deploy_local_//')"
        echo "    $(basename "$f")  ($timestamp)"
    done
    echo ""
    echo "  Usage: $0 <deployment_file.json>"
    exit 0
fi

DEPLOY_FILE="$1"

# Accept bare filename or full path
if [ ! -f "$DEPLOY_FILE" ]; then
    DEPLOY_FILE="$DEPLOY_DIR/$DEPLOY_FILE"
fi

if [ ! -f "$DEPLOY_FILE" ]; then
    echo "ERROR: Deployment file not found: $1"
    exit 1
fi

echo "  Deployment file: $(basename "$DEPLOY_FILE")"
echo ""

# Extract addresses from deployment record
echo "  Contract addresses in deployment:"
if command -v jq &>/dev/null; then
    jq -r 'to_entries[] | "    \(.key): \(.value)"' "$DEPLOY_FILE" 2>/dev/null || \
        cat "$DEPLOY_FILE"
else
    cat "$DEPLOY_FILE"
fi

echo ""
echo "  To complete rollback:"
echo "    1. Stop current services: docker compose -f docker/docker-compose.yml down"
echo "    2. Restore backup:        ./scripts/restore.sh <backup_archive>"
echo "    3. Update .env with contract addresses from the deployment file above"
echo "    4. Restart services:      docker compose -f docker/docker-compose.yml up -d"
echo ""
echo "  NOTE: On-chain contract state cannot be rolled back."
echo "  This script restores off-chain state only."
