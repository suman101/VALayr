#!/usr/bin/env bash
# ── VALayr Backup Script ─────────────────────────────────────────────────────
# Creates a timestamped backup of state data and deployment records.
#
# Usage:
#   ./scripts/backup.sh                    # Backup to default location
#   ./scripts/backup.sh /path/to/backup    # Backup to custom location
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${1:-$PROJECT_ROOT/backups}"
BACKUP_NAME="valayr_backup_${TIMESTAMP}"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  VALayr Backup Utility                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

mkdir -p "$BACKUP_PATH"

# Backup data directory
if [ -d "$PROJECT_ROOT/data" ]; then
    echo "  Backing up data/ ..."
    cp -r "$PROJECT_ROOT/data" "$BACKUP_PATH/data"
fi

# Backup deployment records
if [ -d "$PROJECT_ROOT/deployments" ]; then
    echo "  Backing up deployments/ ..."
    cp -r "$PROJECT_ROOT/deployments" "$BACKUP_PATH/deployments"
fi

# Backup Docker volumes (if Docker is available)
if command -v docker &>/dev/null; then
    echo "  Exporting Docker volumes ..."
    for vol in validator-data miner-data task-corpus; do
        full_vol="valayr_${vol}"
        if docker volume inspect "$full_vol" &>/dev/null 2>&1; then
            docker run --rm -v "${full_vol}:/source:ro" -v "$BACKUP_PATH:/backup" \
                alpine tar czf "/backup/${vol}.tar.gz" -C /source . 2>/dev/null || true
        fi
    done
fi

# Record backup metadata
cat > "$BACKUP_PATH/metadata.json" <<EOF
{
    "timestamp": "$TIMESTAMP",
    "git_sha": "$(cd "$PROJECT_ROOT" && git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(cd "$PROJECT_ROOT" && git branch --show-current 2>/dev/null || echo 'unknown')",
    "hostname": "$(hostname)"
}
EOF

# Create compressed archive
echo "  Creating archive ..."
cd "$BACKUP_DIR"
tar czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

# I-5 fix: verify archive integrity after creation
echo "  Verifying archive integrity ..."
if tar tzf "${BACKUP_NAME}.tar.gz" >/dev/null 2>&1; then
    echo "  ✓ Archive integrity verified"
else
    echo "  ✗ Archive verification failed — backup may be corrupt!"
    exit 1
fi

# Record SHA-256 checksum for later verification
sha256sum "${BACKUP_NAME}.tar.gz" > "${BACKUP_NAME}.tar.gz.sha256"
echo "  ✓ Checksum: $BACKUP_DIR/${BACKUP_NAME}.tar.gz.sha256"

echo ""
echo "  ✓ Backup complete: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"
echo "  Size: $(du -h "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" | cut -f1)"
