#!/usr/bin/env bash
# ── VALayr Restore Script ────────────────────────────────────────────────────
# Restores state from a backup archive created by backup.sh.
#
# Usage:
#   ./scripts/restore.sh /path/to/valayr_backup_YYYYMMDD_HHMMSS.tar.gz
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_archive.tar.gz>"
    exit 1
fi

BACKUP_ARCHIVE="$1"

if [ ! -f "$BACKUP_ARCHIVE" ]; then
    echo "ERROR: Backup archive not found: $BACKUP_ARCHIVE"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                 VALayr Restore Utility                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Archive: $BACKUP_ARCHIVE"
echo ""

# Extract to temp directory
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "  Extracting archive ..."
tar xzf "$BACKUP_ARCHIVE" -C "$TEMP_DIR"

# Find the backup directory inside tar
BACKUP_DIR="$(find "$TEMP_DIR" -maxdepth 1 -type d -name 'valayr_backup_*' | head -1)"
if [ -z "$BACKUP_DIR" ]; then
    echo "ERROR: Invalid backup archive — no valayr_backup_* directory found"
    exit 1
fi

# Show metadata
if [ -f "$BACKUP_DIR/metadata.json" ]; then
    echo "  Backup metadata:"
    cat "$BACKUP_DIR/metadata.json"
    echo ""
fi

# Confirm before overwriting
echo "  WARNING: This will overwrite current data/ and deployments/ directories."
read -r -p "  Continue? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "  Aborted."
    exit 0
fi

# Restore data directory
if [ -d "$BACKUP_DIR/data" ]; then
    echo "  Restoring data/ ..."
    rm -rf "$PROJECT_ROOT/data"
    cp -r "$BACKUP_DIR/data" "$PROJECT_ROOT/data"
fi

# Restore deployment records
if [ -d "$BACKUP_DIR/deployments" ]; then
    echo "  Restoring deployments/ ..."
    rm -rf "$PROJECT_ROOT/deployments"
    cp -r "$BACKUP_DIR/deployments" "$PROJECT_ROOT/deployments"
fi

# Restore Docker volumes (if archives exist)
if command -v docker &>/dev/null; then
    for vol_archive in "$BACKUP_DIR"/*.tar.gz; do
        [ -f "$vol_archive" ] || continue
        vol_name="$(basename "$vol_archive" .tar.gz)"
        # SEC-2.2: validate volume name to prevent injection via crafted archive names.
        if [[ ! "$vol_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "  WARNING: Skipping archive with unsafe name: $vol_name"
            continue
        fi
        full_vol="valayr_${vol_name}"
        echo "  Restoring Docker volume: $full_vol ..."
        docker volume create "$full_vol" 2>/dev/null || true
        docker run --rm -v "${full_vol}:/target" -v "$vol_archive:/backup.tar.gz:ro" \
            alpine sh -c "rm -rf /target/* && tar xzf /backup.tar.gz -C /target" 2>/dev/null || true
    done
fi

echo ""
echo "  ✓ Restore complete."
