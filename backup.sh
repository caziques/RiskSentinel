#!/usr/bin/env bash
# backup.sh — backs up the RiskSentinel database and uploads volumes
# Usage: ./backup.sh [backup-dir]
# Default backup dir: ./backups

set -euo pipefail

CONTAINER="risk-sentinel"
BACKUP_DIR="${1:-$(dirname "$0")/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/risksentinel_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "==> RiskSentinel backup — $(date)"
echo "    Container : $CONTAINER"
echo "    Output    : $BACKUP_FILE"

# Verify container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "ERROR: Container '$CONTAINER' is not running." >&2
  exit 1
fi

# SQLite hot backup inside the container — safe while the app is live
echo "==> Creating SQLite hot backup..."
docker exec "$CONTAINER" sqlite3 /app/instance/vuln_portal.db ".backup /tmp/vuln_portal.db.bak"

# Pull both the hot-backup DB and the uploads directory into a single tarball
echo "==> Packaging backup..."
docker exec "$CONTAINER" tar -czf /tmp/risksentinel_backup.tar.gz \
  -C /tmp vuln_portal.db.bak \
  -C /app uploads

docker cp "$CONTAINER:/tmp/risksentinel_backup.tar.gz" "$BACKUP_FILE"

# Cleanup temp files in container
docker exec "$CONTAINER" rm -f /tmp/vuln_portal.db.bak /tmp/risksentinel_backup.tar.gz

SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)
echo "==> Done — $BACKUP_FILE ($SIZE)"

# Keep only the 10 most recent backups
KEPT=$(ls -t "$BACKUP_DIR"/risksentinel_*.tar.gz 2>/dev/null | tail -n +11)
if [ -n "$KEPT" ]; then
  echo "==> Pruning old backups..."
  echo "$KEPT" | xargs rm -f
  echo "    Removed $(echo "$KEPT" | wc -l | tr -d ' ') old backup(s)"
fi

echo "==> Backup complete."
