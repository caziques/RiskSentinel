#!/usr/bin/env bash
# restore.sh — restores RiskSentinel database and uploads from a backup
# Usage: ./restore.sh <backup-file.tar.gz>

set -euo pipefail

CONTAINER="risk-sentinel"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <backup-file.tar.gz>"
  echo ""
  echo "Available backups:"
  ls -lht "$(dirname "$0")/backups"/risksentinel_*.tar.gz 2>/dev/null || echo "  (none found)"
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: Backup file not found: $BACKUP_FILE" >&2
  exit 1
fi

echo "==> RiskSentinel restore — $(date)"
echo "    Backup    : $BACKUP_FILE"
echo "    Container : $CONTAINER"
echo ""
echo "WARNING: This will overwrite the current database and uploads."
read -r -p "Type 'yes' to continue: " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted."
  exit 0
fi

# Stop the container so nothing is writing to the DB during restore
echo "==> Stopping container..."
docker compose -f "$COMPOSE_FILE" stop risk-sentinel 2>/dev/null || \
  docker stop "$CONTAINER" 2>/dev/null || true

# Start a temporary helper container with the volumes mounted to do the restore
echo "==> Restoring files..."
docker run --rm \
  -v risksentinel_vuln_data:/app/instance \
  -v risksentinel_vuln_uploads:/app/uploads \
  -v "$(realpath "$BACKUP_FILE"):/backup.tar.gz:ro" \
  python:3.12-slim \
  sh -c '
    set -e
    cd /tmp
    tar -xzf /backup.tar.gz

    # Restore database.
    # The WAL and shared-memory sidecars must go first: leaving a stale -wal
    # beside a restored .db lets SQLite replay old transactions over it.
    rm -f /app/instance/vuln_portal.db-wal /app/instance/vuln_portal.db-shm
    cp vuln_portal.db.bak /app/instance/vuln_portal.db
    echo "  Restored: vuln_portal.db (stale WAL sidecars cleared)"

    # Restore uploads (tar extracted uploads/ dir)
    if [ -d uploads ]; then
      rm -rf /app/uploads/*
      cp -r uploads/. /app/uploads/
      echo "  Restored: uploads/"
    fi
  '

# Restart the container
echo "==> Restarting container..."
docker compose -f "$COMPOSE_FILE" start risk-sentinel 2>/dev/null || \
  docker start "$CONTAINER" 2>/dev/null || true

echo "==> Restore complete. Container is back online."
