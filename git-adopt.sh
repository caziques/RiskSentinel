#!/usr/bin/env bash
#
# Convert an existing RiskSentinel installation into a git clone, so it can
# self-update from then on.
#
# Safe to run on a live install. Your database, uploads and credential files are
# excluded from version control, so git never touches them: this only replaces
# application code. A backup is taken first regardless.
#
#   ./git-adopt.sh [repository-url]
#
set -euo pipefail

REPO="${1:-https://github.com/caziques/RiskSentinel.git}"
BRANCH="${BRANCH:-main}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "==> RiskSentinel git adoption"
echo "    directory : $DIR"
echo "    repository: $REPO"
echo "    branch    : $BRANCH"
echo

if [ -d .git ]; then
  echo "==> Already a git repository."
  echo "    remote: $(git remote get-url origin 2>/dev/null || echo 'none')"
  echo "    Use Admin > Software Update, or: git pull"
  exit 0
fi

command -v git >/dev/null 2>&1 || { echo "ERROR: git is not installed."; exit 1; }

# ── 1. Back up the things git will not protect ──────────────────────────────
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP="$DIR/backups/pre-git-adopt-$STAMP.tar.gz"
mkdir -p "$DIR/backups"
echo "==> Backing up data and credentials"
TO_SAVE=()
for p in instance uploads .env .env.levelblue .env.rapid7; do
  [ -e "$p" ] && TO_SAVE+=("$p")
done
for p in .env.levelblue.* .env.cortex.*; do
  [ -e "$p" ] && TO_SAVE+=("$p")
done
if [ ${#TO_SAVE[@]} -gt 0 ]; then
  tar czf "$BACKUP" "${TO_SAVE[@]}" 2>/dev/null
  echo "    saved: $BACKUP ($(du -h "$BACKUP" | cut -f1))"
else
  echo "    nothing to back up"
fi

# ── 2. Adopt the repository without disturbing local data ───────────────────
echo "==> Fetching $REPO"
git init -q
git remote add origin "$REPO"
git fetch -q --depth=50 origin "$BRANCH"

echo "==> Checking what would be overwritten"
# Files the repo tracks that also exist here and differ. These are the update.
git checkout -f -b "$BRANCH" "origin/$BRANCH" 2>&1 | sed 's/^/    /' || {
  echo "ERROR: checkout failed. Nothing was changed by git; your backup is at:"
  echo "       $BACKUP"
  exit 1
}
git branch --set-upstream-to="origin/$BRANCH" "$BRANCH" >/dev/null 2>&1 || true

# ── 3. Verify the data survived ─────────────────────────────────────────────
echo "==> Verifying"
FAIL=0
for p in instance uploads; do
  if [ -d "$p" ]; then
    echo "    $p/ present ($(du -sh "$p" | cut -f1))"
  else
    echo "    WARNING: $p/ is missing"; FAIL=1
  fi
done
for p in .env .env.levelblue .env.cortex.mcr; do
  [ -e "$p" ] && echo "    $p present"
done
DB=$(ls instance/*.db 2>/dev/null | head -1 || true)
[ -n "$DB" ] && echo "    database: $DB ($(du -h "$DB" | cut -f1))"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "==> Done. Now at $(git rev-parse --short HEAD) on $BRANCH."
  echo "    Restart the application, then use Admin > Software Update from here on."
else
  echo "==> Completed with warnings. Restore from $BACKUP if anything is missing."
fi
