#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "==> Setting up RiskSentinel..."

python3 -m venv .venv
source .venv/bin/activate

pip install -q -r requirements.txt

echo "==> Starting RiskSentinel on http://localhost:5001"
echo "    Default login: admin / admin123"
echo "    Change password after first login!"
echo ""

python app.py
