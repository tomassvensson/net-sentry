#!/usr/bin/env bash
# Pre-push hook: runs a quick subset of tests before pushing.
# Install with: cp scripts/pre-push.sh .git/hooks/pre-push && chmod +x .git/hooks/pre-push

set -euo pipefail

echo "Running pre-push checks..."

# Activate virtual environment if present
if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
elif [ -f ".venv/Scripts/activate" ]; then
    # Windows Git Bash
    # shellcheck disable=SC1091
    source .venv/Scripts/activate
fi

echo "Running quick tests..."
pytest tests/ --timeout=60 -x -q

echo "Pre-push checks passed."
