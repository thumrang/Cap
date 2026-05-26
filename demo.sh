#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PYTHON=python
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=python3
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python interpreter not found. Install python or python3." >&2
  exit 1
fi

echo "Running Azure RBAC diff demo..."
"$PYTHON" rbac_diff.py examples/role-definition-old.json examples/role-definition-new.json

echo "\nRole assignment diff:"
"$PYTHON" rbac_diff.py examples/role-assignment-old.json examples/role-assignment-new.json
