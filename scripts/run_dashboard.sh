#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Virtual environment not found. Setting up..."
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt -r requirements-member-b.txt -r requirements-member-c.txt
fi

if [[ -z "${CYBERHEAL_OPA_EXE:-}" ]]; then
  if command -v opa >/dev/null 2>&1; then
    CYBERHEAL_OPA_EXE="$(command -v opa)"
    export CYBERHEAL_OPA_EXE
  fi
fi

export PYTHONPATH="$PWD/src"
exec .venv/bin/python scripts/run_dashboard.py "$@"

