#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -x ".venv/bin/python" ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -r requirements.txt -r requirements-member-b.txt -r requirements-member-c.txt

export PYTHONPATH="$PWD/src"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

if [[ -z "${CYBERHEAL_OPA_EXE:-}" ]]; then
  if command -v opa >/dev/null 2>&1; then
    CYBERHEAL_OPA_EXE="$(command -v opa)"
    export CYBERHEAL_OPA_EXE
  else
    echo "OPA is required for the B policy-backed tests."
    echo "Install the official OPA binary and rerun with CYBERHEAL_OPA_EXE set."
    exit 2
  fi
fi

if [[ ! -x "$CYBERHEAL_OPA_EXE" ]]; then
  echo "CYBERHEAL_OPA_EXE is not an executable: $CYBERHEAL_OPA_EXE"
  exit 2
fi

python_bin=".venv/bin/python"
"$python_bin" -m compileall -q src
"$python_bin" -m pytest -q tests
"$CYBERHEAL_OPA_EXE" test respond/policies -v
"$python_bin" -m cyberheal_recover.demo

echo "Offline validation passed. No AWS calls or live recovery occurred."
