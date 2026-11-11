#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-member-c.txt
export PYTHONPATH="$PWD/src"
python -m pytest -q tests/test_recover_*.py
python -m cyberheal_recover.demo
echo 'Offline AWS C demo passed; this did not contact AWS.'
