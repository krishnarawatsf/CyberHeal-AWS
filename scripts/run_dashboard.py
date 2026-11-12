#!/usr/bin/env python3
"""Launcher for the CyberHeal AI interactive pipeline dashboard."""

import argparse
import os
import sys
from pathlib import Path

# Ensure src/ is on Python module search path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from cyberheal_dashboard.app import create_dashboard_app, get_default_opa_exe  # noqa: E402
import uvicorn  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Run CyberHeal AI Pipeline Dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind dashboard (default: 8080)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--opa", default=None, help="Path to OPA executable (auto-discovered if not passed)")
    args = parser.parse_args()

    opa_exe = args.opa or get_default_opa_exe()
    os.environ["CYBERHEAL_OPA_EXE"] = opa_exe

    db_path = REPO_ROOT / "work" / "cyberheal-dashboard.sqlite3"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    print("==================================================================", flush=True)
    print("      CYBERHEAL AI — AUTONOMOUS PIPELINE DASHBOARD (AWS v0.4)     ", flush=True)
    print("==================================================================", flush=True)
    print(f" * OPA Engine:     {opa_exe}", flush=True)
    print(f" * SQLite Store:   {db_path}", flush=True)
    print(f" * Local URL:      http://{args.host}:{args.port}/", flush=True)
    print("==================================================================", flush=True)
    print("Press Ctrl+C to terminate the dashboard server.\n", flush=True)

    app = create_dashboard_app(opa_exe=opa_exe, db_path=db_path)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
