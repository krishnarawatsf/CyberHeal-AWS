"""Command-line entry point for safe demonstration scenarios."""

import argparse
import json
from pathlib import Path

from .simulators import simulate_credential_anomaly, simulate_file_activity


def main() -> None:
    """Run a selected safe simulator and emit sanitised JSON telemetry."""
    parser = argparse.ArgumentParser(description="CyberHeal safe detection simulators")
    parser.add_argument("scenario", choices=("file", "credential"))
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if args.scenario == "file":
        if args.root is None:
            parser.error("--root is required for the file scenario")
        events = simulate_file_activity(args.root)
    else:
        events = simulate_credential_anomaly()
    print(json.dumps(events, indent=2))
