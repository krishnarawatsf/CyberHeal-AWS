"""Linux-only, read-only integrity check for an EBS clone on the verifier VM.

Never mounts a volume, changes files, or declares the overall workload SAFE.
The operator must independently verify that the mounted device serial matches
an authorized recovery EBS ID before running this command.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from .attest_cli import get_key
from .aws_trust_registry import SnapshotAttestation, verify_attestation
from .scan import collect_tree_sha256


def compare_signed_baseline(root: Path, attestation_path: Path) -> dict:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("isolated read-only verifier must run on Linux")
    root = Path(root).resolve(strict=True)
    # The verifier's dedicated EBS mount must be read-only even for root.
    if not (os.statvfs(root).f_flag & os.ST_RDONLY):
        raise PermissionError("sample-data verifier root is not on a read-only mount")
    package = json.loads(attestation_path.read_text(encoding="utf-8"))
    record = SnapshotAttestation.model_validate(package["record"])
    if not verify_attestation(
        record, signature=package["signature"], secret=get_key()
    ):
        raise PermissionError("snapshot baseline attestation has invalid signature")
    observed = collect_tree_sha256(root)
    expected = record.baseline_sha256
    matches = observed == expected
    return {
        "file_integrity_passed": matches,
        "expected_files": len(expected),
        "observed_files": len(observed),
        "missing_or_modified_files": sorted(
            key for key in expected if observed.get(key) != expected[key]
        ),
        "unexpected_files": sorted(key for key in observed if key not in expected),
        "snapshot_id": record.snapshot_id,
        "NOTE": "FILE FACTOR ONLY; not full five-factor verification or SAFE",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only EBS clone file verifier")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--attestation", required=True, type=Path)
    args = parser.parse_args()
    result = compare_signed_baseline(args.root, args.attestation)
    print(json.dumps(result, indent=2))
    if not result["file_integrity_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
