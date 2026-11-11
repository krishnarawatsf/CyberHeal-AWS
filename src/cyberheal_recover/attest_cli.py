"""Manual signing/checking of operator-verified EBS snapshot attestations.

This tool NEVER creates a snapshot or checks whether a workload is malware-free.
Do not issue a signature unless the operator independently validated the data.
"""

import argparse
import json
import os
from pathlib import Path

from .aws_trust_registry import (
    SnapshotAttestation,
    sign_attestation,
    verify_attestation,
)


def get_key() -> bytes:
    raw = os.environ.get("CYBERHEAL_ATTESTATION_KEY_HEX", "")
    if len(raw) != 64:
        raise RuntimeError("CYBERHEAL_ATTESTATION_KEY_HEX must contain 64 hex digits")
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError("invalid attestation key format") from exc


def main() -> None:
    p = argparse.ArgumentParser(description="Sign manually verified recovery points")
    p.add_argument("command", choices=("issue", "check"))
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path)
    p.add_argument("--operator-validated", action="store_true")
    args = p.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    secret = get_key()
    if args.command == "issue":
        if not args.operator_validated or args.output is None:
            p.error("issue requires --operator-validated and --output")
        record = SnapshotAttestation.model_validate(data)
        package = {
            "record": record.model_dump(mode="json"),
            "signature": sign_attestation(record, secret=secret),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            p.error("refusing to overwrite an existing attestation")
        args.output.write_text(json.dumps(package, indent=2), encoding="utf-8")
        print(
            "Signed operator attestation saved. This is NOT independent proof of cleanliness."
        )
    else:
        record = SnapshotAttestation.model_validate(data["record"])
        if not verify_attestation(record, signature=data["signature"], secret=secret):
            raise PermissionError("attestation failed integrity verification")
        print(
            "Attestation signature valid. Compare against live AWS DescribeSnapshots before recovery."
        )


if __name__ == "__main__":
    main()
