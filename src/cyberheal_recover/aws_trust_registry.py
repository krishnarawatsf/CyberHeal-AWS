"""HMAC-protected recovery-point *attestation*, not a malware classifier.

An authorized operator must first validate the sample files and the snapshot
was captured before the incident, then sign the record using a key held outside
Git and WhatsApp. A signature does not itself prove the snapshot is clean.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .snapshots import TrustedSnapshotCandidate


class SnapshotAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: str = Field(pattern=r"^snap-[a-f0-9]+$")
    volume_id: str = Field(pattern=r"^vol-[a-f0-9]+$")
    account_id: str = Field(pattern=r"^\d{12}$")
    region: str = Field(min_length=1)
    lab_tag: str = Field(min_length=1)
    created_at: datetime
    validated_at: datetime
    baseline_sha256: dict[str, str] = Field(min_length=1)
    reviewer: str = Field(min_length=1)
    validation_ref: str = Field(min_length=1)

    @field_validator("created_at", "validated_at")
    @classmethod
    def timestamp_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include time zone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validated_after_snapshot(self) -> "SnapshotAttestation":
        if self.validated_at < self.created_at:
            raise ValueError("snapshot cannot be validated before it exists")
        return self

    @field_validator("baseline_sha256")
    @classmethod
    def verify_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        for name, digest in value.items():
            if (
                not name
                or name.startswith("/")
                or ".." in name.split("/")
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest.lower())
            ):
                raise ValueError("invalid baseline SHA256 manifest")
        return {name: digest.lower() for name, digest in value.items()}


def _serialize(record: SnapshotAttestation) -> bytes:
    return json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _validate_key(secret: bytes) -> None:
    if len(secret) < 32:
        raise ValueError("attestation HMAC key must be at least 32 bytes")


def sign_attestation(record: SnapshotAttestation, *, secret: bytes) -> str:
    """Sign verified operator evidence; never place secret in the repository."""
    _validate_key(secret)
    return hmac.new(secret, _serialize(record), hashlib.sha256).hexdigest()


def verify_attestation(
    record: SnapshotAttestation, *, signature: str, secret: bytes
) -> bool:
    _validate_key(secret)
    if len(signature) != 64:
        return False
    return hmac.compare_digest(sign_attestation(record, secret=secret), signature)


def candidate_from_aws(
    record: SnapshotAttestation,
    *,
    signature: str,
    secret: bytes,
    aws_snapshot: dict[str, Any],
    account_id: str,
    region: str,
    lab_tag: str,
) -> TrustedSnapshotCandidate:
    """Join operator-signed evidence with live AWS DescribeSnapshots output.

    Only trusted local records plus a live AWS response can mark a snapshot
    eligible for selection. The incident-first-suspicious timestamp is checked
    separately by the snapshot selector.
    """
    if not verify_attestation(record, signature=signature, secret=secret):
        raise PermissionError("untrusted or altered validation attestation")
    if (
        account_id != record.account_id
        or region != record.region
        or lab_tag != record.lab_tag
        or aws_snapshot.get("SnapshotId") != record.snapshot_id
        or aws_snapshot.get("VolumeId") != record.volume_id
        or aws_snapshot.get("OwnerId") != account_id
        or aws_snapshot.get("State") != "completed"
        or not any(
            t.get("Key") == "CyberHealLab" and t.get("Value") == lab_tag
            for t in aws_snapshot.get("Tags", [])
        )
    ):
        raise PermissionError("AWS snapshot mismatches verified lab attestation")
    started = aws_snapshot.get("StartTime")
    if not isinstance(started, datetime) or started.tzinfo is None:
        raise ValueError("AWS snapshot creation timestamp unavailable")
    if abs((started.astimezone(UTC) - record.created_at).total_seconds()) > 2:
        raise PermissionError("snapshot timestamp does not match attestation")
    return TrustedSnapshotCandidate(
        snapshot_id=record.snapshot_id,
        volume_id=record.volume_id,
        account_id=record.account_id,
        created_at=record.created_at,
        state="completed",
        verified_clean=True,
        validation_ref=record.validation_ref,
    )
