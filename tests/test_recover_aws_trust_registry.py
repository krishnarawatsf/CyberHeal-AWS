from datetime import UTC, datetime, timedelta

import pytest

from cyberheal_recover.aws_trust_registry import (
    SnapshotAttestation,
    candidate_from_aws,
    sign_attestation,
    verify_attestation,
)

KEY = b"student-test-secret-is-never-a-real-secret-1234567890"
T = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def sample():
    record = SnapshotAttestation(
        snapshot_id="snap-aabbccdd",
        volume_id="vol-112233aa",
        account_id="123456789012",
        region="ap-south-1",
        lab_tag="cyberheal-student-lab",
        created_at=T,
        validated_at=T + timedelta(hours=1),
        baseline_sha256={"test.txt": "0" * 64},
        reviewer="lab-operator",
        validation_ref="baseline-demo-001",
    )
    aws = {
        "SnapshotId": record.snapshot_id,
        "VolumeId": record.volume_id,
        "OwnerId": record.account_id,
        "State": "completed",
        "StartTime": T,
        "Tags": [{"Key": "CyberHealLab", "Value": record.lab_tag}],
    }
    return record, aws


def join(record, aws, signature):
    return candidate_from_aws(
        record,
        signature=signature,
        secret=KEY,
        aws_snapshot=aws,
        account_id="123456789012",
        region="ap-south-1",
        lab_tag="cyberheal-student-lab",
    )


def test_verified_record_produces_candidate():
    record, aws = sample()
    candidate = join(record, aws, sign_attestation(record, secret=KEY))
    assert candidate.verified_clean and candidate.state == "completed"
    assert candidate.validation_ref == "baseline-demo-001"


def test_tampered_baseline_fails():
    record, aws = sample()
    signature = sign_attestation(record, secret=KEY)
    tampered = record.model_copy(update={"reviewer": "attacker"})
    with pytest.raises(PermissionError, match="attestation"):
        join(tampered, aws, signature)


def test_short_key_fails():
    record, _ = sample()
    with pytest.raises(ValueError, match="at least 32"):
        sign_attestation(record, secret=b"short")


def test_wrong_owner_fails():
    record, aws = sample()
    aws["OwnerId"] = "999999999999"
    with pytest.raises(PermissionError):
        join(record, aws, sign_attestation(record, secret=KEY))


def test_wrong_snapshot_timestamp_fails():
    record, aws = sample()
    aws["StartTime"] = T + timedelta(hours=1)
    with pytest.raises(PermissionError, match="timestamp"):
        join(record, aws, sign_attestation(record, secret=KEY))


def test_not_completed_fails():
    record, aws = sample()
    aws["State"] = "pending"
    with pytest.raises(PermissionError):
        join(record, aws, sign_attestation(record, secret=KEY))


def test_wrong_lab_tag_fails():
    record, aws = sample()
    aws["Tags"] = []
    with pytest.raises(PermissionError):
        join(record, aws, sign_attestation(record, secret=KEY))


def test_invalid_baseline_sha_rejected():
    record, _ = sample()
    with pytest.raises(ValueError, match="SHA256"):
        SnapshotAttestation.model_validate(
            {**record.model_dump(), "baseline_sha256": {"x": "not-sha"}}
        )


def test_signature_matches_only_correct_key():
    record, _ = sample()
    signature = sign_attestation(record, secret=KEY)
    assert verify_attestation(record, signature=signature, secret=KEY)
    assert not verify_attestation(
        record, signature=signature, secret=b"different-student-test-secret-123456789"
    )
