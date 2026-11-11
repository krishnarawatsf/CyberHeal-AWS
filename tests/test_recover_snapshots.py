"""No cloud or volume is touched during recovery-point selection tests."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from cyberheal_recover.contracts import RequestedWindow
from cyberheal_recover.snapshots import (
    TrustedSnapshotCandidate,
    select_trusted_snapshot,
)

BASE = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
WINDOW = RequestedWindow(start=BASE, end=BASE + timedelta(hours=2))
SUSPICIOUS = BASE + timedelta(minutes=90)


def snapshot(
    name: str,
    *,
    minutes: int,
    clean: bool = True,
    state: str = "completed",
    validation_ref: str | None = "baseline:verifier:1",
    volume_id: str = "lab-volume",
    account_id: str = "123456789012",
) -> TrustedSnapshotCandidate:
    return TrustedSnapshotCandidate(
        snapshot_id=name,
        volume_id=volume_id,
        account_id=account_id,
        created_at=BASE + timedelta(minutes=minutes),
        state=state,
        verified_clean=clean,
        validation_ref=validation_ref,
    )


def select(*items: TrustedSnapshotCandidate) -> TrustedSnapshotCandidate:
    return select_trusted_snapshot(
        items,
        volume_id="lab-volume",
        account_id="123456789012",
        window=WINDOW,
        first_suspicious_at=SUSPICIOUS,
    )


def test_picks_latest_verified_preincident_snapshot() -> None:
    chosen = select(
        snapshot("good-early", minutes=20),
        snapshot("good-late", minutes=70),
        snapshot("too-late", minutes=100),
    )
    assert chosen.snapshot_id == "good-late"


def test_unverified_and_missing_evidence_are_rejected() -> None:
    with pytest.raises(LookupError):
        select(snapshot("unverified", minutes=40, clean=False))
    with pytest.raises(LookupError):
        select(snapshot("missing-attestation", minutes=40, validation_ref=None))


def test_incorrect_project_or_volume_is_rejected() -> None:
    with pytest.raises(LookupError):
        select(snapshot("999999999999", minutes=20, account_id="999999999999"))
    with pytest.raises(LookupError):
        select(snapshot("wrong-volume", minutes=20, volume_id="other"))


def test_snapshot_at_suspicious_time_is_rejected() -> None:
    with pytest.raises(LookupError):
        select(snapshot("incident-time", minutes=90))


def test_not_available_is_rejected() -> None:
    with pytest.raises(LookupError):
        select(snapshot("building", minutes=30, state="pending"))


def test_outside_requested_window_is_rejected() -> None:
    with pytest.raises(LookupError):
        select(snapshot("early", minutes=-1))


def test_no_snapshots_is_rejected() -> None:
    with pytest.raises(LookupError):
        select()


def test_missing_suspicious_timestamp_timezone_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone"):
        select_trusted_snapshot(
            [snapshot("good", minutes=15)],
            volume_id="lab-volume",
            account_id="123456789012",
            window=WINDOW,
            first_suspicious_at=datetime(2026, 11, 1, 9, 0),
        )


def test_snapshot_timestamp_requires_timezone() -> None:
    data = snapshot("good", minutes=15).model_dump()
    data["created_at"] = "2026-11-01T08:15:00"
    with pytest.raises(ValidationError):
        TrustedSnapshotCandidate.model_validate(data)
