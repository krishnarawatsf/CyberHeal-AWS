"""Pure recovery-point selection; there are no SDK or volume mutations here."""

from datetime import UTC, datetime
from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import RequestedWindow


class TrustedSnapshotCandidate(BaseModel):
    """Candidate joined with C's independent clean-verification registry.

    A 'clean' snapshot tag alone is NOT sufficient for verified_clean=True.
    """

    model_config = ConfigDict(extra="forbid")
    snapshot_id: str = Field(min_length=1)
    volume_id: str = Field(min_length=1)
    account_id: str = Field(pattern=r"^\d{12}$")
    created_at: datetime
    state: Literal["completed", "pending", "error"]
    verified_clean: bool
    validation_ref: str | None = None

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("snapshot creation timestamp must be timezone aware")
        return value.astimezone(UTC)


def select_trusted_snapshot(
    snapshots: Sequence[TrustedSnapshotCandidate],
    *,
    volume_id: str,
    account_id: str,
    window: RequestedWindow,
    first_suspicious_at: datetime,
) -> TrustedSnapshotCandidate:
    """Select latest independently validated clean snapshot before the attack.

    `first_suspicious_at` must come from a trusted incident timeline maintained
    by B, not from the untrusted client's requested window.
    """
    if not volume_id or not account_id:
        raise ValueError("scope information is required")
    if first_suspicious_at.tzinfo is None or first_suspicious_at.utcoffset() is None:
        raise ValueError("first_suspicious_at must include timezone")
    first_suspicious_at = first_suspicious_at.astimezone(UTC)
    eligible = [
        s
        for s in snapshots
        if s.volume_id == volume_id
        and s.account_id == account_id
        and s.state == "completed"
        and s.verified_clean
        and s.validation_ref is not None
        and bool(s.validation_ref.strip())
        and window.start <= s.created_at <= window.end
        and s.created_at < first_suspicious_at
    ]
    if not eligible:
        raise LookupError("no verified clean recovery point in allowed time window")
    return max(eligible, key=lambda s: (s.created_at, s.snapshot_id))
