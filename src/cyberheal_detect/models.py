"""Validated data models exchanged by the detection pipeline."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Resource(BaseModel):
    """Cloud resource associated with an alert."""

    model_config = ConfigDict(extra="forbid")

    vm_id: str = Field(min_length=1)
    volume_id: str = Field(min_length=1)


class ThreatAlert(BaseModel):
    """Sanitised alert handed to the investigation service."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    incident_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resource: Resource
    alert_type: Literal["ransomware_like", "credential_anomaly"]
    confidence: float = Field(ge=0.0, le=1.0)
    features: dict[str, float] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        """Normalise timezone-aware timestamps to UTC."""
        if value.tzinfo is None:
            raise ValueError("timestamp must include timezone information")
        return value.astimezone(UTC)

    @field_validator("evidence_refs")
    @classmethod
    def reject_secret_like_evidence(cls, value: list[str]) -> list[str]:
        """Reject evidence references that could contain credential material."""
        forbidden = ("password", "passwd", "secret", "token", "api_key")
        if any(any(word in ref.lower() for word in forbidden) for ref in value):
            raise ValueError("evidence references must not contain secrets")
        return value
