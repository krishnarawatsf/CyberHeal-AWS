from datetime import UTC, datetime, timedelta
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, UUID4, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Resource(StrictModel):
    vm_id: str = Field(pattern=r"^i-(?:[0-9a-f]{17}|EXAMPLE)$")
    volume_id: str = Field(pattern=r"^vol-(?:[0-9a-f]{17}|EXAMPLE)$")


class Alert(StrictModel):
    schema_version: Literal["1.0"]
    incident_id: UUID4
    timestamp: datetime
    resource: Resource
    alert_type: Literal["ransomware_like", "credential_anomaly"]
    confidence: float = Field(ge=0, le=1)
    features: dict[str, float] = Field(default_factory=dict, max_length=32)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("timestamp")
    @classmethod
    def utc_time(cls, value):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("UTC timestamp required")
        if value > datetime.now(UTC) + timedelta(minutes=2):
            raise ValueError("future telemetry rejected")
        return value


class Advisory(StrictModel):
    summary: str = Field(min_length=1, max_length=1200)
    timeline: list[str] = Field(max_length=16)
    likely_cause: str = Field(max_length=800)
    risk_explanation: str = Field(max_length=800)


class Empty(StrictModel):
    pass


class RecoveryWindow(StrictModel):
    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def utc_time(cls, value):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("UTC timestamp required")
        return value
