"""Exact Member B -> C and Member C -> A/B data-contract models."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Resource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vm_id: str = Field(min_length=1)
    volume_id: str = Field(min_length=1)


class RequestedWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_order(self) -> "RequestedWindow":
        if self.start > self.end:
            raise ValueError("requested_window.start must not exceed end")
        return self


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: UUID
    resource: Resource
    requested_window: RequestedWindow
    opa_decision_ref: str = Field(min_length=1)

    @field_validator("opa_decision_ref")
    @classmethod
    def require_nonblank_ref(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("OPA decision reference cannot be blank")
        return value


class FactorScores(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity: float = Field(ge=0, le=100, allow_inf_nan=False)
    file_integrity: float = Field(ge=0, le=100, allow_inf_nan=False)
    network: float = Field(ge=0, le=100, allow_inf_nan=False)
    configuration: float = Field(ge=0, le=100, allow_inf_nan=False)
    health: float = Field(ge=0, le=100, allow_inf_nan=False)


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    incident_id: UUID
    rcs: float = Field(ge=0, le=100, allow_inf_nan=False)
    factor_scores: FactorScores
    decision: Literal["SAFE", "REVIEW", "UNSAFE"]
    snapshot_id: str = Field(min_length=1)
