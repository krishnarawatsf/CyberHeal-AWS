"""Fail-closed eligibility checks before any future recovery action."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .contracts import RecoveryRequest, Resource


class TrustedRecoveryDecision(BaseModel):
    """Must be fetched from an authenticated, auditable policy-decision source.

    Do NOT instantiate this from untrusted fields in the recovery HTTP request.
    The production decision lookup and signature/authenticity check are pending B.
    """

    model_config = ConfigDict(extra="forbid")
    decision_ref: str = Field(min_length=1)
    incident_id: UUID
    action: Literal["recover_volume"]
    allowed: bool
    account_id: str = Field(pattern=r"^\d{12}$")
    resource: Resource


def authorize_recovery(
    request: RecoveryRequest,
    *,
    trusted_decision: TrustedRecoveryDecision | None,
    expected_account_id: str,
    allowed_resource_pairs: frozenset[tuple[str, str]],
) -> None:
    """Reject unauthorized, mismatched or out-of-scope recovery requests.

    The caller must resolve `trusted_decision` through an authenticated service,
    and must build `allowed_resource_pairs` from a trusted lab inventory.
    """
    if (
        not expected_account_id
        or len(expected_account_id) != 12
        or not expected_account_id.isdigit()
        or not allowed_resource_pairs
    ):
        raise PermissionError("AWS account and lab allow-list must be configured")
    resource = request.resource
    pair = (resource.vm_id, resource.volume_id)
    if pair not in allowed_resource_pairs:
        raise PermissionError("resource is not in the approved test inventory")
    if trusted_decision is None or not trusted_decision.allowed:
        raise PermissionError("no verified OPA allow decision")
    if (
        trusted_decision.decision_ref != request.opa_decision_ref
        or trusted_decision.incident_id != request.incident_id
        or trusted_decision.resource != resource
        or trusted_decision.account_id != expected_account_id
        or trusted_decision.action != "recover_volume"
    ):
        raise PermissionError("OPA decision does not authorize this recovery")
