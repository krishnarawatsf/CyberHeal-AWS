"""Member C must reject forged or out-of-scope recovery requests."""

from uuid import UUID

import pytest
from pydantic import ValidationError

from cyberheal_recover.authorization import TrustedRecoveryDecision, authorize_recovery
from cyberheal_recover.contracts import RecoveryRequest, Resource

ID = UUID("e70c0b39-1057-48ed-8b10-783d355e03f5")
RESOURCE = Resource(vm_id="lab-vm-1", volume_id="lab-volume-1")
ALLOWED = frozenset({("lab-vm-1", "lab-volume-1")})


def make_request() -> RecoveryRequest:
    return RecoveryRequest(
        incident_id=ID,
        resource=RESOURCE,
        requested_window={
            "start": "2026-11-01T08:00:00Z",
            "end": "2026-11-01T09:00:00Z",
        },
        opa_decision_ref="audit:allow:123",
    )


def make_decision(**changes: object) -> TrustedRecoveryDecision:
    payload = dict(
        decision_ref="audit:allow:123",
        incident_id=ID,
        action="recover_volume",
        allowed=True,
        account_id="123456789012",
        resource=RESOURCE,
    )
    payload.update(changes)
    return TrustedRecoveryDecision.model_validate(payload)


def validate(
    request: RecoveryRequest, decision: TrustedRecoveryDecision | None
) -> None:
    authorize_recovery(
        request,
        trusted_decision=decision,
        expected_account_id="123456789012",
        allowed_resource_pairs=ALLOWED,
    )


def test_matched_trusted_allow_is_eligible() -> None:
    validate(make_request(), make_decision())


def test_no_trusted_decision_is_denied() -> None:
    with pytest.raises(PermissionError, match="verified OPA"):
        validate(make_request(), None)


def test_deny_decision_is_denied() -> None:
    with pytest.raises(PermissionError):
        validate(make_request(), make_decision(allowed=False))


def test_forged_decision_reference_is_denied() -> None:
    with pytest.raises(PermissionError, match="does not authorize"):
        validate(make_request(), make_decision(decision_ref="audit:other"))


def test_different_project_is_denied() -> None:
    with pytest.raises(PermissionError):
        validate(make_request(), make_decision(account_id="999999999999"))


def test_wrong_incident_is_denied() -> None:
    with pytest.raises(PermissionError):
        validate(
            make_request(),
            make_decision(incident_id=UUID("e70c0b39-1057-48ed-8b10-783d355e03f6")),
        )


def test_unknown_resource_is_denied() -> None:
    request = make_request().model_copy(
        update={"resource": Resource(vm_id="lab-vm-2", volume_id="other")}
    )
    with pytest.raises(PermissionError, match="not in the approved"):
        validate(request, make_decision())


def test_missing_and_blank_opa_reference_are_rejected() -> None:
    payload = make_request().model_dump()
    del payload["opa_decision_ref"]
    with pytest.raises(ValidationError):
        RecoveryRequest.model_validate(payload)
    payload["opa_decision_ref"] = "  "
    with pytest.raises(ValidationError):
        RecoveryRequest.model_validate(payload)


def test_invalid_time_window_is_rejected() -> None:
    payload = make_request().model_dump()
    payload["requested_window"] = {
        "start": "2026-11-01T09:00:00Z",
        "end": "2026-11-01T08:00:00Z",
    }
    with pytest.raises(ValidationError):
        RecoveryRequest.model_validate(payload)


def test_naive_timestamp_is_rejected() -> None:
    payload = make_request().model_dump()
    payload["requested_window"] = {
        "start": "2026-11-01T08:00:00",
        "end": "2026-11-01T09:00:00Z",
    }
    with pytest.raises(ValidationError):
        RecoveryRequest.model_validate(payload)
