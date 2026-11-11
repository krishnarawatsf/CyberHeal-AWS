"""C-only integration with mock authorization, EBS and verification source."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from cyberheal_recover.authorization import TrustedRecoveryDecision
from cyberheal_recover.contracts import RecoveryRequest
from cyberheal_recover.rcs import load_policy
from cyberheal_recover.snapshots import TrustedSnapshotCandidate
from cyberheal_recover.workflow import run_recovery
from test_recover_checks import good_evidence

INCIDENT = "49a29bc4-04ca-4ce7-8ead-2671c970e942"
ACCOUNT = "123456789012"


class FakeGateway:
    def __init__(self):
        self.calls = []

    def create_recovery_volume(self, *, source_volume_id, snapshot_id, incident_id):
        self.calls.append((source_volume_id, snapshot_id, incident_id))
        return "fake-new-volume"


class FakeVerifier:
    def __init__(self, evidence=None):
        self.evidence = evidence or good_evidence()
        self.calls = []

    def collect(self, *, recovered_volume_id, incident_id):
        self.calls.append((recovered_volume_id, incident_id))
        return self.evidence


def setup_case():
    now = datetime(2026, 11, 4, tzinfo=UTC)
    req = RecoveryRequest.model_validate(
        {
            "incident_id": INCIDENT,
            "resource": {"vm_id": "vm1", "volume_id": "vol1"},
            "requested_window": {
                "start": (now - timedelta(hours=3)).isoformat(),
                "end": now.isoformat(),
            },
            "opa_decision_ref": "trusted-ref",
        }
    )
    decision = TrustedRecoveryDecision(
        decision_ref="trusted-ref",
        incident_id=UUID(INCIDENT),
        action="recover_volume",
        allowed=True,
        account_id=ACCOUNT,
        resource=req.resource,
    )
    snap = TrustedSnapshotCandidate(
        snapshot_id="clean-snapshot",
        volume_id="vol1",
        account_id=ACCOUNT,
        created_at=now - timedelta(hours=2),
        state="completed",
        verified_clean=True,
        validation_ref="registry-proof-123",
    )
    policy = load_policy(
        __import__("pathlib").Path(__file__).parents[1] / "config/recovery.yaml"
    )
    return dict(
        request=req,
        trusted_decision=decision,
        account_id=ACCOUNT,
        allowlisted_resource_pairs=frozenset({("vm1", "vol1")}),
        first_suspicious_at=now - timedelta(hours=1),
        snapshots=[snap],
        policy=policy,
    )


def test_workflow_safe():
    case = setup_case()
    gateway, verifier = FakeGateway(), FakeVerifier()
    result = run_recovery(**case, gateway=gateway, verifier=verifier)
    assert result.verification.decision == "SAFE"
    assert result.verification.rcs == 100
    assert result.can_return_to_service
    assert gateway.calls == [("vol1", "clean-snapshot", INCIDENT)]
    assert verifier.calls == [("fake-new-volume", INCIDENT)]


def test_untrusted_decision_blocks_any_mutation():
    case = setup_case()
    case["trusted_decision"] = case["trusted_decision"].model_copy(
        update={"allowed": False}
    )
    gateway = FakeGateway()
    with pytest.raises(PermissionError):
        run_recovery(**case, gateway=gateway, verifier=FakeVerifier())
    assert not gateway.calls


def test_no_clean_snapshot_blocks_any_mutation():
    case = setup_case()
    case["snapshots"] = []
    gateway = FakeGateway()
    with pytest.raises(LookupError):
        run_recovery(**case, gateway=gateway, verifier=FakeVerifier())
    assert not gateway.calls


def test_failed_health_yields_no_auto_release():
    case = setup_case()
    evidence = good_evidence()
    evidence = evidence.model_copy(
        update={
            "health": evidence.health.model_copy(
                update={"functional_test_passed": False}
            )
        }
    )
    output = run_recovery(
        **case, gateway=FakeGateway(), verifier=FakeVerifier(evidence)
    )
    assert output.verification.decision != "SAFE"
    assert not output.can_return_to_service
    assert output.verification.rcs == 85  # score alone would be misleading
