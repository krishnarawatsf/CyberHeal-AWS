"""Offline demo for Member C, with CLEARLY MOCKED cloud and trust sources."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from .authorization import TrustedRecoveryDecision
from .checks import (
    ConfigurationEvidence,
    FileIntegrityEvidence,
    HealthEvidence,
    IdentityEvidence,
    NetworkEvidence,
    VerificationEvidence,
)
from .contracts import RecoveryRequest
from .rcs import load_policy
from .snapshots import TrustedSnapshotCandidate
from .workflow import run_recovery

INCIDENT = "4ace1ed3-3b54-41b4-9aa2-6cf4863133b9"
ACCOUNT = "123456789012"
VM = "test-vm-1"
VOLUME = "test-data-volume-1"
SNAPSHOT = "test-clean-snapshot-1"


class DemoGateway:
    def create_recovery_volume(
        self, *, source_volume_id: str, snapshot_id: str, incident_id: str
    ) -> str:
        if source_volume_id != VOLUME or snapshot_id != SNAPSHOT:
            raise ValueError("mock resource mismatch")
        return "MOCK-recovered-volume-1"


class DemoVerifier:
    def collect(
        self, *, recovered_volume_id: str, incident_id: str
    ) -> VerificationEvidence:
        if recovered_volume_id != "MOCK-recovered-volume-1":
            raise ValueError("mock result mismatch")
        digest = hashlib.sha256(b"known-good-test-content").hexdigest()
        return VerificationEvidence(
            identity=IdentityEvidence(
                account_disabled=True,
                actual_roles=frozenset({"reader"}),
                allowed_roles=frozenset({"reader"}),
                observed=True,
            ),
            file_integrity=FileIntegrityEvidence(
                expected_sha256={"sample.txt": digest},
                observed_sha256={"sample.txt": digest},
                scan_complete=True,
            ),
            network=NetworkEvidence(
                actual_ingress_rules=frozenset(),
                approved_ingress_rules=frozenset(),
                isolated=True,
                observed=True,
            ),
            configuration=ConfigurationEvidence(
                expected_sha256={"app.conf": digest},
                observed_sha256={"app.conf": digest},
                scan_complete=True,
            ),
            health=HealthEvidence(
                api_http_status=200, functional_test_passed=True, observed=True
            ),
        )


def main() -> None:
    now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    request = RecoveryRequest.model_validate(
        {
            "incident_id": INCIDENT,
            "resource": {"vm_id": VM, "volume_id": VOLUME},
            "requested_window": {
                "start": (now - timedelta(days=2)).isoformat(),
                "end": now.isoformat(),
            },
            "opa_decision_ref": "MOCK-OPA-approval-1",
        }
    )
    decision = TrustedRecoveryDecision(
        decision_ref="MOCK-OPA-approval-1",
        incident_id=UUID(INCIDENT),
        action="recover_volume",
        allowed=True,
        account_id=ACCOUNT,
        resource=request.resource,
    )
    snapshot = TrustedSnapshotCandidate(
        snapshot_id=SNAPSHOT,
        volume_id=VOLUME,
        account_id=ACCOUNT,
        created_at=now - timedelta(hours=5),
        state="completed",
        verified_clean=True,
        validation_ref="MOCK-known-good-validation",
    )
    policy_path = Path(__file__).resolve().parents[2] / "config" / "recovery.yaml"
    output = run_recovery(
        request,
        trusted_decision=decision,
        account_id=ACCOUNT,
        allowlisted_resource_pairs=frozenset({(VM, VOLUME)}),
        first_suspicious_at=now - timedelta(hours=1),
        snapshots=[snapshot],
        gateway=DemoGateway(),
        verifier=DemoVerifier(),
        policy=load_policy(policy_path),
    )
    print("OFFLINE MOCK DEMO — no AWS calls or real authorization")
    print(json.dumps(output.verification.model_dump(mode="json"), indent=2))
    print("mock_recovered_volume_id:", output.recovered_volume_id)
    print("eligible_for_release_after_manual_review:", output.can_return_to_service)


if __name__ == "__main__":
    main()
