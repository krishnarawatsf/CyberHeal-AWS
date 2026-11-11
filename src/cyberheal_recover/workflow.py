"""Authorization-first, isolated clone recovery orchestration.

Safe for unit testing with a mock backend. Real cloud use requires an authenticated
OPA decision resolver, independently verified snapshot registry, attested
verification probes and an isolated verification VM. This module never switches
production traffic and never modifies the original EBS volume.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Sequence

from .authorization import TrustedRecoveryDecision, authorize_recovery
from .checks import VerificationEvidence, run_all_checks
from .contracts import RecoveryRequest, VerificationResult
from .rcs import RecoveryPolicy, evaluate_checks
from .snapshots import TrustedSnapshotCandidate, select_trusted_snapshot


class RecoveryVolumeGateway(Protocol):
    def create_recovery_volume(
        self, *, source_volume_id: str, snapshot_id: str, incident_id: str
    ) -> str: ...


class TrustedVerifier(Protocol):
    def collect(
        self, *, recovered_volume_id: str, incident_id: str
    ) -> VerificationEvidence: ...


@dataclass(frozen=True)
class RecoveryExecution:
    recovered_volume_id: str
    verification: VerificationResult
    can_return_to_service: bool
    notes: tuple[str, ...]


def run_recovery(
    request: RecoveryRequest,
    *,
    trusted_decision: TrustedRecoveryDecision,
    account_id: str,
    allowlisted_resource_pairs: frozenset[tuple[str, str]],
    first_suspicious_at: datetime,
    snapshots: Sequence[TrustedSnapshotCandidate],
    gateway: RecoveryVolumeGateway,
    verifier: TrustedVerifier,
    policy: RecoveryPolicy,
) -> RecoveryExecution:
    """Perform an isolated recovery attempt; do not switch production service.

    This call is designed for an authenticated, durable job runner with
    idempotency and audit persistence added during cloud integration.
    """
    authorize_recovery(
        request,
        trusted_decision=trusted_decision,
        expected_account_id=account_id,
        allowed_resource_pairs=allowlisted_resource_pairs,
    )
    selected = select_trusted_snapshot(
        snapshots,
        volume_id=request.resource.volume_id,
        account_id=account_id,
        window=request.requested_window,
        first_suspicious_at=first_suspicious_at,
    )
    new_id = gateway.create_recovery_volume(
        source_volume_id=request.resource.volume_id,
        snapshot_id=selected.snapshot_id,
        incident_id=str(request.incident_id),
    )
    evidence = verifier.collect(
        recovered_volume_id=new_id, incident_id=str(request.incident_id)
    )
    evaluated = evaluate_checks(run_all_checks(evidence), policy)
    result = VerificationResult(
        incident_id=request.incident_id,
        rcs=evaluated.rcs,
        factor_scores=evaluated.factor_scores,
        decision=evaluated.decision,
        snapshot_id=selected.snapshot_id,
    )
    return RecoveryExecution(
        recovered_volume_id=new_id,
        verification=result,
        can_return_to_service=evaluated.release_allowed,
        notes=evaluated.reasons,
    )
