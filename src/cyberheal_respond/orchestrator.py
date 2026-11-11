"""B-to-C integration using C's unchanged workflow and synthetic evidence only."""

import json
from datetime import datetime, timedelta
from pathlib import Path

from cyberheal_recover.contracts import RecoveryRequest, VerificationResult
from cyberheal_recover.demo import DemoVerifier
from cyberheal_recover.rcs import load_policy
from cyberheal_recover.snapshots import TrustedSnapshotCandidate
from cyberheal_recover.workflow import run_recovery

from .aws_contain import quarantine


class MockRecovery:
    mock = True

    def __init__(self, lab, scenario="clean"):
        if scenario not in {"clean", "tampered", "health_failed", "no_snapshot"}:
            raise ValueError("unknown mock scenario")
        self.lab, self.scenario = lab, scenario
        self.clones = []

    def create_recovery_volume(self, *, source_volume_id, snapshot_id, incident_id):
        if source_volume_id != self.lab.volume_id or snapshot_id != "snap-EXAMPLE":
            raise PermissionError("wrong mock recovery resource")
        self.clones.append(incident_id)
        return "MOCK-recovered-volume-1"

    def collect(self, *, recovered_volume_id, incident_id):
        evidence = DemoVerifier().collect(
            recovered_volume_id=recovered_volume_id, incident_id=incident_id
        )
        if self.scenario == "tampered":
            evidence.file_integrity.observed_sha256 = {"sample.txt": "0" * 64}
        if self.scenario == "health_failed":
            evidence.health.functional_test_passed = False
        return evidence

    def recover(self, request, decision, first_suspicious_at):
        suspicious = datetime.fromisoformat(first_suspicious_at)
        snapshots = (
            []
            if self.scenario == "no_snapshot"
            else [
                TrustedSnapshotCandidate(
                    snapshot_id="snap-EXAMPLE",
                    volume_id=self.lab.volume_id,
                    account_id=self.lab.account_id,
                    created_at=suspicious - timedelta(hours=2),
                    state="completed",
                    verified_clean=True,
                    validation_ref="MOCK-independent-baseline",
                )
            ]
        )
        return run_recovery(
            request,
            trusted_decision=decision,
            account_id=self.lab.account_id,
            allowlisted_resource_pairs=frozenset(
                {(self.lab.vm_id, self.lab.volume_id)}
            ),
            first_suspicious_at=suspicious,
            snapshots=snapshots,
            gateway=self,
            verifier=self,
            policy=load_policy(
                Path(__file__).resolve().parents[2] / "config" / "recovery.yaml"
            ),
        ).verification


class Orchestrator:
    def __init__(self, *, store, lab, policy, approvals, ec2, recovery):
        self.store, self.lab, self.policy = store, lab, policy
        self.approvals, self.ec2, self.recovery = approvals, ec2, recovery

    def approve(self, incident, action, actor):
        item = self.store.get(incident)
        value = {
            "subject": actor,
            "action": action,
            "scope": self.lab.scope,
            "resource": item["alert"]["resource"],
            "incident_id": incident,
        }
        decision = self.policy.evaluate(value)
        return self.approvals.issue(value, decision, item["first_suspicious_at"])

    def execute(self, incident, action, actor, window=None):
        item = self.store.get(incident)
        previous = self.store.job(incident, action)
        if previous:
            if previous["status"] == "complete":
                return json.loads(previous["output"])
            raise ValueError(
                "action previously started or failed; operator review required"
            )
        if action == "recover_volume":
            contained = self.store.job(incident, "quarantine_instance")
            if not contained or contained["status"] != "complete":
                raise PermissionError("successful containment required before recovery")
            suspicious = datetime.fromisoformat(item["first_suspicious_at"])
            if window.start > window.end or window.end >= suspicious:
                raise ValueError(
                    "recovery window must end before trusted first suspicious timestamp"
                )
        ref = self.approve(incident, action, actor)
        # Claim is durable BEFORE any side effect. Failed/uncertain work requires review.
        self.store.claim(incident, action)
        try:
            record = self.approvals.consume(
                ref, incident=incident, action=action, resource=self.lab.resource
            )
            if action == "quarantine_instance":
                output = quarantine(
                    ec2=self.ec2,
                    store=self.store,
                    lab=self.lab,
                    incident=incident,
                    approval=record,
                )
                output["opa_decision_ref"] = ref
            else:
                request = RecoveryRequest.model_validate(
                    {
                        "incident_id": incident,
                        "resource": self.lab.resource,
                        "requested_window": window.model_dump(),
                        "opa_decision_ref": ref,
                    }
                )
                self.store.audit(
                    incident,
                    "recovery_requested",
                    {
                        "mock": self.recovery.mock,
                        "request": request.model_dump(mode="json"),
                    },
                )
                result = self.recovery.recover(
                    request,
                    self.approvals.c_decision(record),
                    item["first_suspicious_at"],
                )
                validate_result(result, incident)
                envelope = self.store.verification(result, mock=self.recovery.mock)
                output = {"request": request.model_dump(mode="json"), **envelope}
            self.store.finish(incident, action, "complete", output)
            return output
        except Exception:
            self.store.finish(
                incident,
                action,
                "failed",
                {
                    "mock": self.recovery.mock,
                    "error": "action_failed_operator_review_required",
                },
            )
            raise


def validate_result(result: VerificationResult, incident):
    if str(result.incident_id) != incident or not result.snapshot_id.startswith(
        "snap-"
    ):
        raise ValueError("verification binding mismatch")
    scores = result.factor_scores.model_dump()
    # One source of truth for A/B/C policy; never duplicate weights or
    # thresholds in an API handler. The current verifier factors are binary.
    recovery_policy = load_policy(
        Path(__file__).resolve().parents[2] / "config" / "recovery.yaml"
    )
    if abs(
        result.rcs
        - round(
            sum(scores[k] * recovery_policy.weights[k] for k in recovery_policy.weights),
            2,
        )
    ) > 0.001:
        raise ValueError("inconsistent RCS")
    if result.decision == "SAFE" and (
        result.rcs < recovery_policy.safe_threshold
        or any(
            score < recovery_policy.minimum_factor_scores[factor]
            or score != 100  # Binary factor checks: no inferred partial pass.
            for factor, score in scores.items()
        )
    ):
        raise ValueError("SAFE violates verification gates")
