"""B validates C's policy without hard-coded duplicate weights."""
from uuid import uuid4

import pytest

from cyberheal_recover.contracts import VerificationResult
from cyberheal_respond.orchestrator import validate_result


def make_result(*, health=100, decision="SAFE", rcs=None):
    values = {
        "identity": 100,
        "file_integrity": 100,
        "network": 100,
        "configuration": 100,
        "health": health,
    }
    return VerificationResult(
        incident_id=uuid4(),
        rcs=(85 if health == 0 else 100) if rcs is None else rcs,
        factor_scores=values,
        decision=decision,
        snapshot_id="snap-" + "1" * 17,
    )


def test_accept_consistent_safe():
    obj = make_result()
    validate_result(obj, str(obj.incident_id))


def test_reject_unhealthy_even_with_85_rcs():
    obj = make_result(health=0)
    with pytest.raises(ValueError, match="SAFE violates"):
        validate_result(obj, str(obj.incident_id))


def test_accept_review_when_health_failed():
    obj = make_result(health=0, decision="REVIEW")
    validate_result(obj, str(obj.incident_id))


def test_reject_forged_rcs():
    obj = make_result(rcs=99)
    with pytest.raises(ValueError, match="inconsistent RCS"):
        validate_result(obj, str(obj.incident_id))


def test_reject_wrong_incident():
    obj = make_result()
    with pytest.raises(ValueError, match="binding mismatch"):
        validate_result(obj, str(uuid4()))
