"""Deterministic, cloud-free tests for Member C's release gate."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from cyberheal_recover.contracts import VerificationResult
from cyberheal_recover.rcs import FACTORS, FactorCheck, evaluate_checks, load_policy

POLICY = load_policy(Path(__file__).resolve().parents[1] / "config/recovery.yaml")


def checks_at(score: float) -> dict[str, FactorCheck]:
    return {
        name: FactorCheck(score=score, completed=True, passed=True) for name in FACTORS
    }


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, "SAFE"),
        (85, "SAFE"),
        (84.99, "REVIEW"),
        (84, "REVIEW"),
        (70, "REVIEW"),
        (69.99, "UNSAFE"),
        (69, "UNSAFE"),
    ],
)
def test_thresholds(score: float, expected: str) -> None:
    outcome = evaluate_checks(checks_at(score), POLICY)
    assert outcome.decision == expected
    assert outcome.rcs == score
    assert outcome.release_allowed == (expected == "SAFE")


def test_application_failure_cannot_be_safe_at_85() -> None:
    checks = checks_at(100)
    checks["health"] = FactorCheck(score=0, completed=True, passed=False)
    outcome = evaluate_checks(checks, POLICY)
    assert outcome.rcs == 85
    assert outcome.decision == "REVIEW"
    assert "health" in outcome.reasons
    assert not outcome.release_allowed


def test_explicit_failure_blocks_safe_even_at_100() -> None:
    checks = checks_at(100)
    checks["network"] = FactorCheck(score=100, completed=True, passed=False)
    outcome = evaluate_checks(checks, POLICY)
    assert outcome.rcs == 100
    assert outcome.decision == "REVIEW"
    assert not outcome.release_allowed


def test_incomplete_check_refuses_to_decide() -> None:
    checks = checks_at(100)
    checks["identity"] = FactorCheck(score=100, completed=False, passed=True)
    with pytest.raises(ValueError, match="did not complete"):
        evaluate_checks(checks, POLICY)


def test_missing_check_refuses_to_decide() -> None:
    checks = checks_at(100)
    del checks["health"]
    with pytest.raises(ValueError, match="five verification"):
        evaluate_checks(checks, POLICY)


def test_bad_factor_score_is_rejected() -> None:
    with pytest.raises(ValidationError):
        FactorCheck(score=101, completed=True, passed=True)
    with pytest.raises(ValidationError):
        FactorCheck(score=float("nan"), completed=True, passed=True)


def test_wrong_weights_are_rejected(tmp_path: Path) -> None:
    contents = (
        Path(__file__).resolve().parents[1] / "config/recovery.yaml"
    ).read_text()
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text(contents.replace("identity: 0.25", "identity: 0.30"))
    with pytest.raises(ValueError, match="add up to 1"):
        load_policy(invalid)


def test_verification_contract_serializes() -> None:
    result = VerificationResult(
        incident_id="e70c0b39-1057-48ed-8b10-783d355e03f5",
        rcs=85.0,
        factor_scores={name: 85.0 for name in FACTORS},
        decision="SAFE",
        snapshot_id="snapshot-lab-1",
    )
    assert set(result.model_dump(mode="json")) == {
        "schema_version",
        "incident_id",
        "rcs",
        "factor_scores",
        "decision",
        "snapshot_id",
    }
