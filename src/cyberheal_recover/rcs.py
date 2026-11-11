"""Pure, testable Recovery Confidence Score and release-gate policy."""

from dataclasses import dataclass
from math import isclose, isfinite
from pathlib import Path
from typing import Literal, Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field

FACTORS = ("identity", "file_integrity", "network", "configuration", "health")
Decision = Literal["SAFE", "REVIEW", "UNSAFE"]


class FactorCheck(BaseModel):
    """Result from a trusted verifier, not from an HTTP client."""

    model_config = ConfigDict(extra="forbid")
    score: float = Field(ge=0, le=100, allow_inf_nan=False)
    completed: bool
    passed: bool


@dataclass(frozen=True)
class RecoveryPolicy:
    weights: dict[str, float]
    safe_threshold: float
    review_threshold: float
    minimum_factor_scores: dict[str, float]


@dataclass(frozen=True)
class RecoveryEvaluation:
    rcs: float
    decision: Decision
    factor_scores: dict[str, float]
    release_allowed: bool
    reasons: tuple[str, ...]


def _check_factor_mapping(mapping: Mapping[str, float], name: str) -> None:
    if set(mapping) != set(FACTORS):
        raise ValueError(f"{name} must contain exactly {FACTORS}")
    for factor, value in mapping.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name}.{factor} must be numeric")
        if not isfinite(value) or not 0 <= value <= (1 if name == "weights" else 100):
            raise ValueError(f"{name}.{factor} out of range")


def load_policy(path: Path) -> RecoveryPolicy:
    """Read policy from YAML and validate all weights and thresholds."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {
        "weights",
        "thresholds",
        "minimum_factor_scores",
    }:
        raise ValueError("recovery policy must contain the expected sections")
    weights = document["weights"]
    minima = document["minimum_factor_scores"]
    thresholds = document["thresholds"]
    if not all(isinstance(x, dict) for x in (weights, minima, thresholds)):
        raise ValueError("recovery policy sections must be mappings")
    _check_factor_mapping(weights, "weights")
    _check_factor_mapping(minima, "minimum_factor_scores")
    if not isclose(sum(weights.values()), 1.0, rel_tol=0, abs_tol=1e-9):
        raise ValueError("RCS weights must add up to 1")
    if set(thresholds) != {"safe", "review"}:
        raise ValueError("thresholds must contain safe and review")
    safe, review = thresholds["safe"], thresholds["review"]
    if any(
        isinstance(x, bool) or not isinstance(x, (int, float)) for x in (safe, review)
    ):
        raise ValueError("thresholds must be numbers")
    if not (isfinite(safe) and isfinite(review) and 0 < review < safe <= 100):
        raise ValueError("invalid recovery thresholds")
    return RecoveryPolicy(dict(weights), float(safe), float(review), dict(minima))


def evaluate_checks(
    checks: Mapping[str, FactorCheck], policy: RecoveryPolicy
) -> RecoveryEvaluation:
    """Calculate RCS; never release if any check did not run or failed its gate.

    REVIEW may be returned with RCS >= safe_threshold when a critical gate fails.
    This is an explicit *proposal* requiring approval in the shared contract.
    """
    if set(checks) != set(FACTORS):
        raise ValueError("all five verification checks are required")
    for name, check in checks.items():
        if not isinstance(check, FactorCheck):
            raise ValueError(f"{name} is not a validated FactorCheck")
        if not check.completed:
            raise ValueError(f"{name} did not complete: do not issue a decision")
    scores = {name: checks[name].score for name in FACTORS}
    raw_rcs = sum(policy.weights[name] * scores[name] for name in FACTORS)
    rcs = round(raw_rcs, 2)
    reasons = tuple(
        name
        for name in FACTORS
        if not checks[name].passed or scores[name] < policy.minimum_factor_scores[name]
    )
    if raw_rcs >= policy.safe_threshold and not reasons:
        decision: Decision = "SAFE"
    elif raw_rcs >= policy.review_threshold:
        decision = "REVIEW"
    else:
        decision = "UNSAFE"
    return RecoveryEvaluation(
        rcs=rcs,
        decision=decision,
        factor_scores=scores,
        release_allowed=decision == "SAFE",
        reasons=reasons,
    )
