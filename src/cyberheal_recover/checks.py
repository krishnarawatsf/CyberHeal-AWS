"""Deterministic verification of five factors from collected, trusted evidence.

Evidence supplied by untrusted recovery API callers is NOT sufficient to prove
safety. Real deployment must gather this from isolated verification workers and
AWS read-only APIs, and attest the baseline separately.
"""

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from .rcs import FactorCheck


class IdentityEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_disabled: bool
    actual_roles: frozenset[str]
    allowed_roles: frozenset[str]
    observed: bool


class FileIntegrityEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_sha256: dict[str, str] = Field(min_length=1)
    observed_sha256: dict[str, str]
    scan_complete: bool


class NetworkEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actual_ingress_rules: frozenset[str]
    approved_ingress_rules: frozenset[str]
    isolated: bool
    observed: bool


class ConfigurationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_sha256: dict[str, str] = Field(min_length=1)
    observed_sha256: dict[str, str]
    scan_complete: bool


class HealthEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_http_status: int = Field(ge=0, le=599)
    functional_test_passed: bool
    observed: bool


class VerificationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity: IdentityEvidence
    file_integrity: FileIntegrityEvidence
    network: NetworkEvidence
    configuration: ConfigurationEvidence
    health: HealthEvidence


def _binary_score(passed: bool, completed: bool) -> FactorCheck:
    # This experimental policy is deliberately binary. No invented accuracy.
    passed = passed and completed
    return FactorCheck(
        score=100.0 if passed else 0.0, completed=completed, passed=passed
    )


def check_identity(e: IdentityEvidence) -> FactorCheck:
    passed = e.account_disabled and e.actual_roles.issubset(e.allowed_roles)
    return _binary_score(passed, e.observed)


def _hashes_match(expected: Mapping[str, str], observed: Mapping[str, str]) -> bool:
    # Extra/missing files fail. Expected hashes must be real SHA256 hex strings.
    def valid(h: str) -> bool:
        return len(h) == 64 and all(c in "0123456789abcdef" for c in h.lower())

    return (
        bool(expected)
        and all(valid(h) for h in expected.values())
        and (
            {k: v.lower() for k, v in expected.items()}
            == {k: v.lower() for k, v in observed.items()}
        )
    )


def check_file_integrity(e: FileIntegrityEvidence) -> FactorCheck:
    return _binary_score(
        _hashes_match(e.expected_sha256, e.observed_sha256), e.scan_complete
    )


def check_network(e: NetworkEvidence) -> FactorCheck:
    return _binary_score(
        e.isolated and e.actual_ingress_rules == e.approved_ingress_rules,
        e.observed,
    )


def check_configuration(e: ConfigurationEvidence) -> FactorCheck:
    return _binary_score(
        _hashes_match(e.expected_sha256, e.observed_sha256), e.scan_complete
    )


def check_health(e: HealthEvidence) -> FactorCheck:
    return _binary_score(
        e.api_http_status == 200 and e.functional_test_passed, e.observed
    )


def run_all_checks(e: VerificationEvidence) -> dict[str, FactorCheck]:
    """Never skip a factor, even when an earlier one fails."""
    return {
        "identity": check_identity(e.identity),
        "file_integrity": check_file_integrity(e.file_integrity),
        "network": check_network(e.network),
        "configuration": check_configuration(e.configuration),
        "health": check_health(e.health),
    }
