"""Each verification factor: at least one success and one failure."""

import hashlib

import pytest

from cyberheal_recover.checks import (
    ConfigurationEvidence,
    FileIntegrityEvidence,
    HealthEvidence,
    IdentityEvidence,
    NetworkEvidence,
    VerificationEvidence,
    check_configuration,
    check_file_integrity,
    check_health,
    check_identity,
    check_network,
    run_all_checks,
)
from cyberheal_recover.scan import collect_sha256

DIGEST = hashlib.sha256(b"clean").hexdigest()


def good_evidence() -> VerificationEvidence:
    return VerificationEvidence(
        identity=IdentityEvidence(
            account_disabled=True,
            actual_roles=frozenset({"reader"}),
            allowed_roles=frozenset({"reader"}),
            observed=True,
        ),
        file_integrity=FileIntegrityEvidence(
            expected_sha256={"x.txt": DIGEST},
            observed_sha256={"x.txt": DIGEST},
            scan_complete=True,
        ),
        network=NetworkEvidence(
            isolated=True,
            actual_ingress_rules=frozenset(),
            approved_ingress_rules=frozenset(),
            observed=True,
        ),
        configuration=ConfigurationEvidence(
            expected_sha256={"cfg": DIGEST},
            observed_sha256={"cfg": DIGEST},
            scan_complete=True,
        ),
        health=HealthEvidence(
            api_http_status=200, functional_test_passed=True, observed=True
        ),
    )


def test_all_checks_pass():
    checks = run_all_checks(good_evidence())
    assert len(checks) == 5
    assert all(x.passed and x.score == 100 for x in checks.values())


def test_identity_failure():
    good = good_evidence().identity
    assert check_identity(good).passed
    assert not check_identity(
        good.model_copy(update={"account_disabled": False})
    ).passed
    assert not check_identity(
        good.model_copy(update={"actual_roles": frozenset({"admin"})})
    ).passed


def test_integrity_failure():
    good = good_evidence().file_integrity
    assert check_file_integrity(good).passed
    assert not check_file_integrity(
        good.model_copy(update={"observed_sha256": {"x.txt": "f" * 64}})
    ).passed
    assert not check_file_integrity(
        good.model_copy(update={"observed_sha256": {}})
    ).passed


def test_network_failure():
    good = good_evidence().network
    assert check_network(good).passed
    assert not check_network(good.model_copy(update={"isolated": False})).passed
    assert not check_network(
        good.model_copy(update={"actual_ingress_rules": frozenset({"0.0.0.0/0:22"})})
    ).passed


def test_config_failure():
    good = good_evidence().configuration
    assert check_configuration(good).passed
    assert not check_configuration(
        good.model_copy(update={"observed_sha256": {"cfg": "0" * 64}})
    ).passed


def test_health_failure():
    good = good_evidence().health
    assert check_health(good).passed
    assert not check_health(
        good.model_copy(update={"functional_test_passed": False})
    ).passed
    assert not check_health(good.model_copy(update={"api_http_status": 500})).passed


def test_incomplete_factor_is_not_completed():
    good = good_evidence().health
    assert not check_health(good.model_copy(update={"observed": False})).completed


@pytest.mark.parametrize(
    "evidence,checker",
    [
        (good_evidence().identity, check_identity),
        (good_evidence().network, check_network),
        (good_evidence().health, check_health),
    ],
)
def test_missing_observation_cannot_pass(evidence, checker):
    result = checker(evidence.model_copy(update={"observed": False}))
    assert not result.completed
    assert not result.passed
    assert result.score == 0


def test_observation_provenance_must_be_explicit():
    with pytest.raises(ValueError):
        IdentityEvidence(
            account_disabled=True,
            actual_roles=frozenset({"reader"}),
            allowed_roles=frozenset({"reader"}),
        )
    with pytest.raises(ValueError):
        NetworkEvidence(
            actual_ingress_rules=frozenset(),
            approved_ingress_rules=frozenset(),
            isolated=True,
        )
    with pytest.raises(ValueError):
        HealthEvidence(api_http_status=200, functional_test_passed=True)


def test_readonly_hash_scan(tmp_path):
    (tmp_path / "safe.txt").write_bytes(b"clean")
    assert collect_sha256(tmp_path, ("safe.txt",)) == {"safe.txt": DIGEST}


@pytest.mark.parametrize(
    "relative", ("../secret.txt", "/etc/passwd", "safe.txt/../../secret")
)
def test_hash_scan_blocks_traversal(tmp_path, relative):
    (tmp_path / "safe.txt").write_bytes(b"clean")
    with pytest.raises((ValueError, FileNotFoundError)):
        collect_sha256(tmp_path, (relative,))


def test_hash_scan_blocks_symlinks(tmp_path):
    (tmp_path / "safe.txt").write_bytes(b"clean")
    (tmp_path / "link.txt").symlink_to(tmp_path / "safe.txt")
    with pytest.raises(ValueError):
        collect_sha256(tmp_path, ("link.txt",))
