import json
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from cyberheal_respond.policy import Lab, OPA
from test_investigate_api import header, ingest

WINDOW = {"start": "2026-11-03T00:00:00Z", "end": "2026-11-04T08:15:00Z"}
ACTOR = {"actor": "approved-demo-operator", "roles": ["incident-responder"]}


def contain(client, incident):
    return client.post(
        f"/api/v1/incidents/{incident}/contain", json={}, headers=header()
    )


def recover(client, incident, window=None):
    return client.post(
        f"/api/v1/incidents/{incident}/request-recovery",
        json=window or WINDOW,
        headers=header(),
    )


def policy_input(action="recover_volume"):
    lab = Lab()
    return {
        "subject": ACTOR.copy(),
        "action": action,
        "scope": lab.scope,
        "resource": lab.resource,
        "incident_id": str(uuid4()),
    }


@pytest.mark.parametrize("action", ["quarantine_instance", "recover_volume"])
def test_real_opa_allow(action):
    assert (
        OPA(executable=os.environ["CYBERHEAL_OPA_EXE"]).evaluate(policy_input(action))[
            "allow"
        ]
        is True
    )


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("scope", "account_id", "000000000000"),
        ("scope", "region", "us-east-1"),
        ("scope", "lab_tag", "production"),
        ("resource", "vm_id", "i-other"),
        ("resource", "volume_id", "vol-other"),
        ("subject", "roles", ["administrator"]),
        ("subject", "actor", "attacker"),
        (None, "action", "delete_volume"),
        (None, "incident_id", "bad"),
    ],
)
def test_real_opa_negative(section, field, value):
    item = policy_input()
    if section:
        item[section][field] = value
    else:
        item[field] = value
    assert (
        OPA(executable=os.environ["CYBERHEAL_OPA_EXE"]).evaluate(item)["allow"] is False
    )


@pytest.mark.parametrize(
    "field", ["scope", "resource", "subject", "incident_id", "action"]
)
def test_real_opa_missing_input(field):
    item = policy_input()
    del item[field]
    assert (
        OPA(executable=os.environ["CYBERHEAL_OPA_EXE"]).evaluate(item)["allow"] is False
    )


def test_opa_offline_denies_without_mutation(client):
    incident = ingest(client)
    client.app.state.service.policy = OPA(executable="does-not-exist")
    assert contain(client, incident).status_code == 403
    assert client.app.state.service.ec2.changes == []
    assert (
        client.app.state.store.get(incident)["timeline"][-1]["action"]
        == "policy_denied"
    )


@pytest.mark.parametrize(
    "scenario,decision",
    [("clean", "SAFE"), ("tampered", "REVIEW"), ("health_failed", "REVIEW")],
)
def test_c_integration_and_monitoring(client, scenario, decision):
    incident = ingest(client)
    service = client.app.state.service
    service.recovery.scenario = scenario
    assert contain(client, incident).status_code == 200
    response = recover(client, incident)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["verification"]["decision"] == decision
    assert result["alert_required"] == (decision != "SAFE")
    assert result["mock"] is True
    from cyberheal_recover.contracts import RecoveryRequest

    RecoveryRequest.model_validate(result["request"])
    assert result["verification"]["schema_version"] == "1.0"
    assert recover(client, incident).json() == result
    assert contain(client, incident).status_code == 200
    assert len(service.recovery.clones) == len(service.ec2.changes) == 1
    monitoring = client.get("/api/v1/monitoring/results", headers=header()).json()
    assert monitoring[0]["verification"] == result["verification"]
    assert monitoring[0]["alert_required"] == (decision != "SAFE")
    assert service.ec2.groups == [service.lab.quarantine_sg_id]
    assert client.app.state.store.get(incident)["result"] == result["verification"]
    if scenario == "health_failed":
        assert result["verification"]["rcs"] == 85


def test_no_snapshot_denies_and_failed_job_not_retried(client):
    incident = ingest(client)
    client.app.state.service.recovery.scenario = "no_snapshot"
    assert contain(client, incident).status_code == 200
    assert recover(client, incident).status_code == 409
    assert recover(client, incident).status_code == 409
    assert client.app.state.service.recovery.clones == []
    assert client.app.state.store.job(incident, "recover_volume")["status"] == "failed"


def test_recovery_before_containment_and_untrusted_fields(client):
    incident = ingest(client)
    assert recover(client, incident).status_code == 403
    body = {
        **WINDOW,
        "opa_decision_ref": "fake",
        "first_suspicious_at": "2027-01-01T00:00:00Z",
    }
    assert recover(client, incident, body).status_code == 422


@pytest.mark.parametrize(
    "window",
    [
        {"start": "2026-11-04T09:00:00Z", "end": "2026-11-04T10:00:00Z"},
        {"start": "2026-11-04T08:00:00Z", "end": "2026-11-04T08:30:00Z"},
        {"start": "2026-11-04T08:00:00Z", "end": "2026-11-03T08:00:00Z"},
    ],
)
def test_window_rejected(client, window):
    incident = ingest(client)
    assert contain(client, incident).status_code == 200
    assert recover(client, incident, window).status_code == 409
    assert client.app.state.service.recovery.clones == []


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("interfaces", 2),
        ("tag", "production"),
        ("account_id", "999999999999"),
        ("region", "us-east-1"),
    ],
)
def test_fake_inventory_validation(client, attribute, value):
    incident = ingest(client)
    setattr(client.app.state.service.ec2, attribute, value)
    assert contain(client, incident).status_code == 403
    assert client.app.state.service.ec2.changes == []


def test_ec2_failure_original_groups_persisted_no_auto_rollback(client):
    incident = ingest(client)
    ec2 = client.app.state.service.ec2
    ec2.fail = True
    assert contain(client, incident).status_code == 503
    events = client.app.state.store.get(incident)["timeline"]
    proposed = next(
        json.loads(e["detail"]) for e in events if e["action"] == "quarantine_proposed"
    )
    assert proposed["previous_sg_ids"] == ["sg-MOCK-original"]
    ec2.fail = False
    assert contain(client, incident).status_code == 409
    assert ec2.changes == []


def test_approval_expiry_binding_replay_and_protected_lookup(client):
    incident = ingest(client)
    service = client.app.state.service
    ref = service.approve(incident, "recover_volume", ACTOR)
    assert (
        client.get(f"/internal/v1/approvals/{ref}", headers=header()).status_code == 401
    )
    record = client.get(
        f"/internal/v1/approvals/{ref}", headers=header("internal")
    ).json()
    assert record["account_id"] == "123456789012" and "project_id" not in record
    assert record["first_suspicious_at"] == "2026-11-04T08:30:00Z"
    approvals = service.approvals
    for kwargs in (
        {
            "incident": str(uuid4()),
            "action": "recover_volume",
            "resource": service.lab.resource,
        },
        {
            "incident": incident,
            "action": "quarantine_instance",
            "resource": service.lab.resource,
        },
        {
            "incident": incident,
            "action": "recover_volume",
            "resource": {"vm_id": "i-wrong", "volume_id": "vol-EXAMPLE"},
        },
    ):
        with pytest.raises(PermissionError):
            approvals.consume(ref, **kwargs)
    approvals.consume(
        ref, incident=incident, action="recover_volume", resource=service.lab.resource
    )
    with pytest.raises(PermissionError):
        approvals.consume(
            ref,
            incident=incident,
            action="recover_volume",
            resource=service.lab.resource,
        )
    ref2 = service.approve(incident, "recover_volume", ACTOR)
    approvals.clock = lambda: 9999999999
    with pytest.raises(PermissionError):
        approvals.lookup(ref2)
    with pytest.raises(PermissionError):
        approvals.lookup("copied-untrusted-reference")


def test_atomic_approval_consumption(client):
    incident = ingest(client)
    service = client.app.state.service
    ref = service.approve(incident, "recover_volume", ACTOR)

    def consume(_):
        try:
            service.approvals.consume(
                ref,
                incident=incident,
                action="recover_volume",
                resource=service.lab.resource,
            )
            return True
        except PermissionError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(consume, range(4))) == 1


def test_restart_does_not_repeat_recovery(client):
    incident = ingest(client)
    assert contain(client, incident).status_code == 200
    first = recover(client, incident).json()
    from cyberheal_investigate.api import create_app
    from fastapi.testclient import TestClient
    from test_investigate_api import TOKENS

    with TestClient(
        create_app(
            db_path=client.app.state.store.path,
            tokens=TOKENS,
            policy=OPA(executable=os.environ["CYBERHEAL_OPA_EXE"]),
        )
    ) as restarted:
        assert recover(restarted, incident).json() == first
        assert restarted.app.state.service.recovery.clones == []


def test_unbound_internal_verification_denied(client):
    incident = ingest(client)
    result = {
        "schema_version": "1.0",
        "incident_id": incident,
        "rcs": 100,
        "decision": "SAFE",
        "snapshot_id": "snap-EXAMPLE",
        "factor_scores": dict.fromkeys(
            ["identity", "file_integrity", "network", "configuration", "health"], 100
        ),
    }
    assert (
        client.post(
            "/internal/v1/verification-results", json=result, headers=header("internal")
        ).status_code
        == 403
    )


def test_concurrent_job_claim_only_one_winner(client):
    incident = ingest(client)
    store = client.app.state.store

    def claim(_):
        try:
            store.claim(incident, "recover_volume")
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(claim, range(4))) == 1


@pytest.mark.parametrize(
    "change", ["wrong_score", "unsafe_marked_safe", "wrong_snapshot", "wrong_incident"]
)
def test_verification_cannot_bypass_gates(client, change):
    incident = ingest(client)
    assert contain(client, incident).status_code == 200
    result = recover(client, incident).json()["verification"]
    if change == "wrong_score":
        result["rcs"] = 10
    elif change == "unsafe_marked_safe":
        result["factor_scores"]["health"] = 0
        result["rcs"] = 85
    elif change == "wrong_snapshot":
        result["snapshot_id"] = "snapshot-openstack"
    else:
        result["incident_id"] = str(uuid4())
    response = client.post(
        "/internal/v1/verification-results", json=result, headers=header("internal")
    )
    assert response.status_code in {403, 409}
    assert client.app.state.store.get(incident)["result"]["rcs"] == 100


@pytest.mark.parametrize(
    "response_body,expected",
    [
        ({"result": {"allow": True, "version": "test"}}, True),
        ({"result": {"allow": "true", "version": "test"}}, False),
        ({}, False),
        ({"result": {"allow": False, "version": "test"}}, False),
    ],
)
def test_opa_http_requires_explicit_boolean(response_body, expected):
    import httpx

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json=response_body)
    )
    policy = OPA(
        url="http://127.0.0.1:8181/v1/data/cyberheal/decision",
        client=httpx.Client(transport=transport),
    )
    assert policy.evaluate(policy_input())["allow"] is expected
