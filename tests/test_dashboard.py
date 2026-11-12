"""Unit tests for the CyberHeal AI interactive pipeline dashboard."""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from cyberheal_dashboard.app import create_dashboard_app


@pytest.fixture
def dashboard_client(tmp_path: Path):
    exe = os.environ.get("CYBERHEAL_OPA_EXE", "/opt/homebrew/bin/opa")
    db_file = tmp_path / "dashboard_test.sqlite3"
    app = create_dashboard_app(opa_exe=exe, db_path=db_file)
    with TestClient(app) as client:
        yield client


def test_dashboard_html_renders(dashboard_client: TestClient):
    response = dashboard_client.get("/")
    assert response.status_code == 200
    assert "CyberHeal AI" in response.text
    assert "Recovery Confidence Score" in response.text
    assert "Stage 1: Detect" in response.text


def test_dashboard_status_endpoint(dashboard_client: TestClient):
    response = dashboard_client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert data["mode"] == "OFFLINE_MOCK_AWS"
    assert "lab" in data
    assert "metrics" in data


@pytest.mark.parametrize(
    "scenario,expected_decision,expected_rcs",
    [
        ("clean", "SAFE", 100.0),
        ("tampered", "REVIEW", 75.0),
        ("health_failed", "REVIEW", 85.0),
        ("no_snapshot", "DENIED", None),
    ],
)
def test_dashboard_run_scenario(
    dashboard_client: TestClient,
    scenario: str,
    expected_decision: str,
    expected_rcs: float | None,
):
    response = dashboard_client.post("/api/run-scenario", json={"scenario": scenario})
    assert response.status_code == 200
    data = response.json()
    assert data["scenario"] == scenario
    assert data["stage_1_detect"]["status"] == "DETECTED"
    assert data["stage_2_investigate"]["status"] == "ANALYZED"
    assert data["stage_3_respond"]["status"] == "QUARANTINED"

    stage45 = data["stage_4_5_recover_verify"]
    if scenario == "no_snapshot":
        assert stage45["recovery_denied"] is True
        assert stage45["status"] == "DENIED"
    else:
        assert stage45["recovery_denied"] is False
        verification = stage45["result"]["verification"]
        assert verification["decision"] == expected_decision
        assert verification["rcs"] == expected_rcs


def test_dashboard_telemetry_simulation(dashboard_client: TestClient):
    r_cred = dashboard_client.post("/api/simulate-telemetry", json={"type": "credential"})
    assert r_cred.status_code == 200
    d_cred = r_cred.json()
    assert d_cred["type"] == "credential"
    assert d_cred["events_count"] > 0
    assert "features" in d_cred

    r_file = dashboard_client.post("/api/simulate-telemetry", json={"type": "file"})
    assert r_file.status_code == 200
    d_file = r_file.json()
    assert d_file["type"] == "file"
    assert d_file["events_count"] > 0
    assert "features" in d_file


def test_dashboard_metrics_endpoint(dashboard_client: TestClient):
    # Run a scenario first so metrics are populated
    dashboard_client.post("/api/run-scenario", json={"scenario": "clean"})
    response = dashboard_client.get("/api/metrics")
    assert response.status_code == 200
    assert "cyberheal_incidents_total" in response.text
    assert "cyberheal_opa_decisions_total" in response.text
