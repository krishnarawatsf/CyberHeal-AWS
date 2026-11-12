"""CyberHeal AI interactive pipeline dashboard backend and UI."""

import os
import secrets
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel

from cyberheal_detect.features import extract_features
from cyberheal_detect.simulators import (
    simulate_credential_anomaly,
    simulate_file_activity,
)
from cyberheal_investigate.api import create_app as create_core_app
from cyberheal_respond.policy import OPA


class ScenarioRequest(BaseModel):
    scenario: str = "clean"


class TelemetryRequest(BaseModel):
    type: str = "credential"


def get_default_opa_exe() -> str:
    """Locate the OPA executable from env, which, or common fallback paths."""
    if os.environ.get("CYBERHEAL_OPA_EXE"):
        return os.environ["CYBERHEAL_OPA_EXE"]
    for path in (
        "/opt/homebrew/bin/opa",
        "/usr/local/bin/opa",
        "/usr/bin/opa",
    ):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return "opa"


def serialize_metrics_snapshot(snapshot: dict) -> dict:
    """Convert tuple keys into JSON-serializable strings for API responses."""
    return {
        "incidents": snapshot.get("incidents", 0),
        "investigations": snapshot.get("investigations", 0),
        "jobs": snapshot.get("jobs", []),
        "policy_decisions": {
            f"{k[0]}:{k[1]}": v
            for k, v in snapshot.get("policy_decisions", {}).items()
        },
        "verifications": {
            f"{k[0]}:{k[1]}": v
            for k, v in snapshot.get("verifications", {}).items()
        },
    }


def create_dashboard_app(
    *,
    opa_exe: str | None = None,
    db_path: Path | str | None = None,
) -> FastAPI:
    opa_executable = opa_exe or get_default_opa_exe()
    resolved_db = Path(db_path or "work/cyberheal-dashboard.sqlite3")
    resolved_db.parent.mkdir(parents=True, exist_ok=True)

    tokens = {
        role: secrets.token_urlsafe(32) for role in ("detector", "operator", "internal")
    }

    core_app = create_core_app(
        db_path=resolved_db,
        tokens=tokens,
        policy=OPA(executable=opa_executable),
    )

    dashboard = FastAPI(
        title="CyberHeal AI Pipeline Dashboard",
        version="0.4.0",
        description="Unified visual control deck for Detect -> Investigate -> Respond -> Recover -> Verify",
    )

    client = TestClient(core_app)

    @dashboard.get("/api/status")
    def status():
        snapshot = core_app.state.store.metrics_snapshot()
        lab = core_app.state.service.lab
        return {
            "status": "ONLINE",
            "mode": "OFFLINE_MOCK_AWS",
            "opa_executable": opa_executable,
            "database": str(resolved_db),
            "lab": {
                "account_id": lab.scope["account_id"],
                "region": lab.scope["region"],
                "vm_id": lab.resource["vm_id"],
                "volume_id": lab.resource["volume_id"],
                "lab_tag": lab.scope["lab_tag"],
            },
            "metrics": serialize_metrics_snapshot(snapshot),
        }

    @dashboard.post("/api/simulate-telemetry")
    def run_telemetry_simulation(req: TelemetryRequest):
        if req.type == "credential":
            events = simulate_credential_anomaly(username="operator-test", failed_attempts=5)
            features = extract_features(events)
            return {
                "type": "credential",
                "events_count": len(events),
                "features": features,
                "events": events,
            }
        elif req.type == "file":
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                for i in range(4):
                    (root / f"document_{i}.docx").write_text(f"Sample data content {i}")
                events = simulate_file_activity(root)
                features = extract_features(events)
                return {
                    "type": "file",
                    "events_count": len(events),
                    "features": features,
                    "events": events,
                }
        else:
            raise HTTPException(400, "Unknown telemetry type. Must be 'credential' or 'file'.")

    @dashboard.post("/api/run-scenario")
    def run_scenario(req: ScenarioRequest):
        scenario = req.scenario
        if scenario not in {"clean", "tampered", "health_failed", "no_snapshot"}:
            raise HTTPException(400, f"Unsupported scenario: {scenario}")

        incident_id = str(uuid4())
        now = datetime.now(UTC) - timedelta(minutes=1)
        alert_payload = {
            "schema_version": "1.0",
            "incident_id": incident_id,
            "timestamp": now.isoformat(),
            "resource": core_app.state.service.lab.resource,
            "alert_type": "ransomware_like",
            "confidence": 0.94 if scenario != "clean" else 0.88,
            "features": {
                "rename_rate": 16.0 if scenario != "clean" else 8.5,
                "entropy_delta": 2.6 if scenario != "clean" else 1.2,
            },
            "evidence_refs": [f"event:telemetry-{scenario}-01"],
        }

        # Step 1: Detect Alert Ingestion
        h_det = {"Authorization": f"Bearer {tokens['detector']}"}
        r_alert = client.post("/api/v1/alerts", json=alert_payload, headers=h_det)
        if r_alert.status_code != 200:
            raise HTTPException(r_alert.status_code, f"Alert failed: {r_alert.text}")

        # Step 2: Investigate (Advisory LLM)
        h_op = {"Authorization": f"Bearer {tokens['operator']}"}
        r_inv = client.post(f"/api/v1/incidents/{incident_id}/investigate", json={}, headers=h_op)

        # Step 3: Containment (OPA Policy Check & Security Group Swap)
        core_app.state.service.ec2.groups = ["sg-baseline-workload"]
        core_app.state.service.recovery.scenario = scenario
        r_contain = client.post(f"/api/v1/incidents/{incident_id}/contain", json={}, headers=h_op)

        # Step 4: Request Recovery (EBS Clone + 5-Factor RCS Verification)
        window = {
            "start": (now - timedelta(days=2)).isoformat(),
            "end": (now - timedelta(minutes=15)).isoformat(),
        }

        r_rec = client.post(
            f"/api/v1/incidents/{incident_id}/request-recovery",
            json=window,
            headers=h_op,
        )

        recovery_denied = (r_rec.status_code == 409)
        recovery_data = r_rec.json() if not recovery_denied else {
            "error": "No pre-incident snapshot found within authorized time window.",
            "decision": "DENIED",
            "alert_required": True,
        }

        metrics_snapshot = serialize_metrics_snapshot(core_app.state.store.metrics_snapshot())

        return {
            "incident_id": incident_id,
            "scenario": scenario,
            "timestamp": now.isoformat(),
            "stage_1_detect": {
                "alert": alert_payload,
                "status": "DETECTED",
            },
            "stage_2_investigate": {
                "investigation": r_inv.json(),
                "status": "ANALYZED",
            },
            "stage_3_respond": {
                "containment": r_contain.json(),
                "previous_sg": "sg-baseline-workload",
                "quarantine_sg": r_contain.json().get("quarantine_sg_ids", []),
                "status": "QUARANTINED",
            },
            "stage_4_5_recover_verify": {
                "recovery_denied": recovery_denied,
                "result": recovery_data,
                "status": "DENIED" if recovery_denied else recovery_data.get("verification", {}).get("decision", "COMPLETE"),
            },
            "metrics": metrics_snapshot,
        }

    @dashboard.get("/api/metrics", response_class=PlainTextResponse)
    def get_metrics():
        h_op = {"Authorization": f"Bearer {tokens['operator']}"}
        r = client.get("/metrics", headers=h_op)
        return r.text

    @dashboard.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
    def render_dashboard_page():
        return HTML_DASHBOARD

    return dashboard


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberHeal AI — Autonomous Ransomware Pipeline Dashboard</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.2);
      --amber: #f59e0b;
      --amber-glow: rgba(245, 158, 11, 0.2);
      --rose: #ef4444;
      --rose-glow: rgba(239, 68, 68, 0.2);
      --cyan: #06b6d4;
      --cyan-glow: rgba(6, 182, 212, 0.2);
      --indigo: #6366f1;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 20px; line-height: 1.5; }

    header {
      display: flex; justify-content: space-between; align-items: center;
      padding-bottom: 20px; border-bottom: 1px solid var(--card-border); margin-bottom: 24px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon {
      width: 40px; height: 40px; border-radius: 8px; background: linear-gradient(135deg, var(--cyan), var(--indigo));
      display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 20px;
    }
    .title-group h1 { font-size: 20px; font-weight: 700; color: #fff; }
    .title-group p { font-size: 13px; color: var(--text-muted); }

    .header-badges { display: flex; gap: 10px; align-items: center; }
    .badge {
      display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 9999px;
      font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
    }
    .badge-emerald { background: var(--emerald-glow); color: var(--emerald); border: 1px solid var(--emerald); }
    .badge-cyan { background: var(--cyan-glow); color: var(--cyan); border: 1px solid var(--cyan); }
    .badge-amber { background: var(--amber-glow); color: var(--amber); border: 1px solid var(--amber); }

    /* Pipeline Stages Flow */
    .pipeline-flow {
      display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; position: relative;
    }
    .stage-card {
      background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px;
      padding: 16px; position: relative; transition: all 0.25s ease;
    }
    .stage-card.active { border-color: var(--cyan); box-shadow: 0 0 15px var(--cyan-glow); }
    .stage-card.success { border-color: var(--emerald); box-shadow: 0 0 15px var(--emerald-glow); }
    .stage-card.warn { border-color: var(--amber); box-shadow: 0 0 15px var(--amber-glow); }
    .stage-card.danger { border-color: var(--rose); box-shadow: 0 0 15px var(--rose-glow); }

    .stage-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .stage-num { font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; }
    .stage-status { width: 10px; height: 10px; border-radius: 50%; background: #4b5563; }
    .stage-card.active .stage-status { background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }
    .stage-card.success .stage-status { background: var(--emerald); box-shadow: 0 0 8px var(--emerald); }
    .stage-card.warn .stage-status { background: var(--amber); box-shadow: 0 0 8px var(--amber); }
    .stage-card.danger .stage-status { background: var(--rose); box-shadow: 0 0 8px var(--rose); }

    .stage-title { font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 4px; }
    .stage-desc { font-size: 11px; color: var(--text-muted); line-height: 1.3; }

    /* Main Grid */
    .main-grid {
      display: grid; grid-template-columns: 340px 1fr 340px; gap: 20px; margin-bottom: 24px;
    }

    .card {
      background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
      padding: 20px; display: flex; flex-direction: column;
    }
    .card-title {
      font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
      color: var(--text-muted); margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between;
    }

    /* Controls */
    .scenario-btn-group { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; }
    .btn {
      display: flex; align-items: center; justify-content: space-between; width: 100%;
      padding: 12px 14px; border-radius: 8px; border: 1px solid var(--card-border);
      background: #1e293b; color: #fff; font-size: 13px; font-weight: 600; cursor: pointer;
      transition: all 0.15s ease; text-align: left;
    }
    .btn:hover { background: #334155; transform: translateY(-1px); }
    .btn:active { transform: translateY(0); }
    .btn.btn-clean:hover { border-color: var(--emerald); }
    .btn.btn-tamper:hover { border-color: var(--amber); }
    .btn.btn-health:hover { border-color: var(--amber); }
    .btn.btn-nosnap:hover { border-color: var(--rose); }

    .btn-action {
      background: linear-gradient(135deg, #0284c7, #2563eb); border: none;
      padding: 14px; border-radius: 8px; font-size: 14px; font-weight: 700; cursor: pointer;
      color: white; text-align: center; justify-content: center; margin-top: 10px;
    }
    .btn-action:hover { filter: brightness(1.15); }
    .btn-action:disabled { opacity: 0.6; cursor: not-allowed; }

    /* Middle: RCS Gauge & Radar */
    .rcs-hero {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      padding: 24px 0; border-bottom: 1px solid var(--card-border); margin-bottom: 20px;
    }
    .gauge-container { position: relative; width: 180px; height: 180px; margin-bottom: 16px; }
    .gauge-svg { transform: rotate(-90deg); width: 100%; height: 100%; }
    .gauge-bg { fill: none; stroke: #1f2937; stroke-width: 14; }
    .gauge-fill {
      fill: none; stroke: var(--emerald); stroke-width: 14;
      stroke-linecap: round; stroke-dasharray: 471; stroke-dashoffset: 0;
      transition: stroke-dashoffset 0.8s ease, stroke 0.4s ease;
    }
    .gauge-center-text {
      position: absolute; top: 0; left: 0; width: 100%; height: 100%;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .rcs-number { font-size: 38px; font-weight: 800; color: #fff; line-height: 1; }
    .rcs-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-top: 4px; }

    .decision-pill {
      font-size: 16px; font-weight: 800; padding: 6px 20px; border-radius: 9999px;
      letter-spacing: 1px; text-transform: uppercase;
    }
    .decision-SAFE { background: var(--emerald-glow); color: var(--emerald); border: 2px solid var(--emerald); }
    .decision-REVIEW { background: var(--amber-glow); color: var(--amber); border: 2px solid var(--amber); }
    .decision-UNSAFE, .decision-DENIED { background: var(--rose-glow); color: var(--rose); border: 2px solid var(--rose); }

    /* Factors bars */
    .factors-grid { display: flex; flex-direction: column; gap: 12px; }
    .factor-item { display: flex; flex-direction: column; gap: 4px; }
    .factor-header { display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; }
    .factor-name { color: var(--text); }
    .factor-score { color: #fff; }
    .progress-track { height: 8px; background: #1f2937; border-radius: 4px; overflow: hidden; }
    .progress-bar { height: 100%; width: 100%; background: var(--emerald); border-radius: 4px; transition: width 0.6s ease, background-color 0.4s; }

    /* Right Column: State & Telemetry */
    .state-group { display: flex; flex-direction: column; gap: 14px; }
    .info-box {
      background: #0f172a; border: 1px solid var(--card-border); border-radius: 8px; padding: 12px;
    }
    .info-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; }
    .info-val { font-size: 13px; font-weight: 600; color: #fff; font-family: monospace; word-break: break-all; }
    .info-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .tag-quarantine { background: var(--rose-glow); color: var(--rose); border: 1px solid var(--rose); }
    .tag-baseline { background: var(--cyan-glow); color: var(--cyan); border: 1px solid var(--cyan); }

    /* Bottom: Audit & JSON inspector */
    .tabs-header { display: flex; gap: 8px; margin-bottom: 12px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; }
    .tab-btn {
      background: none; border: none; color: var(--text-muted); font-size: 13px; font-weight: 600;
      padding: 6px 14px; border-radius: 6px; cursor: pointer; transition: all 0.15s ease;
    }
    .tab-btn.active { background: #1e293b; color: var(--cyan); }
    .code-box {
      background: #080c14; border: 1px solid var(--card-border); border-radius: 8px;
      padding: 16px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px; color: #e2e8f0; max-height: 240px; overflow-y: auto; white-space: pre-wrap;
    }

    .pulse { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-icon">&#x26E8;</div>
      <div class="title-group">
        <h1>CyberHeal AI — Autonomous Defense & Recovery</h1>
        <p>End-to-End AWS Redesign Architecture &amp; Verification Pipeline</p>
      </div>
    </div>
    <div class="header-badges">
      <div class="badge badge-cyan" id="opa-status-badge">&#x2714; OPA Rego Active</div>
      <div class="badge badge-emerald" id="env-mode-badge">&#x25CF; Offline Lab Edition</div>
      <button class="btn" style="width: auto; padding: 6px 12px; font-size: 12px;" onclick="refreshStatus()">&#x21BB; Refresh</button>
    </div>
  </header>

  <!-- Pipeline 5 Stages Flow -->
  <div class="pipeline-flow">
    <div class="stage-card" id="card-stage-1">
      <div class="stage-header">
        <span class="stage-num">Stage 1: Detect</span>
        <div class="stage-status"></div>
      </div>
      <div class="stage-title">Wazuh &amp; ML Anomaly</div>
      <div class="stage-desc">Entropy Delta, Rename Rate, and Credential Telemetry</div>
    </div>

    <div class="stage-card" id="card-stage-2">
      <div class="stage-header">
        <span class="stage-num">Stage 2: Investigate</span>
        <div class="stage-status"></div>
      </div>
      <div class="stage-title">Sanitize &amp; Advisory LLM</div>
      <div class="stage-desc">Prompt Injection Guard, Timeline Correlation, Incident Store</div>
    </div>

    <div class="stage-card" id="card-stage-3">
      <div class="stage-header">
        <span class="stage-num">Stage 3: Respond / OPA</span>
        <div class="stage-status"></div>
      </div>
      <div class="stage-title">Policy Containment</div>
      <div class="stage-desc">Rego Gate &amp; EC2 Security Group Quarantine (0 in / 0 out)</div>
    </div>

    <div class="stage-card" id="card-stage-4">
      <div class="stage-header">
        <span class="stage-num">Stage 4: Recover EBS</span>
        <div class="stage-status"></div>
      </div>
      <div class="stage-title">Verified Snapshot Clone</div>
      <div class="stage-desc">Pre-incident snapshot selection &amp; Encrypted Volume Restore</div>
    </div>

    <div class="stage-card" id="card-stage-5">
      <div class="stage-header">
        <span class="stage-num">Stage 5: Verify &amp; RCS</span>
        <div class="stage-status"></div>
      </div>
      <div class="stage-title">5-Factor Release Gate</div>
      <div class="stage-desc">Read-only mount hash scan, Identity, Network, Config, Health</div>
    </div>
  </div>

  <!-- Main 3-Column Layout -->
  <div class="main-grid">

    <!-- Column 1: Controls -->
    <div class="card">
      <div class="card-title">
        <span>Pipeline Execution Deck</span>
        <span style="font-size: 11px; color: var(--cyan);">&#x25B6; Interactive</span>
      </div>

      <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
        Trigger end-to-end incident scenarios across the full Detect &rarr; Investigate &rarr; OPA &rarr; Recover &rarr; Verify pipeline:
      </p>

      <div class="scenario-btn-group">
        <button class="btn btn-clean" onclick="triggerScenario('clean')">
          <div>
            <div>1. Clean Baseline</div>
            <div style="font-size: 11px; color: var(--text-muted); font-weight: normal;">Hash match &bull; RCS 100.0 &bull; SAFE</div>
          </div>
          <span style="color: var(--emerald);">&#x2714;</span>
        </button>

        <button class="btn btn-tamper" onclick="triggerScenario('tampered')">
          <div>
            <div>2. Tampered File Anomaly</div>
            <div style="font-size: 11px; color: var(--text-muted); font-weight: normal;">Disk hash deviation &bull; RCS 75.0</div>
          </div>
          <span style="color: var(--amber);">&#x26A0;</span>
        </button>

        <button class="btn btn-health" onclick="triggerScenario('health_failed')">
          <div>
            <div>3. Health Probe Failure</div>
            <div style="font-size: 11px; color: var(--text-muted); font-weight: normal;">Service check failed &bull; Gate blocks</div>
          </div>
          <span style="color: var(--amber);">&#x26A0;</span>
        </button>

        <button class="btn btn-nosnap" onclick="triggerScenario('no_snapshot')">
          <div>
            <div>4. No Snapshot in Window</div>
            <div style="font-size: 11px; color: var(--text-muted); font-weight: normal;">Pre-incident point missing &bull; Denied</div>
          </div>
          <span style="color: var(--rose);">&#x2716;</span>
        </button>
      </div>

      <div style="margin-top: auto; padding-top: 14px; border-top: 1px solid var(--card-border);">
        <div class="card-title" style="margin-bottom: 10px;"><span>Member A Telemetry</span></div>
        <div style="display: flex; gap: 8px;">
          <button class="btn" style="flex: 1; padding: 8px 10px; font-size: 11px;" onclick="simulateTelemetry('credential')">&#x26A1; Auth Brute</button>
          <button class="btn" style="flex: 1; padding: 8px 10px; font-size: 11px;" onclick="simulateTelemetry('file')">&#x1F4C1; File XOR</button>
        </div>
      </div>
    </div>

    <!-- Column 2: RCS Gauge & 5 Factors -->
    <div class="card">
      <div class="card-title">
        <span>Recovery Confidence Score (RCS)</span>
        <span style="font-size: 11px; color: var(--emerald);">Threshold: &ge; 85.0</span>
      </div>

      <div class="rcs-hero">
        <div class="gauge-container">
          <svg class="gauge-svg" viewBox="0 0 180 180">
            <circle class="gauge-bg" cx="90" cy="90" r="75"></circle>
            <circle class="gauge-fill" id="gauge-arc" cx="90" cy="90" r="75"></circle>
          </svg>
          <div class="gauge-center-text">
            <div class="rcs-number" id="rcs-val">100.0</div>
            <div class="rcs-label">RCS Score</div>
          </div>
        </div>
        <div class="decision-pill decision-SAFE" id="decision-badge">SAFE</div>
      </div>

      <div class="factors-grid">
        <div class="factor-item">
          <div class="factor-header">
            <span class="factor-name">1. Identity &amp; Auth (25%)</span>
            <span class="factor-score" id="score-identity">100%</span>
          </div>
          <div class="progress-track"><div class="progress-bar" id="bar-identity" style="width: 100%;"></div></div>
        </div>

        <div class="factor-item">
          <div class="factor-header">
            <span class="factor-name">2. File Integrity Tree (25%)</span>
            <span class="factor-score" id="score-file">100%</span>
          </div>
          <div class="progress-track"><div class="progress-bar" id="bar-file" style="width: 100%;"></div></div>
        </div>

        <div class="factor-item">
          <div class="factor-header">
            <span class="factor-name">3. Network Quarantine (20%)</span>
            <span class="factor-score" id="score-network">100%</span>
          </div>
          <div class="progress-track"><div class="progress-bar" id="bar-network" style="width: 100%;"></div></div>
        </div>

        <div class="factor-item">
          <div class="factor-header">
            <span class="factor-name">4. Configuration Baseline (15%)</span>
            <span class="factor-score" id="score-config">100%</span>
          </div>
          <div class="progress-track"><div class="progress-bar" id="bar-config" style="width: 100%;"></div></div>
        </div>

        <div class="factor-item">
          <div class="factor-header">
            <span class="factor-name">5. Application Health (15%)</span>
            <span class="factor-score" id="score-health">100%</span>
          </div>
          <div class="progress-track"><div class="progress-bar" id="bar-health" style="width: 100%;"></div></div>
        </div>
      </div>
    </div>

    <!-- Column 3: AWS State & Metrics -->
    <div class="card">
      <div class="card-title">
        <span>Cloud State &amp; Response</span>
        <span style="font-size: 11px; color: var(--cyan);">AWS Mock API</span>
      </div>

      <div class="state-group">
        <div class="info-box">
          <div class="info-label">Active Workload Instance</div>
          <div class="info-val" id="val-instance">i-EXAMPLE</div>
        </div>

        <div class="info-box">
          <div class="info-label">Security Group Isolation</div>
          <div style="display: flex; gap: 6px; align-items: center; margin-top: 4px;">
            <span class="info-tag tag-baseline" id="val-sg-prev">sg-baseline</span>
            <span style="color: var(--text-muted);">&rarr;</span>
            <span class="info-tag tag-quarantine" id="val-sg-curr">sg-quarantine (0 in/out)</span>
          </div>
        </div>

        <div class="info-box">
          <div class="info-label">EBS Recovery Volume</div>
          <div class="info-val" id="val-clone">MOCK-recovered-volume-1</div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Restored from <span id="val-snapshot" style="color: #fff;">snap-EXAMPLE</span></div>
        </div>

        <div class="info-box">
          <div class="info-label">Prometheus Metrics Snapshot</div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px;">
            <div>
              <div style="font-size: 10px; color: var(--text-muted);">Incidents</div>
              <div style="font-size: 16px; font-weight: 700; color: #fff;" id="metric-incidents">0</div>
            </div>
            <div>
              <div style="font-size: 10px; color: var(--text-muted);">Investigations</div>
              <div style="font-size: 16px; font-weight: 700; color: #fff;" id="metric-inv">0</div>
            </div>
          </div>
        </div>

        <div class="info-box">
          <div class="info-label">Operator Release Condition</div>
          <div style="font-size: 12px; color: var(--amber); font-weight: 600;">Manual Operator Review Required</div>
          <div style="font-size: 11px; color: var(--text-muted);">Quarantine cannot be unsealed automatically.</div>
        </div>
      </div>
    </div>

  </div>

  <!-- Bottom: Audit & Payload Inspector -->
  <div class="card">
    <div class="tabs-header">
      <button class="tab-btn active" onclick="switchTab('tab-timeline')">&#x23F1; Execution Timeline</button>
      <button class="tab-btn" onclick="switchTab('tab-alert')">&#x1F6A8; Ingestion Alert</button>
      <button class="tab-btn" onclick="switchTab('tab-opa')">&#x1F510; OPA Policy &amp; Containment</button>
      <button class="tab-btn" onclick="switchTab('tab-verification')">&#x1F4CA; 5-Factor Verification</button>
      <button class="tab-btn" onclick="switchTab('tab-prometheus')">&#x1F4C8; Prometheus /metrics</button>
    </div>

    <div id="tab-timeline" class="code-box">Awaiting scenario execution. Click any scenario button above to trigger the pipeline live.</div>
    <div id="tab-alert" class="code-box" style="display: none;">{}</div>
    <div id="tab-opa" class="code-box" style="display: none;">{}</div>
    <div id="tab-verification" class="code-box" style="display: none;">{}</div>
    <div id="tab-prometheus" class="code-box" style="display: none;">Loading metrics...</div>
  </div>

  <script>
    let currentPayload = null;

    async function refreshStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('metric-incidents').innerText = data.metrics.incidents;
        document.getElementById('metric-inv').innerText = data.metrics.investigations;
        document.getElementById('val-instance').innerText = data.lab.vm_id;
      } catch (e) {
        console.error('Failed to load status', e);
      }
    }

    async function triggerScenario(scenarioName) {
      // Highlight pipeline cards to loading
      for (let i = 1; i <= 5; i++) {
        const el = document.getElementById(`card-stage-${i}`);
        el.className = 'stage-card active pulse';
      }

      try {
        const res = await fetch('/api/run-scenario', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: scenarioName })
        });
        const data = await res.json();
        currentPayload = data;
        updateUIWithExecution(data);
      } catch (err) {
        alert('Scenario execution failed: ' + err);
      }
    }

    function updateUIWithExecution(data) {
      // 1. Update Stages
      document.getElementById('card-stage-1').className = 'stage-card success';
      document.getElementById('card-stage-2').className = 'stage-card success';
      document.getElementById('card-stage-3').className = 'stage-card success';

      if (data.stage_4_5_recover_verify.recovery_denied) {
        document.getElementById('card-stage-4').className = 'stage-card danger';
        document.getElementById('card-stage-5').className = 'stage-card danger';
      } else {
        const dec = data.stage_4_5_recover_verify.result.verification.decision;
        const cls = dec === 'SAFE' ? 'stage-card success' : (dec === 'REVIEW' ? 'stage-card warn' : 'stage-card danger');
        document.getElementById('card-stage-4').className = 'stage-card success';
        document.getElementById('card-stage-5').className = cls;
      }

      // 2. Update Gauge & Factors
      const ver = data.stage_4_5_recover_verify.result.verification;
      if (ver) {
        setRCS(ver.rcs, ver.decision);
        setFactor('identity', ver.factor_scores.identity);
        setFactor('file', ver.factor_scores.file_integrity);
        setFactor('network', ver.factor_scores.network);
        setFactor('config', ver.factor_scores.configuration);
        setFactor('health', ver.factor_scores.health);
        document.getElementById('val-snapshot').innerText = ver.snapshot_id || 'N/A';
      } else {
        setRCS(0, 'DENIED');
        setFactor('identity', 0);
        setFactor('file', 0);
        setFactor('network', 0);
        setFactor('config', 0);
        setFactor('health', 0);
      }

      // 3. Update Cloud State
      document.getElementById('val-sg-prev').innerText = data.stage_3_respond.previous_sg;
      const quars = data.stage_3_respond.quarantine_sg;
      document.getElementById('val-sg-curr').innerText = quars.length ? quars.join(', ') : 'sg-quarantine';

      // 4. Update Metrics Counters
      if (data.metrics) {
        document.getElementById('metric-incidents').innerText = data.metrics.incidents;
        document.getElementById('metric-inv').innerText = data.metrics.investigations;
      }

      // 5. Update Tabs
      const timelineLines = [
        `[${data.timestamp}] Incident ID generated: ${data.incident_id}`,
        `[${data.timestamp}] Stage 1 (Detect): Alert ingested. Type=${data.stage_1_detect.alert.alert_type}, Conf=${data.stage_1_detect.alert.confidence}`,
        `[${data.timestamp}] Stage 2 (Investigate): Advisory report produced. Summary: ${data.stage_2_investigate.investigation.report.summary}`,
        `[${data.timestamp}] Stage 3 (Respond): OPA authorized quarantine. Swapped SG to: ${data.stage_3_respond.quarantine_sg}`,
        ver ? `[${data.timestamp}] Stage 4 (Recover): Pre-incident snapshot selected: ${ver.snapshot_id}` : `[${data.timestamp}] Stage 4 (Recover): Snapshot recovery rejected (No snapshot).`,
        ver ? `[${data.timestamp}] Stage 5 (Verify): 5-Factor RCS computed: ${ver.rcs}. Decision: ${ver.decision}` : `[${data.timestamp}] Stage 5 (Verify): Skipped due to recovery rejection.`
      ];
      document.getElementById('tab-timeline').innerText = timelineLines.join('\\n');
      document.getElementById('tab-alert').innerText = JSON.stringify(data.stage_1_detect.alert, null, 2);
      document.getElementById('tab-opa').innerText = JSON.stringify(data.stage_3_respond.containment, null, 2);
      document.getElementById('tab-verification').innerText = JSON.stringify(data.stage_4_5_recover_verify.result, null, 2);
    }

    function setRCS(score, decision) {
      document.getElementById('rcs-val').innerText = score.toFixed(1);
      const arc = document.getElementById('gauge-arc');
      const circumference = 471;
      const offset = circumference - (score / 100) * circumference;
      arc.style.strokeDashoffset = offset;

      const badge = document.getElementById('decision-badge');
      badge.innerText = decision;
      badge.className = `decision-pill decision-${decision}`;

      if (decision === 'SAFE') {
        arc.style.stroke = 'var(--emerald)';
      } else if (decision === 'REVIEW') {
        arc.style.stroke = 'var(--amber)';
      } else {
        arc.style.stroke = 'var(--rose)';
      }
    }

    function setFactor(key, score) {
      document.getElementById(`score-${key}`).innerText = `${Math.round(score)}%`;
      const bar = document.getElementById(`bar-${key}`);
      bar.style.width = `${score}%`;
      bar.style.background = score >= 70 ? 'var(--emerald)' : 'var(--rose)';
    }

    async function simulateTelemetry(type) {
      try {
        const res = await fetch('/api/simulate-telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type })
        });
        const data = await res.json();
        switchTab('tab-timeline');
        document.getElementById('tab-timeline').innerText = 
          `[MEMBER A SIMULATOR (${type.toUpperCase()})] Generated ${data.events_count} events.\\nExtracted Features: ${JSON.stringify(data.features, null, 2)}\\n\\nFirst 3 events:\\n${JSON.stringify(data.events.slice(0, 3), null, 2)}`;
      } catch (e) {
        alert('Simulator failed: ' + e);
      }
    }

    async function switchTab(tabId) {
      const tabs = ['tab-timeline', 'tab-alert', 'tab-opa', 'tab-verification', 'tab-prometheus'];
      tabs.forEach(id => {
        document.getElementById(id).style.display = (id === tabId) ? 'block' : 'none';
      });
      document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
        btn.className = (tabs[idx] === tabId) ? 'tab-btn active' : 'tab-btn';
      });

      if (tabId === 'tab-prometheus') {
        try {
          const res = await fetch('/api/metrics');
          document.getElementById('tab-prometheus').innerText = await res.text();
        } catch (e) {
          document.getElementById('tab-prometheus').innerText = 'Failed to load metrics: ' + e;
        }
      }
    }

    // Initial load
    refreshStatus();
  </script>
</body>
</html>
"""
