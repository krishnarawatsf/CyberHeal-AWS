"""Reproducible offline API demonstration, using real OPA and C's real scoring."""

import argparse
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from cyberheal_respond.policy import OPA

from .api import create_app


def main():
    parser = argparse.ArgumentParser(
        description="Member B OFFLINE MOCK demonstration; no AWS calls"
    )
    parser.add_argument(
        "--opa",
        default=os.environ.get("CYBERHEAL_OPA_EXE"),
        required=not os.environ.get("CYBERHEAL_OPA_EXE"),
    )
    parser.add_argument("--output", default="work/member-b-demo")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    tokens = {
        role: secrets.token_urlsafe(32) for role in ("detector", "operator", "internal")
    }
    app = create_app(
        db_path=output / "incidents.sqlite3",
        tokens=tokens,
        policy=OPA(executable=args.opa),
    )
    now = datetime.now(UTC) - timedelta(minutes=1)
    evidence = {
        "mode": "OFFLINE MOCK — NO AWS CALLS",
        "llm": "deterministic fallback; no model configured",
        "scenarios": [],
    }
    with TestClient(app) as client:
        for scenario in ("clean", "tampered", "health_failed", "no_snapshot"):
            incident = str(uuid4())
            alert = {
                "schema_version": "1.0",
                "incident_id": incident,
                "timestamp": now.isoformat(),
                "resource": app.state.service.lab.resource,
                "alert_type": "ransomware_like",
                "confidence": 0.92,
                "features": {"rename_rate": 12.0, "entropy_delta": 2.1},
                "evidence_refs": ["event:controlled-demo"],
            }

            def post(path, payload, role="operator", expected=200):
                response = client.post(
                    path,
                    json=payload,
                    headers={"Authorization": "Bearer " + tokens[role]},
                )
                if response.status_code != expected:
                    raise RuntimeError(
                        f"{path}: expected {expected}, got {response.status_code}; check audit"
                    )
                return response.json()

            post("/api/v1/alerts", alert, "detector")
            investigation = post(f"/api/v1/incidents/{incident}/investigate", {})
            # Every incident is an independent synthetic EC2 simulation.
            app.state.service.ec2.groups = ["sg-MOCK-original"]
            app.state.service.recovery.scenario = scenario
            containment = post(f"/api/v1/incidents/{incident}/contain", {})
            window = {
                "start": (now - timedelta(days=2)).isoformat(),
                "end": (now - timedelta(minutes=15)).isoformat(),
            }
            result = post(
                f"/api/v1/incidents/{incident}/request-recovery",
                window,
                expected=409 if scenario == "no_snapshot" else 200,
            )
            record = {
                "scenario": scenario,
                "incident_id": incident,
                "investigation": investigation,
                "containment": containment,
                "result": result,
            }
            if scenario != "no_snapshot":
                repeated = post(
                    f"/api/v1/incidents/{incident}/request-recovery", window
                )
                assert repeated == result
                record["duplicate_request_reused_result"] = True
                print(
                    f"{scenario}: {result['verification']['decision']} (RCS {result['verification']['rcs']}), alert_required={result['alert_required']}"
                )
            else:
                print("no_snapshot: DENIED; no recovery clone created")
            evidence["scenarios"].append(record)
        evidence["mock_clone_count"] = len(app.state.service.recovery.clones)
        assert evidence["mock_clone_count"] == 3
        evidence["monitoring"] = app.state.store.monitoring()
        # Genuine OPA deny, without a side effect.
        value = {
            "subject": {
                "actor": "approved-demo-operator",
                "roles": ["incident-responder"],
            },
            "action": "delete_volume",
            "scope": app.state.service.lab.scope,
            "resource": app.state.service.lab.resource,
            "incident_id": str(uuid4()),
        }
        evidence["unknown_action_policy_result"] = app.state.service.policy.evaluate(
            value
        )
        assert evidence["unknown_action_policy_result"]["allow"] is False
    path = output / "DEMO_RESULTS.json"
    path.write_text(json.dumps(evidence, indent=2, ensure_ascii=True), encoding="utf-8")
    print(
        "OFFLINE MOCK ONLY. Live containment/recovery and real LLM inference are not demonstrated."
    )
    print("Evidence:", path.resolve())


if __name__ == "__main__":
    main()
