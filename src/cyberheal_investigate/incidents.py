"""Small durable SQLite store. A claimed action is never retried automatically."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime


def now():
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, path):
        self.path = str(path)
        with self.db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, alert TEXT NOT NULL,
                    first_suspicious_at TEXT NOT NULL, investigation TEXT, result TEXT);
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, incident_id TEXT,
                    timestamp TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS approvals(ref TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
                    action TEXT NOT NULL, expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
                    record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(incident_id TEXT, action TEXT, status TEXT NOT NULL,
                    output TEXT, PRIMARY KEY(incident_id, action));
                CREATE TABLE IF NOT EXISTS outbox(incident_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            """
            )

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def audit(self, incident, action, detail):
        with self.db() as db:
            db.execute(
                "INSERT INTO audit(incident_id,timestamp,action,detail) VALUES(?,?,?,?)",
                (incident, now(), action, json.dumps(detail)),
            )

    def add(self, alert):
        incident = alert["incident_id"]
        raw = json.dumps(alert, sort_keys=True)
        with self.db() as db:
            existing = db.execute(
                "SELECT alert FROM incidents WHERE id=?", (incident,)
            ).fetchone()
            if existing:
                if existing["alert"] != raw:
                    raise ValueError(
                        "incident ID already exists with different content"
                    )
                return False
            db.execute(
                "INSERT INTO incidents(id,alert,first_suspicious_at) VALUES(?,?,?)",
                (incident, raw, alert["timestamp"]),
            )
            db.execute(
                "INSERT INTO audit(incident_id,timestamp,action,detail) VALUES(?,?,?,?)",
                (incident, now(), "alert_accepted", raw),
            )
        return True

    def get(self, incident):
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM incidents WHERE id=?", (incident,)
            ).fetchone()
            if not row:
                raise KeyError("unknown incident")
            item = dict(row)
            for key in ("alert", "investigation", "result"):
                item[key] = json.loads(item[key]) if item[key] else None
            item["timeline"] = [
                dict(r)
                for r in db.execute(
                    "SELECT timestamp,action,detail FROM audit WHERE incident_id=? ORDER BY seq",
                    (incident,),
                )
            ]
            item["jobs"] = [
                dict(r)
                for r in db.execute(
                    "SELECT action,status,output FROM jobs WHERE incident_id=?",
                    (incident,),
                )
            ]
            return item

    def investigation(self, incident, report):
        with self.db() as db:
            db.execute(
                "UPDATE incidents SET investigation=? WHERE id=?",
                (json.dumps(report), incident),
            )
        self.audit(
            incident,
            "investigated",
            {"source": report["source"], "error": report["error"]},
        )

    def job(self, incident, action):
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE incident_id=? AND action=?",
                (incident, action),
            ).fetchone()
            return dict(row) if row else None

    def claim(self, incident, action):
        with self.db() as db:
            cursor = db.execute(
                "INSERT OR IGNORE INTO jobs VALUES(?,?,?,NULL)",
                (incident, action, "running"),
            )
            if cursor.rowcount != 1:
                raise ValueError("action already claimed; operator review required")

    def finish(self, incident, action, status, output):
        with self.db() as db:
            db.execute(
                "UPDATE jobs SET status=?,output=? WHERE incident_id=? AND action=?",
                (status, json.dumps(output), incident, action),
            )
        self.audit(incident, action + "_" + status, output)

    def verification(self, result, *, mock):
        incident = str(result.incident_id)
        payload = result.model_dump(mode="json")
        with self.db() as db:
            row = db.execute(
                "SELECT result FROM incidents WHERE id=?", (incident,)
            ).fetchone()
            if not row:
                raise KeyError("unknown incident")
            if row["result"] and json.loads(row["result"]) != payload:
                raise ValueError("conflicting verification result")
            db.execute(
                "UPDATE incidents SET result=? WHERE id=?",
                (json.dumps(payload), incident),
            )
            envelope = {
                "verification": payload,
                "alert_required": result.decision != "SAFE",
                "mock": mock,
                "release_requires_operator": True,
            }
            db.execute(
                "INSERT OR REPLACE INTO outbox VALUES(?,?)",
                (incident, json.dumps(envelope)),
            )
        self.audit(incident, "verification_stored", envelope)
        return envelope

    def monitoring(self):
        with self.db() as db:
            return [
                json.loads(row[0])
                for row in db.execute("SELECT payload FROM outbox ORDER BY incident_id")
            ]

    def metrics_snapshot(self):
        with self.db() as db:
            incidents = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            investigations = db.execute(
                "SELECT COUNT(*) FROM incidents WHERE investigation IS NOT NULL"
            ).fetchone()[0]
            jobs = [
                dict(row)
                for row in db.execute(
                    "SELECT action,status,COUNT(*) AS value FROM jobs GROUP BY action,status"
                )
            ]
            decisions = {"allow": 0, "deny": 0}
            for row in db.execute(
                "SELECT action,detail FROM audit WHERE action IN ('policy_allowed','policy_denied')"
            ):
                detail = json.loads(row["detail"])
                decision = "allow" if row["action"] == "policy_allowed" else "deny"
                action = detail.get("action") or detail.get("policy_input", {}).get(
                    "action"
                )
                if action in {"quarantine_instance", "recover_volume"}:
                    decisions[(decision, action)] = (
                        decisions.get((decision, action), 0) + 1
                    )
            verifications = {}
            for row in db.execute(
                "SELECT i.result,o.payload FROM incidents i JOIN outbox o ON o.incident_id=i.id WHERE i.result IS NOT NULL"
            ):
                result = json.loads(row["result"])
                envelope = json.loads(row["payload"])
                label = (result["decision"], str(envelope["mock"]).lower())
                verifications[label] = verifications.get(label, 0) + 1
        return {
            "incidents": incidents,
            "investigations": investigations,
            "jobs": jobs,
            "policy_decisions": decisions,
            "verifications": verifications,
        }
