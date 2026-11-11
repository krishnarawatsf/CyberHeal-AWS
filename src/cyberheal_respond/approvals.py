import json
import secrets
import time

from cyberheal_recover.authorization import TrustedRecoveryDecision


class Approvals:
    def __init__(self, store, lab, ttl=300, clock=time.time):
        self.store, self.lab, self.ttl, self.clock = store, lab, ttl, clock

    def issue(self, value, decision, first_suspicious_at):
        if decision.get("allow") is not True:
            self.store.audit(
                value["incident_id"],
                "policy_denied",
                {"input": value, "result": decision},
            )
            raise PermissionError("OPA denied action")
        if (
            value["scope"] != self.lab.scope
            or value["resource"] != self.lab.resource
            or value["action"] not in {"recover_volume", "quarantine_instance"}
        ):
            raise PermissionError("approval scope mismatch")
        ref = secrets.token_urlsafe(32)
        record = {
            "decision_ref": ref,
            "incident_id": value["incident_id"],
            "action": value["action"],
            "allowed": True,
            **self.lab.scope,
            "resource": self.lab.resource,
            "expires_at": self.clock() + self.ttl,
            "first_suspicious_at": first_suspicious_at,
            "policy_input": value,
            "policy_result": decision,
        }
        with self.store.db() as db:
            db.execute(
                "INSERT INTO approvals(ref,incident_id,action,expires,record) VALUES(?,?,?,?,?)",
                (
                    ref,
                    value["incident_id"],
                    value["action"],
                    record["expires_at"],
                    json.dumps(record),
                ),
            )
        self.store.audit(value["incident_id"], "policy_allowed", record)
        return ref

    def lookup(self, ref):
        with self.store.db() as db:
            row = db.execute("SELECT * FROM approvals WHERE ref=?", (ref,)).fetchone()
            if not row or row["expires"] <= self.clock() or row["consumed"]:
                raise PermissionError("approval absent, expired, or consumed")
            return json.loads(row["record"])

    def consume(self, ref, *, incident, action, resource):
        with self.store.db() as db:
            row = db.execute("SELECT * FROM approvals WHERE ref=?", (ref,)).fetchone()
            if not row or row["expires"] <= self.clock() or row["consumed"]:
                raise PermissionError("approval absent, expired, or consumed")
            record = json.loads(row["record"])
            if (
                record["incident_id"] != incident
                or record["action"] != action
                or record["resource"] != resource
                or any(record[k] != v for k, v in self.lab.scope.items())
            ):
                raise PermissionError("approval binding mismatch")
            db.execute(
                "UPDATE approvals SET consumed=1 WHERE ref=? AND consumed=0", (ref,)
            )
            return record

    @staticmethod
    def c_decision(record):
        return TrustedRecoveryDecision.model_validate(
            {
                key: record[key]
                for key in (
                    "decision_ref",
                    "incident_id",
                    "action",
                    "allowed",
                    "account_id",
                    "resource",
                )
            }
        )
