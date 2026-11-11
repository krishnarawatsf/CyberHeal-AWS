import hmac
import os
from pathlib import Path
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cyberheal_recover.contracts import VerificationResult
from cyberheal_respond.approvals import Approvals
from cyberheal_respond.aws_contain import FakeEC2
from cyberheal_respond.orchestrator import MockRecovery, Orchestrator, validate_result
from cyberheal_respond.policy import OPA, Lab

from .incidents import Store
from .llm_client import LocalLLM
from .sanitize import sanitize
from .schemas import Alert, Empty, RecoveryWindow


def create_app(*, db_path, tokens, policy, lab=None, ec2=None, recovery=None, llm=None):
    if (
        set(tokens) != {"detector", "operator", "internal"}
        or any(len(t) < 32 for t in tokens.values())
        or len(set(tokens.values())) != 3
    ):
        raise ValueError("three distinct tokens of at least 32 characters required")
    lab = lab or Lab()
    store = Store(db_path)
    approvals = Approvals(store, lab)
    ec2 = ec2 or FakeEC2(lab)
    recovery = recovery or MockRecovery(lab)
    llm = llm or LocalLLM()
    service = Orchestrator(
        store=store,
        lab=lab,
        policy=policy,
        approvals=approvals,
        ec2=ec2,
        recovery=recovery,
    )
    app = FastAPI(title="CyberHeal Member B — OFFLINE MOCK", version="0.1.0")
    app.state.store, app.state.service = store, service
    app.state.approvals = approvals
    bearer = HTTPBearer(auto_error=False)

    def auth(role):
        def check(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
            if not credentials or not hmac.compare_digest(
                credentials.credentials, tokens[role]
            ):
                raise HTTPException(401, "valid role-specific bearer token required")
            return {
                "actor": "approved-demo-operator" if role == "operator" else role,
                "roles": ["incident-responder"] if role == "operator" else [role],
            }

        return check

    detector, operator, internal = auth("detector"), auth("operator"), auth("internal")

    @app.exception_handler(PermissionError)
    async def denied(request: Request, exc: PermissionError):
        return JSONResponse(
            status_code=403, content={"detail": "action or approval denied"}
        )

    @app.exception_handler(KeyError)
    async def missing(request: Request, exc: KeyError):
        return JSONResponse(status_code=404, content={"detail": "record not found"})

    @app.exception_handler(ValueError)
    async def conflict(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=409,
            content={"detail": "invalid state or conflicting data; review audit"},
        )

    @app.exception_handler(LookupError)
    async def no_recovery_point(request: Request, exc: LookupError):
        return JSONResponse(
            status_code=409,
            content={
                "detail": "no verified clean recovery point; operator review required"
            },
        )

    @app.exception_handler(RuntimeError)
    async def failed(request: Request, exc: RuntimeError):
        return JSONResponse(
            status_code=503,
            content={"detail": "adapter failed; operator review required"},
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "offline_mock", "live_aws": False}

    @app.post("/api/v1/alerts")
    def alerts(alert: Alert, actor=Depends(detector)):
        if alert.resource.model_dump() != lab.resource:
            raise HTTPException(403, "resource outside lab allow-list")
        item = sanitize(alert)
        return {
            "incident_id": item["incident_id"],
            "created": store.add(item),
            "mock": True,
        }

    @app.get("/api/v1/incidents/{incident_id}")
    def incident(incident_id: UUID, actor=Depends(operator)):
        return store.get(str(incident_id))

    @app.post("/api/v1/incidents/{incident_id}/investigate")
    def investigate(incident_id: UUID, body: Empty, actor=Depends(operator)):
        incident = str(incident_id)
        report = llm.investigate(store.get(incident)["alert"])
        store.investigation(incident, report)
        return report

    @app.post("/api/v1/incidents/{incident_id}/contain")
    def contain(incident_id: UUID, body: Empty, actor=Depends(operator)):
        return service.execute(str(incident_id), "quarantine_instance", actor)

    @app.post("/api/v1/incidents/{incident_id}/request-recovery")
    def recover(incident_id: UUID, window: RecoveryWindow, actor=Depends(operator)):
        return service.execute(str(incident_id), "recover_volume", actor, window)

    @app.get("/internal/v1/approvals/{ref}")
    def approval(ref: str, actor=Depends(internal)):
        return approvals.lookup(ref)

    @app.post("/internal/v1/verification-results")
    def verification(result: VerificationResult, actor=Depends(internal)):
        incident = str(result.incident_id)
        job = store.job(incident, "recover_volume")
        if not job:
            raise PermissionError("no server-created recovery job")
        validate_result(result, incident)
        return store.verification(result, mock=True)

    @app.get("/api/v1/monitoring/results")
    def monitoring(actor=Depends(operator)):
        return store.monitoring()

    @app.get("/metrics", response_class=Response)
    def metrics(actor=Depends(operator)):
        snapshot = store.metrics_snapshot()
        lines = [
            "# HELP cyberheal_incidents_total Accepted incidents.",
            "# TYPE cyberheal_incidents_total counter",
            f"cyberheal_incidents_total {snapshot['incidents']}",
            "# HELP cyberheal_investigations_total Incidents with a persisted investigation.",
            "# TYPE cyberheal_investigations_total counter",
            f"cyberheal_investigations_total {snapshot['investigations']}",
            "# HELP cyberheal_opa_decisions_total Persisted OPA decisions by action and outcome.",
            "# TYPE cyberheal_opa_decisions_total counter",
        ]
        for decision in ("allow", "deny"):
            for action in ("quarantine_instance", "recover_volume"):
                value = snapshot["policy_decisions"].get((decision, action), 0)
                lines.append(
                    f'cyberheal_opa_decisions_total{{decision="{decision}",action="{action}"}} {value}'
                )
        lines.extend(
            [
                "# HELP cyberheal_response_jobs Persisted response jobs by action and state.",
                "# TYPE cyberheal_response_jobs gauge",
            ]
        )
        for job in snapshot["jobs"]:
            if job["action"] not in {"quarantine_instance", "recover_volume"} or job[
                "status"
            ] not in {"running", "complete", "failed"}:
                continue
            lines.append(
                f'cyberheal_response_jobs{{action="{job["action"]}",status="{job["status"]}"}} {job["value"]}'
            )
        lines.extend(
            [
                "# HELP cyberheal_recovery_verifications_total Stored recovery decisions by outcome and mock status.",
                "# TYPE cyberheal_recovery_verifications_total counter",
            ]
        )
        for decision in ("SAFE", "REVIEW", "UNSAFE"):
            for mock in ("true", "false"):
                value = snapshot["verifications"].get((decision, mock), 0)
                lines.append(
                    f'cyberheal_recovery_verifications_total{{decision="{decision}",mock="{mock}"}} {value}'
                )
        return Response(
            content="\n".join(lines) + "\n",
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return app


def app_from_env():
    if os.environ.get("CYBERHEAL_MODE", "mock") != "mock":
        raise ValueError(
            "live AWS is a separate team milestone; this release is mock only"
        )
    db = Path(os.environ.get("CYBERHEAL_DB", "work/member-b.sqlite3"))
    db.parent.mkdir(parents=True, exist_ok=True)
    return create_app(
        db_path=db,
        tokens={
            role: os.environ[f"CYBERHEAL_{role.upper()}_TOKEN"]
            for role in ("detector", "operator", "internal")
        },
        policy=OPA(
            executable=os.environ.get("CYBERHEAL_OPA_EXE"),
            url=os.environ.get("CYBERHEAL_OPA_URL"),
        ),
        llm=LocalLLM(os.environ.get("CYBERHEAL_LLM_URL")),
    )
