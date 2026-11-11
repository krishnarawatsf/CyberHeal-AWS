# CyberHeal Member B v0.1 — offline handoff

Built against `CyberHeal_AWS_MASTER_v0.3_WhatsApp.zip`. This patch adds only B-owned files. A/C source, shared contracts, infrastructure and pipeline files are unchanged.

## What is ready

- Authenticated FastAPI alert, investigation, containment, recovery, incident, internal approval/result and monitoring endpoints.
- SQLite incidents, immutable duplicate-alert behavior, audit events, opaque scoped approvals with 5-minute TTL and atomic one-time consumption, durable job claims and monitoring outbox.
- Strict schema/version/UTC/UUID and approved EC2/EBS pair validation; numeric feature and event-reference sanitization.
- Optional loopback llama.cpp OpenAI-compatible chat client, strict advisory JSON validation and deterministic fallback. The LLM has no tools, cloud adapter, approval or action authority.
- Real OPA Rego evaluation through the local binary or loopback HTTP. Missing OPA, malformed result and anything other than explicit boolean allow fail closed.
- Fake EC2 quarantine with inventory checks, original SG audit before mutation, verified proposed SG state, durable idempotency and no automatic rollback/release.
- In-process integration with **C's unchanged `run_recovery`**, `RecoveryRequest`, `TrustedRecoveryDecision`, snapshot selector, five checks and scoring policy. Snapshot metadata, baseline attestation, EC2, EBS clone and verifier evidence are synthetic.
- Persisted C results and authenticated monitoring feed. `decision != SAFE` raises `alert_required`, including health failure at RCS 85.

## Fast setup on Windows

First extract the master ZIP to a new folder. Copy the patch's named B-owned files into that master, preserving relative paths. Do not run the B-only patch as a standalone project: it imports A's feature names and C's contracts/workflow.

From the merged `CyberHeal-AWS` folder, using Python 3.11 or newer:

```powershell
powershell -ExecutionPolicy Bypass -File docs/member-b/SETUP.ps1
powershell -ExecutionPolicy Bypass -File docs/member-b/DEMO.ps1
```

Setup creates a project virtual environment, installs the master/C/B dependencies, and downloads the official pinned Windows OPA v1.0.1 binary to `work/opa.exe`. It does not install a model or use AWS. The demo uses FastAPI TestClient (in-process HTTP) and real local OPA. It saves SQLite and `DEMO_RESULTS.json` under `work/member-b-demo/`.

Expected demo output:

```text
clean: SAFE (RCS 100.0), alert_required=False
tampered: REVIEW (RCS 75.0), alert_required=True
health_failed: REVIEW (RCS 85.0), alert_required=True
no_snapshot: DENIED; no recovery clone created
```

Repeated requests reuse their stored result. Exactly three synthetic clones are recorded across these four scenarios, even though each successful recovery is requested twice. SAFE does not release quarantine.

## Run the real local API

```powershell
powershell -ExecutionPolicy Bypass -File docs/member-b/START_API.ps1
```

Open `http://127.0.0.1:8000/docs`. The launcher prints three newly generated, distinct private local tokens. Keep them out of shared evidence/screenshots. Requests use `Authorization: Bearer <role token>`. Swagger's Authorize button accepts the token for the endpoint's required role; replace it when switching roles.

| Route | Token role | Body |
|---|---|---|
| `GET /health` | none | none |
| `POST /api/v1/alerts` | detector | v1 A alert |
| `GET /api/v1/incidents/{id}` | operator | none |
| `POST /api/v1/incidents/{id}/investigate` | operator | `{}` |
| `POST /api/v1/incidents/{id}/contain` | operator | `{}` |
| `POST /api/v1/incidents/{id}/request-recovery` | operator | `{ "start": "...Z", "end": "...Z" }` |
| `GET /internal/v1/approvals/{ref}` | internal | none |
| `POST /internal/v1/verification-results` | internal | exact C v1 result |
| `GET /api/v1/monitoring/results` | operator | none |

Use the sample alert in the AWS B guide with `i-EXAMPLE` and `vol-EXAMPLE`. These are intentionally mock IDs. Keep its timestamp and the suggested pre-incident window consistent, or use the demo to generate current timestamps. Alert identity, scope, first suspicious time, policy subject and action cannot be supplied in a recovery request.

The authenticated detector's alert timestamp becomes the immutable trusted first suspicious time. A must supply trustworthy telemetry and the actual first event time during integration. The API is loopback-only for local development; remote team access needs a separately configured authenticated TLS/private transport.

## Optional local LLM

Start your own local llama.cpp server with an appropriate GGUF model, then set this before starting the API:

```powershell
$env:CYBERHEAL_LLM_URL = 'http://127.0.0.1:8080/v1/chat/completions'
```

No model weights or llama.cpp server are included. Real model inference has not been demonstrated on this machine. Valid, malformed, extra-field and timeout responses are tested with HTTP stubs. Unavailable/invalid inference produces a labeled deterministic report. Only allow-listed numeric features and incident type/time/confidence reach the prompt; raw evidence and credentials do not.

## Tests

From the merged project root:

```powershell
$env:CYBERHEAL_OPA_EXE = (Resolve-Path work/opa.exe).Path
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
./.venv/Scripts/python.exe -m pytest -q tests/test_investigate_api.py tests/test_respond_flow.py
./work/opa.exe test respond/policies -v
./.venv/Scripts/python.exe -m pytest -q tests
```

The original C symlink test requires Windows symbolic-link privileges, Developer Mode or a compatible Linux environment. On this machine that unchanged test fails before executing the scanner with `WinError 1314`. To reproduce the rest of the combined suite here:

```powershell
./.venv/Scripts/python.exe -m pytest -q tests -k 'not test_hash_scan_blocks_symlinks'
```

See `TEST_RESULTS.md` for actual outcomes and limitations. Do not label the excluded test as passed.

On Linux/macOS, use a Python venv and the official matching OPA executable; set `CYBERHEAL_OPA_EXE` accordingly. The Python module and tests are platform neutral; the supplied PowerShell launchers are for Windows.

## Approval and recovery behavior

The operator token maps to `approved-demo-operator` with only `incident-responder`; public callers cannot submit roles. `lab.json` is server-owned OPA inventory. The sample policy requires exact account, Region, tag, resource pair, operator and action. Unknown actions are denied.

Each allow record stores exact policy input/result, version, resource, account/Region/tag, incident ID, expiry and trusted timestamp. The internal lookup returns only unconsumed, unexpired approvals. The in-process orchestrator atomically consumes an approval and passes the resulting trusted internal object directly to C. Consumed references cannot be replayed or looked up as fresh approvals. An independent C HTTP worker is not implemented; do not use read-only lookup as a substitute for atomic consumption in a future distributed design.

Jobs are uniquely keyed by incident and action. A completed job returns its original output even after approval expiry. A running/failed job is never retried automatically, including after restart; an operator must reconcile it. This deliberately favors avoiding duplicate cloud operations over automatic retry. Unknown adapter exceptions are audited with a generic message, without raw error bodies or secrets.

Monitoring uses a durable outbox available at the authenticated monitoring endpoint; A must poll it or add their chosen transport. There is no configured remote dashboard push in this release. Verification results retain C's exact v1 payload inside an envelope with mock and alert flags. Late, conflicting, unbound or inconsistent SAFE results are rejected. The stricter SAFE result validation reflects C's current binary checks.

## Team handoff and remaining live milestone

Send **only `CyberHeal_B_v0.1_patch.zip` and its checksum** to A/C, rather than the entire local merged copy. A should merge into a new master version and run the union of tests. Do not ship virtual environments, SQLite databases, tokens, AWS credentials/state or model weights.

Before following `docs/aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md` together, A should provide a real recorded detector alert and confirm monitoring integration. C should provide reviewed inventory, scoped roles and actual snapshot/verifier evidence. Current approvals use local bearer authentication and local SQLite, suitable for this trusted laptop rehearsal.

**Not implemented or demonstrated in this B release:** live boto3 Security Group mutation, AWS account/IAM/ENI discovery, actual EC2/EBS snapshots/clones/attachments, live isolated verification, production release, and remote dashboard delivery. `CYBERHEAL_MODE` accepts only `mock`; there is no hidden live switch. The next team phase must implement/review the live EC2 adapter, check account/Region/tag/single ENI and attached data volume, preserve SGs before mutation, verify the applied state, use a scoped role and plan Console rollback. No IAM user is disabled by this release.

OPA sources: [Rego language](https://www.openpolicyagent.org/docs/policy-language), [official OPA v1.0.1 release](https://github.com/open-policy-agent/opa/releases/tag/v1.0.1). FastAPI authentication reference: [security](https://fastapi.tiangolo.com/tutorial/security/first-steps/).
