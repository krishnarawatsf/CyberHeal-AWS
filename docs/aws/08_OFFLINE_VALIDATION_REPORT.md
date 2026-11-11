> **Audit note (2026-11-10):** Earlier all-tests/OPA/Terraform results below were provided with the submitted archive and are *historical results recorded on another machine*. They were not reproduced in the current independent audit. Read `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md` for the new fixes. Current audit independently executed A/C and new AWS adapter Python tests; OPA/Terraform executables were not available in the audit runner, and there was no AWS account access. Do not merge historical and newly executed test counts.

# AWS edition — offline validation summary

**Scope:** historical baseline plus current merged-tree status. Nothing in this report is AWS evidence.

## Current merged-tree status

Validated locally on 2026-11-10 with Python 3.13.5, OPA 1.22.2, and Terraform 1.14:

- Combined Python suite: `153 passed`; the symlink/traversal protection test ran on this macOS host.
- OPA policy suite: `14/14 passed`.
- Python source compilation, repository-wide Ruff and Black checks, shell script syntax, Terraform formatting, and Prometheus/alert/CI YAML plus dashboard JSON parsing: passed.
- Loopback HTTP smoke: health, unauthenticated denial, authenticated alert ingestion, investigation, persisted read-back, mock quarantine, and mock recovery all passed. Recovery returned synthetic SAFE/RCS evidence; it is not an AWS result.
- C recovery demo: passed with explicitly mocked AWS/trust sources.
- Terraform `init -backend=false` and `validate`: passed; AWS provider v6.72.0 is checksummed in `infra/tofu/.terraform.lock.hcl`. No plan or apply was run.
- One Starlette deprecation warning was emitted by the installed TestClient/httpx combination.

Docker image build was not run because the Docker daemon is unavailable. CI itself has not yet run on the Woodpecker server.

No AWS provisioning, live containment, EBS attachment, real recovery, or cloud verification was performed. The active local AWS CLI still has only a `default` profile and failed identity verification; do not treat the instance as integrated with this project.

## Historical baseline

The following results were recorded in the source handoff on another machine, NOT reproduced in the current environment:

- Python 3.11+ source tree compiled with `python -m compileall -q src`.
- `python -m pytest -q tests`: **81 tests passed** (A's original Python detection tests plus C's mock EBS, trust-registry, scope, request, snapshot, verification, RCS and workflow tests).
- `PYTHONPATH=src python -m cyberheal_recover.demo` produced `OFFLINE MOCK DEMO — no AWS calls or real authorization`, RCS 100 and SAFE for a fully synthetic clean case.
- Compared original A `src/cyberheal_detect/*` and A tests to the supplied A+C v0.2 archive: 11 source/test files unchanged byte-for-byte.

**Not tested:** OpenTofu plan/apply; live AWS account/EC2/EBS/IAM operations; real Wazuh events; local LLM inference; live AWS Security Group quarantine; volume attachment/mount/read-only scans; real five verification probes; CI execution; AWS Auto Scaling; complete live end-to-end deployment.

**Do not** claim project is fully operational or use the offline SAFE mock as live incident-response evidence. Complete the joint runbook with account-owner approval.
