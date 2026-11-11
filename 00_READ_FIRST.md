# CyberHeal AI — AWS redesign (approved), team master

**Status:** Offline Python implemented/tested; AWS provision and real recovery have NOT been executed. Never present the mock demonstration as live recovery.

## Workflow

1. Read [`README.md`](README.md) for the current status and commands.
2. Run the offline gate: `bash scripts/run_offline_validation.sh` (or `powershell -ExecutionPolicy Bypass -File scripts/run_offline_validation.ps1`).
3. Use [`docs/aws/01_MEMBER_B_BUILD_GUIDE.md`](docs/aws/01_MEMBER_B_BUILD_GUIDE.md) for B's implementation details.
4. Use [`docs/aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md`](docs/aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md) only after the offline gate passes.
5. Follow the ownership and deployment sequence in [`docs/aws/07_TEAM_WORK_DIVISION_AWS.md`](docs/aws/07_TEAM_WORK_DIVISION_AWS.md).
6. Use [`docs/aws/06_WHATSAPP_MERGE_AND_RELEASE.md`](docs/aws/06_WHATSAPP_MERGE_AND_RELEASE.md) only when exchanging patches without Git.

## Who owns what

- **A — Detection/monitoring/DevOps.** Original `src/cyberheal_detect/` and original pipeline preserved. A must adapt and test Wazuh/telemetry/CI for AWS.
- **B — Investigation/response.** Implemented offline in `src/cyberheal_investigate/`, `src/cyberheal_respond/`, `respond/policies/` and the audit store. Live AWS response is still pending.
- **C — Recover/verify/AWS infrastructure.** `src/cyberheal_recover/` and `infra/tofu/`. Offline code and AWS API adapter tests ready; live verification, volume attachment and release are NOT implemented.

## Zero-cloud-cost demos

Run the full offline workflow first:

```bash
bash scripts/run_offline_validation.sh
```

For the C-only mock demo, use `scripts/run_member_c_demo.bat` on Windows or `bash scripts/run_member_c_demo.sh` on macOS/Linux.

All offline commands use fake AWS/LLM sources and show **MOCK** results. They do **not** connect to AWS.

## Critical preconditions for live AWS

- AWS account owner approves a dedicated test account, Region, cost budget and maximum resource usage.
- No credentials or state files in Git/WhatsApp. Use SSO/role credentials, not long-lived root keys.
- `infra/tofu/` uses an existing **default VPC** and subnet. If not available, pause and modify the design; do not invent a VPC configuration during demo.
- `tofu plan` must be reviewed and approved before `tofu apply`.
- Do not run any untrusted sample code or attacks. Only controlled file operations in the test sample directory.

## Source history

The old OpenStack guides/source are under `docs/legacy_openstack/` **for historical reference only**. Do not deploy from them. Original A detection source and tests are preserved. The merged tree includes B's offline implementation, but it does not claim live AWS response is implemented.

## Audit update — v0.4

Start with `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md` to see verified findings, fixes, exact team responsibilities, and the staged AWS deployment. New cloud adapters default to mutation denial; do **not** turn them on without reviewed IAM and OPA integration. No live cloud tests were performed in this audit.
