# CyberHeal AI — AWS student lab edition

**Approved AWS redesign. Offline workflow available; AWS provisioning and real recovery have not been executed.** **New:** see [2026 audit and explicit deployment path](docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md). The project keeps the detect → investigate → OPA response → recover from verified snapshot → verify with RCS architecture using AWS EC2/EBS/IAM/VPC.

Start with [`00_READ_FIRST.md`](00_READ_FIRST.md), then run the offline gate:

```bash
bash scripts/run_offline_validation.sh
```

| Module | Status |
|---|---|
| A: `src/cyberheal_detect` | Original source and unit tests preserved; live AWS event ingestion/Wazuh integration pending |
| B: `src/cyberheal_investigate` / `src/cyberheal_respond` | Offline investigation, response, OPA policy and audit flow implemented; live AWS response pending |
| C: `src/cyberheal_recover` | Offline RCS, checks, signed snapshot registry, authorization, EBS adapter and tests; no live restore yet |
| `infra/tofu/` | AWS EC2/EBS/SSM and SG Terraform template; provider/live validation pending |
| `.woodpecker.yml` | Original A pipeline preserved; needs reviewed updates for AWS/amd64 and B/C tests |

### Workflow stages

1. **Detect** — A's detector and alert contract.
2. **Investigate** — B validates and sanitizes the alert, persists the incident, and produces advisory evidence.
3. **Respond** — B evaluates OPA, applies approval and idempotency controls, and emits a recovery request.
4. **Recover and verify** — C uses the request contract, mock AWS adapter, snapshot registry and RCS checks.
5. **Deploy later** — A+B+C review `tofu plan` and the AWS runbook before any approved live action.

The offline gate covers stages 1–4 with fake dependencies. It must not be described as AWS evidence. The B API exposes authenticated Prometheus metrics at `/metrics`; [`observability/prometheus.yml`](observability/prometheus.yml) is a local scrape example. Configure scrape authentication with a secret, not a committed dashboard value. Recovery verification requires explicit `observed` flags for identity, network, and health evidence instead of treating omitted flags as successful observations. The Terraform workload security group allows no ingress and limits egress to TCP 443 for SSM; public IPv4 and EC2/EBS charges still apply.

### C-only mock demo (no cloud or VS Code)

Windows: run `scripts\run_member_c_demo.bat` after extracting the archive and installing Python 3.11+.

Mac/Linux: `bash scripts/run_member_c_demo.sh`.

Both run mocked C tests and a simulated report. They do not create AWS resources or demonstrate real ransomware recovery.

### Safety / costs

Never share AWS credentials, signing keys, Terraform state or personal data through WhatsApp. Set a billing budget and use a dedicated test account before live work. Do not execute real malware. AWS volumes/snapshots/EC2/public IPv4 can incur charges.

Old OpenStack sources and guides are archived under `docs/legacy_openstack/` and are **not current deployment instructions**.

### Source-only release v0.4

The cleaned release excludes `__MACOSX`, old workspace archives, `.venv`, cached tools and downloaded Terraform binaries. It adds opt-in (default-deny) AWS quarantine and verifier attachment adapters, strict source-volume readiness checks, whole-tree file scanning and additional mock tests. These adapters are **not** enabled in the B API; no live AWS deployment is claimed. Run `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md` with A/B/C before any cloud mutation.
