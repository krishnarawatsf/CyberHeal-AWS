# CyberHeal AI — AWS-approved team work division (supersedes OpenStack guide)

**Approved change:** AWS replaces self-hosted OpenStack, with A/B/C services local where practical; one EC2 test workload plus EBS, optional isolated verifier. This does not by itself waive unrelated rubric requirements.

| Role | Build now (offline) | Do later (real AWS integration) | Evidence |
|---|---|---|---|
| A / Detect+Monitor | Keep detector, simulators, alert schema, build Wazuh/CI plan | EC2 FIM agent to secure Wazuh manager, send alert to B, metrics, CI | Wazuh event, alert JSON, dashboard, CI logs |
| B / Investigate+Respond | FastAPI, SQLite audit, LLM advisor, OPA, mocked SG quarantine, exact B→C request | Scoped boto3 SG quarantine, authenticated approval store, C verification result, incident state | OPA tests, quarantined EC2 SG, audit records |
| C / Recover+Verify | RCS and checks, trusted snapshot selector, AWS EBS adapter, signed validation record, IaC template | Provision, capture clean EBS snapshot, attach clone to verifier, collect real five checks, result and cleanup | Tests, `tofu plan`, snapshots, recovered volume, real RCS JSON |

## Handoffs

**A→B:** `docs/contracts/alert.md` v1. `resource.vm_id`=AWS EC2 instance ID; `resource.volume_id`=EBS data volume ID.

**B→C:** `docs/contracts/recovery-request.md` v1 plus protected internal OPA approval lookup and `first_suspicious_at` stored in B's trusted incident timeline. C rejects mismatched/expired/missing approval, bad AWS account or resource, or unverified snapshot.

**C→B/A:** `docs/contracts/verification.md` v1 with EBS `snap-*` ID, RCS, five factor scores and SAFE/REVIEW/UNSAFE. SAFE never follows a skipped/failed critical check. The live demo additionally requires operator approval before reconnecting a quarantined workload.

## Integration order

A alert fixtures → B API and OPA tests → C mock result → AWS account & cost limits → C OpenTofu minimal EC2+EBS → A Wazuh agent / live telemetry → B AWS SG quarantine → C real verified EBS restore → C checks + B/A result → observability, CI, optional scaling → repeated demonstrations and cleanup.

## Decisions requiring explicit group agreement

1. Whether three cloud-hosted VMs and Ansible/Gitea/Woodpecker/scaling are still compulsory under AWS approval.
2. Whether B's incident database and C trusted-snapshot evidence are on same trusted machine or communicated over authenticated service calls.
3. How the verified OPA decision is bound to `recover_volume` and replay prevented.
4. Who authorizes final return-to-service and AWS bill cleanup.

See the detailed individual and deployment guides. The old OpenStack document is archived under `docs/legacy_openstack/`.
