# CyberHeal AI AWS — complete team deployment runbook

**Audience:** Members A, B, C. **Status:** Planned deployment, not an installation that has already been performed. B's offline implementation is present in this merged project; all three should follow this checklist together only after the combined offline acceptance tests pass and the account owner approves the deployment plan and potential charges. No Git or VS Code is required, though they help.

## End goal and minimum demonstration

An approved sample-data anomaly on an EC2-attached EBS volume emits A's Wazuh/ML alert → B stores and explains incident (local LLM advisory), gets OPA allow and quarantines **only the test instance** by switching to no-egress Security Group → B creates an incident-scoped approved recovery request → C selects a pre-incident, independently verified EBS snapshot, creates a **new encrypted** EBS volume, attaches it to a separate isolated verifier and reads it **without writing** → C measures file/config/identity/network/health, computes RCS with release gates → B stores C's result, A displays it → operator decides final release. Negative tests show denial/failure paths.

**Student-minimum architecture:** A and B services on laptops/local Linux/Docker, C Python controller on a trusted operator laptop, one short-lived EC2 test instance + EBS data volume, and a temporary verifier EC2 only when needed. No three always-on application EC2 servers, GPU, NAT Gateway, RDS or Kubernetes. The verifier is not a scaling tier.

## Phase 0 — Lock scope and people (everyone; no cloud actions)

- [ ] Record supervisor permission to use **AWS instead of OpenStack** and reduce 3 cloud VMs to 1 test EC2 + temporary verifier.
- [ ] Confirm whether Wazuh, Gitea/Woodpecker, OpenTofu, Ansible and **Auto Scaling** are mandatory rubric items. Do not silently drop them: if required, assign evidence and implement after the core loop.
- [ ] A is integration/release coordinator. B owns backend/OPA and quarantine. C is sole Terraform/AWS volume operator. Designate one person responsible for AWS bills and cleanup.
- [ ] Agree one AWS account, one Region, initial budget, test-name prefix and `CyberHealLab` tag. Agree maximum demo runtime and data sizes.
- [ ] Agree `docs/contracts/*.md` as **v1 AWS-specific contract semantics**. The JSON field names are preserved but `vm_id=i-*`, `volume_id=vol-*`, `snapshot_id=snap-*`; internal `account_id` is the 12-digit AWS account ID. B's offline implementation binds OPA decisions and the trusted first-suspicious time; all three must review how that trust is maintained across live service boundaries.
- [ ] A maintains `CyberHeal_AWS_MASTER_vX.Y.zip`; B and C each deliver only named patches. See `06_WHATSAPP_MERGE_AND_RELEASE.md`.

## Phase 1 — Finish local modules independently before AWS

**A:** Keep `src/cyberheal_detect/`, run original tests, produce a schema-versioned alert JSON for both scenarios, determine how events from EC2 are exported to detector and Wazuh. Decide where Wazuh manager and Prometheus/Grafana run locally. Wazuh manager is significantly larger than a lightweight agent; don't place it on a tiny EC2 by default.

**B:** Review the implementation against `01_MEMBER_B_BUILD_GUIDE.md`, configure official OPA locally, run API and Rego acceptance tests, and resolve failures. The FastAPI/SQLite/advisory LLM/OPA/mock quarantine and C integration modules are already present. No AWS access is needed for this phase.

**C:** Run `scripts/run_member_c_demo.bat` (or `scripts/run_member_c_demo.sh`) and tests, review new `aws_ebs.py`, `aws_trust_registry.py`, `aws_preflight.py` and Terraform templates. No live cloud calls yet. Prepare legitimate real verification evidence plan and sign-off.

**Integration rehearsal:** A creates a sample alert JSON; B posts it to local endpoint; B produces an OPA reference and recovery request; C's **mock** responds; B stores and A displays JSON. Use no AWS secrets. This is only *offline integration*. Do not proceed to AWS phases until the OPA-backed test suite passes.

## Phase 2 — AWS account and cost controls (account owner + C)

1. Create/use a dedicated student AWS test account. Do not use root access keys. Set billing alerts with AWS Budgets; inspect Free Tier/credit status and per-region pricing. Set a cleanup deadline.
2. Choose one Region (example `ap-south-1`, not a requirement) and verify available EC2 instance classes/quotas and EBS costs. An internet-reachable public IPv4 address is **charged**; this starter uses one to reach SSM over HTTPS without NAT Gateway or private VPC endpoints.
3. Configure AWS CLI v2 on C operator machine with short-lived SSO/role credentials; `aws configure sso` where supported, then:

```powershell
aws sts get-caller-identity --profile STUDENT_LAB
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --region ap-south-1 --profile STUDENT_LAB
aws ec2 describe-subnets --filters "Name=default-for-az,Values=true" --region ap-south-1 --profile STUDENT_LAB
```

4. Confirm AWS account ID matches planned 12-digit ID. **STOP** if default VPC or public subnet is missing; Terraform template assumes both. Don't weaken access rules to make deployment work.
5. Use only scoped IAM roles/permissions; the provisioning operator needs enough permissions to create EC2/SSM IAM profile, SG, volume and instance. Runtime B/C identities should only access approved tagged resources and operations. Review [AWS IAM tag-based controls](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html). Prevent inappropriate resource retagging. Do not send credentials or state through WhatsApp.

## Phase 3 — C provisions *minimal* infrastructure (OpenTofu)

Prerequisites: OpenTofu binary installed, AWS CLI authenticated, account owner approval, default VPC, AWS provider download access.

```powershell
cd infra/tofu
Copy-Item terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: real 12-digit account, approved Region and lab tag only.
# Do not enter AWS secret keys.
tofu init
tofu fmt -check
tofu validate
tofu plan -out=cyberheal.plan
# STOP HERE: review the entire proposed plan + expected spend with A/B.
tofu apply cyberheal.plan
# Record outputs privately; do not upload state or plan files to WhatsApp.
tofu output
```

The plan creates **one EC2 test workload**, encrypted gp3 EBS sample volume, no-inbound SSM SG, no-egress quarantine SG, IAM role/instance profile and EBS attachment. `enable_verifier=false` by default. The test instance has a billed public IPv4 and no inbound SSH; SSM access is outbound HTTPS. The source data volume has `prevent_destroy=true`. Terraform plans and state are potentially sensitive; keep local, secure and backed up, with **C as sole state operator**. It is not safe to run a second independent `tofu apply` from a WhatsApp ZIP without the same state.

Record **only** resource IDs, Region, AZ and allowed SG IDs in a private controlled integration config (not credentials). Share sanitized values with B/A. Terraform `apply` may fail on quotas, default VPC, AMI availability or IAM permissions; fix by inspecting the error instead of loosening every permission.

## Phase 4 — Prepare EBS test data and known-good snapshot (C + A)

1. Check EC2 is listed and appears in AWS Systems Manager `Managed nodes`. For Session Manager, use the AWS Console or CLI:

```powershell
aws ssm start-session --target i-REPLACE --region ap-south-1 --profile STUDENT_LAB
```

This requires SSM plugin/role/network readiness. **No inbound TCP/22 is needed.**

2. Identify attached data EBS using `lsblk -f` and `sudo blkid`. EC2 Nitro devices may be `/dev/nvme...`; the Terraform request `/dev/sdf` is not a reliable Linux filesystem path. Verify the filesystem is **new and blank** before formatting, and only format the approved **data** volume (never the root volume or restored volume). Stop if uncertain.
3. Mount at a dedicated directory such as `/srv/cyberheal-sample`; create harmless sample files (no production or personal data), build SHA-256 manifest and application config baseline. Record expected file set, expected checksums and a clear test health criterion.
4. For a simple consistent lab baseline: flush/unmount, stop EC2, detach the EBS data volume, wait until `available`, take a snapshot, wait for state `completed`. Do not take a snapshot after simulation and label it clean.
5. Perform independent known-good validation and create a signed attestation with C's `attest_cli`, keeping the signing key in the operator's secret store, **outside the ZIP**. The attestation binds snapshot ID, source volume, AWS account, Region, lab tag, AWS creation time and checked baseline hashes. Restore the original EBS attachment and mount after snapshot. Store snapshot and attestation safely.
6. A runs a controlled file simulator only inside the pre-approved sample directory. Keep a reversible clean sample, ensure Wazuh/ML detects the anomaly and labels a real first suspicious timestamp. No real ransomware or real credential abuse.

## Phase 5 — A monitoring / telemetry (A lead)

- Deploy Wazuh manager on suitable local Linux/Docker hardware, Wazuh agent on AWS EC2, or obtain supervisor-approved lab topology. Remote telemetry needs an authenticated and securely connected transport; avoid opening Wazuh server publicly on a home router. A VPN/tunnel or managed network is a separate setup step. Test agent status with one benign file-integrity modification.
- Run A's feature extraction and scikit-learn detector with same stable schema as `docs/contracts/alert.md`. Send a validated alert into B's API and retain evidence refs, timestamps and counts.
- Run Prometheus/Grafana/Alertmanager locally; record alert count, response success/failure, C RCS and decision. C currently does not expose Prometheus metrics; A/B/C must add a small authenticated metrics adapter when integrating. Alert when `decision != SAFE` **even if RCS >=85** and when restore fails.
- A maintains CI/CD; the original `.woodpecker.yml` references Mac ARM builds and only A tests. Use `docs/aws/04_MEMBER_A_MIGRATION.md` to propose AWS-compatible changes. There is no Gitea or Woodpecker deployment bundled in this package.

## Phase 6 — B investigation and containment (B lead)

- Start FastAPI, OPA and local LLM services. In tests, replace LLM and AWS with fake adapters. Send A's alert; verify sanitized investigation and incident log.
- B resolves `vm_id` and `volume_id` against C's approved AWS lab inventory, checks OPA, and records a decision-bound approval ref with expiry. Do not let the LLM authorize.
- Once approved, apply **only** the no-egress SG to the test instance; log original SG and verify changed state using AWS. It will disrupt SSM: A/B must capture evidence first and know how to restore the original SG via AWS Console. Never change other instances/SGs.
- B stores `first_suspicious_at` based on trusted event timeline and sends the v1 recovery request to C. A recovery approval must cover `recover_volume` explicitly, not merely `quarantine_instance`; two distinct actions may require separate OPA decisions.

## Phase 7 — C real recovery, verification and result (C lead)

**Current gap: not yet turnkey.** The gateway implements **new volume creation**, and a separate opt-in attachment adapter (`aws_attach.py`) now exists but is not wired into the approved live job runner. Read-only file comparison CLI is available; all five independent live probes are not. The following live work still must be completed with B/C and tested in AWS:

1. From B's protected audit store, resolve signed/scoped OPA `recover_volume` approval and trusted first suspicious timestamp, enforce expiry and no replay. Validate account/Region/lab tag and exact EC2/EBS pair.
2. Read AWS completed snapshot metadata and C's separate signed validation registry, select latest clean snapshot before suspicious time in requested window; fail closed if none.
3. Create a new encrypted recovery EBS volume from that snapshot (C's `AwsEbsLabGateway`), leave original EBS volume/snapshot intact. It is a charged resource. Wait for `available`.
4. Enable temporary verifier only for verified recovery test: change `enable_verifier=true`, review Terraform plan and apply. Verify same AZ, healthy SSM access, no inbound ports.
5. Attach recovered volume to **verifier EC2**, not original compromised test instance. Identify correct device (NVMe mapping), mount read-only, scan files against signed baseline, and collect configuration hashes. Do not mount/execute untrusted scripts read-write.
6. Collect remaining trusted evidence: test identity/account disabled/expected roles, test instance still quarantined and no unwanted SG exposures, application functional test in isolated environment, and approved config. Do not invent a `health=100` check from a mere snapshot ID.
7. Feed trusted `VerificationEvidence` into C's five checks and RCS; if any check didn't complete or failed, refuse automatic SAFE. Create exact v1 result and audit result, EBS recovered volume ID and operator decision. If a manual proof is used, label it as operator-assisted, not fully automated.
8. B records C result and A dashboard displays score + decision and failed status. Do not undo quarantine without an operator release decision. Revoke incident credentials if applicable only for designated test identity.
9. Preserve snapshots for demonstration/audit; plan explicit cleanup of temporary verifier/recovery volumes when audit complete.

## Phase 8 — end-to-end security tests (all 3)

Run the entire flow at least twice, record logs, UTC times and screenshots of actual AWS resource IDs (mask secrets). Required outcomes:

| Scenario | Expected response |
|---|---|
| Known-good baseline + simulated file anomaly | A alert → B OPA allow/quarantine → C select old clean snapshot → real restore→ all checks → SAFE only if policy passes |
| Tampered snapshot / changed manifest | Snapshot rejected or file integrity fails, NOT SAFE |
| Missing/expired/ref-only OPA decision | No EBS create/attach; audited denial |
| Resource outside approved AWS account, lab tag or EBS ID | Denied before mutation |
| No pre-incident verified recovery point | No recovery; audited failure |
| Health endpoint fails or IAM check missing | REVIEW/UNSAFE, never SAFE |
| Repeated same recovery request | No unwanted extra volume; durable job idempotency tested |
| Quarantine revocation | Human-authorized only, SG restored to recorded original |
| B LLM offline or injects malicious text | Backend reports degraded investigation; no autonomous cloud action |

Metrics: time-to-alert, time-to-OPA-decision, quarantine latency, snapshot recovery time, verification time, restore success rate, false positives/negatives on labeled A simulations, RCS and decisions. Keep *actual* measurements; do not invent performance numbers.

## Phase 9 — optional/remaining rubric items and release evidence

- A: finish Wazuh telemetry, Prometheus/Grafana/Alertmanager, Gitea + Woodpecker CI if required. One screenshot per required pipeline stage, test results and container build.
- C: OpenTofu plan/apply evidence and a reproducible SSM-based preparation procedure. The existing Ansible role is a generic directory-creation template; on AWS, Ansible requires an approved SSM connection plugin or secure management path. Do **not** open SSH to 0.0.0.0/0 just to use Ansible.
- Scaling: AWS EC2 Auto Scaling is the Senlin replacement **only if required**. Must define a genuine *stateless worker*, an actual launch template/ASG and demonstrate scaling by metric; simply toggling verifier instance count is **not** scaling proof. Add after the core recovery demo works.
- Preserve tests, cloud logs, audit records, before/after snapshots, incident JSON, deployment screenshots and cost report. All three rehearse individually and together. State which results came from mock tests and which from AWS.

## Phase 10 — cleanup and handoff (C + account owner)

1. Freeze evidence and confirm snapshot retention requirements. Record required IDs and bills.
2. Remove optional verifier and unused recovered clones after C/A/B sign-off, with explicit target IDs. Confirm backups before deleting any snapshot/volume.
3. Since `aws_ebs_volume.sample_data` has `prevent_destroy = true`, a normal `tofu destroy` will **not fully succeed** until a reviewed change removes that protection. This is deliberate. Do not use `-target` to bypass safety casually. Review plan of every destructive action.
4. Terminate other paid EC2 resources, release public IPv4, clear unused EBS/snapshot storage and check AWS Billing to ensure charges stop. Never delete evidence still required for grading without archived copies.
5. Archive a versioned source ZIP, sanitized configuration, readme, test summaries, role evidence, diagrams and a **separate** secure state/credential backup (never WhatsApp).

## Red-flag troubleshooting

- **No default VPC:** do not run the provided Terraform; create a separate approved design with VPC/subnets or use an existing suitable VPC.
- **SSM unavailable:** verify profile, agent, public subnet internet route, SG outbound 443 and SSM managed node status; do not open inbound SSH by default.
- **B cannot reach C:** start with B importing the C Python module on a single trusted machine using mock inputs; add a protected HTTP endpoint only if distributed deployment truly requires it.
- **AWS create-volume denied:** verify EBS volume tag, snapshot owner/source/status, expected account/Region and scoped IAM. Do not use wide AdministratorAccess to bypass guards.
- **EBS attach fails:** verify target verifier AZ equals volume AZ, state `available`, mount device mapping and EC2 permissions.
- **RCS says REVIEW despite 85+:** deliberate safety rule; an individual factor failed. See `config/recovery.yaml`.
- **Wazuh manager unreachable:** private VPN/secure path is needed; do not publicly expose management interfaces without plan.
- **Unable to cleanup source EBS:** `prevent_destroy` is intentional. Follow sign-off and review Terraform modification.

## Reference docs

- EBS: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-restoring-volume.html
- SSM: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
- EC2 Security Groups: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/changing-security-group.html
- OpenTofu AWS provider: https://search.opentofu.org/provider/hashicorp/aws/latest
- IAM: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html
- AWS Free Tier: https://aws.amazon.com/free/


**2026-11-10 audit update:** Follow `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md` for the current source-only release, corrected EBS mount prerequisites, new opt-in adapters and honest remaining work.
