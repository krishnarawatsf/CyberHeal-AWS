# CyberHeal AI AWS — Independent code audit and deployment route (10 November 2026)

**This is a source audit, not a production-security certification.** Cloud permissions, account configuration, Wazuh networking, Terraform apply, actual EC2 quarantine, EBS restore/attach, five live verification probes, local LLM inference, and full A→B→C deployment have not been executed by this audit. Never present synthetic SAFE/RCS results as evidence of a live recovery.

## 1. What was in CH_part2.zip

Active code was under `untitled folder/CyberHeal-Workspace/CyberHeal-AWS/`. The ZIP included another archive tree, an entire macOS Python virtual environment, downloaded macOS ARM Terraform provider binaries, cached test artifacts and `__MACOSX` metadata. Those are not a cross-platform release; the **clean v0.4 source ZIP** excludes them. Original A/B/C source is retained, and the existing B mock/API modules remain in mock mode.

## 2. Findings and fixes

| Severity | Finding | Fix/status |
|---|---|---|
| High | No complete live A→B→C pipeline; B's `app_from_env` explicitly refuses live AWS | **Not fixed:** requires live configuration, actual service auth, worker and account access. Use the integration steps below. |
| High | C created detached EBS clones without attaching or scanning them | **Partly fixed:** new opt-in `aws_attach.py` validates a tagged verifier and exact clone/snapshot/incident before requesting attachment. New `verify_directory.py` reads a read-only mount and checks a signed baseline. Manual mounting and other four real probes still needed. |
| High | B containment was mock-only | **Partly fixed:** new opt-in `aws_live_contain.py` validates account, Region, lab tag, exact VM/EBS and quarantine SG with no ingress/egress. B must review and explicitly wire into a live service. |
| High | Ansible's sample directory was on the root disk by default, not necessarily EBS | **Fixed for fail-closed behavior:** role now refuses to succeed unless `/srv/cyberheal-sample` is a mounted filesystem. Formatting/mounting the approved EBS device still requires a carefully verified operator step. |
| High | C's explicit file-list hash scan could overlook files added outside the list | **Fixed for live-use option:** `collect_tree_sha256` enumerates all files, rejects symlinks/special files, checks bounds and detects unexpected files; signed baseline CLI compares the whole tree. |
| Medium | AWS read-only preflight trusted counts/tags/AZ but didn't match returned instance/volume IDs and attachment | **Fixed:** new strict ID, encrypted-volume and exact attachment checks with tests. |
| Medium | Windows validation omitted symlink security test unconditionally | **Fixed:** it now runs all tests or reports that Windows symlink permissions prevent a full pass. |
| Medium | 285 MB ZIP included `.venv`, `.terraform`, caches, old copies and metadata | **Fixed:** use the source-only ZIP; rebuild environments on target OS. Terraform lock retained. |
| Medium | Terraform's verifier EC2 lacked a dedicated role tag | **Fixed:** `Role=CyberHealVerifier` now distinguishes it for attachment guard. |
| High | No real Wazuh ingestion, deployed LLM, cloud-backed data collection, audit transfer to A or verified health | **Not fixed:** assigned to A+B+C integration, using real probes and documented evidence. |
| Medium | AWS cost/SSM/cleanup complexities | **Not software bugs:** documented below; verify before provisioning. |

The new cloud adapters default to `allow_mutations=False`, are **not** wired into the FastAPI service, and have been mock-tested only. They do not justify enabling broad IAM privileges or declaring production readiness.

## 3. Deployment decisions and owner responsibilities

**Minimum-cost lab:** one AWS test EC2 instance with an attached encrypted EBS sample volume, and one verifier EC2 instance created only for a scheduled recovery demo. A/B/C Python services, OPA, local LLM and monitoring run on a trusted local Linux/Windows/Mac host. No NAT Gateway, GPU or public inbound ports. The Wazuh manager should run on an adequately provisioned separate local Linux host; the test EC2 runs only a Wazuh agent.

| Member | Before AWS | During AWS deployment | Evidence for review |
|---|---|---|---|
| A | Verify actual alert schema, improve detector-to-B adapter, configure Wazuh manager and pipeline | Connect AWS agent over private authenticated route, emit a real alert, configure local Prometheus/Grafana/Alertmanager | Wazuh event, sample-safe simulator logs, alert JSON, dashboards and CI run |
| B | Finish backend, persist incidents, run actual OPA, local LLM and integration tests | Update `Lab` and OPA `respond/policies/lab.json` with genuine approved IDs; review and wire the opt-in EC2 quarantine adapter | OPA allow/deny decisions, before/after AWS SG inventory, audit logs, recovery request |
| C | RCS, signatures, snapshot selector and all offline tests; review new read-only verifier script | Provision EC2/EBS, prepare actual mounted data, take clean snapshot, create clone, request attachment to tagged verifier, collect five real evidence factors | Terraform plan/apply, snapshot IDs and signed baseline, read-only file scan, RCS report and cleanup |

**No Git required for initial lab runs, but versioned ZIPs alone are not a CI/CD audit trail.** If Gitea/Woodpecker remains in the rubric, A must run them on a Linux machine and preserve pipeline evidence. Do not claim CI/CD just because `.woodpecker.yml` exists.

## 4. First checkpoint: complete OFFLINE tests

### Windows PowerShell

1. Install Python 3.11 or 3.12, and obtain the official OPA executable for Windows from the Open Policy Agent site. Do not run the macOS `.venv` binaries from CH_part2.zip.
2. Extract this source-only ZIP, open PowerShell in its **CyberHeal-AWS** directory.
3. Run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-member-b.txt -r requirements-member-c.txt
$env:CYBERHEAL_OPA_EXE = (Resolve-Path "C:\path\to\opa.exe").Path
powershell -ExecutionPolicy Bypass -File scripts\run_offline_validation.ps1
```

On Windows, the symlink test may need Developer Mode/administrator symlink permission or WSL/Linux. A missing OPA executable is a **blocker** for the full B/OPA acceptance gate; do not substitute a mock and claim OPA tests passed.

### Linux/macOS

```bash
export CYBERHEAL_OPA_EXE=/absolute/path/to/opa
bash scripts/run_offline_validation.sh
```

Only after all tests pass should AWS planning begin. `PYTHONPATH=src python -m cyberheal_recover.demo` prints simulated results, not cloud results.

## 5. AWS account setup: do this before creating EC2

1. The AWS account owner creates or designates a **dedicated non-production lab account** and turns on billing notifications, an AWS Budget with a small alert threshold and a separate spending review process. Budgets are **not a hard spending cap**.
2. Choose **one Region** (e.g., `ap-south-1`) and a reviewable maximum: one test EC2 (`t3.small` default), one 8 GiB data EBS volume, one optional verifier EC2 (`t3.micro` default), snapshots and a public IPv4 address. Check current regional pricing first.
3. Configure a human AWS IAM Identity Center/role or other approved short-lived role access on each operator's machine. Never share root keys, access keys, token values, signing secrets, `.aws`, `.env`, `.tfstate`, or `terraform.tfvars` over WhatsApp.
4. C installs the official AWS CLI v2 and OpenTofu, and signs in with the approved account. The `aws` and `tofu` executables must work on C's machine.
5. Confirm the identity and **default VPC** (the supplied OpenTofu template expects this). These are read-only:

```powershell
aws sts get-caller-identity
aws ec2 describe-vpcs --region ap-south-1 --filters Name=isDefault,Values=true
aws ec2 describe-subnets --region ap-south-1
```

If there is no default VPC, **stop**. A new custom VPC/subnet/endpoint design is needed; don't run `tofu apply` against guessed infrastructure. Obtain least-privilege permissions for planning and narrowly scoped mutation roles for provisioning, B quarantine and C recovery; IAM is the primary access control.

## 6. C's OpenTofu build (account-owner approval required)

From the project root on C's computer:

```powershell
cd infra\tofu
Copy-Item terraform.tfvars.example terraform.tfvars
# Open terraform.tfvars and replace the account ID with your approved account.
# Confirm Region, test instance type, data size and enable_verifier=false.
tofu init
tofu fmt -check
tofu validate
tofu plan -out=lab.tfplan
```

**Read the plan with the account owner**, record intended resource count, estimated cost and account/Region. Only with explicit approval:

```powershell
tofu apply lab.tfplan
tofu output
```

Do not run a broad `tofu destroy` without reviewing backup retention and cost cleanup. The data volume has `prevent_destroy=true` intentionally. Do not send Terraform state files through WhatsApp.

### SSM readiness checkpoint

In the AWS console open **Systems Manager → Fleet Manager / Managed nodes** and locate the test EC2. If it is not managed, inspect SSM IAM profile, EC2 agent, outbound TCP 443, public subnet internet route (or VPC endpoints), Region and EC2 state. Do **not** open public SSH/22 as a workaround. The quarantine SG has no egress, so it **will disable SSM connectivity after containment**.

## 7. C's sample EBS baseline (careful, one-time operator task)

This step needs a real data volume; the Terraform resource alone does **not** initialize its filesystem. Use the AWS console's browser-based Session Manager to connect to the lab instance.

**Protect against formatting the root/system disk.** First run only read-only commands:

```bash
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS,SERIAL
sudo blkid
findmnt -n -o SOURCE,TARGET / 
```

Using EC2 console/volume attachment metadata, match the EBS **Volume ID**, size, and NVMe serial to the Terraform `sample_data_volume_id`. The device might be `/dev/nvme1n1` even though Terraform requested `/dev/sdf`. If you are not certain, **do not format anything**.

For a fresh, empty, confirmed **test-only** data disk, an authorized operator can format it once (never format a disk containing evidence). Substitute the individually confirmed DEVICE path:

```bash
# WARNING: destructive to DEVICE. Execute only after positive EBS serial/ID match.
sudo mkfs.ext4 /dev/CONFIRMED_EMPTY_EBS_DATA_DEVICE
sudo mkdir -p /srv/cyberheal-sample
sudo mount /dev/CONFIRMED_EMPTY_EBS_DATA_DEVICE /srv/cyberheal-sample
findmnt --mountpoint /srv/cyberheal-sample
sudo mkdir -p /srv/cyberheal-sample/data
sudo chown ec2-user:ec2-user /srv/cyberheal-sample/data
printf 'CyberHeal verified lab sample\n' > /srv/cyberheal-sample/data/sample.txt
sync
```

If reusing a prepared EBS volume, **skip mkfs** and mount the existing filesystem. Write down UUID and mount mapping, make an explicit reviewed persistent mount decision (e.g., `/etc/fstab` by UUID) only after verifying expected device; never assume Linux device numbering is stable after reboot.

1. Establish a SHA-256 baseline of the **`data/`** tree, not the filesystem root (`lost+found` may exist). For initial operator review use `sha256sum /srv/cyberheal-sample/data/sample.txt` and inspect the full file list; capture the manifest under C's control.
2. Flush and unmount the volume, stop writes, and follow AWS console steps for an application-consistent clean snapshot. A detached available EBS volume is simplest; it may require temporary detachment/re-attachment.
3. Record snapshot `snap-*`, source `vol-*`, AWS account/Region, creation time (UTC), baseline file hashes and reviewer. After independent validation, issue C's HMAC snapshot attestation using `python -m cyberheal_recover.attest_cli issue ... --operator-validated` with a 32-byte secret supplied **out of band** in `CYBERHEAL_ATTESTATION_KEY_HEX`. Never include the key in the ZIP or shell history screenshots.
4. Reattach the approved original EBS data volume, remount it and confirm `sample.txt` is present. Only then should A run the harmless simulator inside this mounted sample directory.

## 8. A's REAL detector/telemetry checkpoint

1. A installs a Wazuh agent on EC2 and an appropriately sized Wazuh manager on a separate approved host. Establish a private/authenticated VPN/tunnel or equivalent protected path; the code does not provide this automatically.
2. Add file-integrity monitoring for `/srv/cyberheal-sample/data`, verify a normal file update is reported, and use the detector's validated alert schema with genuine EC2 `i-*` and EBS `vol-*` IDs.
3. A submits the alert to B's authenticated `/api/v1/alerts` endpoint. If B runs on a laptop, use **private reachable networking**, not a wide-open public API or exposed debug Swagger. A keeps the first trusted suspicious timestamp for snapshot cutoff.
4. Confirm `/metrics`/Grafana shows live incident events; synthetic data must be labelled mock and kept separate.

## 9. B's REAL authorization and containment checkpoint

1. B must replace mock identity/resource values in both `respond/policies/lab.json` and his approved `Lab(...)` constructor with the actual AWS test account, Region, tag, instance ID, attached volume ID and quarantine SG ID. The current `app_from_env()` is **mock-only** and deliberately refuses `CYBERHEAL_MODE=live`.
2. Use the real local LLM endpoint if the rubric requires LLM evidence; fallback text proves API resilience, **not live LLM inference**. Sanitize alert data; LLM is advisory only.
3. Test OPA policies with the **real lab inventory** and both permitted and denied requests. Verify approval expiry, exact incident/action/resource and single-use behavior in B's SQLite audit store.
4. Review new `src/cyberheal_respond/aws_live_contain.py`. Its opt-in `AwsLabQuarantineAdapter` uses B's existing `quarantine()` interface and validates inventory, tags and quarantine SG; **it is not wired into FastAPI**. C/B review IAM restrictions and deliberately configure/enable it in a separate live-only service release; it should never silently fall back to mock during a live demo.
5. On an approved test incident, record original Security Group IDs, get OPA approval, apply the no-egress quarantine SG, and verify AWS inventory. Expect SSM to disconnect. Rollback requires an **operator-authorized** return to the previous recorded SG.
6. B issues a **separate** approval for `recover_volume` and transfers the protected approval record/validated first-suspicious time through a trusted backend to C. A plain string `opa_decision_ref` alone is not authorization.

## 10. C's isolated EBS recovery checkpoint

1. From C's independently signed registry and live `DescribeSnapshots`, select a completed snapshot of the approved volume taken before the first suspicious time. Abort if none qualify.
2. C's existing `AwsEbsLabGateway` can create a *new, detached and encrypted* EBS recovery volume. It defaults to mutations disabled, requires the exact approved volume/snapshot and account/Region/tag, and has mock tests. **This release does not wire an authenticated OPA job runner into the live gateway.** Record a manual/operator-assisted operation honestly until B/C build and validate that integration.
3. For the recovery demo, enable `enable_verifier=true` in Terraform, review the plan and apply with approval. Verify the verifier EC2 has `Role=CyberHealVerifier` and is in the **same Availability Zone** as the clone.
4. The new `AwsIsolatedVerifierAttachment` provides opt-in `inspect()` and `attach()` with strict AWS/incident/snapshot verification. It is not an automatic mount. An operator may instead use the AWS console to attach the approved **clone only** to the verifier; never mount unknown data on the original affected instance.
5. Connect to verifier using browser SSM. Check `lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS,SERIAL` and confirm NVMe serial matches the *recovery clone* EBS ID. Do NOT format the restored clone. Mount the existing filesystem read-only; ext4 example after exact device confirmation:

```bash
sudo mkdir -p /mnt/cyberheal-recovery
sudo mount -t ext4 -o ro,noload /dev/CONFIRMED_RECOVERED_EBS_DEVICE /mnt/cyberheal-recovery
findmnt --mountpoint /mnt/cyberheal-recovery -o SOURCE,TARGET,OPTIONS
```

For XFS or other filesystems, use appropriate recovery-safe read-only options; do not guess them. Make the scanner root `/mnt/cyberheal-recovery/data`, not the EBS filesystem root. Obtain a **signed snapshot attestation** on the verifier through an approved secure transfer (not a shared WhatsApp ZIP containing the signing key). Run the Python verifier with project code installed on the verifier:

```bash
# From a trusted copy of project source with dependencies installed and
# CYBERHEAL_ATTESTATION_KEY_HEX securely loaded in this session:
PYTHONPATH=src python -m cyberheal_recover.verify_directory \
    --root /mnt/cyberheal-recovery/data \
    --attestation /approved/private/attestation.json
```

It refuses a writeable mount and checks signed expected hashes against the entire directory tree. **Output is file-integrity evidence only, NOT SAFE.** Ensure the protected baseline `baseline_sha256` keys are relative to `data/`, such as `sample.txt`, not `data/sample.txt`.
6. Collect **four other actual factors** separately: test identity/account restriction (IAM/SSM plus named test user), test network/SG isolation via AWS `DescribeNetworkInterfaces` and SG rules, approved configuration baseline hashes, and a truly isolated functional application-health check. An application that cannot run safely in isolation must not be labelled healthy just because the disk hash matches.
7. Use C's existing RCS evaluator with verified evidence and its thresholds, return `docs/contracts/verification.md` fields, and store B/A audit outputs. Any unobserved/failed critical factor must prevent SAFE. Releasing quarantine is an explicit human-approved decision, not automatic.

## 11. Integration gate and what counts as "finished"

The three of you must complete **at least two real, observed runs** of a benign sample-data anomaly:

- A Wazuh receives real file events, A emits schema-correct alert, B stores it.
- B's actual local LLM (if required) creates advisory summary; OPA gives real allow/deny; genuine AWS test instance is quarantined and audit includes before/after SG.
- C selects a signed pre-incident AWS snapshot, creates a different EBS volume, safely attaches and mounts it read-only on a distinct verifier, verifies all five factors, computes RCS and sends a persistent B/A result.
- A shows genuine counts/decisions, including failures/REVIEW/UNSAFE; pipeline and DevOps evidence is captured for any rubric requirements.
- Run negative cases: wrong account/tag/ID, expired or missing OPA approval, missing/tampered snapshot attestation, unexpected extra file, incomplete health check, retry/idempotency and failed restore.
- Record real times, screenshots, resources, ownership, cloud bills, test outputs and cleanup. **Do not fabricate metrics.**

**Must still be implemented:** real B live configuration/backend integration, verified C five-factor evidence collector and durable job state, actual A telemetry pipeline and live metrics, any required CI/deployment/Auto Scaling, deployment testing. `aws_live_contain.py` and `aws_attach.py` are vetted starter components, not drop-in substitutes for those tasks.

## 12. Safe teardown

After approved evidence collection, shut down verifier, detach/delete only authorized temporary clone volumes after review, and carefully clean up unused snapshots/instances. Source EBS is `prevent_destroy=true`, so `tofu destroy` will fail until a reviewed config change explicitly removes that guard. Leave no forgotten EBS, public IPv4 or running EC2. Stop/terminate does not eliminate EBS and snapshot storage charges. Preserve required audit artifacts and check AWS Billing after cleanup.

## Official reference links

- [AWS EBS snapshot restore](https://docs.aws.amazon.com/en_en/ebs/latest/userguide/ebs-restoring-volume.html)
- [AWS EBS attachment and same-AZ requirement](https://docs.aws.amazon.com/en_en/ebs/latest/userguide/ebs-attaching-volume.html)
- [AWS SSM Agent connectivity](https://docs.aws.amazon.com/systems-manager/latest/userguide/troubleshooting-ssm-agent.html)
- [AWS EC2 Security Group updates](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/changing-security-group.html)
- [AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html)
- [Boto3 EC2 CreateVolume](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/create_volume.html)
