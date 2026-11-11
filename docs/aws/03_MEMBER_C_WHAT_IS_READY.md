# Member C — exactly what has been done and what is still necessary

## Implemented in this AWS edition (offline)

- `src/cyberheal_recover/contracts.py`: strict Pydantic B→C and C→A/B v1 message models. **Resource IDs now mean AWS EC2 ID and EBS volume ID**; schema field names are unchanged.
- `authorization.py`: verifies trusted allow decision is bound to incident, `recover_volume`, AWS account and specific EC2/EBS pair. Must receive trusted lookup from B; no public endpoint yet.
- `snapshots.py`: latest independently validated snapshot before first suspicious timestamp, within permitted window; AWS snapshot state is now `completed`.
- `aws_trust_registry.py`, `attest_cli.py`: signing and validating operator-review records with an HMAC key stored outside the project. Only verified AWS metadata + signed attestation qualifies. An HMAC record is **not** proof of malware absence.
- `rcs.py`, `checks.py`, `scan.py`: RCS, strict release gates, five deterministic verification checks and filesystem hash helper. Real evidence collection not yet built.
- `workflow.py`, `demo.py`: end-to-end mocked policy→snapshot→new-volume→verification flow. NO live cloud calls.
- `aws_ebs.py`: boto3 adapter validates AWS account, Region, EBS volume ownership/tag, completed snapshot owner/source, then optionally creates a **new detached** encrypted EBS volume from snapshot; refuses mutation by default. Baseline snapshot helper only works on a detached available data volume.
- `aws_preflight.py`: **read-only** readiness check of account, Region, instance/volume tag and AZ.
- `infra/tofu/`: proposed AWS plan: one EC2 test workload, encrypted EBS, SSM role/SG, separate no-egress quarantine group, optional temporary verifier EC2. **Not run through `tofu init/validate/plan` yet** because no AWS account/provider runtime available.
- `tests/test_recover_*.py`: deterministic tests with fake AWS clients, no AWS network access.

## Run your offline demonstration (no VS Code)

1. Install Python 3.11+ and allow Python package downloads on first run.
2. Windows: run `scripts/run_member_c_demo.bat`. Mac/Linux: `bash scripts/run_member_c_demo.sh`.
3. Confirm tests pass and JSON says `OFFLINE MOCK DEMO`. This is evidence of logic only; do not call this completed AWS recovery.

## Read-only AWS setup (only after account, role and spend controls approved)

1. Install AWS CLI v2 and configure a non-root IAM Identity Center/role profile (`aws configure sso` where enabled).
2. `aws sts get-caller-identity --profile YOUR_PROFILE` and verify the 12-digit account ID. Never share tokens.
3. After the team has applied the approved lab infrastructure and knows actual IDs, run:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m cyberheal_recover.aws_preflight --account 123456789012 --region ap-south-1 --lab-tag cyberheal-student-lab --instance-id i-REPLACE --volume-id vol-REPLACE --profile YOUR_PROFILE
```

This prints scoped IDs/status only, **does not create or delete resources**, and refuses mismatched scope.

## Safe baseline snapshot/attestation procedure (operator assisted)

1. In the isolated EC2 test instance, prepare harmless sample files on the **attached EBS data volume**. Collect SHA-256 baseline hashes and known-good configuration. Do not treat snapshot tags as trust.
2. Flush and unmount the sample volume; stop the test EC2 instance, detach ONLY the approved data volume and wait until EBS shows `available`. Confirm instance/volume IDs twice.
3. Create a C EBS snapshot using the AWS Console or reviewed, explicitly opted-in `AwsEbsLabGateway.create_snapshot_of_clean_detached_volume(...)`. **Do not issue an attestation until the snapshot is `completed` and evidence was reviewed.**
4. Create an operator-reviewed JSON attestation document using fields in `SnapshotAttestation`: snapshot/volume IDs, AWS account/Region/lab tag, snapshot creation time (UTC), post-snapshot validation timestamp, pre-simulation SHA-256 baseline map, reviewer, validation reference. This step requires trustworthy known-good evidence.
5. Generate a **private** 32-byte secret (`python -c "import secrets; print(secrets.token_hex(32))"`), store it securely outside the project, and set the 64-hex-character `CYBERHEAL_ATTESTATION_KEY_HEX` environment variable locally. **Never send the secret in WhatsApp.**
6. Run `python -m cyberheal_recover.attest_cli issue --input reviewed.json --output private_attestation.json --operator-validated`. Check with `python -m cyberheal_recover.attest_cli check --input private_attestation.json`. Do not commit the private record to a shared repository without access control.
7. Restore/re-attach the original sample EBS volume to the original EC2 instance and resume the controlled test workload. Confirm correct EBS device mapping using `lsblk`; Linux/Nitro NVMe names may differ from `/dev/sdf`.

## Before C can claim a live recovery demonstration

1. Implement/integrate a **durable job store and idempotency** (prevent duplicate incident restore requests) and protect the B decision lookup with authentication, expiry and replay prevention.
2. Bind B's approved IAM account/instance/volume decision to the selected snapshot and the first suspicious time held in B's trusted incident store.
3. Enable an isolated verifier instance, **create an EBS recovery clone** from a verified trusted snapshot, wait for `available`, and attach the clone ONLY to the verifier (same AZ). `aws_ebs.py` currently stops after creating the clone and does NOT perform attachment.
4. Mount the clone read-only on the isolated verifier and collect *real*, auditable file/config hashes, known-good role/account status, quarantine Security Group state and application-functional evidence. Never accept verification scores supplied by the untrusted request sender.
5. Build a `TrustedVerifier.collect(...)` implementation based on those probes. The existing demo verifier fabricates *mock* passing evidence for testing; it must never be used for a real SAFE decision.
6. Run failure cases: tampered files, wrong IAM account, wrong snapshot, missing/expired OPA allow, failed health, no candidate snapshot, duplicate incident; verify deny/review/unsafe and audit.
7. Return structured verification JSON to B; send metrics/events to A. Only SAFE AND approved operator action may resume service in the first live system.
8. If supervisor still requires scaling, implement a minimal AWS Auto Scaling demo after core flow passes; don't treat the optional verifier switch as auto-scaling.

## Member C handoff to the team

Give A `docs/aws/04_MEMBER_A_MIGRATION.md`, B `docs/aws/01_MEMBER_B_BUILD_GUIDE.md`, and everyone `docs/aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md`. The plain `docs/contracts/` models are the source of truth for the current v1 message shapes. Contract semantics must be approved before integration.

## Known limitations

- AWS IAM/VPC checks are **not** implemented as live evidence collectors. Only deterministic check logic and tests exist.
- No live EBS volume attach, mount, data-health verifier, production release or SDK integration has been run.
- The AWS infrastructure plan and IAM permissions still need real provider initialization, validation and plan review.
- AWS account/profile/Region/AMI/prices/quotas are site-specific and cannot be inserted here.
