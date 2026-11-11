# Member C — START HERE (AWS approved)

The previous OpenStack setup has been replaced. This ZIP now contains an AWS-based C module with offline boto3 fake-client tests and initial AWS OpenTofu infrastructure templates. **It is not deployed on AWS yet.**

1. From the project root, Windows: run `scripts\run_member_c_demo.bat`. Mac/Linux: `bash scripts/run_member_c_demo.sh`.
2. Read `../aws/03_MEMBER_C_WHAT_IS_READY.md` to distinguish completed C code from live AWS work still required.
3. Send B `../aws/01_MEMBER_B_BUILD_GUIDE.md` and A `../aws/04_MEMBER_A_MIGRATION.md`.
4. B's offline backend is already included in this merged project. All three follow `../aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md` only after the OPA-backed offline suite passes, the AWS account/region/resource limits are approved, and billing alerts are configured.
5. Source is now at `../../src/cyberheal_recover/`. The original OpenStack code is archived under `../legacy_openstack/`.

Only one nominated member (C) should run Terraform with the same protected local state. Do not share account secrets, IAM session tokens, signing keys, terraform.tfstate, or private incident data through WhatsApp.
