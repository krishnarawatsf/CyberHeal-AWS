# Member C — AWS OpenTofu infrastructure (template, unvalidated live)

Requires: approved AWS test account, one Region with a **default VPC and default subnet**, AWS CLI non-root SSO/role session, OpenTofu installed, valid quotas and reviewed spend budget. This was not run against a live AWS account in this release.

Provider initialization and static validation have been run locally with Terraform 1.14 and AWS provider 6.72.0. The checksummed `.terraform.lock.hcl` is committed with the project. This does not substitute for an authenticated plan review.

This creates a single Amazon Linux 2023 EC2 test workload with no inbound Security Group, TCP 443-only outbound connectivity for AWS Systems Manager, a separate no-egress quarantine Security Group, an IAM SSM instance profile, a separate encrypted EBS sample-data volume, and optionally (`enable_verifier=true`) one short-lived isolated verifier EC2. Uses a billed public IPv4 for outbound SSM; no NAT gateway or open SSH. AWS output IDs are for the test account only.

## Commands (PowerShell)

```powershell
aws sts get-caller-identity --profile STUDENT_LAB
cd infra/tofu
Copy-Item terraform.tfvars.example terraform.tfvars
# Replace placeholders (account ID/Region) and verify costs and default VPC.
tofu init
tofu fmt -check
tofu validate
tofu plan -out=cyberheal.plan
# Examine plan with your team and account owner BEFORE applying.
tofu apply cyberheal.plan
tofu output
```

**Never** publish `.tfvars`, `.tfstate*`, `.terraform/`, saved plan, credentials or secret keys. `aws_ebs_volume.sample_data` has `prevent_destroy` to avoid accidental data loss, so cleanup needs a separate approved plan removing that safeguard after evidence retention. If no default VPC exists, pause and redesign.

Switch `enable_verifier=true` only for scheduled isolated recovery tests; this adds an EC2 instance and cost. It **does not automatically attach a restored EBS clone** and is not an Auto Scaling demo. The attach/mount and live verifier are pending real AWS integration.

Important: A's original Woodpecker CI does not run these Terraform checks. A must add validated pipeline gates before claiming automated IaC deployment.
