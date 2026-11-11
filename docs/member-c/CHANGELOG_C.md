# Member C changelog

## AWS redesign v0.3 (2026-11-04)

- Supervisor-approved conceptual migration OpenStack → AWS documented; code remains offline-unverified on live cloud.
- Scoped `AwsEbsLabGateway` using injected boto3 EC2/STS clients: account, Region, lab tags, explicit source volume, completed snapshot owner/source, opt-in mutation only; creates a new detached encrypted recovery volume.
- Added read-only AWS lab preflight and signed snapshot-validation record helpers and tests.
- Renamed internal cloud `project_id` references to AWS `account_id`; snapshot states use AWS `completed/pending/error`.
- Created OpenTofu AWS minimal EC2/EBS/SSM/quarantine/optional verifier template; needs live provider initialization, validation, plan and cost approval.
- Added separate detailed B implementation, A migration, C completion and all-three deployment/WhatsApp guides.
- Archived legacy OpenStack code/guides. A's detection source remains unchanged.
- No live AWS calls, EBS attachment, isolated verification or production-grade secure B approval lookup implemented in this release.
