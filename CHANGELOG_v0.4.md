# CyberHeal AWS source-only review v0.4 — 10 November 2026

**Base:** `CH_part2.zip`, active subtree `untitled folder/CyberHeal-Workspace/CyberHeal-AWS/`.

- Removed macOS `__MACOSX`, `.venv`, `.terraform`, cache folders, old duplicate workspace backups and bundled provider binary from the shareable source release.
- Retained B's merged FastAPI / SQLite / LLM / OPA / mock response source and A's original detection implementation.
- Hardened C's read-only AWS preflight with exact ID/attachment/encryption checks and new tests.
- Added `AwsLabQuarantineAdapter` (B opt-in, mock-tested) for read-only inventory and exact no-rule SG quarantine action; **not wired into live API**.
- Added `AwsIsolatedVerifierAttachment` (C opt-in, mock-tested), verifier instance tag and exact incident/snapshot/EBS checks; **does not mount or scan by itself**.
- Added bounded `collect_tree_sha256` and `verify_directory` to compare a signed baseline to **all** files under a Linux read-only mount, preventing extra-file omission.
- Ansible sample-data role now fails if the sample directory isn't an actual mountpoint.
- Windows offline script no longer silently skips the symlink-path security test.
- New detailed phased deployment and integration guide: `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md`.
- Retained Terraform provider lockfile; regenerated release file checksums.

**No claim of live AWS testing or turnkey deployment.**
