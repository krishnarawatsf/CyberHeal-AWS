# Send this file with `CyberHeal_AWS_Clean_v0.4.zip`

**Project status, 10 November 2026: OFFLINE PARTLY TESTED; NOT DEPLOYED TO AWS.**

Use this clean v0.4 archive as the next **review candidate**, not as a replacement for a live-tested release. It keeps the merged A/B/C source from `CH_part2.zip`, removes Mac `.venv`/Terraform binaries and repeated backup trees, and adds fail-closed recovery/deployment safeguards. The full findings and AWS steps are in `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md`.

## What each member does next

**A**: review your own detection files, connect a real Wazuh agent over a private link, emit a genuine AWS EC2/EBS alert, set up monitoring and CI. Do not claim a live alert from the existing simulator alone.

**B**: review the new `src/cyberheal_respond/aws_live_contain.py`. It is *not enabled* in FastAPI and cannot change AWS resources unless explicitly opted in after testing and approval. Keep the existing backend and OPA policy. Update the mock AWS account/VM/volume/SG values and implement the protected live AWS path, including C handoff and audit.

**C**: review the strengthened `aws_preflight.py`, new `aws_attach.py` and `verify_directory.py`, plus the stricter Ansible EBS-mount guard. Complete a real EBS baseline/snapshot, then verified recovery and all five live factors. Attachment and signed file verification can now be exercised in isolation; neither constitutes a live SAFE result by itself.

**All three**: First pass offline tests with a real OPA executable, then set an AWS Budget and confirm the account/Region before running `tofu plan`. Follow `docs/aws/09_AUDIT_FIXES_AND_DEPLOYMENT_PATH.md` in order. Record real proof of each stage, don't guess IDs or use broad admin keys.

## Claims you must NOT make yet

- "Fully self-healing on AWS", "complete live automatic recovery", "actual LLM evidence" or "real EBS attachment tested".
- "All tests passed on this audit runner" — OPA was unavailable for the complete B suite. Historical test reports in `docs/member-b` and `docs/aws/08...` come from the submitter's environment.
- "Auto Scaling, Wazuh dashboard and CI are operational" until you deploy and demonstrate them.

## Source-folder directions

Open the **top-level** `CyberHeal-AWS/` folder within the clean ZIP. Do not use `__MACOSX` or old `archive/` folders from the original. You can use Python/PowerShell and AWS browser console without VS Code. No AWS credentials are included or should be shared over WhatsApp.
