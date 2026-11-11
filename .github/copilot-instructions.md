# CyberHeal AI — team AI coding instructions (AWS approved)

## Scope and ownership

CyberHeal AWS is a final-year student lab: A detects controlled ransomware-like file/credential anomalies; B investigates with local LLM **advisory only** and authorizes bounded AWS EC2 quarantine using OPA; C restores separately validated clean EBS snapshots and verifies via Recovery Confidence Score. Supervisor approved AWS to avoid installing OpenStack. Do not refer to the old archived OpenStack docs as current requirements.

- A owns `src/cyberheal_detect/`, `wazuh/`, `observability/`, `.woodpecker.yml`.
- B owns `src/cyberheal_investigate/`, `src/cyberheal_respond/`, OPA policies and the incident store; the offline implementation is present, while live AWS response remains pending.
- C owns `src/cyberheal_recover/`, `infra/tofu/`, AWS recovery and checks.
- Shared `docs/contracts/` changes need A+B+C approval. No raw secrets, test-only resources.

## Engineering

Python >=3.11, type hints, Pydantic models, `ruff`, `black`, `pytest`; config YAML not hard-coded secrets/IDs. Deterministic unit tests use fake boto3/LLM/OPA, not actual AWS. Use explicit AWS account, Region, approved resource IDs, `CyberHealLab` tags and scoped IAM. No real ransomware, dangerous credential actions or data deletion.

LLM output is untrusted and cannot make authorization decisions or execute cloud calls. OPA decision record must be independently verified, incident+resource+action bound, expiring and non-replayable. Missing verification evidence is NOT SAFE. The C RCS gate additionally requires every critical check complete and passed. Restore to a **new** EBS volume, and verify on an isolated instance before manual release.

Cloud mutations are disabled by default in C's AWS adapter. `infra/tofu/` is only a template until `tofu init`, `tofu validate`, reviewed `plan` and live tests. No automatic apply/destruction. State/credentials and signed registry HMAC secrets must not be in WhatsApp ZIP.

Read `docs/aws/01_MEMBER_B_BUILD_GUIDE.md`, `docs/aws/03_MEMBER_C_WHAT_IS_READY.md`, and `docs/aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md` for architecture and status. B service and live recovery are still unfinished.
