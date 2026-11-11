# WhatsApp-only versioning and merge instructions (no Git required initially)

**Coordinator:** Member A. **Master archive:** `CyberHeal_AWS_MASTER_v0.x.zip`. Never overwrite the only master copy. ZIP folders are not version control; assign ownership, manifest changes and preserve test results.

## What each member sends

- A keeps `src/cyberheal_detect/`, `wazuh/`, `observability/`, `.woodpecker.yml` and overall project integration.
- B sends `CyberHeal_B_v0.1_PATCH.zip` containing ONLY his `src/cyberheal_investigate/`, `src/cyberheal_respond/`, `respond/policies/`, B tests, B requirements and B handoff documentation. No copy of A/C source.
- C sends `CyberHeal_C_AWS_v0.3_PATCH.zip` with C source, C tests, `config/recovery.yaml`, `infra/tofu/`, C requirements, AWS contracts and C documentation. Merge shared contracts only after A+B+C review.

## Safe merge, manually using File Explorer or Explorer 7-Zip

1. Save original master and patch ZIPs unchanged in a `releases/` local folder.
2. Check patch contains no `.venv/`, `clouds.yaml`, `~/.aws/`, `.env`, `*.tfstate*`, `*.tfvars`, `*.plan`, local SQLite incidents, keys, model weights, PII or logs with secrets.
3. Extract master to a **NEW** directory named e.g. `CyberHeal_AWS_MASTER_v0.4/`.
4. Extract patch to a separate temporary folder. Before copying files, compare names. Do **NOT** copy a whole `src/` directory on top without review. Copy only owned module files, then separately review contract changes.
5. Keep A's `.woodpecker.yml` and detector code intact unless A has explicitly accepted changes. Copy B's files into empty B folders; copy C's into C-owned folders.
6. Run tests for all modules (`python -m pytest -q tests`) in an environment with the union of dependencies, including `requirements-member-b.txt`. Run the mock A→B→C end-to-end test.
7. Keep a `docs/team/DECISIONS.md` entry with date, what changed, whose approval, version. Record a checksum and send it in WhatsApp:

```powershell
Get-FileHash -Algorithm SHA256 .\CyberHeal_AWS_MASTER_v0.4.zip
```

8. Send **one** newly numbered master ZIP to all three and write a one-line changelog. Do not rename an older ZIP to pretend it is newer.
9. Keep AWS Terraform `terraform.tfstate*`, SSO configuration and access keys on C's secure operator machine only. A/B may use read-only sanitized IDs for integration, but should not re-run Terraform from their ZIP copies as a second state owner.

## Recommended later upgrade

Use a private Git/Gitea repository when the team is ready; that makes merge conflicts, authorship, CI and version history reliable. Git is not required to run the offline demo, but the original project rubric explicitly called for a Gitea/Woodpecker workflow.
