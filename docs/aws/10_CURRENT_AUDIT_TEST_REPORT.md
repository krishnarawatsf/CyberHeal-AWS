# Independent audit test report — 10 November 2026

**Input:** user-provided `CH_part2.zip` (active AWS project only; irrelevant caches and duplicate archives excluded). **Output:** `CyberHeal_AWS_Reviewed_v0.4_WhatsApp.zip` source-only candidate.

## Tests actually executed on this audit runner

- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src pytest -q tests/test_recover*.py tests/test_features.py tests/test_detector.py tests/test_alert.py tests/test_simulators.py tests/test_respond_aws_live_contain.py tests/test_respond_verification_contract.py tests/test_investigate_api.py::test_llm_validates_and_never_acts tests/test_investigate_api.py::test_no_remote_llm`: **119 passed**.
- `python -m compileall -q src`: **passed**.
- Bash `-n` checks for included `.sh` scripts: **passed**.
- Python YAML parsing of project configs, Ansible tasks, Woodpecker and monitoring rules; JSON parsing of Grafana dashboards: **passed**.
- Source-only ZIP packaging and SHA256 manifest integrity check: performed after this report is generated.

## Not executed here

- **Full B API and OPA suite:** the official OPA executable was not available in this audit runner. An attempt at full pytest failed during B test fixture initialization because `CYBERHEAL_OPA_EXE` was missing. Historical B reports (153 tests and 14 OPA tests) are submitter-provided, **not** independently reproduced in this audit.
- OpenTofu `init/validate/plan/apply`, Ansible `ansible-lint` and real playbook execution, Ruff, Black, mypy, Woodpecker CI, image build/deploy.
- AWS identity, live API calls and mutation, SSM connectivity, Wazuh manager/agent, local LLM inference, quarantine, EBS snapshot/restore/attach/mount, real five-factor evidence, Grafana/Alertmanager or scaling.

**Do not state that CyberHeal AI is a deployed, fully automated cloud recovery system based on these tests.** The new adapters default to read-only/mutations off and must be reviewed by the responsible member before live use.
