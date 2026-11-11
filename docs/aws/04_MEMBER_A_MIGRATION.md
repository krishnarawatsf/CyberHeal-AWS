# Member A — AWS conversion instructions (detection, CI, observability)

A's existing detection package in `src/cyberheal_detect/` was preserved. **Do not assume the Wazuh agent, live telemetry or CI is operational.** Only A's original Python code and tests are present.

## Stage A1 — local tests and contracts

1. Run `python -m pytest -q tests/test_alert.py tests/test_detector.py tests/test_features.py tests/test_simulators.py`. Use Python venv and install `requirements.txt`.
2. Confirm generated `ThreatAlert` fields match `docs/contracts/alert.md`: `resource.vm_id=i-*` and `resource.volume_id=vol-*` during AWS integration. No personal data or secrets in `evidence_refs`.
3. Produce saved synthetic alert examples for B: one file anomaly and one credential anomaly. State source, time, features and confidence. The simulator remains strictly in a test sample directory.
4. Coordinate detection of *actual* test EBS sample-data activity. A's Python file simulator currently runs wherever installed; remote AWS file events do not magically appear at the local ML detector. Define an explicit event collection/transfer step and test it.

## Stage A2 — Wazuh agent and manager

1. Run Wazuh manager/indexer/dashboard on an adequately sized local Linux VM or approved existing host; **not** on the small AWS test instance by default.
2. Install a Wazuh agent on the test EC2 instance and enable FIM for its mounted test-data directory, e.g. `/srv/cyberheal-sample` only. Follow the Wazuh version-matched official installation instructions.
3. Connect agent to manager over an authenticated private VPN/tunnel or another approved secure channel. Avoid publishing the Wazuh manager to the open internet or forwarding management ports through a home router without security design.
4. Generate a harmless file rename/write in the sample directory and prove A receives an event. Extract features with existing A pipeline, emit validated alert to B API.
5. Explain what is real vs simulated. Credential anomaly can stay synthetic unless supervisor explicitly approves a test-only IAM identity.

## Stage A3 — CI/CD and metrics

- `.woodpecker.yml` is retained as originally supplied by A. It builds `linux/arm64` images because A uses an M3 Mac; AWS EC2 template uses **x86_64**, so Confirm the existing `linux/amd64` target matches the chosen EC2 AMI/architecture; multi-architecture builds are optional. Do not edit the CI pipeline without A's review.
- Existing tests do **not** test B's missing package or the new C AWS adapter in a deployed cloud. Add C offline test stage and B API/OPA tests to CI when available. Do not add `tofu apply` to a public PR pipeline. Require human approval and trusted account boundaries for deployments.
- If no Git repository exists, manual running tests and recording outputs can serve as a temporary workflow, but this does NOT satisfy a rubric specifically requiring Gitea/Woodpecker until A sets it up. Start a small Gitea/Forgejo repository or GitHub private repository when ready.
- B's offline API exposes authenticated, low-cardinality Prometheus text metrics at `/metrics`: accepted incidents, persisted investigations, OPA decisions, response job states, and recovery decisions labelled `mock=true|false`. Configure Prometheus with the operator bearer credential; keep it in a secret store and never in dashboard JSON. The current endpoint has no per-incident labels.
- `observability/prometheus.yml` is a local scrape example. Change the target to the API's reachable address; mount the operator token as `/run/secrets/cyberheal-operator-token` (one token line, no committed secret file). Do not expose `/metrics` on an untrusted network.
- The supplied Grafana dashboard and Prometheus rules consume the metrics that B actually exports. A's detector event counters and C's live AWS/RCS collector metrics are still integration work; do not alert on names that no component emits. Alert on any live `REVIEW`/`UNSAFE`, response job failure, and OPA denial. Mock results are separately labelled and explicitly identified as non-live evidence.

## Stage A4 — live success criteria

- Test EC2 agent reports a controlled file-integrity event to Wazuh manager.
- A's detector emits a valid v1 alert, B accepts it, timestamps are UTC.
- Alertmanager/Grafana shows at least one genuine incident and C result after integration.
- CI validates A's detection and C/B mock suites. Document any unimplemented DevOps rubric item honestly.
- A supplies original source unchanged, logs/screenshots of detection and monitoring, and a versioned master ZIP with only reviewed patches.

See `docs/aws/02_ALL_THREE_DEPLOYMENT_RUNBOOK.md` for team-wide phases.
