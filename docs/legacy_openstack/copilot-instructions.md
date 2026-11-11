# GitHub Copilot Instructions: Member A (Detect and Monitor)

Save this file as `.github/copilot-instructions.md` in the CyberHeal AI repository. Copilot reads it automatically and applies it to suggestions and chat in this repo.

---

## Project Context

CyberHeal AI is a cloud and DevOps final year project on OpenStack. It detects ransomware-like file activity and compromised-credential behaviour, investigates incidents with a local LLM, applies OPA-controlled containment, and restores workloads from trusted snapshots with a Recovery Confidence Score.

There are three members. Member A owns the detection pipeline, observability, and CI/CD. Member B owns investigation and response. Member C owns recovery, verification, and infrastructure as code. Do not write code for B's or C's modules unless the task explicitly asks for an interface stub.

## My Module (Member A)

I am responsible for:

- Test workload setup on VM-1 and the Wazuh agent configuration.
- Wazuh file-integrity monitoring rules for the sample-data directory.
- The ransomware-like simulator (safe file transformation and renaming on sample data only).
- The credential-anomaly simulator (controlled failed logins and privilege changes).
- Feature extraction: entropy change, modification and rename frequency, hash changes, failed auth patterns, privilege changes, abnormal admin API actions.
- The scikit-learn detector: training, threshold tuning, evaluation on labelled simulations.
- Producing threat alerts in the agreed schema.
- Prometheus, Grafana dashboards, and Alertmanager rules.
- Gitea repository setup, Woodpecker CI pipelines, and Podman/Buildah builds.

## Environment

- Development machine: MacBook with Apple M3 (Apple Silicon, arm64, macOS).
- Container runtime: Podman via `podman machine`. Use `--platform linux/arm64` when building images unless a target requires amd64.
- Wazuh server and any Linux-only tooling run in a Linux VM (UTM or Multipass) or on the shared lab machine. Do not write scripts that assume Linux-only paths on macOS without a guard.
- OpenStack VMs are reached over the network. Use the OpenStack SDK or CLI with credentials from environment variables, never hard-coded.
- Python 3.11 or newer. Use a virtual environment (`python3 -m venv .venv`) and pin dependencies in `requirements.txt`.

## Code Style and Conventions

- Python: follow PEP 8. Use type hints on all public functions. Use `pathlib` for file paths, not string concatenation.
- Format with `black` and lint with `ruff`. Both must pass in CI.
- Keep functions short and single-purpose. Prefer pure functions for feature extraction so they can be unit-tested.
- Write docstrings for modules and public functions in a short Google-style format.
- Logging: use the `logging` module, never `print`, in any code that runs in the pipeline.
- Configuration lives in YAML files under `config/`, loaded through one settings module. Do not scatter magic numbers through the code. Thresholds such as entropy cut-offs must come from config.
- Use `dataclasses` or `pydantic` models for the threat alert, and validate it before emitting.

## Safety Rules (Important)

- All simulators act only on the designated sample-data directory on the test VM. Hard-code a guard that refuses any path outside that root.
- Simulators must never encrypt real data, delete system files, or touch anything outside the sandbox. Use reversible, harmless transformations such as XOR with a fixed key or renaming with a known suffix.
- Never generate real malware, real exploit code, or code intended to spread or evade detection.
- Never include secrets, passwords, API keys, or OpenStack credentials in code, tests, logs, or commits. Use environment variables and `.env` files listed in `.gitignore`.
- Sanitise any evidence included in an alert. Do not place raw credentials or secrets in the alert payload.

## Threat Alert Schema (Handoff to Member B)

Every alert must include these fields, exactly as named:

- `incident_id`: string, UUID v4
- `timestamp`: string, ISO 8601 UTC
- `resource`: object with `vm_id` and `volume_id`
- `alert_type`: string, one of `ransomware_like`, `credential_anomaly`
- `confidence`: float between 0.0 and 1.0
- `features`: object with the feature values that triggered the alert
- `evidence_refs`: list of strings referencing sanitised evidence, no raw secrets

Do not change field names without updating `docs/contracts/alert.md` and telling Member B. Put a schema version in a `schema_version` field, starting at `"1.0"`.

## Testing

- Use `pytest`. Place tests in `tests/`, mirroring the source layout.
- Every feature extractor needs unit tests with fixed inputs and expected outputs.
- The detector needs evaluation tests that report precision, recall, and F1 on the labelled simulation set.
- Tests must not require OpenStack or Wazuh to be running. Mock external calls, and use recorded sample data for Wazuh events.
- Tests must be deterministic. Set random seeds for any model training.

## Git and Commits

- Work on feature branches named `detect/<short-description>`, for example `detect/entropy-features`.
- Never commit directly to `main`.
- Commit messages start with `[detect]`, for example `[detect] add entropy change feature`.
- Keep commits small and focused. One logical change per commit.
- Open a pull request for every merge. Request review from one other member.

## CI/CD (Woodpecker)

- Pipeline stages in order: lint (`ruff`, `black --check`), type check (`mypy` on the detect package), tests (`pytest`), dependency and image scan, build image with Podman/Buildah, deploy to the test environment on `main` only.
- Pipeline config lives at `.woodpecker.yml` in the repository root.
- Never disable a failing check to get a build green. Fix the cause or raise it at the weekly meeting.

## Observability

- Metric names use the prefix `cyberheal_detect_`, for example `cyberheal_detect_alerts_total`.
- Alertmanager rules live in `observability/alerts/detect.yml`.
- Grafana dashboard JSON is stored in `observability/dashboards/`, so it can be reviewed in pull requests.

## When Writing Documentation

- Keep module READMEs short: purpose, how to run, how to test, and the schema it emits.
- Use plain English. Explain detection choices in terms of the evidence they rely on, not marketing language.

## What Not to Do

- Do not add LLM calls to detection code. The LLM belongs to Member B's module.
- Do not add containment actions (isolating networks, disabling accounts). Those belong to B.
- Do not add recovery or snapshot logic. Those belong to C.
- Do not add new dependencies without a comment in `requirements.txt` explaining why they are needed.
- Do not generate large, unexplained code blocks. Prefer small, reviewable changes.
