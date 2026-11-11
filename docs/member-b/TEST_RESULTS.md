# Member B v0.1 test results — 5 November 2026

Master: `CyberHeal_AWS_MASTER_v0.3_WhatsApp.zip`.
Master SHA256: `ad4b21e540d1ea2d4fa060b65d99f74f1c6f0cd67ed7455c170a3a722710e28a`.
All 88 original files were compared byte for byte and remain unchanged.

## Actual executed outcomes

| Check | Result |
|---|---|
| B Python tests, included in combined run | 67 passed |
| Existing A/C Python tests, included in combined run | 80 passed |
| Combined executed Python tests | 147 passed, 1 deselected |
| Actual OPA Rego tests | 14/14 passed |
| Real Uvicorn process and loopback HTTP health/OpenAPI smoke | Passed |
| Offline API -> OPA -> fake EC2 -> unchanged C workflow -> SQLite/monitoring | Passed |
| Source compile check | Passed |

The unchanged C test `tests/test_recover_checks.py::test_hash_scan_blocks_symlinks` was deselected in the final combined run. An earlier full run actually attempted it and failed at `Path.symlink_to` with `WinError 1314: A required privilege is not held by the client`. This is an OS permission failure before the scanner runs, not a passed security check. Run it in Linux/WSL or with appropriate Windows symlink privileges before claiming the complete master suite passes. No C test/source was edited or marked skipped in the patch.

## Environment

Windows amd64, Python 3.12.7, project venv using existing local packages; FastAPI 0.135.2, Pydantic 2.12.5, httpx 0.28.1, pytest 8.4.2, Uvicorn 0.42.0. Official OPA 1.0.1 windows/amd64, Rego v1. Pytest plugin autoload disabled for reproducibility. A clean install on another machine has not been separately certified.

Final Python command (from project root, OPA executable configured):

```powershell
$env:CYBERHEAL_OPA_EXE = (Resolve-Path work/opa.exe).Path
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
python -m pytest -q tests -k 'not test_hash_scan_blocks_symlinks' --junitxml=combined-tests.xml
```

OPA command:

```powershell
./work/opa.exe test respond/policies -v
```

## Coverage exercised

Alert validation/duplicates/resource inventory and role separation; UTC and required fields; secret/evidence sanitization and prompt injection; valid/invalid/timeout LLM stubs and fallback; actual OPA allow/deny for account/Region/tag/resource/operator/action/missing data; explicit boolean HTTP decisions and OPA unavailable; durable approval expiry, binding, replay and concurrent consumption; fake EC2 inventory failure, previous SG audit and failed mutation; C clean/tampered/health/no-snapshot scenarios; recovery before quarantine, invalid windows and untrusted request fields; duplicate and restart idempotency; concurrent job claims; protected verification and RCS/SAFE validation; persistent monitoring including REVIEW at 85.

The Uvicorn smoke test started a subprocess on 127.0.0.1:18763, fetched `/health` and `/openapi.json` over HTTP, then stopped it. The demo uses TestClient separately and real OPA executable evaluation.

## Demonstrated synthetic results

| Scenario | Result |
|---|---|
| Clean synthetic verifier evidence | SAFE, RCS 100 |
| Tampered synthetic file hash | REVIEW, RCS 75, monitoring alert |
| Synthetic failed functional health | REVIEW, RCS 85, monitoring alert |
| No verified clean snapshot | Denied, no clone |
| Repeated successful request | Stored result reused; no duplicate clone |
| Unknown action | Actual OPA deny |

`DEMO_RESULTS.json` is generated evidence, not a live AWS record. All resource IDs and verification observations are mock. Real local LLM inference, live AWS containment, snapshot recovery, verifier attachment/mounting, and external dashboard delivery were not performed. Live EC2 adapter work remains a separate team milestone.

Raw final Python and OPA output is included in `PYTEST_RESULTS.txt` and `OPA_RESULTS.txt`. The combined JUnit report is included as `combined-tests.xml`.
