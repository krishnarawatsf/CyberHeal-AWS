@echo off
setlocal
cd /d "%~dp0.."
where py >nul 2>nul
if errorlevel 1 (
  echo Python 3.11 or newer required. Install Python from python.org.
  pause
  exit /b 1
)
py -3 -c "import sys; assert sys.version_info >= (3, 11)" >nul 2>nul
if errorlevel 1 (
  echo Python 3.11 or newer is required.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
if errorlevel 1 goto FAIL
".venv\Scripts\python.exe" -m pip install -r requirements-member-c.txt
if errorlevel 1 goto FAIL
set "PYTHONPATH=%CD%\src"
echo ==== MEMBER C AWS POLICY AND CLOUD ADAPTER MOCK TESTS ====
".venv\Scripts\python.exe" -m pytest -q tests\test_recover_authorization.py tests\test_recover_checks.py tests\test_recover_rcs.py tests\test_recover_snapshots.py tests\test_recover_workflow.py tests\test_recover_aws_ebs.py tests\test_recover_aws_trust_registry.py tests\test_recover_aws_preflight.py
if errorlevel 1 goto FAIL
echo ==== OFFLINE AWS RECOVERY DEMO: NOT LIVE ====
".venv\Scripts\python.exe" -m cyberheal_recover.demo
if errorlevel 1 goto FAIL
echo SUCCESS: AWS offline tests and demonstration passed. No AWS mutation occurred.
pause
exit /b 0
:FAIL
echo Member C tests failed. Share the error, never AWS secrets.
pause
exit /b 1
