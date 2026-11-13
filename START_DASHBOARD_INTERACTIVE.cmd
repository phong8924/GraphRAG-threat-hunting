@echo off
setlocal
cd /d "%~dp0"
set "TH_INTERACTIVE_PYTHON=.venv\Scripts\python.exe"
if not exist "%TH_INTERACTIVE_PYTHON%" set "TH_INTERACTIVE_PYTHON=outputs\review\acceptance_audit_v19_20261101\venv\Scripts\python.exe"
if not exist "%TH_INTERACTIVE_PYTHON%" (
  echo Chua co Python environment. Xem START_HERE.md.
  exit /b 1
)
if not "%~1"=="" if /I not "%~1"=="--live" (
  echo Su dung: START_DASHBOARD_INTERACTIVE.cmd [--live]
  exit /b 1
)
echo Interactive tung cau, khong chung nhan benchmark. Mo http://127.0.0.1:8032/
if /I "%~1"=="--live" (
  echo LIVE cap6. Can bat Live ro rang tai dashboard truoc khi gui cau hoi.
  "%TH_INTERACTIVE_PYTHON%" -B scripts\serve_interactive_ui.py --live --max-requests 6
) else (
  echo OFFLINE mac dinh: retrieval va gate, 0 request LLM.
  "%TH_INTERACTIVE_PYTHON%" -B scripts\serve_interactive_ui.py
)
endlocal
