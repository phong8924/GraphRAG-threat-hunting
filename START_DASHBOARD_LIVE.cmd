@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Missing project .venv. See docs/LIVE_DASHBOARD.md.
  exit /b 1
)
echo Current resizable dashboard - LIVE, maximum 6 dashboard requests, no retry/fallback.
echo http://127.0.0.1:8034/ - enable Live explicitly before sending a new question.
".venv\Scripts\python.exe" -B scripts\serve_current_interactive_ui.py --config configs\interactive\dashboard_live_v10.json --manifest configs\interactive\runtime_manifest_live_v9.json --live --max-requests 6 --port 8034
set "TH_LIVE_EXIT=%ERRORLEVEL%"
endlocal & exit /b %TH_LIVE_EXIT%
