@echo off
setlocal
cd /d "%~dp0"
echo Saved DeepSeek results - no API key required, 0 new API calls.
echo http://127.0.0.1:8034/results
".venv\Scripts\python.exe" -B scripts\serve_saved_results.py --port 8034
set "TH_RESULTS_EXIT=%ERRORLEVEL%"
endlocal & exit /b %TH_RESULTS_EXIT%
