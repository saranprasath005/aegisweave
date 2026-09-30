@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Project Python environment is missing. Run this from the original project folder.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\start_prototype.py
if errorlevel 1 pause
