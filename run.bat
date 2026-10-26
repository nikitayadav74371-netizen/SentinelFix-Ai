@echo off
setlocal
cd /d "%~dp0"
title Sentinel AI AI
echo ============================================
echo   Sentinel AI AI  -  starting up
echo ============================================

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python 3.10+ was not found on PATH. Install it from https://www.python.org/downloads/
  echo         and tick "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)
where git >nul 2>nul
if errorlevel 1 echo [WARN] git not found - GitHub scanning will be unavailable. Local scanning works fine.

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv .venv
)
echo Installing dependencies (first run only takes a minute)...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Dependency install failed.
  pause
  exit /b 1
)

echo.
echo Open  http://127.0.0.1:8080  in your browser  (Ctrl+C here to stop)
start "" http://127.0.0.1:8080
".venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8080
pause

@REM  @echo off
@REM  setlocal
@REM  cd /d "%~dp0"
@REM  title Sentinel AI AI
@REM  echo ============================================
@REM  echo   Sentinel AI AI  -  starting up
@REM  echo ============================================

@REM  where python >nul 2>nul
@REM  if errorlevel 1 (
@REM    echo [ERROR] Python 3.10+ was not found on PATH. Install it from https://www.python.org/downloads/
@REM    echo         and tick "Add python.exe to PATH" during setup.
@REM    pause
@REM    exit /b 1
@REM  )
@REM  where git >nul 2>nul
@REM  if errorlevel 1 echo [WARN] git not found - GitHub scanning will be unavailable. Local scanning works fine.

@REM  if not exist ".venv\Scripts\python.exe" (
@REM    echo Creating virtual environment...
@REM    python -m venv .venv
@REM  )
@REM  echo Installing dependencies (first run only takes a minute)...
@REM  ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt
@REM  if errorlevel 1 (
@REM    echo [ERROR] Dependency install failed.
@REM    pause
@REM    exit /b 1
@REM  )

@REM  echo.
@REM  echo Open  http://localhost:8000  in your browser  (Ctrl+C here to stop)
@REM  start "" http://localhost:8000
@REM  ".venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
@REM  pause
