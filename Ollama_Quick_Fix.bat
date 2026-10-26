
@echo off
setlocal
title Ollama Quick Fix
color 0A

set "OLLAMA_HOST=http://127.0.0.1:11434"
set "OLLAMA_EXE=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"

echo ==========================================
echo          OLLAMA QUICK FIX
echo ==========================================
echo.

if not exist "%OLLAMA_EXE%" (
    echo ERROR: Ollama executable not found.
    echo Check your Ollama installation.
    pause
    exit /b 1
)

echo [1/3] Checking Ollama server...

curl.exe -fsS --max-time 4 http://127.0.0.1:11434/ >nul 2>&1

if not errorlevel 1 goto SERVER_READY

echo Server is not responding.
echo Restarting Ollama...

taskkill /F /IM ollama.exe /T >nul 2>&1
timeout /t 3 /nobreak >nul

echo Starting Ollama server...
start "Ollama Server" /min "%OLLAMA_EXE%" serve

echo Waiting for server...

for /L %%I in (1,1,20) do (
    curl.exe -fsS --max-time 2 http://127.0.0.1:11434/ >nul 2>&1
    if not errorlevel 1 goto SERVER_READY
    timeout /t 1 /nobreak >nul
)

echo ERROR: Ollama server did not respond.
echo Check the Ollama logs before trying again.
pause
exit /b 1

:SERVER_READY
echo Server is responding.
echo.
echo [2/3] Using explicit local server address...
echo %OLLAMA_HOST%
echo.
echo [3/3] Listing installed models...
echo.

"%OLLAMA_EXE%" list

if errorlevel 1 (
    echo.
    echo The CLI returned an error.
    echo Check the Ollama logs for details.
)

echo.
echo Finished.
pause
