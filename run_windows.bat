@echo off
setlocal enabledelayedexpansion
REM CyberSec Toolkit - Windows Runner

REM ─────────────────────────────────────────────
REM Paths
REM ─────────────────────────────────────────────

set BASE_DIR=%~dp0
set SCRIPT_DIR=%BASE_DIR%scripts
set DASHBOARD_DIR=%BASE_DIR%dashboard
set LOG_DIR=%BASE_DIR%logs
set OUTPUT_DIR=%BASE_DIR%outputs

set WEB_RECON_DIR=%OUTPUT_DIR%\web_recon
set NET_DIR=%OUTPUT_DIR%\network
set FORENSIC_DIR=%OUTPUT_DIR%\forensics
set SYSTEM_DIR=%OUTPUT_DIR%\system

for %%d in ("%LOG_DIR%" "%WEB_RECON_DIR%" "%NET_DIR%" "%FORENSIC_DIR%" "%SYSTEM_DIR%") do (
    if not exist %%d mkdir %%d
)

for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set TS=%%i
set LOG_FILE=%LOG_DIR%\run_%TS%.log

REM Export to child scripts
set WEB_RECON_DIR=%WEB_RECON_DIR%
set NET_DIR=%NET_DIR%
set FORENSIC_DIR=%FORENSIC_DIR%
set SYSTEM_DIR=%SYSTEM_DIR%

REM ─────────────────────────────────────────────
REM Banner
REM ─────────────────────────────────────────────

:banner
cls
echo ===============================================
echo   CyberSec Toolkit - Windows Runner
echo ===============================================

REM ─────────────────────────────────────────────
REM Menu
REM ─────────────────────────────────────────────

:menu
echo 1) Secure System
echo 2) Detect Suspicious Net
echo 3) Revert Security
echo 4) Forensic Collection
echo 5) System Information
echo 6) Web Reconnaissance
echo 7) Launch Dashboard
echo 8) View Logs
echo 9) Run All Security
echo 0) Exit
echo.

set /p choice=Choice:

if "%choice%"=="1" call :run secure_system
if "%choice%"=="2" call :run detect_suspicious_net
if "%choice%"=="3" call :run revert_security
if "%choice%"=="4" call :run forensic_collect
if "%choice%"=="5" call :run system_info
if "%choice%"=="6" call :run web_recon
if "%choice%"=="7" start "" "%DASHBOARD_DIR%\index.html"
if "%choice%"=="8" type "%LOG_FILE%"
if "%choice%"=="9" (
    call :run secure_system
    call :run detect_suspicious_net
)
if "%choice%"=="0" exit /b

pause
goto banner

REM ─────────────────────────────────────────────
REM Run helper
REM ─────────────────────────────────────────────

:run
set SCRIPT=%SCRIPT_DIR%\%1.bat
if not exist "%SCRIPT%" (
    echo Missing script: %SCRIPT%
    goto :eof
)
echo Running %1...
call "%SCRIPT%" >> "%LOG_FILE%" 2>&1
goto :eof
