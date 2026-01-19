@echo off
setlocal enabledelayedexpansion

:: Networking & Cybersecurity Tools - Windows Runner Script
:: This script provides a menu-driven interface to run various security tools

title Networking ^& Cybersecurity Tools - Windows Runner

:: Set up colors (Windows 10+)
:: Note: Color codes work with echo command in Windows 10+

:: Directory setup
set "SCRIPT_DIR=%~dp0"
set "SCRIPTS_PATH=%SCRIPT_DIR%scripts"
set "OUTPUT_DIR=%SCRIPT_DIR%output"
set "LOGS_DIR=%SCRIPT_DIR%logs"

:: Create timestamp
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set "TIMESTAMP=%datetime:~0,8%_%datetime:~8,6%"

:: Create necessary directories
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

:: Main menu loop
:menu
cls
echo ============================================================
echo    Networking ^& Cybersecurity Tools - Windows Runner
echo ============================================================
echo.
echo Output Directory: %OUTPUT_DIR%
echo Logs Directory: %LOGS_DIR%
echo.
echo Available Tools:
echo   1) System Information Collection
echo   2) Detect Suspicious Network Activity
echo   3) Secure System Configuration
echo   4) Forensic Data Collection
echo   5) Web Reconnaissance
echo.
echo   6) Run All Security Scripts (1-5)
echo   7) Open Dashboard
echo   8) Clean Output/Logs Directories
echo   9) Open Output Folder
echo   0) Exit
echo.

set /p choice="Enter your choice [0-9]: "

if "%choice%"=="1" goto system_info
if "%choice%"=="2" goto detect_suspicious
if "%choice%"=="3" goto secure_system
if "%choice%"=="4" goto forensic_collect
if "%choice%"=="5" goto web_recon
if "%choice%"=="6" goto run_all
if "%choice%"=="7" goto open_dashboard
if "%choice%"=="8" goto clean_dirs
if "%choice%"=="9" goto open_output
if "%choice%"=="0" goto exit_script

echo Invalid option. Please try again.
timeout /t 2 >nul
goto menu

:: Function to run a script
:run_script
set "script_name=%~1"
set "script_path=%SCRIPTS_PATH%\%script_name%"
set "script_base=%~n1"
set "log_file=%LOGS_DIR%\%script_base%_%TIMESTAMP%.log"

if not exist "%script_path%" (
    echo.
    echo [ERROR] Script %script_name% not found!
    echo.
    pause
    goto :eof
)

echo.
echo ================================================
echo Running %script_name%...
echo Log file: %log_file%
echo ================================================
echo.

:: Log execution details
echo === Execution started at %date% %time% === > "%log_file%"
echo Script: %script_name% >> "%log_file%"
echo Output directory: %OUTPUT_DIR% >> "%log_file%"
echo ====================================== >> "%log_file%"
echo. >> "%log_file%"

:: Change to output directory and run script
cd /d "%OUTPUT_DIR%"
call "%script_path%" 2>&1 | "%SCRIPT_DIR%\tee_to_file.bat" "%log_file%"
set "exit_code=!errorlevel!"
cd /d "%SCRIPT_DIR%"

:: Log completion
echo. >> "%log_file%"
echo === Execution ended at %date% %time% === >> "%log_file%"

if !exit_code! equ 0 (
    echo.
    echo [SUCCESS] %script_name% completed successfully
) else (
    echo.
    echo [ERROR] %script_name% failed with exit code !exit_code!
)

echo.
pause
goto :eof

:: Individual script execution
:system_info
call :run_script "system_info.bat"
goto menu

:detect_suspicious
call :run_script "detect_suspicious_net_windows.bat"
goto menu

:secure_system
call :run_script "secure_system.bat"
goto menu

:forensic_collect
call :run_script "forensic_collect.bat"
goto menu

:web_recon
call :run_script "web_recon.bat"
goto menu

:: Run all scripts
:run_all
cls
echo ============================================================
echo Running all security scripts...
echo ============================================================
echo.

call :run_script "system_info.bat"
call :run_script "detect_suspicious_net_windows.bat"
call :run_script "secure_system.bat"
call :run_script "forensic_collect.bat"
call :run_script "web_recon.bat"

echo.
echo ============================================================
echo [SUCCESS] All scripts completed
echo ============================================================
echo.
pause
goto menu

:: Open dashboard
:open_dashboard
set "dashboard_path=%SCRIPT_DIR%dashboard\index.html"

if not exist "%dashboard_path%" (
    echo.
    echo [ERROR] Dashboard not found at %dashboard_path%
    echo.
    pause
    goto menu
)

echo.
echo Opening dashboard...
start "" "%dashboard_path%"
timeout /t 2 >nul
goto menu

:: Clean directories
:clean_dirs
cls
echo ============================================================
echo Clean Output and Logs Directories
echo ============================================================
echo.
echo This will delete all files in output and logs directories.
echo.
set /p confirm="Are you sure? (yes/no): "

if /i "%confirm%"=="yes" (
    echo.
    echo Cleaning directories...
    del /q "%OUTPUT_DIR%\*.*" 2>nul
    del /q "%LOGS_DIR%\*.*" 2>nul
    echo.
    echo [SUCCESS] Directories cleaned successfully
) else (
    echo.
    echo Operation cancelled
)
echo.
pause
goto menu

:: Open output folder
:open_output
echo.
echo Opening output folder...
start "" explorer "%OUTPUT_DIR%"
timeout /t 1 >nul
goto menu

:: Exit script
:exit_script
cls
echo.
echo ============================================================
echo Thank you for using the Security Tools Runner!
echo ============================================================
echo.
timeout /t 2 >nul
exit /b 0

:: Helper function for tee functionality (save this as tee_to_file.bat in root)
:tee_to_file
:: This is a placeholder - Windows doesn't have native tee
:: The actual implementation would need a separate helper script
:: For now, output will only go to log file
:: Alternative: Use PowerShell or download GNU tee for Windows