@echo off
REM CyberSec Toolkit - Windows Runner
REM Centralized execution script for all security tools

setlocal enabledelayedexpansion

REM Configuration
set "SCRIPT_DIR=..\scripts"
set "LOG_DIR=..\logs"
set "DASHBOARD_DIR=..\dashboard"
set "TIMESTAMP=%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TIMESTAMP=%TIMESTAMP: =0%"
set "LOG_FILE=%LOG_DIR%\run_%TIMESTAMP%.log"

REM Create log directory if it doesn't exist
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Colors (Windows 10+)
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "PURPLE=[95m"
set "CYAN=[96m"
set "NC=[0m"

goto :main

:show_banner
cls
echo %CYAN%
echo ================================================================
echo.
echo        🛡️  CyberSec Toolkit - Windows Runner 🛡️
echo.
echo           Network Security ^& Forensics Suite
echo.
echo ================================================================
echo %NC%
echo.
exit /b 0

:log_message
REM %1 = level, %2 = message
set "timestamp=%date% %time%"
echo [%timestamp%] [%~1] %~2 >> "%LOG_FILE%"
exit /b 0

:check_script
REM %1 = script name
set "script_path=%SCRIPT_DIR%\%~1_windows.bat"

if not exist "%script_path%" (
    echo %RED%Error: Script not found: %script_path%%NC%
    exit /b 1
)
exit /b 0

:execute_script
REM %1 = script name
set "script_name=%~1"
set "script_path=%SCRIPT_DIR%\%~1_windows.bat"

echo %BLUE%=============================================================%NC%
echo %GREEN%▶ Executing: %script_name%%NC%
echo %BLUE%=============================================================%NC%
echo.

call :log_message "INFO" "Starting execution of %script_name%"

REM Execute the script
call "%script_path%" 2>&1 | tee -a "%LOG_FILE%"

if !errorlevel! equ 0 (
    call :log_message "SUCCESS" "%script_name% completed successfully"
    echo.
    echo %GREEN%✓ Script completed successfully%NC%
) else (
    call :log_message "ERROR" "%script_name% failed with exit code !errorlevel!"
    echo.
    echo %RED%✗ Script failed%NC%
)
exit /b !errorlevel!

:show_menu
echo %PURPLE%=============================================================%NC%
echo %CYAN%                    MAIN MENU%NC%
echo %PURPLE%=============================================================%NC%
echo.
echo %GREEN%Security Tools:%NC%
echo   1) Secure System           - Harden system security
echo   2) Detect Suspicious Net   - Monitor network activity
echo.
echo %GREEN%Forensic Tools:%NC%
echo   3) Forensic Collection     - Collect system artifacts
echo   4) System Information      - Gather system info
echo.
echo %GREEN%Reconnaissance:%NC%
echo   5) Web Reconnaissance      - Web-based recon
echo.
echo %GREEN%Dashboard ^& Utilities:%NC%
echo   6) Launch Dashboard        - Open web dashboard
echo   7) View Logs              - Display execution logs
echo   8) Run All Security       - Execute all security tools
echo   9) Help                   - Show help information
echo.
echo %RED%  0) Exit%NC%
echo.
echo %PURPLE%=============================================================%NC%
echo.
exit /b 0

:launch_dashboard
echo %CYAN%Launching Web Dashboard...%NC%

if not exist "%DASHBOARD_DIR%\index.html" (
    echo %RED%Error: Dashboard not found at %DASHBOARD_DIR%\index.html%NC%
    exit /b 1
)

REM Open with default browser
start "" "%DASHBOARD_DIR%\index.html"

call :log_message "INFO" "Dashboard launched"
echo %GREEN%Dashboard opened in default browser%NC%
exit /b 0

:view_logs
echo %CYAN%Recent Log Entries:%NC%
echo %BLUE%=============================================================%NC%

if exist "%LOG_FILE%" (
    REM Display last 50 lines of log file
    powershell -Command "Get-Content '%LOG_FILE%' -Tail 50"
) else (
    echo %YELLOW%No logs available for this session%NC%
)

echo.
echo %BLUE%=============================================================%NC%
exit /b 0

:run_all_security
echo %CYAN%Running all security tools...%NC%
echo.

set "failed=0"

call :check_script "secure_system"
if !errorlevel! equ 0 (
    call :execute_script "secure_system"
    echo.
) else (
    set /a failed+=1
)

call :check_script "detect_suspicious_net"
if !errorlevel! equ 0 (
    call :execute_script "detect_suspicious_net"
    echo.
) else (
    set /a failed+=1
)

echo %BLUE%=============================================================%NC%
if !failed! equ 0 (
    echo %GREEN%All security tools completed successfully%NC%
) else (
    echo %YELLOW%!failed! tool(s) failed or were not found%NC%
)
exit /b 0

:show_help
echo %CYAN%=============================================================%NC%
echo %GREEN%CyberSec Toolkit Help%NC%
echo %CYAN%=============================================================%NC%
echo.
echo This runner script provides a unified interface to execute
echo all security, forensic, and reconnaissance tools.
echo.
echo %GREEN%Usage:%NC%
echo   run_windows.bat [option]
echo.
echo %GREEN%Options:%NC%
echo   /auto-secure    Run all security tools automatically
echo   /dashboard      Launch dashboard directly
echo   /help           Show this help message
echo.
echo %GREEN%Features:%NC%
echo   • Automatic logging of all operations
echo   • Script validation and permission checking
echo   • Color-coded output for better readability
echo   • Web-based dashboard for visual monitoring
echo.
echo %GREEN%Log Location:%NC%
echo   %LOG_FILE%
echo.
echo %GREEN%Requirements:%NC%
echo   • Windows 10 or later (for color support)
echo   • Administrator privileges (for some tools)
echo   • PowerShell (for advanced features)
echo.
exit /b 0

:main
call :show_banner

REM Check for command line arguments
if "%~1"=="/auto-secure" (
    call :run_all_security
    goto :eof
)
if "%~1"=="/dashboard" (
    call :launch_dashboard
    goto :eof
)
if "%~1"=="/help" (
    call :show_help
    goto :eof
)
if not "%~1"=="" (
    echo %RED%Unknown option: %~1%NC%
    echo Use /help for usage information
    goto :eof
)

call :log_message "INFO" "CyberSec Toolkit Runner started"

REM Interactive menu loop
:menu_loop
call :show_menu
set /p "choice=Enter your choice: "
echo.

if "%choice%"=="1" (
    call :check_script "secure_system"
    if !errorlevel! equ 0 call :execute_script "secure_system"
) else if "%choice%"=="2" (
    call :check_script "detect_suspicious_net"
    if !errorlevel! equ 0 call :execute_script "detect_suspicious_net"
) else if "%choice%"=="3" (
    call :check_script "forensic_collect"
    if !errorlevel! equ 0 call :execute_script "forensic_collect"
) else if "%choice%"=="4" (
    call :check_script "system_info"
    if !errorlevel! equ 0 call :execute_script "system_info"
) else if "%choice%"=="5" (
    call :check_script "web_recon"
    if !errorlevel! equ 0 call :execute_script "web_recon"
) else if "%choice%"=="6" (
    call :launch_dashboard
) else if "%choice%"=="7" (
    call :view_logs
) else if "%choice%"=="8" (
    call :run_all_security
) else if "%choice%"=="9" (
    call :show_help
) else if "%choice%"=="0" (
    echo %GREEN%Exiting CyberSec Toolkit...%NC%
    call :log_message "INFO" "CyberSec Toolkit Runner stopped"
    goto :eof
) else (
    echo %RED%Invalid choice. Please try again.%NC%
)

echo.
pause
cls
call :show_banner
goto :menu_loop

:eof
endlocal