@echo off
setlocal EnableDelayedExpansion

REM ==========================================
REM Networking & Cybersecurity Automation Toolkit
REM Windows Main Control Script
REM ==========================================

REM ---------- Directories ----------
set PROJECT_ROOT=%~dp0
set PROJECT_ROOT=%PROJECT_ROOT:~0,-1%
set SCRIPT_DIR=%PROJECT_ROOT%\scripts
set LOG_DIR=%PROJECT_ROOT%\logs
set OUTPUT_DIR=%PROJECT_ROOT%\output
set DASHBOARD_DIR=%PROJECT_ROOT%\dashboard
set TOOLS=%PROJECT_ROOT%\tools

REM Create required directories
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM ---------- Colors (Windows 10+ ANSI) ----------
set RED=[1;31m
set GREEN=[1;32m
set YELLOW=[1;33m
set BLUE=[1;34m
set MAGENTA=[1;35m
set CYAN=[1;36m
set WHITE=[1;37m
set BOLD=[1m
set NC=[0m

REM ---------- Banner ----------
:show_banner
cls
echo %CYAN%%BOLD%â•"â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—%NC%
echo %CYAN%%BOLD%â•'%NC%                                                                %CYAN%%BOLD%â•'%NC%
echo %CYAN%%BOLD%â•'%NC%  %RED%ðŸš€%YELLOW% Networking %GREEN%^&%BLUE% Cybersecurity %MAGENTA%Automation Toolkit%NC%   %CYAN%%BOLD%â•'%NC%
echo %CYAN%%BOLD%â•'%NC%  %BLUE%ðŸ"'%WHITE% Professional %CYAN%Security %GREEN%^& %YELLOW%Network Analysis Suite%NC% %CYAN%%BOLD%â•'%NC%
echo %CYAN%%BOLD%â•'%NC%                                                                %CYAN%%BOLD%â•'%NC%
echo %CYAN%%BOLD%â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.
exit /b

REM ---------- OS Detection ----------
:detect_os
echo windows
exit /b

REM ---------- Main Menu ----------
:show_main_menu
echo %BOLD%%BLUE%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Main Menu â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.
echo %GREEN%1.%NC% Run Security Scripts
echo %GREEN%2.%NC% View Dashboard
echo %GREEN%3.%NC% View Recent Logs
echo %GREEN%4.%NC% Clean Logs ^& Output
echo %GREEN%5.%NC% System Information
echo %GREEN%6.%NC% Help ^& Documentation
echo %GREEN%7.%NC% See networking tools
echo %RED%0.%NC% Exit
echo.
echo %BLUE%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
exit /b

REM ---------- Script Selection Menu ----------
:show_script_menu
call :show_banner
echo %BOLD%%MAGENTA%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Available Scripts â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.

echo %CYAN%Network Analysis:%NC%
echo %GREEN%2.%NC% Detect Suspicious Network Activity (Windows)

echo.
echo %CYAN%System Security:%NC%
echo %GREEN%5.%NC% Secure System (Windows)

echo.
echo %CYAN%System Information:%NC%
echo %GREEN%7.%NC% System Information (Windows)

echo.
echo %CYAN%Forensics:%NC%
echo %GREEN%9.%NC% Forensic Data Collection (Windows)

echo.
echo %CYAN%Web Reconnaissance:%NC%
echo %GREEN%11.%NC% Web Reconnaissance (Windows)

echo.
echo %GREEN%12.%NC% Run All Compatible Scripts
echo %RED%0.%NC% Back to Main Menu
echo.
echo %MAGENTA%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
exit /b

REM ---------- Execute Script ----------
:execute_script
set SCRIPT_PATH=%~1
set SCRIPT_NAME=%~nx1

for /f "tokens=1-6 delims=/:. " %%a in ("%date% %time%") do (
    set TIMESTAMP=%%c%%a%%b_%%d%%e%%f
)

set LOG_FILE=%LOG_DIR%\%SCRIPT_NAME%_!TIMESTAMP!.log

echo.
echo %YELLOW%Executing: %SCRIPT_NAME%%NC%
echo %BLUE%Log file: %LOG_FILE%%NC%
echo.

echo === Execution started at %DATE% %TIME% === > "%LOG_FILE%"

pushd "%OUTPUT_DIR%"
call "%SCRIPT_PATH%" >> "%LOG_FILE%" 2>&1
set EXIT_CODE=%ERRORLEVEL%
popd

echo === Execution completed at %DATE% %TIME% with exit code %EXIT_CODE% === >> "%LOG_FILE%"

if "%EXIT_CODE%"=="0" (
    echo.
    echo %GREEN%âœ" Script completed successfully%NC%
) else (
    echo.
    echo %RED%âœ— Script completed with errors (exit code: %EXIT_CODE%)%NC%
)

echo.
pause
exit /b

:run_script
set choice=%1

if "%choice%"=="1" call :execute_script "%SCRIPT_DIR%\detect_suspicious_net_linux.sh"
if "%choice%"=="2" call :execute_script "%SCRIPT_DIR%\detect_suspicious_net_windows.bat"
if "%choice%"=="3" call :execute_script "%SCRIPT_DIR%\secure_system.sh"
if "%choice%"=="4" call :execute_script "%SCRIPT_DIR%\revert_security.sh"
if "%choice%"=="5" call :execute_script "%SCRIPT_DIR%\secure_system.bat"
if "%choice%"=="6" call :execute_script "%SCRIPT_DIR%\system_info.sh"
if "%choice%"=="7" call :execute_script "%SCRIPT_DIR%\system_info.bat"
if "%choice%"=="8" call :execute_script "%SCRIPT_DIR%\forensic_collect.sh"
if "%choice%"=="9" call :execute_script "%SCRIPT_DIR%\forensic_collect.bat"
if "%choice%"=="10" call :execute_script "%SCRIPT_DIR%\web_recon.sh"
if "%choice%"=="11" call :execute_script "%SCRIPT_DIR%\web_recon.bat"
if "%choice%"=="12" call :run_all_scripts
if "%choice%"=="0" exit /b

exit /b

:run_all_scripts
echo %YELLOW%Running all compatible scripts for Windows...%NC%
echo.

for %%f in ("%SCRIPT_DIR%\*.bat") do (
    call :execute_script "%%f"
)

echo.
echo %GREEN%All scripts completed%NC%
pause
exit /b

:start_dashboard
cls
call :show_banner
echo %YELLOW%Starting Dashboard...%NC%
echo.

REM Move safely to dashboard directory
pushd "%DASHBOARD_DIR%" || exit /b

REM Detect Python
where python >nul 2>&1
if errorlevel 1 (
    echo %RED%Python is not installed. Opening static dashboard...%NC%
    start "" "index.html"
    popd
    exit /b
)

REM Check if port 8000 is already in use
netstat -ano | find ":8000" >nul
if %errorlevel%==0 (
    echo %GREEN%âœ" Dashboard already running at http://localhost:8000%NC%
) else (
    echo %GREEN%âœ" Starting dashboard server at http://localhost:8000%NC%
    start "" /b python server.py
    timeout /t 1 >nul
)

REM Open dashboard via server
start "" "http://localhost:8000"

popd
echo.
echo %CYAN%Dashboard running in background%NC%
pause
exit /b

:view_logs
cls
call :show_banner
echo %BOLD%%CYAN%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Recent Logs â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.

dir "%LOG_DIR%" /b >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%No logs found. Run some scripts first.%NC%
    pause
    exit /b
)

echo %GREEN%Available log files:%NC%
echo.
dir "%LOG_DIR%" /o-d /t:w

echo.
set /p log_choice=Enter log file name to view (or q to quit): 

if /i "%log_choice%"=="q" exit /b
if exist "%LOG_DIR%\%log_choice%" (
    notepad "%LOG_DIR%\%log_choice%"
)

pause
exit /b

:clean_data
cls
call :show_banner
echo %RED%%BOLD%Warning: This will delete all logs and output files!%NC%
set /p confirm=Are you sure? (yes/no): 

if /i "%confirm%"=="yes" (
    del /q "%LOG_DIR%\*" 2>nul
    del /q "%OUTPUT_DIR%\*" 2>nul
    echo %GREEN%âœ" Cleaned successfully%NC%
) else (
    echo %CYAN%Operation cancelled%NC%
)

pause
exit /b

:show_system_info
cls
call :show_banner
echo %BOLD%%CYAN%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• System Information â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.

echo %GREEN%Operating System:%NC% Windows
echo %GREEN%Hostname:%NC% %COMPUTERNAME%
echo %GREEN%User:%NC% %USERNAME%
echo %GREEN%Date:%NC% %DATE% %TIME%

echo.
echo %GREEN%Toolkit Statistics:%NC%
for /f %%a in ('dir "%LOG_DIR%" /a-d /b 2^>nul ^| find /c /v ""') do echo   Log files: %%a
for /f %%a in ('dir "%OUTPUT_DIR%" /a-d /b 2^>nul ^| find /c /v ""') do echo   Output files: %%a
for /f %%a in ('dir "%SCRIPT_DIR%" /a-d /b 2^>nul ^| find /c /v ""') do echo   Available scripts: %%a

pause
exit /b

:show_help
cls
call :show_banner
echo %BOLD%%CYAN%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Help ^& Documentation â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.
echo %GREEN%ðŸ"– About:%NC%
echo   This toolkit automates security and network analysis tasks,
echo   making it easier to detect threats, secure systems, and gather forensic data.
echo.
echo %GREEN%âœ¨ Features:%NC%
echo   â€¢ Detect suspicious network activity
echo   â€¢ System hardening and configuration
echo   â€¢ Forensic data collection
echo   â€¢ Web reconnaissance ^& scanning
echo   â€¢ Comprehensive logging and reporting
echo.
echo %GREEN%ðŸ› ï¸ Usage:%NC%
echo   1) Choose scripts from the main menu
echo   2) Execute tasks and monitor output
echo   3) Check logs for detailed insights
echo.
echo %GREEN%ðŸ"‚ Logs Location:%NC% %LOG_DIR%
echo %GREEN%ðŸ"‚ Output Location:%NC% %OUTPUT_DIR%
echo.
pause
exit /b

REM ==========================================
REM CORRECTED NETWORK TOOLS SECTION
REM This matches the Linux run.sh behavior exactly
REM ==========================================

:tools
cls
echo %BLUE%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo %GREEN%        ðŸ›   Available Tools%NC%
echo %BLUE%â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•%NC%
echo.
echo %GREEN% 1.%NC% Run Network Tools
echo %GREEN% 2.%NC% Back to Main Menu
echo.
echo %BLUE%â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€%NC%
set /p choice=%YELLOW%ðŸ'‰ Choose an option: %NC%
echo.

if "%choice%"=="1" (
    REM Check for Windows batch version first (preferred)
    if exist "%TOOLS%\network_tools.bat" (
        echo %GREEN%[+] Running network tools (Windows native)...%NC%
        call "%TOOLS%\network_tools.bat"
    ) else if exist "%TOOLS%\network_tools.sh" (
        REM If only .sh exists, check for bash availability
        echo %YELLOW%[*] Windows batch version not found, checking for bash...%NC%
        
        REM Try WSL bash first
        where wsl >nul 2>&1
        if not errorlevel 1 (
            echo %GREEN%[+] Running network tools via WSL...%NC%
            wsl bash "%TOOLS%\network_tools.sh"
        ) else (
            REM Try Git Bash
            where bash >nul 2>&1
            if not errorlevel 1 (
                echo %GREEN%[+] Running network tools via Git Bash...%NC%
                bash "%TOOLS%\network_tools.sh"
            ) else (
                REM No bash available
                echo %RED%[!] network_tools.sh found but bash is not available.%NC%
                echo %YELLOW%[*] Please either:%NC%
                echo     1. Install WSL (Windows Subsystem for Linux)
                echo     2. Install Git for Windows (includes Git Bash)
                echo     3. Create a Windows batch version: network_tools.bat
                echo.
                pause
                goto :tools
            )
        )
    ) else (
        REM Neither .bat nor .sh exists
        echo %RED%[!] Network tools not found.%NC%
        echo %YELLOW%[*] Looking for:%NC%
        echo     - %TOOLS%\network_tools.bat (preferred for Windows)
        echo     - %TOOLS%\network_tools.sh (requires bash)
        echo.
        pause
        goto :tools
    )
)

if "%choice%"=="2" (
    echo %YELLOW%[*] Returning to main menu...%NC%
    timeout /t 1 >nul
    exit /b
)

if not "%choice%"=="1" if not "%choice%"=="2" (
    echo %RED%[!] Invalid option. Please try again.%NC%
    timeout /t 1 >nul
    goto :tools
)

exit /b

REM ==========================================
REM END OF CORRECTED SECTION
REM ==========================================

:main
:main_loop
cls
call :show_banner
call :show_main_menu

echo.
set /p choice=%YELLOW%Enter your choice:%NC% 

if "%choice%"=="1" (
    :script_menu_loop
    call :show_script_menu
    echo.
    set /p script_choice=%YELLOW%Enter your choice:%NC% 

    if "%script_choice%"=="0" goto main_loop

    call :run_script %script_choice%
    goto script_menu_loop
)

if "%choice%"=="2" call :start_dashboard
if "%choice%"=="3" call :view_logs
if "%choice%"=="4" call :clean_data
if "%choice%"=="5" call :show_system_info
if "%choice%"=="6" call :show_help
if "%choice%"=="7" call :tools

if "%choice%"=="0" (
    echo.
    echo %GREEN%Thank you for using the Networking ^& Cybersecurity Toolkit!%NC%
    exit /b
)

echo %RED%Invalid choice. Please try again.%NC%
timeout /t 2 >nul
goto main_loop