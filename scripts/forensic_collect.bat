@echo off
REM =============================================================================
REM Script: forensic_collect_windows.bat
REM Purpose:
REM   Collect volatile and non-volatile forensic artifacts from a Windows system.
REM   Designed for post-incident response and evidence preservation.
REM
REM Artifacts Collected:
REM   - Windows Event Logs (text + EVTX)
REM   - Network configuration and state
REM   - Process and service inventory
REM   - Firewall and Sysmon logs
REM   - User accounts and installed software
REM   - Disk, DNS, USN Journal, IIS logs
REM
REM Output:
REM   All artifacts stored in .\forensic_output\
REM   Final archive: forensic_output.zip
REM
REM Notes:
REM   - Run as Administrator for best coverage
REM   - Script prioritizes read-only collection
REM =============================================================================


REM Setup

REM Create forensic output directory
md "%cd%\forensic_output" 2>nul


REM Event Log Enumeration & Collection

REM List all available event logs
wevtutil el > "%cd%\forensic_output\wevtutil_logs.txt"

REM Export recent events (text format) for quick triage
wevtutil qe System      /f:text /c:5000 > "%cd%\forensic_output\System.txt"      2>nul
wevtutil qe Security    /f:text /c:5000 > "%cd%\forensic_output\Security.txt"    2>nul
wevtutil qe Application /f:text /c:5000 > "%cd%\forensic_output\Application.txt" 2>nul

REM Export full EVTX logs for offline forensic analysis
wevtutil epl Security    "%cd%\forensic_output\Security.evtx"    2>nul
wevtutil epl System      "%cd%\forensic_output\System.evtx"      2>nul
wevtutil epl Application "%cd%\forensic_output\Application.evtx" 2>nul

REM List all event logs again (verification)
wevtutil el > "%cd%\forensic_output\all_event_logs_list.txt"

REM Capture metadata for critical logs
for %%L in (System Security Application) do (
  wevtutil gl %%L > "%cd%\forensic_output\%%L_properties.txt" 2>nul
)


REM Network Configuration & State

REM Hosts file (DNS hijacking indicator)
type "%windir%\System32\drivers\etc\hosts" ^
  > "%cd%\forensic_output\hosts.txt" 2>nul

REM Full IP configuration
ipconfig /all > "%cd%\forensic_output\ipconfig_all.txt"

REM Network connections with PIDs
netstat -ano > "%cd%\forensic_output\netstat_ano.txt"

REM ARP cache (lateral movement indicator)
arp -a > "%cd%\forensic_output\arp.txt"

REM Routing table
route print > "%cd%\forensic_output\route.txt"


REM Process, Services & Execution State

REM Running processes with verbose output
tasklist /v   > "%cd%\forensic_output\tasklist_v.txt"
tasklist /svc > "%cd%\forensic_output\tasklist_svc.txt"

REM Full process details (includes command line)
wmic process list full > "%cd%\forensic_output\wmic_process_full.txt"

REM All services and their states
sc query state= all > "%cd%\forensic_output\services_all.txt"


REM Firewall & Security Controls

REM Windows Firewall rules
netsh advfirewall firewall show rule name=all ^
  > "%cd%\forensic_output\firewall_rules.txt"

REM Firewall connection log (if enabled)
copy "%windir%\System32\LogFiles\Firewall\pfirewall.log" ^
     "%cd%\forensic_output\pfirewall.log" 2>nul


REM Advanced Logging (Sysmon, Security)

REM Sysmon operational log (if Sysmon is installed)
wevtutil qe "Microsoft-Windows-Sysmon/Operational" ^
  /f:text /c:5000 > "%cd%\forensic_output\Sysmon.txt" 2>nul

REM Security events from last 7 days (focused review)
for /f "delims=" %%G in ('
  powershell -Command ^
    "Get-WinEvent -FilterHashtable @{LogName=''Security'';StartTime=(Get-Date).AddDays(-7)} |
     Select-Object -First 500 |
     Format-List -Property *"
') do (
  echo %%G >> "%cd%\forensic_output\Security_last7days.txt"
)

REM List event log files on disk
powershell -Command ^
  "Get-ChildItem 'C:\Windows\System32\winevt\Logs' |
   Select-Object FullName,Length,LastWriteTime |
   Out-File '%cd%\forensic_output\event_files_listing.txt'"


REM Disk, DNS & System State

REM DNS resolver cache (C2 residue indicator)
ipconfig /displaydns > "%cd%\forensic_output\dns_cache.txt"

REM NTFS USN journal (file activity history)
fsutil usn queryjournal C: > "%cd%\forensic_output\usn_journal.txt" 2>nul

REM Installed software inventory
wmic product get Name,Version > "%cd%\forensic_output\installed_programs.txt" 2>nul

REM User accounts
net user > "%cd%\forensic_output\users.txt"

REM Local administrators (privilege escalation evidence)
net localgroup administrators > "%cd%\forensic_output\local_administrators.txt"

REM Mounted volumes
mountvol > "%cd%\forensic_output\mountvol.txt"


REM IIS Logs (If Web Server Present)

REM List IIS log locations
dir "%systemdrive%\inetpub\logs\LogFiles" /s /b ^
  > "%cd%\forensic_output\iis_logs_listing.txt" 2>nul

REM Copy IIS logs for analysis
xcopy "%systemdrive%\inetpub\logs\LogFiles" ^
      "%cd%\forensic_output\IIS_Logs" /E /I /Y 2>nul


REM Short Network Trace (Volatile Evidence)

REM Capture short network trace (10 seconds)
netsh trace start capture=yes ^
  tracefile="%cd%\forensic_output\nettrace.etl" ^
  persistent=no maxSize=1024 2>nul

timeout /t 10 >nul

netsh trace stop 2>nul


REM Archive Results

REM Compress all forensic artifacts
powershell -Command ^
  "Compress-Archive -Path '%cd%\forensic_output\*' ^
   -DestinationPath '%cd%\forensic_output.zip' -Force" 2>nul
