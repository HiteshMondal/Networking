@echo off
md "%cd%\forensic_output" 2>nul
wevtutil el > "%cd%\forensic_output\wevtutil_logs.txt"
wevtutil qe System /f:text /c:5000 > "%cd%\forensic_output\System.txt" 2>nul
wevtutil qe Security /f:text /c:5000 > "%cd%\forensic_output\Security.txt" 2>nul
wevtutil qe Application /f:text /c:5000 > "%cd%\forensic_output\Application.txt" 2>nul
wevtutil epl Security "%cd%\forensic_output\Security.evtx" 2>nul
wevtutil epl System "%cd%\forensic_output\System.evtx" 2>nul
wevtutil epl Application "%cd%\forensic_output\Application.evtx" 2>nul
wevtutil el > "%cd%\forensic_output\all_event_logs_list.txt" 2>nul
for %%L in (System Security Application) do wevtutil gl %%L > "%cd%\forensic_output\%%L_properties.txt" 2>nul
type "%windir%\System32\drivers\etc\hosts" > "%cd%\forensic_output\hosts.txt" 2>nul
ipconfig /all > "%cd%\forensic_output\ipconfig_all.txt"
netstat -ano > "%cd%\forensic_output\netstat_ano.txt"
arp -a > "%cd%\forensic_output\arp.txt"
route print > "%cd%\forensic_output\route.txt"
tasklist /v > "%cd%\forensic_output\tasklist_v.txt"
tasklist /svc > "%cd%\forensic_output\tasklist_svc.txt"
wmic process list full > "%cd%\forensic_output\wmic_process_full.txt"
sc query state= all > "%cd%\forensic_output\services_all.txt"
netsh advfirewall firewall show rule name=all > "%cd%\forensic_output\firewall_rules.txt"
copy "%windir%\System32\LogFiles\Firewall\pfirewall.log" "%cd%\forensic_output\pfirewall.log" 2>nul
wevtutil qe "Microsoft-Windows-Sysmon/Operational" /f:text /c:5000 > "%cd%\forensic_output\Sysmon.txt" 2>nul
for /f "delims=" %%G in ('powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddDays(-7)} | Select-Object -First 500 | Format-List -Property *"') do echo %%G >> "%cd%\forensic_output\Security_last7days.txt"
powershell -Command "Get-ChildItem 'C:\Windows\System32\winevt\Logs' | Select-Object FullName,Length,LastWriteTime | Out-File '%cd%\forensic_output\event_files_listing.txt'"
ipconfig /displaydns > "%cd%\forensic_output\dns_cache.txt"
fsutil usn queryjournal C: > "%cd%\forensic_output\usn_journal.txt" 2>nul
wmic product get Name,Version > "%cd%\forensic_output\installed_programs.txt" 2>nul
net user > "%cd%\forensic_output\users.txt"
net localgroup administrators > "%cd%\forensic_output\local_administrators.txt"
mountvol > "%cd%\forensic_output\mountvol.txt"
dir "%systemdrive%\inetpub\logs\LogFiles" /s /b > "%cd%\forensic_output\iis_logs_listing.txt" 2>nul
xcopy "%systemdrive%\inetpub\logs\LogFiles" "%cd%\forensic_output\IIS_Logs" /E /I /Y 2>nul || true
netsh trace start capture=yes tracefile="%cd%\forensic_output\nettrace.etl" persistent=no maxSize=1024 2>nul
timeout /t 10 >nul
netsh trace stop 2>nul
powershell -Command "Compress-Archive -Path '%cd%\forensic_output\*' -DestinationPath '%cd%\forensic_output.zip' -Force" 2>nul
