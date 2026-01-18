@echo off
mkdir "%cd%\suspicious_scan" 2>nul
powershell -Command "Get-Date -Format o" > "%cd%\suspicious_scan\run_timestamp.txt"
systeminfo > "%cd%\suspicious_scan\systeminfo.txt"
whoami /all > "%cd%\suspicious_scan\whoami.txt"
tasklist /v > "%cd%\suspicious_scan\tasklist_v.txt"
netstat -ano > "%cd%\suspicious_scan\netstat_ano.txt"
netstat -abno > "%cd%\suspicious_scan\netstat_abno.txt" 2>nul || true
powershell -Command "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Sort-Object RemoteAddress | Out-File -FilePath '%cd%\\suspicious_scan\\net_connections_ps.txt' -Width 512" 2>nul
powershell -Command "gc '%cd%\\suspicious_scan\\net_connections_ps.txt' | Select-String -Pattern '\\d+\\.\\d+\\.\\d+\\.\\d+' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File '%cd%\\suspicious_scan\\remote_ips.txt'" 2>nul
for /f "usebackq delims=" %%I in ("%cd%\suspicious_scan\remote_ips.txt") do @powershell -Command "Write-Output '=== %%I ===' > '%cd%\\suspicious_scan\\whois_%%I.txt'; try{ $r=Invoke-RestMethod -Uri 'https://ipinfo.io/%%I/json' -TimeoutSec 8; $r | ConvertTo-Json | Out-File -FilePath '%cd%\\suspicious_scan\\whois_%%I.txt' -Append } catch { nslookup %%I | Out-File -FilePath '%cd%\\suspicious_scan\\whois_%%I.txt' -Append }" 2>nul
for /f "tokens=5 delims= " %%P in ('netstat -ano ^| findstr /R /C:"ESTABLISHED"') do @for /f "usebackq delims=" %%T in ('tasklist /FI "PID eq %%P" /FO LIST ^| findstr /I "Image Name"') do @echo PID=%%P >> "%cd%\suspicious_scan\connections_processes.txt" 2>nul
powershell -Command "Get-Process | Select-Object Id,ProcessName,Path,StartTime | Sort-Object StartTime -Descending | Out-File -FilePath '%cd%\\suspicious_scan\\processes_with_path.txt' -Width 512" 2>nul
powershell -Command "Get-Process | Where-Object {$_.Path -ne $null} | ForEach-Object { if(Test-Path $_.Path){ $h=@(); $h += @{MD5=(Get-FileHash $_.Path -Algorithm MD5).Hash; SHA256=(Get-FileHash $_.Path -Algorithm SHA256).Hash; Path=$_.Path; Id=$_.Id; Name=$_.ProcessName}; $h | ConvertTo-Json | Out-File -FilePath '%cd%\\suspicious_scan\\process_hashes.json' -Append } }" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s > "%cd%\suspicious_scan\run_keys.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s > "%cd%\suspicious_scan\run_keys_current.txt" 2>nul
schtasks /Query /FO LIST /V > "%cd%\suspicious_scan\schtasks.txt" 2>nul
powershell -Command "Get-ScheduledTask | Where-Object { $_.TaskPath -ne '\' } | Out-File -FilePath '%cd%\\suspicious_scan\\scheduled_tasks.txt' -Width 512" 2>nul
dir "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" /b > "%cd%\suspicious_scan\startup_folder.txt" 2>nul
dir "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" /b > "%cd%\suspicious_scan\startup_allusers.txt" 2>nul
powershell -Command "Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Out-File -FilePath '%cd%\\suspicious_scan\\auto_services_not_running.txt' -Width 512" 2>nul
powershell -Command "Get-Service | Where-Object {$_.StartType -eq 'Auto' } | Out-File -FilePath '%cd%\\suspicious_scan\\auto_services.txt' -Width 512" 2>nul
powershell -Command "Get-ChildItem -Path C:\Windows\Temp,C:\Users\*\AppData\Local\Temp -Recurse -Force | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName,Length,LastWriteTime | Out-File -FilePath '%cd%\\suspicious_scan\\recent_temp_files.txt' -Width 512" 2>nul
powershell -Command "Get-ChildItem -Path C:\ -Include *.exe,*.ps1,*.vbs -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName,Length,LastWriteTime | Out-File '%cd%\\suspicious_scan\\recent_executables.txt' -Width 512" 2>nul
powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 | Format-List | Out-File '%cd%\\suspicious_scan\\security_events_last7days.txt' -Width 200" 2>nul
powershell -Command "Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 | Format-List | Out-File '%cd%\\suspicious_scan\\system_events_last7days.txt' -Width 200" 2>nul
powershell -Command "Compress-Archive -Path '%cd%\\suspicious_scan\\*' -DestinationPath '%cd%\\suspicious_scan.zip' -Force" 2>nul
