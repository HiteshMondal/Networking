@echo off
set /p TARGET=Enter target URL or host: 
for /f "usebackq delims=" %%H in (`powershell -NoProfile -Command "(New-Object System.Uri('%TARGET%')).Host"`) do set HOST=%%H
if "%HOST%"=="" set HOST=%TARGET%
for /f "tokens=1-3 delims=/: " %%a in ("%HOST%") do set HOST=%%a
for /f "tokens=1 delims=:" %%x in ("%HOST%") do set HOST=%%x
set DATE=%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%
set OUTPREFIX=%HOST%_%DATE%
hostname
whoami
echo %HOST%
ping -n 4 %HOST%
nslookup %HOST% > %OUTPREFIX%_nslookup.txt 2>nul
whois %HOST% > %OUTPREFIX%_whois.txt 2>nul || powershell -NoProfile -Command "(Resolve-DnsName -Name '%HOST%' -Type A) | Out-File -FilePath '%OUTPREFIX%_resolve.txt'"
curl -I --max-time 15 "http://%HOST%" > %OUTPREFIX%_http_headers.txt 2>nul
curl -I --max-time 15 "https://%HOST%" >> %OUTPREFIX%_http_headers.txt 2>nul
where nmap >nul 2>&1 && nmap -Pn -sS -sV -p- -T4 -oA %OUTPREFIX%_nmap %HOST% || powershell -NoProfile -Command "Test-NetConnection -ComputerName '%HOST%' -Port 443 | Out-File -FilePath '%OUTPREFIX%_tnc_443.txt'"
where openssl >nul 2>&1 && openssl s_client -connect "%HOST%:443" -servername "%HOST%" < NUL > %OUTPREFIX%_openssl_443.txt 2>nul
where whatweb >nul 2>&1 && whatweb "http://%HOST%" -v > %OUTPREFIX%_whatweb.txt 2>nul
where nikto >nul 2>&1 && nikto -host "http://%HOST%" -output %OUTPREFIX%_nikto.txt 2>nul
tracert -d %HOST% > %OUTPREFIX%_tracert.txt
route print > %OUTPREFIX%_route.txt
netstat -ano > %OUTPREFIX%_netstat.txt
arp -a > %OUTPREFIX%_arp.txt
type %windir%\system32\drivers\etc\hosts > %OUTPREFIX%_hosts.txt
powershell -NoProfile -Command "Invoke-WebRequest -Uri 'http://%HOST%' -Method Head -UseBasicParsing | Select-Object -Property Headers | Out-File -FilePath '%OUTPREFIX%_ps_headers.txt'"
powershell -NoProfile -Command "Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File -FilePath '%OUTPREFIX%_services.txt'"
powershell -NoProfile -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Out-File -FilePath '%OUTPREFIX%_processes.txt'"
