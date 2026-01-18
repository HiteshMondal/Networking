@echo off
set /p TARGET=Enter target URL (e.g. https://example.com or example.com): 
for /f "usebackq delims=" %%H in (`powershell -Command "(New-Object System.Uri('%TARGET%')).Host" 2^>nul`) do set HOST=%%H
if "%HOST%"=="" set HOST=%TARGET%
echo %HOST% > target.txt
nslookup %HOST% > nslookup.txt 2>nul
ping -n 4 %HOST% > ping.txt 2>nul
tracert -d %HOST% > traceroute.txt 2>nul
where nmap >nul 2>&1 && nmap -Pn -sS -sV -O -p- -oA nmap_full %HOST% || true
where curl >nul 2>&1 && curl -I --max-time 15 http://%HOST% > curl_http_headers.txt 2>nul || true
where curl >nul 2>&1 && curl -I --max-time 15 https://%HOST% > curl_https_headers.txt 2>nul || true
where whatweb >nul 2>&1 && whatweb -a 3 http://%HOST% > whatweb_http.txt 2>nul || true
where whatweb >nul 2>&1 && whatweb -a 3 https://%HOST% > whatweb_https.txt 2>nul || true
where nikto >nul 2>&1 && nikto -h http://%HOST% -o nikto_http.txt || true
where openssl >nul 2>&1 && openssl s_client -connect %HOST%:443 -servername %HOST% -showcerts < NUL > openssl_sclient.pem 2>nul && openssl x509 -in openssl_sclient.pem -noout -text > openssl_cert.txt 2>nul || powershell -Command "try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $c=New-Object System.Net.WebClient; $c.DownloadString('https://api.hackertarget.com/sslcertlookup/?q=%HOST%') } catch {}" > ssl_lookup.txt 2>nul || true
where nmap >nul 2>&1 && nmap --script=http-title,http-server-header -p 80,443,8080,8443 -oN nmap_web_services.txt %HOST% || true
where curl >nul 2>&1 && curl -sL --max-time 20 http://%HOST% > page_http.html 2>nul || true
where curl >nul 2>&1 && curl -sL --max-time 20 https://%HOST% > page_https.html 2>nul || true
powershell -Command "Get-ChildItem Env:* | Out-File env_web_recon.txt"
