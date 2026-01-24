@echo off
REM ============================================================================
REM Windows Web Reconnaissance Script
REM Purpose : Perform DNS, network, and web service enumeration against a target
REM Output  : Saves all results into local text / HTML files
REM Usage   : Run and enter a domain or URL when prompted
REM ============================================================================

REM TARGET INPUT

set /p TARGET=Enter target URL (e.g. https://example.com or example.com): 

REM Extract hostname if a full URL is provided (PowerShell URI parser)
for /f "usebackq delims=" %%H in (`
  powershell -Command "(New-Object System.Uri('%TARGET%')).Host" 2^>nul
`) do set HOST=%%H

REM Fallback: if parsing fails, treat input as hostname
if "%HOST%"=="" set HOST=%TARGET%

REM Save resolved host
echo %HOST% > target.txt

REM BASIC NETWORK ENUMERATION

REM DNS resolution
nslookup %HOST% > nslookup.txt 2>nul

REM ICMP reachability
ping -n 4 %HOST% > ping.txt 2>nul

REM Network path discovery (no DNS resolution)
tracert -d %HOST% > traceroute.txt 2>nul

REM PORT SCANNING & SERVICE DETECTION (IF AVAILABLE)

REM Full TCP port scan with OS + service detection
where nmap >nul 2>&1 && (
  nmap -Pn -sS -sV -O -p- -oA nmap_full %HOST%
)

REM HTTP / HTTPS HEADER ENUMERATION

REM Fetch HTTP headers (plain HTTP)
where curl >nul 2>&1 && (
  curl -I --max-time 15 http://%HOST% > curl_http_headers.txt 2>nul
)

REM Fetch HTTPS headers
where curl >nul 2>&1 && (
  curl -I --max-time 15 https://%HOST% > curl_https_headers.txt 2>nul
)

REM WEB TECHNOLOGY FINGERPRINTING

REM WhatWeb aggressive scan (HTTP)
where whatweb >nul 2>&1 && (
  whatweb -a 3 http://%HOST% > whatweb_http.txt 2>nul
)

REM WhatWeb aggressive scan (HTTPS)
where whatweb >nul 2>&1 && (
  whatweb -a 3 https://%HOST% > whatweb_https.txt 2>nul
)

REM WEB VULNERABILITY SCANNING

REM Nikto scan (HTTP only)
where nikto >nul 2>&1 && (
  nikto -h http://%HOST% -o nikto_http.txt
)

REM SSL / TLS CERTIFICATE ENUMERATION

REM Attempt OpenSSL certificate retrieval
where openssl >nul 2>&1 && (
  openssl s_client -connect %HOST%:443 -servername %HOST% -showcerts < NUL > openssl_sclient.pem 2>nul
  openssl x509 -in openssl_sclient.pem -noout -text > openssl_cert.txt 2>nul
) || (
  REM Fallback to online SSL lookup if OpenSSL is unavailable
  powershell -Command ^
    "try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
      (New-Object System.Net.WebClient).DownloadString(
        'https://api.hackertarget.com/sslcertlookup/?q=%HOST%'
      )
    } catch {}" > ssl_lookup.txt 2>nul
)

REM TARGETED WEB SERVICE SCANS

REM Check common web ports for titles and server headers
where nmap >nul 2>&1 && (
  nmap --script=http-title,http-server-header ^
       -p 80,443,8080,8443 ^
       -oN nmap_web_services.txt %HOST%
)

REM PAGE CONTENT COLLECTION

REM Download homepage over HTTP
where curl >nul 2>&1 && (
  curl -sL --max-time 20 http://%HOST% > page_http.html 2>nul
)

REM Download homepage over HTTPS
where curl >nul 2>&1 && (
  curl -sL --max-time 20 https://%HOST% > page_https.html 2>nul
)

REM ENVIRONMENT CAPTURE

REM Save environment variables (useful for execution context debugging)
powershell -Command "Get-ChildItem Env:* | Out-File env_web_recon.txt"

REM END
echo Recon completed for %HOST%
