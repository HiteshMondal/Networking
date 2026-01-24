#!/bin/sh
# Web Reconnaissance Script (Linux / macOS)
# Purpose : Perform DNS, network, web, and SSL reconnaissance against a target
# Output  : Saves results into individual text / HTML files
# Usage   : Run and enter a domain or URL when prompted

# TARGET INPUT & NORMALIZATION

# Prompt user for target
read -r -p "Enter target URL (e.g. https://example.com or example.com): " TARGET

# Strip protocol, paths, and ports → extract clean hostname
TARGET=$(printf "%s" "$TARGET" | sed -E '
  s#^https?://##;
  s#^ssh://##;
  s#/.*##;
  s/:.*$##
')

# Save normalized target
echo "$TARGET" > target.txt

# DNS ENUMERATION

# A / AAAA records
dig +noall +answer "$TARGET" > dig_a.txt 2>/dev/null || true

# Name servers
dig +short NS "$TARGET" > dig_ns.txt 2>/dev/null || true

# SOA record
dig +short SOA "$TARGET" > dig_soa.txt 2>/dev/null || true

# ANY records (often restricted, but worth trying)
dig ANY "$TARGET" +noall +answer > dig_any.txt 2>/dev/null || true

# Alternative DNS tools
host "$TARGET" > host.txt 2>/dev/null || true
nslookup "$TARGET" > nslookup.txt 2>/dev/null || true

# WHOIS registration info
whois "$TARGET" > whois.txt 2>/dev/null || true

# BASIC NETWORK ENUMERATION

# ICMP reachability
ping -c 4 "$TARGET" > ping.txt 2>/dev/null || true

# Network path discovery
traceroute "$TARGET" > traceroute.txt 2>/dev/null \
  || tracepath "$TARGET" > traceroute.txt 2>/dev/null || true

# HTTP / HTTPS HEADER ENUMERATION

# HTTP headers
curl -I --max-time 15 "http://$TARGET" > curl_http_headers.txt 2>/dev/null || true

# HTTPS headers
curl -I --max-time 15 "https://$TARGET" > curl_https_headers.txt 2>/dev/null || true

# PORT SCANNING & SERVICE DETECTION

# Full TCP scan + OS + service detection
command -v nmap >/dev/null 2>&1 && \
  nmap -Pn -sS -sV -O --script "default,safe" -oA nmap_full "$TARGET" || true

# Fast full-range port discovery (if available)
command -v masscan >/dev/null 2>&1 && \
  masscan -p1-65535 --rate=1000 "$TARGET" -oL masscan.out || true

# WEB TECHNOLOGY FINGERPRINTING

# WhatWeb aggressive scan (HTTP)
command -v whatweb >/dev/null 2>&1 && \
  whatweb -a 3 "http://$TARGET" > whatweb_http.txt 2>/dev/null || true

# WhatWeb aggressive scan (HTTPS)
command -v whatweb >/dev/null 2>&1 && \
  whatweb -a 3 "https://$TARGET" > whatweb_https.txt 2>/dev/null || true

# Detect live HTTP(S) services
command -v httprobe >/dev/null 2>&1 && \
  printf "%s\n" "$TARGET" | httprobe > httprobe.out 2>/dev/null || true

# Screenshot target (headless)
command -v gowitness >/dev/null 2>&1 && \
  gowitness single "http://$TARGET" \
    --disable-db --no-browser --single-timeout 20 \
    --output gowitness_http || true

# WEB VULNERABILITY SCANNING

# Nikto (HTTP)
command -v nikto >/dev/null 2>&1 && \
  nikto -h "http://$TARGET" -o nikto_http.txt || true

# Directory brute force (HTTP)
command -v gobuster >/dev/null 2>&1 && \
  gobuster dir -u "http://$TARGET" \
    -w /usr/share/wordlists/dirb/common.txt \
    -o gobuster_dir_http.txt || true

# Directory brute force (HTTPS)
command -v gobuster >/dev/null 2>&1 && \
  gobuster dir -u "https://$TARGET" \
    -w /usr/share/wordlists/dirb/common.txt \
    -o gobuster_dir_https.txt || true

# SSL / TLS ENUMERATION

# SSL configuration scanning
command -v sslscan >/dev/null 2>&1 && \
  sslscan "$TARGET" > sslscan.txt 2>/dev/null || true

command -v sslyze >/dev/null 2>&1 && \
  sslyze --regular "$TARGET" > sslyze.txt 2>/dev/null || true

# Certificate extraction via OpenSSL
command -v openssl >/dev/null 2>&1 && \
  openssl s_client -connect "$TARGET:443" \
    -servername "$TARGET" -showcerts < /dev/null \
    > openssl_sclient.pem 2>/dev/null && \
  openssl x509 -in openssl_sclient.pem -noout -text \
    > openssl_cert.txt 2>/dev/null || true

# Targeted web-service Nmap scripts
command -v nmap >/dev/null 2>&1 && \
  nmap --reason -p 80,443,8080,8443 -sV \
    --script=http-title,http-server-header,vuln \
    -oN nmap_web_services.txt "$TARGET" || true

# PAGE CONTENT COLLECTION

# Download homepage over HTTP
command -v curl >/dev/null 2>&1 && \
  curl -sL --max-time 20 "http://$TARGET" > page_http.html 2>/dev/null || true

# Download homepage over HTTPS
command -v curl >/dev/null 2>&1 && \
  curl -sL --max-time 20 "https://$TARGET" > page_https.html 2>/dev/null || true

# IP-BASED ENUMERATION

# Resolve first IP address
ip=$(dig +short "$TARGET" | head -n1)

if [ -n "$ip" ]; then
  echo "$ip" > target_ip.txt

  # Scan IP directly
  command -v nmap >/dev/null 2>&1 && \
    nmap -Pn -sS -sV -oN nmap_ip_top_ports.txt "$ip" || true

  # Reverse IP lookup (shared hosting discovery)
  command -v curl >/dev/null 2>&1 && \
    curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip" \
      > reverse_ip.txt 2>/dev/null || true
fi

# ENVIRONMENT CAPTURE

# Save execution environment
env > env_web_recon.txt

# END OF SCRIPT
