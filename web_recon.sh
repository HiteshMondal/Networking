#!/bin/sh
read -p "Enter target URL or host: " TARGET
HOST=$(printf "%s" "$TARGET" | sed -E 's#^[[:space:]]+##; s#https?://##i; s#/.*##')
DATE=$(date +%Y%m%d_%H%M%S)
OUTPREFIX="${HOST}_${DATE}"
hostname
uname -a
id
whoami
echo "$HOST"
ping -c 4 "$HOST" 2>/dev/null || true
host "$HOST" 2>/dev/null || true
dig +noall +answer A "$HOST" > "${OUTPREFIX}_dig_A.txt" 2>/dev/null || true
dig any "$HOST" +noall +answer > "${OUTPREFIX}_dig_any.txt" 2>/dev/null || true
dig +short NS "$HOST" > "${OUTPREFIX}_dig_ns.txt" 2>/dev/null || true
dig +short TXT "$HOST" > "${OUTPREFIX}_dig_txt.txt" 2>/dev/null || true
whois "$HOST" > "${OUTPREFIX}_whois.txt" 2>/dev/null || true
nslookup "$HOST" > "${OUTPREFIX}_nslookup.txt" 2>/dev/null || true
curl -I --max-time 15 "http://$HOST" > "${OUTPREFIX}_http_headers.txt" 2>/dev/null || true
curl -I --max-time 15 "https://$HOST" >> "${OUTPREFIX}_http_headers.txt" 2>/dev/null || true
curl -sSL --head --max-redirs 5 "http://$HOST" -o "${OUTPREFIX}_curl_head_raw.txt" 2>/dev/null || true
command -v wget >/dev/null 2>&1 && wget --server-response --spider --timeout=15 -S "http://$HOST" -O "${OUTPREFIX}_wget_head.txt" 2>&1 || true
command -v openssl >/dev/null 2>&1 && openssl s_client -connect "${HOST}:443" -servername "$HOST" -brief < /dev/null > "${OUTPREFIX}_openssl_443.txt" 2>/dev/null || true
command -v sslyze >/dev/null 2>&1 && sslyze --regular "${HOST}" --json_out="${OUTPREFIX}_sslyze.json" || true
command -v nmap >/dev/null 2>&1 && nmap -Pn -sS -sV -p- --min-rate 1000 --open -oA "${OUTPREFIX}_nmap_full" "$HOST" || true
command -v nmap >/dev/null 2>&1 && nmap -Pn -p 80,443,8080 --script http-enum,http-server-header,http-title -oN "${OUTPREFIX}_nmap_http" "$HOST" || true
command -v whatweb >/dev/null 2>&1 && whatweb --log-verbose="${OUTPREFIX}_whatweb.txt" "http://$HOST" || true
command -v wappalyzer >/dev/null 2>&1 && wappalyzer "http://$HOST" --quiet > "${OUTPREFIX}_wappalyzer.txt" 2>/dev/null || true
command -v nikto >/dev/null 2>&1 && nikto -host "http://$HOST" -output "${OUTPREFIX}_nikto.txt" || true
command -v gobuster >/dev/null 2>&1 && gobuster dir -u "http://$HOST" -w /usr/share/wordlists/dirb/common.txt -o "${OUTPREFIX}_gobuster.txt" || true
command -v dirb >/dev/null 2>&1 && dirb "http://$HOST" /usr/share/wordlists/dirb/common.txt -o "${OUTPREFIX}_dirb.txt" || true
command -v sslscan >/dev/null 2>&1 && sslscan --no-failed "${HOST}:443" > "${OUTPREFIX}_sslscan.txt" 2>/dev/null || true
command -v traceroute >/dev/null 2>&1 && traceroute "$HOST" > "${OUTPREFIX}_traceroute.txt" 2>/dev/null || true
command -v mtr >/dev/null 2>&1 && mtr --report "$HOST" > "${OUTPREFIX}_mtr.txt" 2>/dev/null || true
command -v masscan >/dev/null 2>&1 && masscan -p1-65535 --rate=1000 "$HOST" -oL "${OUTPREFIX}_masscan.out" || true
command -v ncat >/dev/null 2>&1 && echo | ncat "$HOST" 80 > "${OUTPREFIX}_ncat_test.txt" 2>/dev/null || true
env > "${OUTPREFIX}_env.txt"
ps aux > "${OUTPREFIX}_ps.txt" 2>/dev/null || true
