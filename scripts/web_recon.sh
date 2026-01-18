#!/bin/sh
read -r -p "Enter target URL (e.g. https://example.com or example.com): " TARGET
TARGET=$(printf "%s" "$TARGET" | sed -E 's#^https?://##; s#^ssh://##; s#/.*##; s/:.*$##')
echo "$TARGET" > target.txt
dig +noall +answer "$TARGET" > dig_a.txt 2>/dev/null || true
dig +short NS "$TARGET" > dig_ns.txt 2>/dev/null || true
dig +short SOA "$TARGET" > dig_soa.txt 2>/dev/null || true
dig ANY "$TARGET" +noall +answer > dig_any.txt 2>/dev/null || true
host "$TARGET" > host.txt 2>/dev/null || true
nslookup "$TARGET" > nslookup.txt 2>/dev/null || true
whois "$TARGET" > whois.txt 2>/dev/null || true
ping -c 4 "$TARGET" > ping.txt 2>/dev/null || true
traceroute "$TARGET" > traceroute.txt 2>/dev/null || tracepath "$TARGET" > traceroute.txt 2>/dev/null || true
curl -I --max-time 15 "http://$TARGET" > curl_http_headers.txt 2>/dev/null || true
curl -I --max-time 15 "https://$TARGET" > curl_https_headers.txt 2>/dev/null || true
command -v nmap >/dev/null 2>&1 && nmap -Pn -sS -sV -O --script "default,safe" -oA nmap_full "$TARGET" || true
command -v masscan >/dev/null 2>&1 && masscan -p1-65535 --rate=1000 "$TARGET" -oL masscan.out || true
command -v whatweb >/dev/null 2>&1 && whatweb -a 3 "http://$TARGET" > whatweb_http.txt 2>/dev/null || true
command -v whatweb >/dev/null 2>&1 && whatweb -a 3 "https://$TARGET" > whatweb_https.txt 2>/dev/null || true
command -v httprobe >/dev/null 2>&1 && printf "%s\n" "$TARGET" | httprobe > httprobe.out 2>/dev/null || true
command -v gowitness >/dev/null 2>&1 && gowitness single "http://$TARGET" --disable-db --no-browser --single-timeout 20 --output gowitness_http || true
command -v nikto >/dev/null 2>&1 && nikto -h "http://$TARGET" -o nikto_http.txt || true
command -v gobuster >/dev/null 2>&1 && gobuster dir -u "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o gobuster_dir_http.txt || true
command -v gobuster >/dev/null 2>&1 && gobuster dir -u "https://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o gobuster_dir_https.txt || true
command -v sslscan >/dev/null 2>&1 && sslscan "$TARGET" > sslscan.txt 2>/dev/null || true
command -v sslyze >/dev/null 2>&1 && sslyze --regular "$TARGET" > sslyze.txt 2>/dev/null || true
command -v openssl >/dev/null 2>&1 && openssl s_client -connect "$TARGET:443" -servername "$TARGET" -showcerts < /dev/null > openssl_sclient.pem 2>/dev/null && openssl x509 -in openssl_sclient.pem -noout -text > openssl_cert.txt 2>/dev/null || true
command -v nmap >/dev/null 2>&1 && nmap --reason -p 80,443,8080,8443 -sV --script=http-title,http-server-header,vuln -oN nmap_web_services.txt "$TARGET" || true
command -v curl >/dev/null 2>&1 && curl -sL --max-time 20 "http://$TARGET" > page_http.html 2>/dev/null || true
command -v curl >/dev/null 2>&1 && curl -sL --max-time 20 "https://$TARGET" > page_https.html 2>/dev/null || true
ip=$(dig +short "$TARGET" | head -n1)
if [ -n "$ip" ]; then
  echo "$ip" > target_ip.txt
  command -v nmap >/dev/null 2>&1 && nmap -Pn -sS -sV -oN nmap_ip_top_ports.txt "$ip" || true
  command -v curl >/dev/null 2>&1 && curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip" > reverse_ip.txt 2>/dev/null || true
fi
env > env_web_recon.txt
