#!/usr/bin/env bash
# /modules/reconnaissance/web_recon.sh
# Web reconnaissance: DNS, ports, web tech, SSL, vulnerability scanning
# Usage: web_recon.sh [TARGET]  — if TARGET omitted, prompts interactively

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/web_recon"
mkdir -p "$OUTPUT_DIR"

ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"

_note_err() {
    local label="$1" ec="${2:-?}"
    echo "[ERROR] '$label' failed (exit $ec)" >> "$ERRORS_FILE"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"

# TARGET INPUT & NORMALISATION

if [ -n "${1:-}" ]; then
    RAW_TARGET="$1"
else
    read -r -p "Enter target URL (e.g. https://example.com or example.com): " RAW_TARGET
fi

# Strip protocol, paths, and ports → clean hostname
TARGET=$(printf "%s" "$RAW_TARGET" | sed -E '
    s#^https?://##;
    s#^ssh://##;
    s#/.*##;
    s/:.*$##
')

echo "Target: $TARGET" | tee "$OUTPUT_DIR/target.txt"

# SECTION 1 — DNS ENUMERATION

echo "[*] Enumerating DNS records..."

dig +noall +answer "$TARGET"       > "$OUTPUT_DIR/dig_a.txt"       2>"$ERR_DIR/dns_a.err"   || _note_err "dig A" $?
dig +short NS "$TARGET"            > "$OUTPUT_DIR/dig_ns.txt"      2>"$ERR_DIR/dns_ns.err"  || _note_err "dig NS" $?
dig +short SOA "$TARGET"           > "$OUTPUT_DIR/dig_soa.txt"     2>"$ERR_DIR/dns_soa.err" || _note_err "dig SOA" $?
dig ANY "$TARGET" +noall +answer   > "$OUTPUT_DIR/dig_any.txt"     2>"$ERR_DIR/dns_any.err" || _note_err "dig ANY" $?
host "$TARGET"                     > "$OUTPUT_DIR/host.txt"        2>"$ERR_DIR/host.err"    || _note_err "host" $?
nslookup "$TARGET"                 > "$OUTPUT_DIR/nslookup.txt"    2>"$ERR_DIR/ns.err"      || _note_err "nslookup" $?
whois "$TARGET"                    > "$OUTPUT_DIR/whois.txt"       2>"$ERR_DIR/whois.err"   || _note_err "whois" $?

for f in "$ERR_DIR"/dns_*.err "$ERR_DIR/host.err" "$ERR_DIR/ns.err" "$ERR_DIR/whois.err"; do
    [ -s "$f" ] \
        && echo "[WARN] $(basename "$f" .err): see errors/$(basename "$f")" >> "$ERRORS_FILE" \
        || rm -f "$f"
done

# SECTION 2 — BASIC NETWORK REACHABILITY

echo "[*] Checking network reachability..."

ping -c 4 "$TARGET"                > "$OUTPUT_DIR/ping.txt"        2>/dev/null || true
traceroute "$TARGET"               > "$OUTPUT_DIR/traceroute.txt"  2>/dev/null \
    || tracepath "$TARGET"         >> "$OUTPUT_DIR/traceroute.txt" 2>/dev/null || true

# SECTION 3 — HTTP / HTTPS HEADER ENUMERATION

echo "[*] Fetching HTTP/HTTPS headers..."

curl -I --max-time 15 "http://$TARGET"  > "$OUTPUT_DIR/curl_http_headers.txt"  2>/dev/null || true
curl -I --max-time 15 "https://$TARGET" > "$OUTPUT_DIR/curl_https_headers.txt" 2>/dev/null || true

# SECTION 4 — PORT SCANNING & SERVICE DETECTION

echo "[*] Running port scans..."

command -v nmap >/dev/null 2>&1 && \
    nmap -Pn -sS -sV -O --script "default,safe" \
        -oA "$OUTPUT_DIR/nmap_full" "$TARGET" 2>"$ERR_DIR/nmap_full.err" \
    || _note_err "nmap full scan" $?
[ -s "$ERR_DIR/nmap_full.err" ] || rm -f "$ERR_DIR/nmap_full.err"

command -v masscan >/dev/null 2>&1 && \
    masscan -p1-65535 --rate=1000 "$TARGET" \
        -oL "$OUTPUT_DIR/masscan.out" 2>"$ERR_DIR/masscan.err" \
    || _note_err "masscan" $?
[ -s "$ERR_DIR/masscan.err" ] || rm -f "$ERR_DIR/masscan.err"

# SECTION 5 — WEB TECHNOLOGY FINGERPRINTING

echo "[*] Fingerprinting web technologies..."

command -v whatweb >/dev/null 2>&1 && {
    whatweb -a 3 "http://$TARGET"  > "$OUTPUT_DIR/whatweb_http.txt"  2>/dev/null || true
    whatweb -a 3 "https://$TARGET" > "$OUTPUT_DIR/whatweb_https.txt" 2>/dev/null || true
}

command -v httprobe >/dev/null 2>&1 && \
    printf "%s\n" "$TARGET" | httprobe > "$OUTPUT_DIR/httprobe.out" 2>/dev/null || true

command -v gowitness >/dev/null 2>&1 && \
    gowitness single "http://$TARGET" \
        --disable-db --no-browser --single-timeout 20 \
        --output "$OUTPUT_DIR/gowitness_http" 2>/dev/null || true

# SECTION 6 — WEB VULNERABILITY SCANNING

echo "[*] Running web vulnerability scans..."

command -v nikto >/dev/null 2>&1 && \
    nikto -h "http://$TARGET" \
        -o "$OUTPUT_DIR/nikto_http.txt" 2>"$ERR_DIR/nikto.err" \
    || _note_err "nikto" $?
[ -s "$ERR_DIR/nikto.err" ] || rm -f "$ERR_DIR/nikto.err"

command -v gobuster >/dev/null 2>&1 && {
    gobuster dir -u "http://$TARGET" \
        -w /usr/share/wordlists/dirb/common.txt \
        -o "$OUTPUT_DIR/gobuster_http.txt"  2>/dev/null || true
    gobuster dir -u "https://$TARGET" \
        -w /usr/share/wordlists/dirb/common.txt \
        -o "$OUTPUT_DIR/gobuster_https.txt" 2>/dev/null || true
}

# SECTION 7 — SSL / TLS ENUMERATION

echo "[*] Enumerating SSL/TLS configuration..."

command -v sslscan >/dev/null 2>&1 && \
    sslscan "$TARGET" > "$OUTPUT_DIR/sslscan.txt" 2>/dev/null || true

command -v sslyze >/dev/null 2>&1 && \
    sslyze --regular "$TARGET" > "$OUTPUT_DIR/sslyze.txt" 2>/dev/null || true

command -v openssl >/dev/null 2>&1 && {
    openssl s_client -connect "$TARGET:443" \
        -servername "$TARGET" -showcerts \
        < /dev/null > "$OUTPUT_DIR/openssl_sclient.pem" 2>/dev/null || true
    openssl x509 -in "$OUTPUT_DIR/openssl_sclient.pem" \
        -noout -text \
        > "$OUTPUT_DIR/openssl_cert.txt" 2>/dev/null || true
}

command -v nmap >/dev/null 2>&1 && \
    nmap --reason -p 80,443,8080,8443 -sV \
        --script=http-title,http-server-header,vuln \
        -oN "$OUTPUT_DIR/nmap_web_services.txt" \
        "$TARGET" 2>/dev/null || true

# SECTION 8 — PAGE CONTENT COLLECTION

echo "[*] Downloading page content..."

curl -sL --max-time 20 "http://$TARGET"  > "$OUTPUT_DIR/page_http.html"  2>/dev/null || true
curl -sL --max-time 20 "https://$TARGET" > "$OUTPUT_DIR/page_https.html" 2>/dev/null || true

# SECTION 9 — IP-BASED ENUMERATION

echo "[*] Running IP-based enumeration..."

RESOLVED_IP=$(dig +short "$TARGET" 2>/dev/null | head -1)

if [ -n "$RESOLVED_IP" ]; then
    echo "$RESOLVED_IP" > "$OUTPUT_DIR/target_ip.txt"

    command -v nmap >/dev/null 2>&1 && \
        nmap -Pn -sS -sV \
            -oN "$OUTPUT_DIR/nmap_ip_top_ports.txt" \
            "$RESOLVED_IP" 2>/dev/null || true

    curl -s "https://api.hackertarget.com/reverseiplookup/?q=$RESOLVED_IP" \
        > "$OUTPUT_DIR/reverse_ip.txt" 2>/dev/null || true
else
    echo "(could not resolve $TARGET)" > "$OUTPUT_DIR/target_ip.txt"
fi

# ENVIRONMENT CAPTURE

env > "$OUTPUT_DIR/env_web_recon.txt" 2>/dev/null || true

# ARCHIVE (contents only, no embedded absolute path)

ARCHIVE="$OUTPUT_DIR/web_recon_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] Web recon complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"