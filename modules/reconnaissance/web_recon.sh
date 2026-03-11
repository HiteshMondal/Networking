#!/usr/bin/env bash
# /modules/reconnaissance/web_recon.sh
# Work on all Linux computers independent of distro
# Web reconnaissance: DNS, ports, web tech, SSL, vulnerability scanning
# Usage: web_recon.sh [TARGET]  — if TARGET omitted, prompts interactively

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"
log_init "web_recon"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/web_recon"
mkdir -p "$OUTPUT_DIR"

ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"

_note_err() {
    local label="$1" ec="${2:-?}"
    local msg="[ERROR] '$label' failed (exit $ec)"
    echo "$msg" >> "$ERRORS_FILE"
    log_error "$msg"
}

_section_err() {
    local sec="$1" errfile="$2"
    if [ -s "$errfile" ]; then
        local msg="[WARN] $sec: see errors/$(basename "$errfile")"
        echo "$msg" >> "$ERRORS_FILE"
        log_warning "$msg"
    else
        rm -f "$errfile"
    fi
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"

# TARGET INPUT & NORMALISATION

log_section "Target Acquisition"

if [[ -n "${1:-}" ]]; then
    RAW_TARGET="$1"

elif [[ -n "${TARGET:-}" ]]; then
    RAW_TARGET="$TARGET"

else
    log_error "No target provided."
    echo "Usage:"
    echo "  web_recon.sh <target>"
    echo "or"
    echo "  TARGET=example.com web_recon.sh"
    exit 1
fi

# Strip protocol, paths, and ports → clean hostname
TARGET=$(printf '%s' "$RAW_TARGET" | sed -E '
    s#^https?://##;
    s#^ssh://##;
    s#/.*##;
    s/:.*$//
')

if [ -z "$TARGET" ]; then
    echo "[-] Could not extract a valid hostname from: $RAW_TARGET" >&2
    exit 1
fi

echo "Target: $TARGET" | tee "$OUTPUT_DIR/target.txt"
log_metric "target" "$TARGET" "label"

# SECTION 1 — DNS ENUMERATION

log_section "DNS Enumeration"
echo "[*] Enumerating DNS records..."

dig +noall +answer "$TARGET"       > "$OUTPUT_DIR/dig_a.txt"    2>"$ERR_DIR/dns_a.err"   || _note_err "dig A"   $?
dig +short NS      "$TARGET"       > "$OUTPUT_DIR/dig_ns.txt"   2>"$ERR_DIR/dns_ns.err"  || _note_err "dig NS"  $?
dig +short SOA     "$TARGET"       > "$OUTPUT_DIR/dig_soa.txt"  2>"$ERR_DIR/dns_soa.err" || _note_err "dig SOA" $?
dig ANY            "$TARGET" +noall +answer \
                                   > "$OUTPUT_DIR/dig_any.txt"  2>"$ERR_DIR/dns_any.err" || _note_err "dig ANY" $?
host      "$TARGET"                > "$OUTPUT_DIR/host.txt"     2>"$ERR_DIR/host.err"    || _note_err "host"    $?
nslookup  "$TARGET"                > "$OUTPUT_DIR/nslookup.txt" 2>"$ERR_DIR/ns.err"      || _note_err "nslookup" $?
whois     "$TARGET"                > "$OUTPUT_DIR/whois.txt"    2>"$ERR_DIR/whois.err"   || _note_err "whois"   $?

for f in "$ERR_DIR"/dns_*.err "$ERR_DIR/host.err" "$ERR_DIR/ns.err" "$ERR_DIR/whois.err"; do
    _section_err "DNS enum $(basename "$f" .err)" "$f"
done

RESOLVED_IP=$(dig +short "$TARGET" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
log_metric "resolved_ip" "${RESOLVED_IP:-unresolved}" "label"
[ -z "$RESOLVED_IP" ] && log_finding "medium" \
    "Target hostname did not resolve to an IP" \
    "target=$TARGET — DNS may be unreachable or target is offline"

# SECTION 2 — BASIC NETWORK REACHABILITY

log_section "Network Reachability"
echo "[*] Checking network reachability..."

ping -c 4 "$TARGET"                > "$OUTPUT_DIR/ping.txt"        2>/dev/null || true
traceroute "$TARGET"               > "$OUTPUT_DIR/traceroute.txt"  2>/dev/null \
    || tracepath "$TARGET"         >> "$OUTPUT_DIR/traceroute.txt" 2>/dev/null || true

ping_loss=$(grep -Eo '[0-9.]+% packet loss' "$OUTPUT_DIR/ping.txt" 2>/dev/null | head -1 || true)
log_metric "ping_packet_loss" "${ping_loss:-unknown}" "label"

# SECTION 3 — HTTP / HTTPS HEADER ENUMERATION

log_section "HTTP/HTTPS Header Enumeration"
echo "[*] Fetching HTTP/HTTPS headers..."

curl -I --max-time 15 "http://$TARGET"  > "$OUTPUT_DIR/curl_http_headers.txt"  2>/dev/null || true
curl -I --max-time 15 "https://$TARGET" > "$OUTPUT_DIR/curl_https_headers.txt" 2>/dev/null || true

# Check for security-relevant response headers
for hdr_file in "$OUTPUT_DIR/curl_http_headers.txt" "$OUTPUT_DIR/curl_https_headers.txt"; do
    [ -s "$hdr_file" ] || continue
    case "$hdr_file" in
    *https*) proto=https ;;
    *http*)  proto=http ;;
    *) proto=unknown ;;
    esac
    grep -qiE 'Strict-Transport-Security' "$hdr_file" \
        || log_finding "low" "Missing HSTS header on $proto" "target=$TARGET"
    grep -qiE 'X-Frame-Options|Content-Security-Policy' "$hdr_file" \
        || log_finding "low" "Missing clickjacking protection header on $proto" "target=$TARGET"
    grep -qiE 'Server:' "$hdr_file" \
        && log_finding "info" "Server header present (version disclosure risk)" \
            "target=$TARGET $(grep -i 'Server:' "$hdr_file" | head -1)"
done

# SECTION 4 — PORT SCANNING & SERVICE DETECTION

log_section "Port Scanning and Service Detection"
echo "[*] Running port scans..."

if command -v nmap >/dev/null 2>&1; then
    _nmap_os_flag=""
    if [ "$EUID" -eq 0 ] 2>/dev/null; then
        _nmap_os_flag="-O"
    elif grep -qE 'CapEff:\s*[1-9a-f]' "/proc/$$/status" 2>/dev/null; then
        _nmap_os_flag="-O"
    else
        log_warning "nmap OS detection (-O) skipped — requires root or CAP_NET_RAW"
    fi
    # shellcheck disable=SC2086
    nmap -Pn -sS -sV $_nmap_os_flag --script "default,safe" \
        -oA "$OUTPUT_DIR/nmap_full" "$TARGET" 2>"$ERR_DIR/nmap_full.err" \
        || _note_err "nmap full scan" $?
    _section_err "Section 4 nmap" "$ERR_DIR/nmap_full.err"
else
    echo "(nmap not installed)" >> "$ERRORS_FILE"
    log_warning "nmap not found — skipping full port scan"
fi

if command -v masscan >/dev/null 2>&1; then
    masscan -p1-65535 --rate=1000 "$TARGET" \
        -oL "$OUTPUT_DIR/masscan.out" 2>"$ERR_DIR/masscan.err" \
        || _note_err "masscan" $?
    _section_err "Section 4 masscan" "$ERR_DIR/masscan.err"

    open_ports=$(grep -c '^open' "$OUTPUT_DIR/masscan.out" 2>/dev/null || true)
    open_ports=${open_ports:-0}
    log_metric "masscan_open_ports" "$open_ports" "count"
fi

# SECTION 5 — WEB TECHNOLOGY FINGERPRINTING

log_section "Web Technology Fingerprinting"
echo "[*] Fingerprinting web technologies..."

if command -v whatweb >/dev/null 2>&1; then
    whatweb -a 3 "http://$TARGET"  > "$OUTPUT_DIR/whatweb_http.txt"  2>/dev/null || true
    whatweb -a 3 "https://$TARGET" > "$OUTPUT_DIR/whatweb_https.txt" 2>/dev/null || true
else
    log_warning "whatweb not found — web tech fingerprinting unavailable"
fi

command -v httprobe >/dev/null 2>&1 && \
    printf "%s\n" "$TARGET" | httprobe > "$OUTPUT_DIR/httprobe.out" 2>/dev/null || true

if command -v gowitness >/dev/null 2>&1; then
    gowitness single "http://$TARGET" \
        --disable-db --timeout 20 \
        --output "$OUTPUT_DIR/gowitness_http" 2>"$ERR_DIR/gowitness.err" \
        || _note_err "gowitness" $?
    _section_err "Section 5 gowitness" "$ERR_DIR/gowitness.err"
fi

# SECTION 6 — WEB VULNERABILITY SCANNING

log_section "Web Vulnerability Scanning"
echo "[*] Running web vulnerability scans..."

if command -v nikto >/dev/null 2>&1; then
    nikto -h "http://$TARGET" \
        -o "$OUTPUT_DIR/nikto_http.txt" 2>"$ERR_DIR/nikto.err" \
        || _note_err "nikto" $?
    _section_err "Section 6 nikto" "$ERR_DIR/nikto.err"

    nikto_findings=$(grep -cE 'OSVDB|CVE|WARNING' "$OUTPUT_DIR/nikto_http.txt" 2>/dev/null || echo 0)
    log_metric "nikto_findings" "$nikto_findings" "count"
    [ "$nikto_findings" -gt 0 ] && log_finding "medium" \
        "Nikto found potential web vulnerabilities" \
        "count=$nikto_findings — review nikto_http.txt"
else
    log_warning "nikto not found — web vulnerability scan skipped"
fi

if command -v gobuster >/dev/null 2>&1; then
    for wordlist in /usr/share/wordlists/dirb/common.txt \
                    /usr/share/dirb/wordlists/common.txt; do
        [ -r "$wordlist" ] || continue
        gobuster dir -u "http://$TARGET"  -w "$wordlist" \
            -o "$OUTPUT_DIR/gobuster_http.txt"  2>/dev/null || true
        gobuster dir -u "https://$TARGET" -w "$wordlist" \
            -o "$OUTPUT_DIR/gobuster_https.txt" 2>/dev/null || true
        break
    done
fi

# SECTION 7 — SSL / TLS ENUMERATION

log_section "SSL/TLS Enumeration"
echo "[*] Enumerating SSL/TLS configuration..."

command -v sslscan >/dev/null 2>&1 && \
    sslscan "$TARGET" > "$OUTPUT_DIR/sslscan.txt" 2>/dev/null || true

command -v sslyze >/dev/null 2>&1 && \
    sslyze --regular "$TARGET" > "$OUTPUT_DIR/sslyze.txt" 2>/dev/null || true

if command -v openssl >/dev/null 2>&1; then
    openssl s_client -connect "$TARGET:443" -servername "$TARGET" -showcerts \
        </dev/null > "$OUTPUT_DIR/openssl_sclient.pem" 2>/dev/null || true
    awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print}' \
    "$OUTPUT_DIR/openssl_sclient.pem" \
    | sed -n '1,/END CERTIFICATE/p' > "$OUTPUT_DIR/server_cert.pem"

    # Check certificate validity / expiry
    expiry=$(openssl x509 -in "$OUTPUT_DIR/server_cert.pem" \
        -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    if [ -n "$expiry" ]; then
        log_metric "tls_cert_expiry" "$expiry" "date"
        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || gdate -d "$expiry" +%s 2>/dev/null || true)
        now_epoch=$(date +%s)
        if [ -n "$expiry_epoch" ] && [ "$expiry_epoch" -lt "$now_epoch" ]; then
            log_finding "high" "TLS certificate has expired" \
                "target=$TARGET expired=$expiry"
        elif [ -n "$expiry_epoch" ]; then
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            [ "$days_left" -lt 30 ] && log_finding "medium" \
                "TLS certificate expiring soon" \
                "target=$TARGET days_left=$days_left"
        fi
    fi
fi

if command -v nmap >/dev/null 2>&1; then
    nmap --reason -p 80,443,8080,8443 -sV \
        --script=http-title,http-server-header,vuln \
        -oN "$OUTPUT_DIR/nmap_web_services.txt" \
        "$TARGET" 2>/dev/null || true
fi

# SECTION 8 — PAGE CONTENT COLLECTION

log_section "Page Content Collection"
echo "[*] Downloading page content..."

curl -sL --max-time 20 "http://$TARGET"  > "$OUTPUT_DIR/page_http.html"  2>/dev/null || true
curl -sL --max-time 20 "https://$TARGET" > "$OUTPUT_DIR/page_https.html" 2>/dev/null || true

# Extract links and forms for further recon
for html in "$OUTPUT_DIR/page_http.html" "$OUTPUT_DIR/page_https.html"; do
    [ -s "$html" ] || continue
    case "$html" in
    *https*) proto=https ;;
    *http*)  proto=http ;;
    *) proto=unknown ;;
    esac
    grep -oiE 'href="[^"]*"|src="[^"]*"' "$html" | sort -u \
        > "$OUTPUT_DIR/links_${proto}.txt" 2>/dev/null || true
    grep -oiE '<form[^>]*>' "$html" \
        > "$OUTPUT_DIR/forms_${proto}.txt" 2>/dev/null || true
done

form_count=$(find "$OUTPUT_DIR" -name 'forms_*.txt' -type f -exec cat {} + 2>/dev/null | wc -l)
log_metric "html_forms_found" "$form_count" "count"

# SECTION 9 — IP-BASED ENUMERATION

log_section "IP-based Enumeration"
echo "[*] Running IP-based enumeration..."

if [ -n "$RESOLVED_IP" ]; then
    echo "$RESOLVED_IP" > "$OUTPUT_DIR/target_ip.txt"

    if command -v nmap >/dev/null 2>&1; then
        nmap -Pn -sS -sV \
            -oN "$OUTPUT_DIR/nmap_ip_top_ports.txt" \
            "$RESOLVED_IP" 2>/dev/null || true
    fi

    curl -s --max-time 15 \
        "https://api.hackertarget.com/reverseiplookup/?q=$RESOLVED_IP" \
        > "$OUTPUT_DIR/reverse_ip.txt" 2>/dev/null || true

    reverse_count=$(grep -c "^[a-zA-Z0-9]" "$OUTPUT_DIR/reverse_ip.txt" 2>/dev/null || echo 0)
    log_metric "reverse_ip_hostnames" "$reverse_count" "count"
else
    echo "(could not resolve $TARGET)" > "$OUTPUT_DIR/target_ip.txt"
    log_warning "Could not resolve $TARGET to an IP address — IP-based scans skipped"
fi

# ENVIRONMENT CAPTURE (filtered — remove secrets)

# AWS_SECRET_ACCESS_KEY, tokens, passwords etc. Filter to safe/useful vars only.
env | grep -vEi '(SECRET|TOKEN|PASSWORD|KEY)' \
    > "$OUTPUT_DIR/env_web_recon.txt" 2>/dev/null || true

# SUMMARY

log_section "Web Recon Summary"

{
    echo "========================================================"
    echo "  Web Reconnaissance — Summary"
    echo "  Generated: $(date)"
    echo "  Target:    $TARGET ($RESOLVED_IP)"
    echo "========================================================"
    echo

    echo "--- DNS ---"
    [ -s "$OUTPUT_DIR/dig_a.txt" ]  && echo "  A records:  $(wc -l < "$OUTPUT_DIR/dig_a.txt") lines"
    [ -s "$OUTPUT_DIR/dig_ns.txt" ] && echo "  NS records: $(cat "$OUTPUT_DIR/dig_ns.txt")"

    echo
    echo "--- Open Ports (masscan) ---"
    [ -f "$OUTPUT_DIR/masscan.out" ] && grep "^open" "$OUTPUT_DIR/masscan.out" 2>/dev/null | head -20 || echo "  (not run)"

    echo
    echo "--- Web Tech ---"
    cat "$OUTPUT_DIR/whatweb_https.txt" "$OUTPUT_DIR/whatweb_http.txt" 2>/dev/null | head -5 \
        || echo "  (not run)"

    echo
    echo "--- TLS Certificate ---"
    [ -s "$OUTPUT_DIR/openssl_cert.txt" ] \
        && grep -E 'Subject:|Not After' "$OUTPUT_DIR/openssl_cert.txt" | head -4 \
        || echo "  (not available)"

    echo
    echo "--- Script Errors ---"
    if [ -s "$ERRORS_FILE" ]; then
        cat "$ERRORS_FILE"
    else
        echo "[OK] No section errors recorded."
    fi

} > "$OUTPUT_DIR/web_recon_summary.txt"

cat "$OUTPUT_DIR/web_recon_summary.txt"

# ARCHIVE

ARCHIVE="$OUTPUT_DIR/web_recon_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] Web recon complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"