#!/usr/bin/env bash
# /modules/threat_detection/data_exfil_detect.sh
# Data exfiltration detection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"
log_init "data_exfil_detect"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/exfil_detect"
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
uname -a  >> "$OUTPUT_DIR/run_timestamp.txt"
whoami    >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — DNS TUNNELLING DETECTION

log_section "DNS Tunnelling Detection"
echo "[*] Detecting DNS tunnelling indicators..."

{
    echo "========================================================"
    echo "  DNS Tunnelling Detection"
    echo "========================================================"
    echo

    echo "=== High-frequency DNS resolution activity ==="
    dns_count=$(ss -tunap 2>>"$ERR_DIR/s1_dns.err" | grep -cE ':53\b' || true)
    dns_count=${dns_count:-0}
    echo "Current DNS connections: $dns_count"
    [ "$dns_count" -gt 10 ] && echo "[WARN] High DNS connection count — possible tunnelling"
    ss -tunap 2>>"$ERR_DIR/s1_dns.err" | grep ':53\b' | head -20 || true

    echo
    echo "=== DNS query volume from /proc/net/udp ==="
    dns_udp=$(awk 'NR>1 { split($2,a,":"); if(a[2]=="0035") c++ } END{print c+0}' \
        /proc/net/udp 2>>"$ERR_DIR/s1_dns.err" || echo 0)
    echo "UDP port 53 socket entries: $dns_udp"

    echo
    echo "=== systemd-resolved statistics ==="
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl statistics 2>>"$ERR_DIR/s1_dns.err" | head -20
    else
        echo "(resolvectl not available)"
    fi

    echo
    echo "=== Excessively long DNS domain names in logs (>40 chars in label) ==="
    for logfile in /var/log/syslog /var/log/messages /var/log/dns.log; do
        [ -r "$logfile" ] || continue
        grep -oE '[A-Za-z0-9+/]{40,}\.[A-Za-z0-9.-]+' "$logfile" 2>>"$ERR_DIR/s1_dns.err" \
        | head -20 | while IFS= read -r domain; do
            echo "[SUSPICIOUS] Long subdomain: $domain"
        done
    done

    echo
    echo "=== High TXT record query rate ==="
    for logfile in /var/log/syslog /var/log/messages; do
        [ -r "$logfile" ] || continue
        count=$(grep -c " TXT " "$logfile" 2>>"$ERR_DIR/s1_dns.err" || echo 0)
        [ "$count" -gt 50 ] && echo "[WARN] High TXT query count in $logfile: $count"
    done

    echo
    echo "=== Processes making direct DNS connections (excluding resolvers) ==="
    ss -tunapH 2>>"$ERR_DIR/s1_dns.err" \
        | awk '$5 ~ /:53$/' \
        | grep -vE 'systemd-resolve|dnsmasq|named|unbound' | head -20 || true

    echo
    echo "=== DNS tunnelling tools ==="
    for tool in iodine dns2tcp dnscat nstx dnstt; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "[HIGH] DNS tunnelling tool found: $tool at $(command -v "$tool")"
        find /tmp /opt /home /root -name "$tool" -type f 2>>"$ERR_DIR/s1_dns.err" \
            -exec echo "[HIGH] $tool binary found on disk: {}" \; || true
    done

} > "$OUTPUT_DIR/dns_tunnelling.txt"
_section_err "Section 1 DNS tunnelling" "$ERR_DIR/s1_dns.err"

if grep -qE '\[SUSPICIOUS\]|\[WARN\].*High DNS|\[HIGH\]' \
        "$OUTPUT_DIR/dns_tunnelling.txt" 2>/dev/null; then
    log_finding "high" "DNS tunnelling indicators detected" \
        "review dns_tunnelling.txt for long subdomains, high TXT rates, or tunnel tools"
fi
log_metric "dns_connection_count" "${dns_count:-0}" "count"
log_metric "dns_udp_sockets"      "${dns_udp:-0}"   "count"

# SECTION 2 — ICMP COVERT CHANNEL DETECTION

log_section "ICMP Covert Channel Detection"
echo "[*] Detecting ICMP covert channel indicators..."

{
    echo "========================================================"
    echo "  ICMP Covert Channel Detection"
    echo "========================================================"
    echo

    echo "=== ICMP socket activity ==="
    cat /proc/net/icmp  2>>"$ERR_DIR/s2_icmp.err" | head -20 || true
    cat /proc/net/icmp6 2>>"$ERR_DIR/s2_icmp.err" | head -20 || true

    echo
    echo "=== Processes using raw sockets ==="
    echo "--- /proc/net/raw entries ---"
    cat /proc/net/raw 2>>"$ERR_DIR/s2_icmp.err" | head -20 || true

    raw_inodes=$(awk 'NR>1{print $10}' /proc/net/raw 2>>"$ERR_DIR/s2_icmp.err" | sort -u)
    if [ -n "$raw_inodes" ]; then
        echo
        echo "--- Processes owning raw sockets ---"
        for inode in $raw_inodes; do
            find /proc/*/fd -lname "socket:\[$inode\]" 2>>"$ERR_DIR/s2_icmp.err" \
            | while IFS= read -r fd; do
                pid=$(echo "$fd" | grep -oE '[0-9]+' | head -1)
                exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
                echo "PID $pid ($exe): raw socket inode=$inode"
            done
        done
    fi

    echo
    echo "=== ICMP tunnelling tools ==="
    for tool in ptunnel ptunnel-ng icmptunnel icmpsh; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "[HIGH] ICMP tunnel tool found: $tool"
        find /tmp /opt /home /root -name "$tool" -type f 2>>"$ERR_DIR/s2_icmp.err" \
            -exec echo "[HIGH] $tool binary found on disk: {}" \; || true
    done

    echo
    echo "=== ICMP statistics ==="
    cat /proc/net/snmp 2>>"$ERR_DIR/s2_icmp.err" | grep -A1 "^Icmp:" | head -4 || true

} > "$OUTPUT_DIR/icmp_covert_channels.txt"
_section_err "Section 2 ICMP" "$ERR_DIR/s2_icmp.err"

if grep -q "\[HIGH\]" "$OUTPUT_DIR/icmp_covert_channels.txt" 2>/dev/null; then
    log_finding "high" "ICMP tunnelling tool found on system" \
        "review icmp_covert_channels.txt"
fi
raw_socket_count=$(awk 'NR>1' /proc/net/raw 2>/dev/null | wc -l || echo 0)
log_metric "raw_socket_entries" "$raw_socket_count" "count"

# SECTION 3 — HTTP/HTTPS C2 BEACONING DETECTION

log_section "HTTP/HTTPS C2 Beaconing Detection"
echo "[*] Detecting HTTP/HTTPS C2 beaconing patterns..."

{
    echo "========================================================"
    echo "  HTTP/HTTPS C2 Beaconing Detection"
    echo "========================================================"
    echo

    echo "=== Established outbound HTTP/HTTPS connections ==="
    ss -tnp state established 2>>"$ERR_DIR/s3_http.err" \
        | awk '$5 ~ /:80$|:443$|:8080$|:8443$|:4444$|:4443$|:1337$/ {print}' \
        | head -30 || true

    echo
    echo "=== Persistent HTTP connections (keepalive indicator) ==="
    ss -tnpo state established 2>>"$ERR_DIR/s3_http.err" \
        | awk '$5 ~ /:80$|:443$|:8080$/ && /timer:keepalive/ {print}' \
        | head -20 || true

    echo
    echo "=== Processes making outbound HTTP connections ==="
    ss -tnpH state established 2>>"$ERR_DIR/s3_http.err" \
        | awk '$5 ~ /:80$|:443$/ {print $6}' \
        | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u \
        | while IFS= read -r pid; do
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-80)
            echo "$exe" | grep -qE 'firefox|chrome|apt|yum|dnf|snap|curl|wget' \
                || echo "PID $pid | $exe | $cmd"
        done | head -20 || true

    echo
    echo "=== Known C2 / RAT / implant process names ==="
    for name in metasploit msfconsole meterpreter agent.py \
                empire stager listener cobalt beacon \
                sliver implant nighthawk havoc \
                merlin covenant mythic deimos shad0w \
                pwncat reverse_shell; do
        ps auxww 2>>"$ERR_DIR/s3_http.err" \
            | grep -i "$name" | grep -v grep \
            | while IFS= read -r line; do
            echo "[HIGH] Possible C2 process: $line"
        done
    done

    echo
    echo "=== Connections on non-standard ports ==="
    ss -tnpH state established 2>>"$ERR_DIR/s3_http.err" \
        | awk '$5 !~ /:(22|80|443|3306|5432|6379|27017|53|25|587|110|995|143|993|8080|8443)$/ \
               && $5 !~ /127\.0\.0\.1|::1/ {print}' \
        | grep -vE '(local|Private)' | head -20 || true

    echo
    echo "=== Periodic connection timing analysis (10-second sample) ==="

} > "$OUTPUT_DIR/http_c2_beaconing.txt"
# run python3 OUTSIDE the brace-redirect block so that:
# (a) _note_err writes to ERRORS_FILE (not to the redirected output file)
# (b) the exit code of python3 is reliably captured in py_exit
python3 - >> "$OUTPUT_DIR/http_c2_beaconing.txt" 2>"$ERR_DIR/s3_beacon.err" << 'PYEOF'
import time, subprocess, collections, sys

DURATION = 10
interval  = 1
dest_times = collections.defaultdict(list)

start = time.time()
while time.time() - start < DURATION:
    try:
        out = subprocess.check_output(
            ['ss', '-tnH', 'state', 'established'], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                dest_times[parts[4]].append(time.time())
    except Exception as e:
        print(f"[ERROR] ss sampling failed: {e}", file=sys.stderr)
        break
    time.sleep(interval)

print("Destination IPs with repeated connections in 10s window:")
found = False
for dest, times in dest_times.items():
    if len(times) >= 3:
        print(f"  {dest:<30} {len(times)} connection events")
        found = True
if not found:
    print("  (none detected)")
PYEOF
py_exit=$?
[ "$py_exit" -ne 0 ] && _note_err "beaconing timing sample" "$py_exit"
_section_err "Section 3 HTTP beaconing" "$ERR_DIR/s3_http.err"
_section_err "Section 3 beaconing Python" "$ERR_DIR/s3_beacon.err"

if grep -q "\[HIGH\] Possible C2 process" "$OUTPUT_DIR/http_c2_beaconing.txt" 2>/dev/null; then
    c2_count=$(grep -c "\[HIGH\] Possible C2 process" "$OUTPUT_DIR/http_c2_beaconing.txt")
    log_finding "critical" "Known C2/RAT process names detected in running processes" \
        "count=$c2_count — review http_c2_beaconing.txt immediately"
fi

# SECTION 4 — LARGE OUTBOUND TRANSFER DETECTION

log_section "Large Outbound Transfer Detection"
echo "[*] Detecting large outbound data transfers..."

{
    echo "========================================================"
    echo "  Large Outbound Transfer Detection"
    echo "========================================================"
    echo

    echo "=== Network interface statistics (cumulative TX bytes) ==="
    awk 'NR>2 {
        bytes_rx=$2; bytes_tx=$10;
        mb_rx=bytes_rx/1048576; mb_tx=bytes_tx/1048576;
        printf "  %-12s  RX: %10.2f MB   TX: %10.2f MB\n", $1, mb_rx, mb_tx
    }' /proc/net/dev 2>>"$ERR_DIR/s4_transfer.err" || _note_err "/proc/net/dev" $?

    echo
    echo "=== Real-time bandwidth snapshot (2-second sample) ==="
    python3 - << 'PYEOF' 2>>"$ERR_DIR/s4_transfer.err" || true
import time, sys

def read_net_stats():
    stats = {}
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                parts = line.split()
                if ':' not in parts[0]:
                    continue
                iface = parts[0].rstrip(':')
                stats[iface] = {'rx': int(parts[1]), 'tx': int(parts[9])}
    except Exception as e:
        print(f"[ERROR] /proc/net/dev: {e}", file=sys.stderr)
    return stats

s1 = read_net_stats()
time.sleep(2)
s2 = read_net_stats()

print(f"{'Interface':<12}  {'RX (KB/s)':>12}  {'TX (KB/s)':>12}  Alert")
print("-" * 55)
for iface in s1:
    if iface not in s2:
        continue
    rx_rate = (s2[iface]['rx'] - s1[iface]['rx']) / 2 / 1024
    tx_rate = (s2[iface]['tx'] - s1[iface]['tx']) / 2 / 1024
    alert = " [HIGH TX!]" if tx_rate > 500 else ""
    print(f"{iface:<12}  {rx_rate:>12.1f}  {tx_rate:>12.1f} {alert}")
PYEOF

    echo
    echo "=== Files staged in /tmp for exfiltration ==="
    find /tmp /var/tmp /dev/shm -type f \( \
        -name "*.tar"  -o -name "*.tar.gz" -o -name "*.tgz"  \
        -o -name "*.zip" -o -name "*.7z"  -o -name "*.rar"   \
        -o -name "*.gz"  -o -name "*.bz2" -o -name "*.xz"    \
    \) -ls 2>>"$ERR_DIR/s4_transfer.err" | sort -k7 -rn | head -20 || true

    echo
    echo "=== Large files (>1MB) in writable directories ==="
    find /tmp /var/tmp /dev/shm -type f -size +1M -ls 2>>"$ERR_DIR/s4_transfer.err" \
        | sort -k7 -rn | head -20 || true

    echo
    echo "=== Active upload processes ==="
    ps auxww 2>>"$ERR_DIR/s4_transfer.err" \
        | grep -E '(scp |rsync .*(--[-a-z]+ )*[^-].*@|curl.*(--upload|-T|-d @)|sftp |ftp )' \
        | grep -v grep | head -20 || true

    echo
    echo "=== Recent large file transfers via SSH ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] \
            && grep -iE "scp|sftp|rsync" "$logfile" 2>>"$ERR_DIR/s4_transfer.err" | tail -20
    done

    echo
    echo "=== Archives created in last 24 hours ==="
    _ref=$(mktemp "$ERR_DIR/timeref_XXXXXX")
    touch -d "24 hours ago" "$_ref" 2>/dev/null || touch "$_ref"
    find /home /var/www /opt /tmp /var/tmp \
        -type f \( -name "*.tar*" -o -name "*.zip" -o -name "*.7z" \) \
        -newer "$_ref" 2>>"$ERR_DIR/s4_transfer.err" | head -20 || true
    rm -f "$_ref"

} > "$OUTPUT_DIR/large_outbound_transfers.txt"
_section_err "Section 4 large outbound transfers" "$ERR_DIR/s4_transfer.err"

if grep -q "\[HIGH TX\!\]" "$OUTPUT_DIR/large_outbound_transfers.txt" 2>/dev/null; then
    log_finding "high" "High outbound data transfer rate detected" \
        "TX rate exceeded 500 KB/s during 2-second sample"
fi
staged_count=$(find /tmp /var/tmp /dev/shm -type f \
    \( -name "*.tar*" -o -name "*.zip" -o -name "*.7z" \) 2>/dev/null | wc -l || echo 0)
log_metric "staged_archives_in_tmp" "$staged_count" "count"
[ "$staged_count" -gt 0 ] && log_finding "medium" \
    "Archive files found in temporary directories" \
    "count=$staged_count — possible staging for exfiltration"

# SECTION 5 — STEGANOGRAPHY INDICATORS

log_section "Steganography Indicators"
echo "[*] Checking for steganography indicators..."

{
    echo "========================================================"
    echo "  Steganography Indicators"
    echo "========================================================"
    echo

    echo "=== Steganography tools installed ==="
    for tool in steghide outguess stegdetect stegseek openstego stepic stegpy exiftool; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool at $(command -v "$tool")"
    done

    echo
    echo "=== Suspicious image files in writable locations ==="
    find /tmp /var/tmp /dev/shm /home /root -type f \
        \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \
           -o -name "*.bmp" -o -name "*.gif" \) \
        -size +100k -ls 2>>"$ERR_DIR/s5_steg.err" | head -20 || true

    echo
    echo "=== Oversized PNG/JPG files (possible data embedding) ==="
    find /home /var/www /opt /tmp /var/tmp \
        -type f -name "*.png" -size +10M -ls 2>>"$ERR_DIR/s5_steg.err" | head -10 || true
    find /home /var/www /opt /tmp /var/tmp \
        -type f -name "*.jpg" -size +5M  -ls 2>>"$ERR_DIR/s5_steg.err" | head -10 || true

    echo
    echo "=== Audio files in unusual locations ==="
    find /tmp /var/tmp /dev/shm /home -type f \
        \( -name "*.wav" -o -name "*.mp3" -o -name "*.flac" \) \
        -ls 2>>"$ERR_DIR/s5_steg.err" | head -10 || true

    echo
    echo "=== Base64 blob files (encoded payload) ==="

    # Pass the path via argv instead; python reads sys.argv[1] safely.
    find /tmp /var/tmp /dev/shm -type f -size +10k 2>>"$ERR_DIR/s5_steg.err" \
    | while IFS= read -r f; do
        python3 - "$f" 2>>"$ERR_DIR/s5_steg.err" << 'PYEOF'
import sys
try:
    with open(sys.argv[1], 'rb') as fp:
        data = fp.read(4096)
    text = data.decode('ascii')
    b64_chars = sum(
        1 for c in text
        if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    )
    if b64_chars / max(len(text), 1) > 0.9:
        print(f"POSSIBLE BASE64 BLOB: {sys.argv[1]}")
except Exception:
    sys.exit(1)
PYEOF
    done | head -10

} > "$OUTPUT_DIR/steganography_indicators.txt"
_section_err "Section 5 steganography" "$ERR_DIR/s5_steg.err"

steg_tools=$(grep -c "^FOUND:" "$OUTPUT_DIR/steganography_indicators.txt" 2>/dev/null || echo 0)
log_metric "steganography_tools_found" "$steg_tools" "count"
[ "$steg_tools" -gt 0 ] && log_finding "medium" \
    "Steganography tools found on system" \
    "count=$steg_tools — review steganography_indicators.txt"

# SECTION 6 — DLP: SENSITIVE DATA STAGED FOR EXFILTRATION

log_section "DLP Sensitive Data Staging Check"
echo "[*] Running DLP checks for staged sensitive data..."

{
    echo "========================================================"
    echo "  DLP — Sensitive Data Staging Check"
    echo "========================================================"
    echo

    DLP_DIRS="/tmp /var/tmp /dev/shm /home /root /var/www /opt"

    echo "=== SSH private keys in writable/world-accessible locations ==="
    # shellcheck disable=SC2086
    find $DLP_DIRS -type f \
        \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
           -o -name "*.pem" -o -name "*.key" \) \
        2>>"$ERR_DIR/s6_dlp.err" | head -20 || true

    echo
    echo "=== Password/credential pattern matches in text files ==="
    # shellcheck disable=SC2086
    find /tmp /var/tmp /dev/shm /home /root \
        -type f -size -5M 2>>"$ERR_DIR/s6_dlp.err" \
    | while IFS= read -r f; do
        file "$f" 2>/dev/null | grep -q "text\|ASCII\|UTF-8" || continue
        grep -lniE \
            '(password[[:space:]]*[:=][[:space:]]*\S{6,}|passwd[[:space:]]*[:=]|secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=])' \
            "$f" 2>>"$ERR_DIR/s6_dlp.err" \
        | while IFS= read -r match; do echo "SENSITIVE: $match"; done
    done | head -20

    echo
    echo "=== Credit card number patterns ==="
    # shellcheck disable=SC2086
    find $DLP_DIRS -type f -size -10M 2>>"$ERR_DIR/s6_dlp.err" \
    | while IFS= read -r f; do
        file "$f" 2>/dev/null | grep -q "text\|ASCII\|UTF-8" || continue
        grep -lE '\b4[0-9]{15}\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b|\b6011[0-9]{12}\b' \
            "$f" 2>>"$ERR_DIR/s6_dlp.err" \
        | while IFS= read -r match; do echo "POSSIBLE_PAN: $match"; done
    done | head -10

    echo
    echo "=== Database dumps in staging areas ==="
    find /tmp /var/tmp /dev/shm /home /root -type f \
        \( -name "*.sql" -o -name "*.dump" -o -name "*.db" \
           -o -name "*.sqlite" -o -name "*backup*" \) \
        -ls 2>>"$ERR_DIR/s6_dlp.err" | sort -k7 -rn | head -20 || true

    echo
    echo "=== /etc/shadow copies in writable locations ==="
    find /tmp /var/tmp /dev/shm /home /root -type f 2>>"$ERR_DIR/s6_dlp.err" \
    | while IFS= read -r f; do
        head -1 "$f" 2>/dev/null \
            | grep -qE '^\S+:\$[156y]\$' \
            && echo "POSSIBLE SHADOW COPY: $f"
    done | head -10

    echo
    echo "=== Source code / IP archives ==="
    find /tmp /var/tmp /dev/shm -type f \
        \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" \) \
        -ls 2>>"$ERR_DIR/s6_dlp.err" | sort -k7 -rn | head -10 || true

    echo
    echo "=== Recently created archives (last 24h) ==="

    _ref=$(mktemp "$ERR_DIR/timeref_XXXXXX")
    touch -d "24 hours ago" "$_ref" 2>/dev/null || touch "$_ref"
    find /home /var/www /opt /tmp /var/tmp \
        -type f \( -name "*.tar*" -o -name "*.zip" -o -name "*.7z" \) \
        -newer "$_ref" 2>>"$ERR_DIR/s6_dlp.err" | head -20 || true
    rm -f "$_ref"

} > "$OUTPUT_DIR/dlp_staging_check.txt"
_section_err "Section 6 DLP" "$ERR_DIR/s6_dlp.err"

for _pat in "SENSITIVE:" "POSSIBLE_PAN:" "POSSIBLE SHADOW COPY:"; do
    _cnt=$(grep -c "$_pat" "$OUTPUT_DIR/dlp_staging_check.txt" 2>/dev/null || echo 0)
    if [ "$_cnt" -gt 0 ]; then
        _lbl=$(printf '%s' "$_pat" | tr -d ':' | tr '[:upper:] ' '[:lower:]_')
        log_finding "high" "DLP: ${_pat} matches in staging directories" \
            "count=$_cnt — review dlp_staging_check.txt"
        log_metric "dlp_${_lbl}_hits" "$_cnt" "count"
    fi
done

# SECTION 7 — PROTOCOL ANOMALY DETECTION

log_section "Protocol Anomaly Detection"
echo "[*] Detecting protocol-level anomalies..."

{
    echo "========================================================"
    echo "  Protocol Anomaly Detection"
    echo "========================================================"
    echo

    echo "=== Connections on unexpected ports for common protocols ==="
    ss -tnpH state established 2>>"$ERR_DIR/s7_proto.err" \
        | awk '$5 !~ /:(80|443|8080|8443|8000|8888|3000|5000)$/ \
               && ($6 ~ /curl|wget|python|node|java/) {print "Possible HTTP C2: "$0}' \
        | head -10 || true

    echo
    echo "=== Tor indicators ==="
    if pgrep -x tor >/dev/null 2>&1; then
        echo "[HIGH] Tor process is running!"
        pgrep -al tor 2>>"$ERR_DIR/s7_proto.err" || true
    fi
    ss -tnpH 2>>"$ERR_DIR/s7_proto.err" \
        | grep -E ':9050|:9051|:9150|:9001|:9030' | head -10 || true

    echo
    echo "=== I2P / anonymous network indicators ==="
    pgrep -al "i2p\|i2pd" 2>>"$ERR_DIR/s7_proto.err" || true
    ss -tnpH 2>>"$ERR_DIR/s7_proto.err" \
        | grep -E ':7654|:4444|:7656|:7657' | head -5 || true

    echo
    echo "=== Proxychains / SOCKS proxy usage ==="
    find /home /root /tmp -name "proxychains*.conf" -type f -ls \
        2>>"$ERR_DIR/s7_proto.err" | head -5
    pgrep -al "proxychains\|proxytunnel\|3proxy" 2>>"$ERR_DIR/s7_proto.err" || true

    echo
    echo "=== HTTPS certificate pinning bypass tools ==="
    for tool in mitmproxy burpsuite charles fiddler sslstrip; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool (potential HTTPS interception/bypass)"
    done

    echo
    echo "=== Email exfiltration indicators ==="
    ss -tnpH state established 2>>"$ERR_DIR/s7_proto.err" \
        | awk '$5 ~ /:25$|:465$|:587$/ {print "[SMTP outbound]: "$0}' | head -10 || true
    pgrep -al "sendmail\|postfix\|ssmtp\|msmtp\|swaks" 2>>"$ERR_DIR/s7_proto.err" || true

} > "$OUTPUT_DIR/protocol_anomalies.txt"
_section_err "Section 7 protocol anomalies" "$ERR_DIR/s7_proto.err"

if grep -q "\[HIGH\] Tor process is running" "$OUTPUT_DIR/protocol_anomalies.txt" 2>/dev/null; then
    log_finding "high" "Tor anonymisation network is active" \
        "tor process running — outbound traffic may be anonymised"
fi

# SECTION 8 — EXFILTRATION SUMMARY

log_section "Exfiltration Detection Summary"
echo "[*] Generating exfiltration detection summary..."

# Tally findings independently — avoids the original compound-brace bug where
# only the last grep in a { } block determined whether the block succeeded.
_critical=0; _high=0
grep -q "\[HIGH\] Possible C2 process"   "$OUTPUT_DIR/http_c2_beaconing.txt"    2>/dev/null && _critical=$((_critical+1))
grep -q "\[HIGH\] Tor process"           "$OUTPUT_DIR/protocol_anomalies.txt"   2>/dev/null && _high=$((_high+1))
grep -q "\[HIGH TX\!\]"                  "$OUTPUT_DIR/large_outbound_transfers.txt" 2>/dev/null && _high=$((_high+1))
grep -qE '\[HIGH\].*DNS tunnelling|\[SUSPICIOUS\]' \
                                          "$OUTPUT_DIR/dns_tunnelling.txt"       2>/dev/null && _high=$((_high+1))

log_metric "critical_findings" "$_critical" "count"
log_metric "high_findings"     "$_high"     "count"

{
    echo "========================================================"
    echo "  Data Exfiltration Detection — Summary"
    echo "  Generated: $(date)"
    echo "  Host:      $(hostname)"
    echo "========================================================"
    echo

    echo "--- High-Priority Findings ---"

    grep -qE '\[HIGH\].*DNS tunnelling|\[SUSPICIOUS\].*Long subdomain' \
        "$OUTPUT_DIR/dns_tunnelling.txt" 2>/dev/null \
        && echo "[HIGH] DNS tunnelling indicators detected"

    grep -qiE "\[HIGH\].*ICMP|raw socket" \
        "$OUTPUT_DIR/icmp_covert_channels.txt" 2>/dev/null \
        && echo "[MEDIUM] ICMP covert channel indicators detected"

    grep -q "\[HIGH\] Possible C2 process" \
        "$OUTPUT_DIR/http_c2_beaconing.txt" 2>/dev/null \
        && echo "[CRITICAL] Known C2/RAT process names detected"

    grep -q "\[HIGH TX\!\]" "$OUTPUT_DIR/large_outbound_transfers.txt" 2>/dev/null \
        && echo "[HIGH] High outbound data transfer rate detected"

    _dlp=false
    grep -qE "SENSITIVE|POSSIBLE_PAN|POSSIBLE SHADOW COPY" \
        "$OUTPUT_DIR/dlp_staging_check.txt"        2>/dev/null && _dlp=true
    grep -q "POSSIBLE BASE64 BLOB" \
        "$OUTPUT_DIR/steganography_indicators.txt"  2>/dev/null && _dlp=true
    $_dlp && echo "[HIGH] Sensitive data found in writable/staging directories"

    grep -q "Tor process is running" \
        "$OUTPUT_DIR/protocol_anomalies.txt" 2>/dev/null \
        && echo "[HIGH] Tor anonymisation network is active"

    grep -qE "FOUND.*steghide|FOUND.*outguess|FOUND.*stegseek" \
        "$OUTPUT_DIR/steganography_indicators.txt" 2>/dev/null \
        && echo "[MEDIUM] Steganography tools found on system"

    echo
    echo "--- Metrics ---"
    echo "  Critical findings : $_critical"
    echo "  High findings     : $_high"

    echo
    echo "--- Script Errors ---"
    if [ -s "$ERRORS_FILE" ]; then
        cat "$ERRORS_FILE"
    else
        echo "[OK] No section errors recorded."
    fi

    echo
    echo "--- Output Files ---"
    ls -lh "$OUTPUT_DIR/"*.txt 2>/dev/null

} > "$OUTPUT_DIR/exfil_summary.txt"

cat "$OUTPUT_DIR/exfil_summary.txt"

ARCHIVE="$OUTPUT_DIR/exfil_detect_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] Exfiltration detection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"