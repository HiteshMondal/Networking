#!/bin/bash
# Data Exfiltration Detection Script
# Purpose : Detect data exfiltration techniques: DNS tunnelling,
#           ICMP covert channels, HTTP C2 beaconing, large outbound
#           transfers, steganography indicators, clipboard/screen capture,
#           and DLP-style checks for sensitive data staged for exfil.
# Output  : exfil_detect/ directory + archive

set -eo pipefail

OUTPUT_DIR="exfil_detect"
mkdir -p "$OUTPUT_DIR"

# ── Error capture infrastructure ─────────────────────────────────────────────
ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"

_note_err() {
    local label="$1" ec="${2:-?}"
    echo "[ERROR] '$label' failed (exit $ec)" >> "$ERRORS_FILE"
}

_section_err() {
    local sec="$1" errfile="$2"
    [ -s "$errfile" ] \
        && echo "[WARN] $sec: see errors/$(basename "$errfile")" >> "$ERRORS_FILE" \
        || rm -f "$errfile"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a  >> "$OUTPUT_DIR/run_timestamp.txt"
whoami    >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — DNS TUNNELLING DETECTION

echo "[*] Detecting DNS tunnelling indicators..."

{
    echo "========================================================"
    echo "  DNS Tunnelling Detection"
    echo "========================================================"
    echo

    echo "=== High-frequency DNS resolution activity ==="
    dns_count=$(ss -tunap 2>>"$ERR_DIR/s1_dns.err" | grep -c ':53\b' || echo 0)
    echo "Current DNS connections: $dns_count"
    [ "$dns_count" -gt 10 ] && echo "[WARN] High DNS connection count — possible tunnelling"

    ss -tunap 2>>"$ERR_DIR/s1_dns.err" | grep ':53\b' | head -20

    echo
    echo "=== DNS query volume from /proc/net/udp ==="
    dns_udp=$(grep -c " 0035 \| 0035:" /proc/net/udp 2>>"$ERR_DIR/s1_dns.err" || echo 0)
    echo "UDP port 53 socket entries: $dns_udp"

    echo
    echo "=== Suspicious DNS patterns (systemd-resolved stats) ==="
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl statistics 2>>"$ERR_DIR/s1_dns.err" | head -20
    else
        echo "(resolvectl not available)"
        echo "[INFO] Section 1: resolvectl not found" >> "$ERRORS_FILE"
    fi

    echo
    echo "=== Excessively long DNS domain names in logs (>50 chars in label) ==="
    for logfile in /var/log/syslog /var/log/messages /var/log/dns.log; do
        [ -r "$logfile" ] || continue
        grep -oE '[a-zA-Z0-9]{50,}\.[a-zA-Z0-9.-]+' "$logfile" 2>>"$ERR_DIR/s1_dns.err" | \
            head -20 | while read -r domain; do
            echo "[SUSPICIOUS] Long subdomain: $domain"
        done
    done

    echo
    echo "=== High TXT record query rate ==="
    for logfile in /var/log/syslog /var/log/messages; do
        [ -r "$logfile" ] || continue
        count=$(grep -c "TXT" "$logfile" 2>>"$ERR_DIR/s1_dns.err" || echo 0)
        [ "$count" -gt 50 ] && echo "[WARN] High TXT query count in $logfile: $count"
    done

    echo
    echo "=== Processes making direct DNS connections ==="
    ss -tunapH 2>>"$ERR_DIR/s1_dns.err" | awk '$5 ~ /:53$/' | \
        grep -vE 'systemd-resolve|dnsmasq|named|unbound' | head -20

    echo
    echo "=== DNS tunnelling tools ==="
    for tool in iodine dns2tcp dnscat nstx dnstt; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "[HIGH] DNS tunnelling tool found: $tool at $(which "$tool")"
        find /tmp /opt /home /root -name "$tool" -type f 2>>"$ERR_DIR/s1_dns.err" \
            && echo "[HIGH] $tool binary found on disk" || true
    done

} > "$OUTPUT_DIR/dns_tunnelling.txt"
_section_err "Section 1 DNS tunnelling" "$ERR_DIR/s1_dns.err"

# SECTION 2 — ICMP COVERT CHANNEL DETECTION

echo "[*] Detecting ICMP covert channel indicators..."

{
    echo "========================================================"
    echo "  ICMP Covert Channel Detection"
    echo "========================================================"
    echo

    echo "=== ICMP socket activity ==="
    cat /proc/net/icmp  2>>"$ERR_DIR/s2_icmp.err" | head -20
    cat /proc/net/icmp6 2>>"$ERR_DIR/s2_icmp.err" | head -20

    echo
    echo "=== Processes using raw sockets ==="
    echo "--- /proc/net/raw entries ---"
    cat /proc/net/raw 2>>"$ERR_DIR/s2_icmp.err" | head -20

    raw_inodes=$(awk 'NR>1{print $10}' /proc/net/raw 2>>"$ERR_DIR/s2_icmp.err" | sort -u)
    if [ -n "$raw_inodes" ]; then
        echo
        echo "--- Processes owning raw sockets ---"
        for inode in $raw_inodes; do
            find /proc/*/fd -lname "socket:\[$inode\]" 2>>"$ERR_DIR/s2_icmp.err" | while read -r fd; do
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
            && echo "[HIGH] $tool binary found on disk" || true
    done

    echo
    echo "=== ICMP statistics ==="
    cat /proc/net/snmp 2>>"$ERR_DIR/s2_icmp.err" | grep -A1 "^Icmp:" | head -4

} > "$OUTPUT_DIR/icmp_covert_channels.txt"
_section_err "Section 2 ICMP" "$ERR_DIR/s2_icmp.err"

# SECTION 3 — HTTP/HTTPS C2 BEACONING DETECTION

echo "[*] Detecting HTTP/HTTPS C2 beaconing patterns..."

{
    echo "========================================================"
    echo "  HTTP/HTTPS C2 Beaconing Detection"
    echo "========================================================"
    echo

    echo "=== Established outbound HTTP/HTTPS connections ==="
    ss -tnp state established 2>>"$ERR_DIR/s3_http.err" | \
        awk '$5 ~ /:80$|:443$|:8080$|:8443$|:4444$|:4443$|:1337$/ {print}' | head -30

    echo
    echo "=== Persistent HTTP connections (keepalive indicator) ==="
    ss -tnpo state established 2>>"$ERR_DIR/s3_http.err" | \
        awk '$5 ~ /:80$|:443$|:8080$/ && /timer:keepalive/ {print}' | head -20

    echo
    echo "=== Processes making outbound HTTP connections ==="
    ss -tnpH state established 2>>"$ERR_DIR/s3_http.err" | \
        awk '$5 ~ /:80$|:443$/ {print $6}' | \
        grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u | \
        while read -r pid; do
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | cut -c1-80)
            echo "$exe" | grep -qE 'firefox|chrome|apt|yum|dnf|snap|curl|wget' || \
                echo "PID $pid | $exe | $cmd"
        done | head -20

    echo
    echo "=== Known C2 / RAT / implant process names ==="
    for name in metasploit msfconsole meterpreter agent.py \
                empire stager listener cobalt beacon \
                sliver implant nighthawk havoc brute \
                merlin covenant mythic deimos shad0w \
                pwncat reverse_shell; do
        ps auxww 2>>"$ERR_DIR/s3_http.err" | grep -i "$name" | grep -v grep | \
            while read -r line; do
            echo "[HIGH] Possible C2 process: $line"
        done
    done

    echo
    echo "=== Connections on non-standard ports ==="
    ss -tnpH state established 2>>"$ERR_DIR/s3_http.err" | \
        awk '$5 !~ /:(22|80|443|3306|5432|6379|27017|53|25|587|110|995|143|993|8080|8443)$/ \
             && $5 !~ /127\.0\.0\.1|::1/ {print}' | \
        grep -vE '(local|Private)' | head -20

    echo
    echo "=== Periodic connection timing analysis (10-second sample) ==="
    python3 - << 'PYEOF' 2>>"$ERR_DIR/s3_http.err" || _note_err "beaconing timing sample" $?
import time, subprocess, collections, sys

DURATION = 10
interval = 1
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
                dest = parts[4]
                dest_times[dest].append(time.time())
    except Exception as e:
        print(f"[ERROR] ss sampling failed: {e}", file=sys.stderr)
        break
    time.sleep(interval)

print("Destination IPs with repeated connections in 10s window:")
for dest, times in dest_times.items():
    if len(times) >= 3:
        print(f"  {dest:<30} {len(times)} connection events")
PYEOF

} > "$OUTPUT_DIR/http_c2_beaconing.txt"
_section_err "Section 3 HTTP C2 beaconing" "$ERR_DIR/s3_http.err"

# SECTION 4 — LARGE OUTBOUND TRANSFER DETECTION

echo "[*] Detecting large outbound data transfers..."

{
    echo "========================================================"
    echo "  Large Outbound Transfer Detection"
    echo "========================================================"
    echo

    echo "=== Network interface statistics (cumulative TX bytes) ==="
    cat /proc/net/dev 2>>"$ERR_DIR/s4_transfer.err" | \
        awk 'NR>2 {
            bytes_rx=$2; bytes_tx=$10;
            mb_rx=bytes_rx/1048576; mb_tx=bytes_tx/1048576;
            printf "  %-12s  RX: %10.2f MB   TX: %10.2f MB\n", $1, mb_rx, mb_tx
        }'

    echo
    echo "=== Real-time bandwidth snapshot (2-second sample) ==="
    python3 - << 'PYEOF' 2>>"$ERR_DIR/s4_transfer.err" || _note_err "bandwidth snapshot" $?
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
        -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" \
        -o -name "*.zip" -o -name "*.7z" -o -name "*.rar" \
        -o -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \
    \) -ls 2>>"$ERR_DIR/s4_transfer.err" | sort -k7 -rn | head -20

    echo
    echo "=== Large files (>1MB) in writable directories ==="
    find /tmp /var/tmp /dev/shm -type f -size +1M -ls 2>>"$ERR_DIR/s4_transfer.err" \
        | sort -k7 -rn | head -20

    echo
    echo "=== Active upload processes ==="
    ps auxww 2>>"$ERR_DIR/s4_transfer.err" | grep -E \
        '(scp |rsync .*(--[-a-z]+ )*[^-].*@|curl.*(--upload|-T|-d @)|sftp |ftp )' | \
        grep -v grep | head -20

    echo
    echo "=== Recent large file transfers via ssh ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep -iE "scp|sftp|rsync" "$logfile" 2>>"$ERR_DIR/s4_transfer.err" | \
            tail -20
    done

} > "$OUTPUT_DIR/large_outbound_transfers.txt"
_section_err "Section 4 large outbound transfers" "$ERR_DIR/s4_transfer.err"

# SECTION 5 — STEGANOGRAPHY INDICATORS

echo "[*] Checking for steganography indicators..."

{
    echo "========================================================"
    echo "  Steganography Indicators"
    echo "========================================================"
    echo

    echo "=== Steganography tools installed ==="
    for tool in steghide outguess stegdetect stegseek openstego \
                stepic stegpy digital-watermarking exiftool; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool at $(which "$tool")"
    done

    echo
    echo "=== Suspicious image files in writable locations ==="
    find /tmp /var/tmp /dev/shm /home /root -type f \
        \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \
           -o -name "*.bmp" -o -name "*.gif" \) \
        -size +100k -ls 2>>"$ERR_DIR/s5_steg.err" | head -20

    echo
    echo "=== Oversized PNG/JPG files (possible data embedding) ==="
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f -name "*.png" -size +10M -ls 2>>"$ERR_DIR/s5_steg.err" | head -10
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f -name "*.jpg" -size +5M -ls 2>>"$ERR_DIR/s5_steg.err" | head -10

    echo
    echo "=== Audio files in unusual locations ==="
    find /tmp /var/tmp /dev/shm /home -type f \
        \( -name "*.wav" -o -name "*.mp3" -o -name "*.flac" \) \
        -ls 2>>"$ERR_DIR/s5_steg.err" | head -10

    echo
    echo "=== Base64 blob files (encoded payload) ==="
    find /tmp /var/tmp /dev/shm -type f -size +10k 2>>"$ERR_DIR/s5_steg.err" | while read -r f; do
        if python3 -c "
import sys
try:
    with open('$f','rb') as fp: data=fp.read(4096)
    text=data.decode('ascii')
    b64_chars=sum(1 for c in text if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    ratio=b64_chars/max(len(text),1)
    sys.exit(0 if ratio > 0.9 else 1)
except: sys.exit(1)" 2>>"$ERR_DIR/s5_steg.err"; then
            echo "POSSIBLE BASE64 BLOB: $f"
        fi
    done | head -10

} > "$OUTPUT_DIR/steganography_indicators.txt"
_section_err "Section 5 steganography" "$ERR_DIR/s5_steg.err"

# SECTION 6 — DLP: SENSITIVE DATA STAGED FOR EXFILTRATION

echo "[*] Running DLP checks for staged sensitive data..."

{
    echo "========================================================"
    echo "  DLP — Sensitive Data Staging Check"
    echo "========================================================"
    echo

    DLP_DIRS="/tmp /var/tmp /dev/shm /home /root /var/www /opt"

    echo "=== SSH private keys in writable/world-accessible locations ==="
    find $DLP_DIRS -type f \( -name "id_rsa" -o -name "id_ed25519" \
        -o -name "id_ecdsa" -o -name "*.pem" -o -name "*.key" \) \
        2>>"$ERR_DIR/s6_dlp.err" | head -20

    echo
    echo "=== Password/credential pattern matches in text files ==="
    find /tmp /var/tmp /dev/shm /home /root -type f -size -5M 2>>"$ERR_DIR/s6_dlp.err" | \
        while read -r f; do
        file "$f" 2>/dev/null | grep -q "text\|ASCII\|UTF-8" || continue
        grep -lniE '(password[[:space:]]*[:=][[:space:]]*\S{6,}|passwd[[:space:]]*[:=]|secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=])' \
            "$f" 2>>"$ERR_DIR/s6_dlp.err" | while read -r match; do
            echo "SENSITIVE: $match"
        done
    done | head -20

    echo
    echo "=== Credit card number patterns ==="
    find $DLP_DIRS -type f -size -10M 2>>"$ERR_DIR/s6_dlp.err" | \
        while read -r f; do
        file "$f" 2>/dev/null | grep -q "text\|ASCII\|UTF-8" || continue
        grep -lE '\b4[0-9]{15}\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b|\b6011[0-9]{12}\b' \
            "$f" 2>>"$ERR_DIR/s6_dlp.err" | while read -r match; do
            echo "POSSIBLE_PAN: $match"
        done
    done | head -10

    echo
    echo "=== Database dumps in staging areas ==="
    find /tmp /var/tmp /dev/shm /home /root -type f \
        \( -name "*.sql" -o -name "*.dump" -o -name "*.db" \
           -o -name "*.sqlite" -o -name "*backup*" \) \
        -ls 2>>"$ERR_DIR/s6_dlp.err" | sort -k7 -rn | head -20

    echo
    echo "=== /etc/shadow copies in writable locations ==="
    find /tmp /var/tmp /dev/shm /home /root -type f 2>>"$ERR_DIR/s6_dlp.err" | while read -r f; do
        head -1 "$f" 2>/dev/null | grep -qE '^\S+:\$[156y]\$' \
            && echo "POSSIBLE SHADOW COPY: $f"
    done | head -10

    echo
    echo "=== Source code / IP archives ==="
    find /tmp /var/tmp /dev/shm -type f \
        \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" \) \
        -ls 2>>"$ERR_DIR/s6_dlp.err" | sort -k7 -rn | head -10

    echo
    echo "=== Recently created archives (last 24h) ==="
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f \( -name "*.tar*" -o -name "*.zip" -o -name "*.7z" \) \
        -newer /tmp 2>>"$ERR_DIR/s6_dlp.err" | head -20

} > "$OUTPUT_DIR/dlp_staging_check.txt"
_section_err "Section 6 DLP" "$ERR_DIR/s6_dlp.err"

# SECTION 7 — PROTOCOL ANOMALY DETECTION

echo "[*] Detecting protocol-level anomalies..."

{
    echo "========================================================"
    echo "  Protocol Anomaly Detection"
    echo "========================================================"
    echo

    echo "=== Connections on unexpected ports for common protocols ==="
    ss -tnpH state established 2>>"$ERR_DIR/s7_proto.err" | \
        awk '$5 !~ /:(80|443|8080|8443|8000|8888|3000|5000)$/ \
             && ($6 ~ /curl|wget|python|node|java/) {print "Possible HTTP C2: "$0}' | head -10

    echo
    echo "=== Tor indicators ==="
    if pgrep -x tor >/dev/null 2>>"$ERR_DIR/s7_proto.err" || pgrep -x "tor$" >/dev/null 2>&1; then
        echo "[HIGH] Tor process is running!"
        pgrep -al tor 2>>"$ERR_DIR/s7_proto.err"
    fi
    ss -tnpH 2>>"$ERR_DIR/s7_proto.err" | grep -E ':9050|:9051|:9150|:9001|:9030' | head -10

    echo
    echo "=== I2P / anonymous network indicators ==="
    pgrep -al "i2p\|i2pd" 2>>"$ERR_DIR/s7_proto.err" || true
    ss -tnpH 2>>"$ERR_DIR/s7_proto.err" | grep ':7654\|:4444\|:7656\|:7657' | head -5

    echo
    echo "=== Proxychains / SOCKS proxy usage ==="
    find /home /root /tmp -name "proxychains*.conf" -type f -ls 2>>"$ERR_DIR/s7_proto.err" | head -5
    pgrep -al "proxychains\|proxytunnel\|3proxy" 2>>"$ERR_DIR/s7_proto.err" || true

    echo
    echo "=== HTTPS certificate pinning bypass tools ==="
    for tool in mitmproxy burpsuite charles fiddler sslstrip; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool (potential HTTPS interception/bypass)"
    done

    echo
    echo "=== Email exfiltration indicators ==="
    ss -tnpH state established 2>>"$ERR_DIR/s7_proto.err" | \
        awk '$5 ~ /:25$|:465$|:587$/ {print "[SMTP outbound]: "$0}' | head -10

    pgrep -al "sendmail\|postfix\|ssmtp\|msmtp\|swaks" 2>>"$ERR_DIR/s7_proto.err" || true

} > "$OUTPUT_DIR/protocol_anomalies.txt"
_section_err "Section 7 protocol anomalies" "$ERR_DIR/s7_proto.err"

# SECTION 8 — EXFILTRATION SUMMARY

echo "[*] Generating exfiltration detection summary..."

{
    echo "========================================================"
    echo "  Data Exfiltration Detection — Summary"
    echo "  Generated: $(date)"
    echo "  Host:      $(hostname)"
    echo "========================================================"
    echo

    echo "--- High-Priority Findings ---"

    grep -q "DNS tunnelling tool found\|SUSPICIOUS.*Long subdomain" \
        "$OUTPUT_DIR/dns_tunnelling.txt" 2>/dev/null && \
        echo "[HIGH] DNS tunnelling indicators detected"

    grep -q "ICMP tunnel tool found\|raw socket" \
        "$OUTPUT_DIR/icmp_covert_channels.txt" 2>/dev/null && \
        echo "[MEDIUM] ICMP covert channel indicators detected"

    grep -q "Possible C2 process\|C2 framework" \
        "$OUTPUT_DIR/http_c2_beaconing.txt" 2>/dev/null && \
        echo "[CRITICAL] Known C2/RAT process names detected"

    grep -q "HIGH TX" "$OUTPUT_DIR/large_outbound_transfers.txt" 2>/dev/null && \
        echo "[HIGH] High outbound data transfer rate detected"

    grep -q "POSSIBLE BASE64 BLOB\|SENSITIVE\|POSSIBLE_PAN\|POSSIBLE SHADOW COPY" \
        "$OUTPUT_DIR/dlp_staging_check.txt" "$OUTPUT_DIR/steganography_indicators.txt" 2>/dev/null && \
        echo "[HIGH] Sensitive data staged in writable directories"

    grep -q "Tor process is running" \
        "$OUTPUT_DIR/protocol_anomalies.txt" 2>/dev/null && \
        echo "[HIGH] Tor anonymisation network is active"

    grep -q "FOUND.*steghide\|FOUND.*outguess\|FOUND.*stegseek" \
        "$OUTPUT_DIR/steganography_indicators.txt" 2>/dev/null && \
        echo "[MEDIUM] Steganography tools found on system"

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

tar -czf exfil_detect_archive.tar.gz "$OUTPUT_DIR" 2>/dev/null || true
echo
echo "[+] Exfiltration detection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: exfil_detect_archive.tar.gz"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors were recorded — see $OUTPUT_DIR/errors_summary.txt and $ERR_DIR/"