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
    # Count DNS queries (port 53 connections)
    dns_count=$(ss -tunap 2>/dev/null | grep -c ':53\b' || echo 0)
    echo "Current DNS connections: $dns_count"
    [ "$dns_count" -gt 10 ] && echo "[WARN] High DNS connection count — possible tunnelling"

    ss -tunap 2>/dev/null | grep ':53\b' | head -20

    echo
    echo "=== DNS query volume from /proc/net/udp (port 35 = 0x0035) ==="
    # hex 0x0035 = 53
    dns_udp=$(grep -c " 0035 \| 0035:" /proc/net/udp 2>/dev/null || echo 0)
    echo "UDP port 53 socket entries: $dns_udp"

    echo
    echo "=== Suspicious DNS patterns in system resolver cache ==="
    # Check if systemd-resolved has unusual stats
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl statistics 2>/dev/null | head -20
    fi

    echo
    echo "=== Excessively long DNS domain names in logs (>50 chars in label) ==="
    for logfile in /var/log/syslog /var/log/messages /var/log/dns.log; do
        [ -r "$logfile" ] || continue
        # DNS tunnelling often uses long subdomains to encode data
        grep -oE '[a-zA-Z0-9]{50,}\.[a-zA-Z0-9.-]+' "$logfile" 2>/dev/null | \
            head -20 | while read -r domain; do
            echo "[SUSPICIOUS] Long subdomain: $domain"
        done
    done

    echo
    echo "=== High TXT record query rate (common tunnelling technique) ==="
    grep -c "TXT" /var/log/syslog 2>/dev/null | \
        while read -r count; do
        [ "$count" -gt 50 ] && echo "[WARN] High TXT query count: $count"
    done || true

    echo
    echo "=== Processes making direct DNS connections (not via resolver) ==="
    # Processes connecting to port 53 other than systemd-resolved/dnsmasq
    ss -tunapH 2>/dev/null | awk '$5 ~ /:53$/' | \
        grep -vE 'systemd-resolve|dnsmasq|named|unbound' | head -20

    echo
    echo "=== Tools known for DNS tunnelling ==="
    for tool in iodine dns2tcp dnscat nstx dnstt; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "[HIGH] DNS tunnelling tool found: $tool at $(which "$tool")"
        find /tmp /opt /home /root -name "$tool" -type f 2>/dev/null \
            && echo "[HIGH] $tool binary found on disk"
    done || true

} > "$OUTPUT_DIR/dns_tunnelling.txt" 2>/dev/null || true

# SECTION 2 — ICMP COVERT CHANNEL DETECTION

echo "[*] Detecting ICMP covert channel indicators..."

{
    echo "========================================================"
    echo "  ICMP Covert Channel Detection"
    echo "========================================================"
    echo

    echo "=== ICMP socket activity ==="
    # Raw ICMP sockets (required for ping tunnels)
    cat /proc/net/icmp  2>/dev/null | head -20
    cat /proc/net/icmp6 2>/dev/null | head -20

    echo
    echo "=== Processes using raw sockets (ICMP tunnel indicator) ==="
    # Raw socket users show up in /proc/net/raw
    echo "--- /proc/net/raw entries ---"
    cat /proc/net/raw 2>/dev/null | head -20

    # Match raw socket inodes to processes
    raw_inodes=$(awk 'NR>1{print $10}' /proc/net/raw 2>/dev/null | sort -u)
    if [ -n "$raw_inodes" ]; then
        echo
        echo "--- Processes owning raw sockets ---"
        for inode in $raw_inodes; do
            find /proc/*/fd -lname "socket:\[$inode\]" 2>/dev/null | while read -r fd; do
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
        find /tmp /opt /home /root -name "$tool" -type f 2>/dev/null \
            && echo "[HIGH] $tool binary found on disk" || true
    done

    echo
    echo "=== ICMP statistics (large payload counts may indicate tunnelling) ==="
    cat /proc/net/snmp 2>/dev/null | grep -A1 "^Icmp:" | head -4

} > "$OUTPUT_DIR/icmp_covert_channels.txt" 2>/dev/null || true

# SECTION 3 — HTTP/HTTPS C2 BEACONING DETECTION

echo "[*] Detecting HTTP/HTTPS C2 beaconing patterns..."

{
    echo "========================================================"
    echo "  HTTP/HTTPS C2 Beaconing Detection"
    echo "========================================================"
    echo

    echo "=== Established outbound HTTP/HTTPS connections ==="
    ss -tnp state established 2>/dev/null | \
        awk '$5 ~ /:80$|:443$|:8080$|:8443$|:4444$|:4443$|:1337$/ {print}' | head -30

    echo
    echo "=== Persistent HTTP connections (long-lived — beacon indicator) ==="
    # TCP connections open for more than 5 minutes to HTTP ports
    ss -tnpo state established 2>/dev/null | \
        awk '$5 ~ /:80$|:443$|:8080$/ && /timer:keepalive/ {print}' | head -20

    echo
    echo "=== Processes making outbound HTTP connections (excluding browsers/package mgr) ==="
    ss -tnpH state established 2>/dev/null | \
        awk '$5 ~ /:80$|:443$/ {print $6}' | \
        grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u | \
        while read -r pid; do
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | cut -c1-80)
            # Exclude known-good browsers and package managers
            echo "$exe" | grep -qE 'firefox|chrome|apt|yum|dnf|snap|curl|wget' || \
                echo "PID $pid | $exe | $cmd"
        done | head -20

    echo
    echo "=== User-agent strings in process command lines (C2 framework indicators) ==="
    grep -r "User-Agent:" /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | head -10 || true

    echo
    echo "=== Known C2 / RAT / implant process names ==="
    # Common C2 framework and RAT names
    for name in metasploit msfconsole meterpreter agent.py \
                empire stager listener cobalt beacon \
                sliver implant nighthawk havoc brute \
                merlin covenant mythic deimos shad0w \
                pwncat reverse_shell; do
        ps auxww 2>/dev/null | grep -i "$name" | grep -v grep | \
            while read -r line; do
            echo "[HIGH] Possible C2 process: $line"
        done
    done

    echo
    echo "=== Connections to non-standard ports that may bypass firewall ==="
    # Outbound to ports not typically in /etc/services
    ss -tnpH state established 2>/dev/null | \
        awk '$5 !~ /:(22|80|443|3306|5432|6379|27017|53|25|587|110|995|143|993|8080|8443)$/ \
             && $5 !~ /127\.0\.0\.1|::1/ {print}' | \
        grep -vE '(local|Private)' | head -20

    echo
    echo "=== Periodic connection timing analysis (beaconing = regular intervals) ==="
    # Capture 60 seconds of new connection creation timestamps
    echo "Sampling new TCP connections for 10 seconds (lightweight)..."
    python3 - << 'PYEOF' 2>/dev/null || true
import time, subprocess, collections

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
    except Exception:
        pass
    time.sleep(interval)

print("Destination IPs with repeated connections in 10s window:")
for dest, times in dest_times.items():
    if len(times) >= 3:
        print(f"  {dest:<30} {len(times)} connection events")
PYEOF

} > "$OUTPUT_DIR/http_c2_beaconing.txt" 2>/dev/null || true

# SECTION 4 — LARGE OUTBOUND TRANSFER DETECTION

echo "[*] Detecting large outbound data transfers..."

{
    echo "========================================================"
    echo "  Large Outbound Transfer Detection"
    echo "========================================================"
    echo

    echo "=== Network interface statistics (cumulative TX bytes) ==="
    cat /proc/net/dev 2>/dev/null | \
        awk 'NR>2 {
            bytes_rx=$2; bytes_tx=$10;
            mb_rx=bytes_rx/1048576; mb_tx=bytes_tx/1048576;
            printf "  %-12s  RX: %10.2f MB   TX: %10.2f MB\n", $1, mb_rx, mb_tx
        }'

    echo
    echo "=== Real-time bandwidth snapshot (2-second sample) ==="
    python3 - << 'PYEOF' 2>/dev/null || true
import time

def read_net_stats():
    stats = {}
    with open('/proc/net/dev') as f:
        for line in f:
            parts = line.split()
            if ':' not in parts[0]:
                continue
            iface = parts[0].rstrip(':')
            stats[iface] = {'rx': int(parts[1]), 'tx': int(parts[9])}
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
    echo "=== Connections with large send buffers (high-volume transfer) ==="
    ss -tnp 2>/dev/null | awk 'NR>1 {
        # snd_buf field (column varies) - look for large values
        for(i=1;i<=NF;i++) {
            if($i ~ /^snd_buf:/ || $i ~ /^[0-9]{6,}/) print $0
        }
    }' | head -20

    echo
    echo "=== Files staged in /tmp for exfiltration (archives and large files) ==="
    find /tmp /var/tmp /dev/shm -type f \( \
        -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" \
        -o -name "*.zip" -o -name "*.7z" -o -name "*.rar" \
        -o -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \
    \) -ls 2>/dev/null | sort -k7 -rn | head -20

    # Large files in /tmp (>1MB)
    echo
    echo "=== Large files (>1MB) in writable directories ==="
    find /tmp /var/tmp /dev/shm -type f -size +1M -ls 2>/dev/null \
        | sort -k7 -rn | head -20

    echo
    echo "=== Active upload processes (scp, rsync, curl POST, ftp) ==="
    ps auxww 2>/dev/null | grep -E \
        '(scp |rsync .*(--[-a-z]+ )*[^-].*@|curl.*(--upload|-T|-d @)|sftp |ftp )' | \
        grep -v grep | head -20

    echo
    echo "=== Recent large file transfers via ssh (auth log) ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep -iE "scp|sftp|rsync" "$logfile" 2>/dev/null | \
            tail -20 || true
    done

} > "$OUTPUT_DIR/large_outbound_transfers.txt" 2>/dev/null || true

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
    # Images in /tmp or large images in unusual locations
    find /tmp /var/tmp /dev/shm /home /root -type f \
        \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \
           -o -name "*.bmp" -o -name "*.gif" \) \
        -size +100k -ls 2>/dev/null | head -20

    echo
    echo "=== Image files with unusually high sizes (possible data embedding) ==="
    # A 1920x1080 PNG should be < ~6MB uncompressed; larger may hide data
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f -name "*.png" -size +10M -ls 2>/dev/null | head -10
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f -name "*.jpg" -size +5M -ls 2>/dev/null | head -10

    echo
    echo "=== Audio files in unusual locations (audio steganography vector) ==="
    find /tmp /var/tmp /dev/shm /home -type f \
        \( -name "*.wav" -o -name "*.mp3" -o -name "*.flac" \) \
        -ls 2>/dev/null | head -10

    echo
    echo "=== Base64 blob files (encoded payload or data) ==="
    find /tmp /var/tmp /dev/shm -type f -size +10k 2>/dev/null | while read -r f; do
        # Check if file is >60% base64 chars
        if python3 -c "
import sys
with open('$f','rb') as fp: data=fp.read(4096)
try:
    text=data.decode('ascii')
    b64_chars=sum(1 for c in text if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    ratio=b64_chars/max(len(text),1)
    sys.exit(0 if ratio > 0.9 else 1)
except: sys.exit(1)" 2>/dev/null; then
            echo "POSSIBLE BASE64 BLOB: $f"
        fi
    done | head -10

} > "$OUTPUT_DIR/steganography_indicators.txt" 2>/dev/null || true

# SECTION 6 — DLP: SENSITIVE DATA STAGED FOR EXFILTRATION

echo "[*] Running DLP checks for staged sensitive data..."

{
    echo "========================================================"
    echo "  DLP — Sensitive Data Staging Check"
    echo "========================================================"
    echo

    DLP_DIRS="/tmp /var/tmp /dev/shm /home /root /var/www /opt"

    echo "=== SSH private keys in writable/world-accessible locations ==="
    find $DLP_DIRS -type f -name "id_rsa" -o -name "id_ed25519" \
        -o -name "id_ecdsa" -o -name "*.pem" -o -name "*.key" \
        2>/dev/null | head -20

    echo
    echo "=== Password/credential pattern matches in text files ==="
    # Search in writable areas only (likely attacker staging)
    find /tmp /var/tmp /dev/shm /home /root -type f -size -5M 2>/dev/null | \
        while read -r f; do
        file "$f" 2>/dev/null | grep -q "text\|ASCII\|UTF-8" || continue
        grep -lniE '(password[[:space:]]*[:=][[:space:]]*\S{6,}|passwd[[:space:]]*[:=]|secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=])' \
            "$f" 2>/dev/null | while read -r match; do
            echo "SENSITIVE: $match"
        done
    done | head -20

    echo
    echo "=== Credit card number patterns (PCI DSS) ==="
    find $DLP_DIRS -type f -size -10M 2>/dev/null | \
        while read -r f; do
        file "$f" 2>/dev/null | grep -q "text\|ASCII\|UTF-8" || continue
        # Luhn-passable 16-digit PAN patterns
        grep -lE '\b4[0-9]{15}\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b|\b6011[0-9]{12}\b' \
            "$f" 2>/dev/null | while read -r match; do
            echo "POSSIBLE_PAN: $match"
        done
    done | head -10

    echo
    echo "=== Database dumps in staging areas ==="
    find /tmp /var/tmp /dev/shm /home /root -type f \
        \( -name "*.sql" -o -name "*.dump" -o -name "*.db" \
           -o -name "*.sqlite" -o -name "*backup*" \) \
        -ls 2>/dev/null | sort -k7 -rn | head -20

    echo
    echo "=== /etc/shadow copies in writable locations ==="
    find /tmp /var/tmp /dev/shm /home /root -type f 2>/dev/null | while read -r f; do
        head -1 "$f" 2>/dev/null | grep -qE '^\S+:\$[156y]\$' \
            && echo "POSSIBLE SHADOW COPY: $f"
    done | head -10

    echo
    echo "=== Source code / intellectual property archives ==="
    find /tmp /var/tmp /dev/shm -type f \
        \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" \) \
        -ls 2>/dev/null | sort -k7 -rn | head -10

    echo
    echo "=== Recently created archives (last 24h) ==="
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f \( -name "*.tar*" -o -name "*.zip" -o -name "*.7z" \) \
        -newer /tmp 2>/dev/null | head -20

} > "$OUTPUT_DIR/dlp_staging_check.txt" 2>/dev/null || true

# SECTION 7 — PROTOCOL ANOMALY DETECTION

echo "[*] Detecting protocol-level anomalies..."

{
    echo "========================================================"
    echo "  Protocol Anomaly Detection"
    echo "========================================================"
    echo

    echo "=== Connections on unexpected ports for common protocols ==="
    # HTTP on non-80/443 (potential C2 HTTP mimicry)
    ss -tnpH state established 2>/dev/null | \
        awk '$5 !~ /:(80|443|8080|8443|8000|8888|3000|5000)$/ \
             && ($6 ~ /curl|wget|python|node|java/) {print "Possible HTTP C2: "$0}' | head -10

    echo
    echo "=== TOR exit node connection indicators ==="
    # Check if tor is running
    if pgrep -x tor >/dev/null 2>&1 || pgrep -x "tor$" >/dev/null 2>&1; then
        echo "[HIGH] Tor process is running!"
        pgrep -al tor 2>/dev/null
    fi
    # Tor default ports
    ss -tnpH 2>/dev/null | grep -E ':9050|:9051|:9150|:9001|:9030' | head -10

    echo
    echo "=== I2P / anonymous network indicators ==="
    pgrep -al "i2p\|i2pd" 2>/dev/null || true
    ss -tnpH 2>/dev/null | grep ':7654\|:4444\|:7656\|:7657' | head -5

    echo
    echo "=== Proxychains / SOCKS proxy usage ==="
    find /home /root /tmp -name "proxychains*.conf" -type f -ls 2>/dev/null | head -5
    pgrep -al "proxychains\|proxytunnel\|3proxy" 2>/dev/null || true

    echo
    echo "=== HTTPS certificate pinning bypass tools ==="
    for tool in mitmproxy burpsuite charles fiddler sslstrip; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool (potential HTTPS interception/bypass)"
    done || true

    echo
    echo "=== Email exfiltration indicators ==="
    # Direct SMTP connections to external MTAs
    ss -tnpH state established 2>/dev/null | \
        awk '$5 ~ /:25$|:465$|:587$/ {print "[SMTP outbound]: "$0}' | head -10

    pgrep -al "sendmail\|postfix\|ssmtp\|msmtp\|swaks" 2>/dev/null || true

} > "$OUTPUT_DIR/protocol_anomalies.txt" 2>/dev/null || true

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
    echo "--- Output Files ---"
    ls -lh "$OUTPUT_DIR/"*.txt 2>/dev/null

} > "$OUTPUT_DIR/exfil_summary.txt"

cat "$OUTPUT_DIR/exfil_summary.txt"

# ARCHIVE

tar -czf exfil_detect_archive.tar.gz "$OUTPUT_DIR" 2>/dev/null || true
echo
echo "[+] Exfiltration detection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: exfil_detect_archive.tar.gz"