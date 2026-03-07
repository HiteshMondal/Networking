#!/bin/bash
# Lateral Movement Detection Script
# Purpose : Detect indicators of lateral movement, credential-based attacks,
#           unusual authentication patterns, pass-the-hash/ticket artefacts,
#           network share enumeration, and pivot staging on a Linux host.
# Output  : lateral_movement/ directory + archive

set -eo pipefail

OUTPUT_DIR="lateral_movement"
mkdir -p "$OUTPUT_DIR"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a  >> "$OUTPUT_DIR/run_timestamp.txt"
whoami    >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — AUTHENTICATION ANOMALY DETECTION

echo "[*] Analysing authentication logs for anomalies..."

# Collect auth log from multiple possible locations
AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
    [ -r "$f" ] && AUTH_LOG="$f" && break
done

if [ -n "$AUTH_LOG" ]; then

    # Failed login attempts per user/IP
    echo "=== Failed SSH login attempts (top 30 by IP) ===" \
        > "$OUTPUT_DIR/failed_logins.txt"
    grep "Failed password" "$AUTH_LOG" 2>/dev/null \
        | grep -oP 'from \K[\d.]+' \
        | sort | uniq -c | sort -rn | head -30 \
        >> "$OUTPUT_DIR/failed_logins.txt"

    echo >> "$OUTPUT_DIR/failed_logins.txt"
    echo "=== Failed login usernames (top 20) ===" >> "$OUTPUT_DIR/failed_logins.txt"
    grep "Failed password" "$AUTH_LOG" 2>/dev/null \
        | grep -oP 'for \K\S+' \
        | sort | uniq -c | sort -rn | head -20 \
        >> "$OUTPUT_DIR/failed_logins.txt"

    # ── Brute force detection: ≥5 failures within 60 seconds from same IP ───
    echo "[*] Brute-force burst detection..."
    python3 - "$AUTH_LOG" << 'PYEOF' > "$OUTPUT_DIR/bruteforce_bursts.txt" 2>/dev/null || true
import sys, re, datetime

log_file = sys.argv[1]
year = datetime.datetime.now().year
pattern = re.compile(
    r'(\w+ \d+ \d+:\d+:\d+).*Failed password.*from ([\d.]+)'
)
events = {}  # ip → list of timestamps

with open(log_file, errors='replace') as f:
    for line in f:
        m = pattern.search(line)
        if not m:
            continue
        try:
            ts = datetime.datetime.strptime(f"{m.group(1)} {year}", "%b %d %H:%M:%S %Y")
        except ValueError:
            continue
        ip = m.group(2)
        events.setdefault(ip, []).append(ts)

print(f"{'IP Address':<20} {'Burst Count':>12} {'Window (s)':>12}  First event")
print("-" * 70)
for ip, times in events.items():
    times.sort()
    for i in range(len(times)):
        window = [t for t in times[i:] if (t - times[i]).total_seconds() <= 60]
        if len(window) >= 5:
            print(f"{ip:<20} {len(window):>12} {'60':>12}  {times[i]}")
            break
PYEOF

    # ── Successful logins after multiple failures (password spray success) ──
    echo "[*] Checking for success after failures (spray success indicator)..."
    {
        echo "=== IPs with both failures AND successes ==="
        failed_ips=$(grep "Failed password" "$AUTH_LOG" 2>/dev/null \
            | grep -oP 'from \K[\d.]+' | sort -u)
        accepted_ips=$(grep "Accepted " "$AUTH_LOG" 2>/dev/null \
            | grep -oP 'from \K[\d.]+' | sort -u)
        echo "$failed_ips" | sort > /tmp/_lm_failed.tmp
        echo "$accepted_ips" | sort > /tmp/_lm_accepted.tmp
        comm -12 /tmp/_lm_failed.tmp /tmp/_lm_accepted.tmp
        rm -f /tmp/_lm_failed.tmp /tmp/_lm_accepted.tmp
    } > "$OUTPUT_DIR/spray_success_ips.txt" 2>/dev/null || true

    # Off-hours logins (outside 07:00–19:00 local time)
    echo "[*] Checking for off-hours authentication..."
    grep "Accepted " "$AUTH_LOG" 2>/dev/null \
        | awk '{
            split($3, t, ":");
            h = t[1]+0;
            if (h < 7 || h >= 19) print $0
        }' > "$OUTPUT_DIR/offhours_logins.txt" 2>/dev/null || true

    # Successful logins from new/previously unseen IPs
    echo "[*] Extracting all successful login sources..."
    grep "Accepted " "$AUTH_LOG" 2>/dev/null \
        | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn \
        > "$OUTPUT_DIR/accepted_login_ips.txt" 2>/dev/null || true

    # Root logins
    grep "Accepted.*root\|session opened.*root" "$AUTH_LOG" 2>/dev/null \
        > "$OUTPUT_DIR/root_logins.txt" || true

    # Interactive logins vs non-interactive
    grep "pam_unix.*session.*opened" "$AUTH_LOG" 2>/dev/null \
        > "$OUTPUT_DIR/pam_session_opens.txt" || true

else
    echo "[-] No auth log found — trying journald..." \
        > "$OUTPUT_DIR/failed_logins.txt"
    journalctl -u ssh -u sshd --no-pager 2>/dev/null \
        | grep -E "Failed|Accepted|Invalid" \
        | tail -500 >> "$OUTPUT_DIR/failed_logins.txt" || true
fi

# SECTION 2 — SSH LATERAL MOVEMENT INDICATORS

echo "[*] Checking SSH lateral movement indicators..."

# Outbound SSH connections (this host pivoting to others)
ss -tnp state established 2>/dev/null \
    | awk '$4 ~ /:22$/ || $5 ~ /:22$/ {print}' \
    > "$OUTPUT_DIR/ssh_established_connections.txt" || true

# SSH known_hosts — maps trusted targets (pivot network)
find /home /root -name "known_hosts" -type f 2>/dev/null | while read -r kh; do
    echo "=== $kh ===" >> "$OUTPUT_DIR/ssh_known_hosts.txt"
    cat "$kh"          >> "$OUTPUT_DIR/ssh_known_hosts.txt" 2>/dev/null
    echo               >> "$OUTPUT_DIR/ssh_known_hosts.txt"
done || true

# SSH agent forwarding indicators (enables one-hop pivot)
{
    echo "=== SSH_AUTH_SOCK in running processes ==="
    grep -l "SSH_AUTH_SOCK" /proc/*/environ 2>/dev/null | while read -r env_file; do
        pid=$(echo "$env_file" | grep -oE '[0-9]+')
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        echo "PID $pid ($exe): SSH agent socket forwarded"
        tr '\0' '\n' < "$env_file" 2>/dev/null | grep "SSH_AUTH_SOCK"
    done
} > "$OUTPUT_DIR/ssh_agent_forwarding.txt" 2>/dev/null || true

# Authorized keys modified recently (backdoor placement)
find /home /root -name "authorized_keys" -type f -mtime -7 2>/dev/null \
    > "$OUTPUT_DIR/recently_modified_authorized_keys.txt" || true

# All authorized keys (may contain attacker-added keys)
find /home /root -name "authorized_keys" -type f 2>/dev/null | while read -r ak; do
    echo "=== $ak ===" >> "$OUTPUT_DIR/all_authorized_keys.txt"
    cat "$ak"          >> "$OUTPUT_DIR/all_authorized_keys.txt" 2>/dev/null
    echo               >> "$OUTPUT_DIR/all_authorized_keys.txt"
done || true

# SSH config override files
find /home /root -name "config" -path "*/.ssh/*" -type f 2>/dev/null \
    | while read -r cfg; do
    echo "=== $cfg ===" >> "$OUTPUT_DIR/ssh_client_configs.txt"
    cat "$cfg"          >> "$OUTPUT_DIR/ssh_client_configs.txt" 2>/dev/null
done || true

# ── SSH multiplexed sockets (ControlMaster sessions — persistent tunnels) ───
find /tmp /run /home /root -name "*.ssh" -o -name "cm_*" -type s 2>/dev/null \
    > "$OUTPUT_DIR/ssh_mux_sockets.txt" || true

# SECTION 3 — CREDENTIAL THEFT INDICATORS

echo "[*] Scanning for credential theft artefacts..."

# /etc/passwd and shadow anomalies
{
    echo "=== UID 0 (root-equivalent) accounts ==="
    awk -F: '$3 == 0 {print}' /etc/passwd 2>/dev/null

    echo
    echo "=== Accounts with no password (empty hash) ==="
    awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || true
    awk -F: 'length($2) < 4 && $2 != "!" && $2 != "*" && $2 != "x" {print $1}' \
        /etc/shadow 2>/dev/null || true

    echo
    echo "=== Recently added accounts (uid > 999, non-service) ==="
    awk -F: '$3 >= 1000 && $3 != 65534 {print}' /etc/passwd 2>/dev/null

    echo
    echo "=== Accounts with interactive shells ==="
    grep -vE '(/nologin|/false|/sync)$' /etc/passwd 2>/dev/null

} > "$OUTPUT_DIR/account_anomalies.txt"

# Sudo privilege escalation checks
{
    echo "=== /etc/sudoers NOPASSWD entries ==="
    grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

    echo
    echo "=== Sudo rights for all users ==="
    grep -rE '^\s*[^#].*ALL\s*=.*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

    echo
    echo "=== sudoers.d directory ==="
    ls -la /etc/sudoers.d/ 2>/dev/null

} > "$OUTPUT_DIR/sudo_privilege_escalation.txt"

# Credential files in common locations
echo "[*] Searching for exposed credential files..."
find /home /root /var/www /opt /etc -type f 2>/dev/null \
    \( -name ".netrc" -o -name ".pgpass" -o -name "credentials" \
       -o -name "*.credentials" -o -name ".aws/credentials" \
       -o -name ".docker/config.json" -o -name "*.kubeconfig" \
       -o -name "kubeconfig" -o -name "*.token" \) \
    -ls >> "$OUTPUT_DIR/credential_files.txt" 2>/dev/null || true

# History file credential exposure
echo "[*] Checking shell history for credentials..."
find /home /root -name ".*history" -type f 2>/dev/null | while read -r hist; do
    echo "=== $hist ===" >> "$OUTPUT_DIR/history_credential_exposure.txt"
    grep -iE '(password|passwd|secret|token|key|curl.*-u|wget.*--user|mysql.*-p|sshpass)' \
        "$hist" 2>/dev/null | head -20 \
        >> "$OUTPUT_DIR/history_credential_exposure.txt" || true
done

# Mimikatz / credential dumper presence
echo "[*] Checking for credential-dumping tools..."
for tool in mimikatz pypykatz impacket-secretsdump crackmapexec bloodhound \
            ldapdomaindump kerbrute hashcat john hydra medusa ncrack; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool found at: $(which "$tool")" \
            >> "$OUTPUT_DIR/credential_dumping_tools.txt"
    fi
done
find /home /root /tmp /opt -name "mimikatz*" -o -name "pypykatz*" \
    -o -name "lazagne*" 2>/dev/null \
    >> "$OUTPUT_DIR/credential_dumping_tools.txt" || true

# SECTION 4 — NETWORK SHARE & SMB ENUMERATION EVIDENCE

echo "[*] Checking for network share access and mounting activity..."

# Currently mounted network filesystems
{
    echo "=== Network mounts (NFS, CIFS, SMB) ==="
    mount | grep -E 'type (nfs|cifs|smbfs|glusterfs|cephfs)'

    echo
    echo "=== /etc/fstab network entries ==="
    grep -E '(nfs|cifs|smbfs)' /etc/fstab 2>/dev/null || echo "(none)"

    echo
    echo "=== autofs maps (automounted shares) ==="
    [ -r /etc/auto.master ] && cat /etc/auto.master
    find /etc -name "auto.*" -type f 2>/dev/null | xargs cat 2>/dev/null || true

} > "$OUTPUT_DIR/network_mounts.txt"

# SMB/CIFS client activity
{
    echo "=== SMB connections from this host ==="
    ss -tnp state established 2>/dev/null | awk '$5 ~ /:445$/ || $5 ~ /:139$/ {print}'
    ss -tnp state established 2>/dev/null | awk '$5 ~ /:445$/ || $5 ~ /:139$/ {print}'

    echo
    echo "=== Samba/CIFS client processes ==="
    pgrep -a -x "smbd\|nmbd\|winbindd\|smbclient\|mount\.cifs" 2>/dev/null || echo "(none)"

} > "$OUTPUT_DIR/smb_activity.txt"

# NFS exports / imports
showmount -e localhost > "$OUTPUT_DIR/nfs_exports.txt" 2>/dev/null || true
cat /proc/net/rpc/nfs > "$OUTPUT_DIR/nfs_stats.txt" 2>/dev/null || true

# SECTION 5 — WMI / DCOM / RPC LATERAL MOVEMENT INDICATORS

echo "[*] Checking RPC/WMI lateral movement indicators..."

# RPC portmapper / rpcbind
{
    echo "=== rpcinfo -p (local RPC services) ==="
    rpcinfo -p localhost 2>/dev/null || rpcinfo 2>/dev/null || echo "(rpcinfo unavailable)"

    echo
    echo "=== RPC-related processes ==="
    pgrep -al "rpcbind\|rpc\.\|dbus-daemon\|systemd-logind" 2>/dev/null || true

} > "$OUTPUT_DIR/rpc_services.txt"

# D-Bus / Polkit abuse indicators
{
    echo "=== Polkit rules (custom privilege grants) ==="
    find /etc/polkit-1 /usr/share/polkit-1 -name "*.rules" 2>/dev/null | while read -r r; do
        echo "--- $r ---"
        cat "$r"
    done

    echo
    echo "=== Active D-Bus system sessions ==="
    busctl list 2>/dev/null | head -30 || dbus-send --system --print-reply \
        --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames 2>/dev/null || true

} > "$OUTPUT_DIR/dbus_polkit_analysis.txt" 2>/dev/null || true

# SECTION 6 — PORT FORWARDING & TUNNELLING

echo "[*] Detecting port forwarding and tunnelling setups..."

{
    echo "=== iptables port forwarding rules ==="
    sudo iptables -t nat -L -n -v 2>/dev/null | grep -E "DNAT|REDIRECT|SNAT" \
        || echo "(no iptables NAT rules or insufficient privilege)"

    echo
    echo "=== nftables port forwarding ==="
    sudo nft list ruleset 2>/dev/null | grep -E "dnat|redirect|snat" \
        || echo "(no nft rules or nft not installed)"

    echo
    echo "=== Processes with port forwarding in cmdline ==="
    # SSH tunnel/forward indicators
    ps auxww 2>/dev/null | grep -E '\-[LRD] [0-9]|ssh.*-N|ssh.*-w|autossh' \
        | grep -v grep

    echo
    echo "=== socat / ncat / netcat tunnel processes ==="
    ps auxww 2>/dev/null | grep -E '(socat|ncat|nc |netcat).*:[0-9]' | grep -v grep

    echo
    echo "=== Chisel / ligolo / frp tunnel tools ==="
    for tool in chisel ligolo ligolo-ng frp frpc frps; do
        pgrep -a "$tool" 2>/dev/null && echo "$tool is running" || true
        find /tmp /opt /home /root -name "$tool" -type f 2>/dev/null \
            && echo "$tool binary found on disk" || true
    done

    echo
    echo "=== Unexpected LISTEN sockets on high ports ==="
    ss -tlnp 2>/dev/null | awk 'NR>1 && $4 ~ /:[0-9]+$/ {
        split($4, a, ":"); port=a[length(a)]+0;
        if (port > 1024 && port != 3306 && port != 5432 && port != 6379 \
            && port != 8080 && port != 8443 && port != 9200) print $0
    }'

} > "$OUTPUT_DIR/port_forwarding_tunnels.txt" 2>/dev/null || true

# SECTION 7 — PTRACE / PROCESS INJECTION INDICATORS

echo "[*] Checking for process injection indicators..."

{
    echo "=== Processes with ptrace capabilities ==="
    cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null \
        && echo "(0=permissive, 1=restricted, 2=admin-only, 3=disabled)"

    echo
    echo "=== Processes ptracing others ==="
    ps auxww 2>/dev/null | grep -E '\-\-pid|gdb|strace|ltrace|ptrace' | grep -v grep

    echo
    echo "=== /proc/*/status Tracer fields (non-zero = being traced) ==="
    grep -l "TracerPid:[^0]" /proc/*/status 2>/dev/null | while read -r s; do
        pid=$(echo "$s" | grep -oE '[0-9]+')
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        tracer=$(grep "TracerPid" "$s" 2>/dev/null)
        echo "PID $pid ($exe): $tracer"
    done || echo "(none)"

    echo
    echo "=== LD_PRELOAD in process environments (library injection) ==="
    grep -rl "LD_PRELOAD" /proc/*/environ 2>/dev/null | while read -r env_f; do
        pid=$(echo "$env_f" | grep -oE '[0-9]+')
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        val=$(tr '\0' '\n' < "$env_f" 2>/dev/null | grep "LD_PRELOAD")
        echo "PID $pid ($exe): $val"
    done || echo "(none)"

} > "$OUTPUT_DIR/process_injection_indicators.txt" 2>/dev/null || true

# SECTION 8 — NETWORK RECON SIGNS (ATTACKER DISCOVERY PHASE)

echo "[*] Checking for signs of internal network reconnaissance..."

{
    echo "=== ARP table anomalies (excessive entries may indicate scanning) ==="
    arp_count=$(ip neigh show 2>/dev/null | wc -l)
    echo "Total ARP entries: $arp_count"
    [ "$arp_count" -gt 100 ] && echo "WARNING: High ARP entry count — possible ARP scan"
    ip neigh show 2>/dev/null | head -30

    echo
    echo "=== Recent nmap / masscan / zmap processes ==="
    ps auxww 2>/dev/null | grep -E 'nmap|masscan|zmap|rustscan|naabu' | grep -v grep

    echo
    echo "=== nmap output files (recent) ==="
    find /home /root /tmp /opt -name "*.xml" -o -name "nmap_*" -o -name "masscan*" \
        -mtime -7 -type f 2>/dev/null | head -20

    echo
    echo "=== TCP connection bursts to sequential IPs ==="
    # Unique /24 subnets connected to (wide lateral scan indicator)
    ss -tnp state established 2>/dev/null \
        | awk 'NR>1{print $5}' \
        | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' \
        | sort | uniq -c | sort -rn | head -10

} > "$OUTPUT_DIR/network_recon_indicators.txt" 2>/dev/null || true

# SECTION 9 — WTMP / UTMP / BTMP ANALYSIS (LOGIN RECORDS)

echo "[*] Analysing login record databases..."

{
    echo "=== last (successful logins from wtmp) ==="
    last -n 100 -i 2>/dev/null || last -n 100 2>/dev/null || true

    echo
    echo "=== lastb (failed logins from btmp — requires root) ==="
    sudo lastb -n 50 2>/dev/null || echo "(requires root access)"

    echo
    echo "=== Currently logged-in users ==="
    who -a 2>/dev/null || w 2>/dev/null || true

    echo
    echo "=== lastlog (last login per account) ==="
    lastlog 2>/dev/null | grep -v "Never logged in" | head -30 || true

} > "$OUTPUT_DIR/login_records.txt"

# SECTION 10 — LATERAL MOVEMENT SUMMARY

echo "[*] Generating lateral movement summary report..."

{
    echo "========================================================"
    echo "  Lateral Movement Detection — Summary Report"
    echo "  Generated: $(date)"
    echo "  Host:      $(hostname)"
    echo "========================================================"

    echo
    echo "--- High-Priority Findings ---"

    # Root-equivalent accounts
    root_eq=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
    [ -n "$root_eq" ] && echo "[!] CRITICAL: Extra UID 0 accounts: $root_eq"

    # NOPASSWD sudo
    nopasswd=$(grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -3)
    [ -n "$nopasswd" ] && echo "[!] HIGH: NOPASSWD sudo entries found"

    # SSH agent forwarding active
    [ -s "$OUTPUT_DIR/ssh_agent_forwarding.txt" ] && \
        echo "[!] MEDIUM: SSH agent forwarding detected in running processes"

    # Port forwarding
    grep -qE 'DNAT|ssh.*-[LRD]' "$OUTPUT_DIR/port_forwarding_tunnels.txt" 2>/dev/null \
        && echo "[!] MEDIUM: Port forwarding or tunnelling detected"

    # LD_PRELOAD injection
    grep -q "LD_PRELOAD" "$OUTPUT_DIR/process_injection_indicators.txt" 2>/dev/null \
        && echo "[!] HIGH: LD_PRELOAD library injection detected"

    # Recently modified authorized_keys
    [ -s "$OUTPUT_DIR/recently_modified_authorized_keys.txt" ] && \
        echo "[!] HIGH: authorized_keys files modified in last 7 days"

    # Credential dumping tools
    [ -s "$OUTPUT_DIR/credential_dumping_tools.txt" ] && \
        echo "[!] HIGH: Credential dumping tools found on system"

    echo
    echo "--- Counts ---"
    failed_count=$(grep -c "Failed" "$OUTPUT_DIR/failed_logins.txt" 2>/dev/null || echo 0)
    echo "  Failed login IPs:        $failed_count"
    root_logins=$(wc -l < "$OUTPUT_DIR/root_logins.txt" 2>/dev/null || echo 0)
    echo "  Root login events:       $root_logins"
    offhours=$(wc -l < "$OUTPUT_DIR/offhours_logins.txt" 2>/dev/null || echo 0)
    echo "  Off-hours login events:  $offhours"
    spray_ips=$(grep -vc '^===' "$OUTPUT_DIR/spray_success_ips.txt" 2>/dev/null || echo 0)
    echo "  Spray success IPs:       $spray_ips"

} > "$OUTPUT_DIR/lateral_movement_summary.txt"

cat "$OUTPUT_DIR/lateral_movement_summary.txt"

# ARCHIVE

tar -czf lateral_movement_archive.tar.gz "$OUTPUT_DIR" 2>/dev/null || true
echo
echo "[+] Detection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: lateral_movement_archive.tar.gz"