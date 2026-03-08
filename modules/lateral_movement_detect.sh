#!/bin/bash
# Lateral Movement Detection Script
# Purpose : Detect indicators of lateral movement, credential-based attacks,
#           unusual authentication patterns, pass-the-hash/ticket artefacts,
#           network share enumeration, and pivot staging on a Linux host.
# Output  : lateral_movement/ directory + archive

set -eo pipefail

OUTPUT_DIR="lateral_movement"
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
        && echo "[WARN] $sec: see $(basename "$errfile")" >> "$ERRORS_FILE" \
        || rm -f "$errfile"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a  >> "$OUTPUT_DIR/run_timestamp.txt"
whoami    >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — AUTHENTICATION ANOMALY DETECTION

echo "[*] Analysing authentication logs for anomalies..."

AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
    [ -r "$f" ] && AUTH_LOG="$f" && break
done

if [ -n "$AUTH_LOG" ]; then

    {
        echo "=== Failed SSH login attempts (top 30 by IP) ==="
        grep "Failed password" "$AUTH_LOG" 2>>"$ERR_DIR/s1_auth.err" \
            | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -30

        echo
        echo "=== Failed login usernames (top 20) ==="
        grep "Failed password" "$AUTH_LOG" 2>>"$ERR_DIR/s1_auth.err" \
            | grep -oP 'for \K\S+' | sort | uniq -c | sort -rn | head -20
    } > "$OUTPUT_DIR/failed_logins.txt"
    _section_err "Section 1 failed logins" "$ERR_DIR/s1_auth.err"

    echo "[*] Brute-force burst detection..."
    python3 - "$AUTH_LOG" << 'PYEOF' > "$OUTPUT_DIR/bruteforce_bursts.txt" \
        2>"$ERR_DIR/s1_brute.err" || _note_err "bruteforce burst python3" $?
import sys, re, datetime

log_file = sys.argv[1]
year = datetime.datetime.now().year
pattern = re.compile(r'(\w+ \d+ \d+:\d+:\d+).*Failed password.*from ([\d.]+)')
events = {}

try:
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
except Exception as e:
    print(f"[ERROR] Could not read {log_file}: {e}", file=sys.stderr)
    sys.exit(1)

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
    _section_err "Section 1 brute force" "$ERR_DIR/s1_brute.err"

    echo "[*] Checking for success after failures..."
    {
        echo "=== IPs with both failures AND successes ==="
        failed_ips=$(grep "Failed password" "$AUTH_LOG" 2>>"$ERR_DIR/s1_spray.err" \
            | grep -oP 'from \K[\d.]+' | sort -u)
        accepted_ips=$(grep "Accepted " "$AUTH_LOG" 2>>"$ERR_DIR/s1_spray.err" \
            | grep -oP 'from \K[\d.]+' | sort -u)
        echo "$failed_ips" | sort > /tmp/_lm_failed.tmp
        echo "$accepted_ips" | sort > /tmp/_lm_accepted.tmp
        comm -12 /tmp/_lm_failed.tmp /tmp/_lm_accepted.tmp
        rm -f /tmp/_lm_failed.tmp /tmp/_lm_accepted.tmp
    } > "$OUTPUT_DIR/spray_success_ips.txt" 2>>"$ERR_DIR/s1_spray.err" \
        || _note_err "spray success detection" $?
    _section_err "Section 1 spray" "$ERR_DIR/s1_spray.err"

    grep "Accepted " "$AUTH_LOG" 2>"$ERR_DIR/s1_offhours.err" \
        | awk '{split($3,t,":");h=t[1]+0;if(h<7||h>=19)print $0}' \
        > "$OUTPUT_DIR/offhours_logins.txt" \
        || _note_err "off-hours logins" $?
    _section_err "Section 1 off-hours" "$ERR_DIR/s1_offhours.err"

    grep "Accepted " "$AUTH_LOG" 2>"$ERR_DIR/s1_accepted.err" \
        | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn \
        > "$OUTPUT_DIR/accepted_login_ips.txt" \
        || _note_err "accepted login IPs" $?
    _section_err "Section 1 accepted IPs" "$ERR_DIR/s1_accepted.err"

    grep "Accepted.*root\|session opened.*root" "$AUTH_LOG" 2>"$ERR_DIR/s1_root.err" \
        > "$OUTPUT_DIR/root_logins.txt" || true
    _section_err "Section 1 root logins" "$ERR_DIR/s1_root.err"

    grep "pam_unix.*session.*opened" "$AUTH_LOG" 2>"$ERR_DIR/s1_pam.err" \
        > "$OUTPUT_DIR/pam_session_opens.txt" || true
    _section_err "Section 1 PAM sessions" "$ERR_DIR/s1_pam.err"

else
    {
        echo "[-] No auth log found — trying journald..."
        journalctl -u ssh -u sshd --no-pager 2>/dev/null \
            | grep -E "Failed|Accepted|Invalid" | tail -500
    } > "$OUTPUT_DIR/failed_logins.txt" 2>"$ERR_DIR/s1_journald.err" \
        || _note_err "journald auth fallback" $?
    _section_err "Section 1 journald fallback" "$ERR_DIR/s1_journald.err"
fi

# SECTION 2 — SSH LATERAL MOVEMENT INDICATORS

echo "[*] Checking SSH lateral movement indicators..."

ss -tnp state established 2>"$ERR_DIR/s2_ssh_conns.err" \
    | awk '$4 ~ /:22$/ || $5 ~ /:22$/ {print}' \
    > "$OUTPUT_DIR/ssh_established_connections.txt" \
    || _note_err "ssh established connections" $?
_section_err "Section 2 SSH connections" "$ERR_DIR/s2_ssh_conns.err"

{
    find /home /root -name "known_hosts" -type f 2>>"$ERR_DIR/s2_known_hosts.err" \
    | while read -r kh; do
        echo "=== $kh ===" ; cat "$kh" 2>>"$ERR_DIR/s2_known_hosts.err" ; echo
    done
} > "$OUTPUT_DIR/ssh_known_hosts.txt"
_section_err "Section 2 known_hosts" "$ERR_DIR/s2_known_hosts.err"

{
    echo "=== SSH_AUTH_SOCK in running processes ==="
    grep -l "SSH_AUTH_SOCK" /proc/*/environ 2>>"$ERR_DIR/s2_agent.err" | while read -r env_file; do
        pid=$(echo "$env_file" | grep -oE '[0-9]+' | head -1)
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        echo "PID $pid ($exe): SSH agent socket forwarded"
        tr '\0' '\n' < "$env_file" 2>>"$ERR_DIR/s2_agent.err" | grep "SSH_AUTH_SOCK"
    done
} > "$OUTPUT_DIR/ssh_agent_forwarding.txt"
_section_err "Section 2 SSH agent" "$ERR_DIR/s2_agent.err"

find /home /root -name "authorized_keys" -type f -mtime -7 2>"$ERR_DIR/s2_authkeys.err" \
    > "$OUTPUT_DIR/recently_modified_authorized_keys.txt" || true
_section_err "Section 2 authorized_keys" "$ERR_DIR/s2_authkeys.err"

{
    find /home /root -name "authorized_keys" -type f 2>>"$ERR_DIR/s2_allkeys.err" \
    | while read -r ak; do
        echo "=== $ak ===" ; cat "$ak" 2>>"$ERR_DIR/s2_allkeys.err" ; echo
    done
} > "$OUTPUT_DIR/all_authorized_keys.txt"
_section_err "Section 2 all authorized_keys" "$ERR_DIR/s2_allkeys.err"

{
    find /home /root -name "config" -path "*/.ssh/*" -type f 2>>"$ERR_DIR/s2_sshcfg.err" \
    | while read -r cfg; do
        echo "=== $cfg ===" ; cat "$cfg" 2>>"$ERR_DIR/s2_sshcfg.err"
    done
} > "$OUTPUT_DIR/ssh_client_configs.txt"
_section_err "Section 2 SSH client configs" "$ERR_DIR/s2_sshcfg.err"

find /tmp /run /home /root \( -name "*.ssh" -o -name "cm_*" \) -type s 2>"$ERR_DIR/s2_mux.err" \
    > "$OUTPUT_DIR/ssh_mux_sockets.txt" || true
_section_err "Section 2 SSH mux sockets" "$ERR_DIR/s2_mux.err"

# SECTION 3 — CREDENTIAL THEFT INDICATORS

echo "[*] Scanning for credential theft artefacts..."

{
    echo "=== UID 0 (root-equivalent) accounts ==="
    awk -F: '$3 == 0 {print}' /etc/passwd 2>>"$ERR_DIR/s3_creds.err"

    echo
    echo "=== Accounts with no password ==="
    awk -F: '$2 == "" {print $1}' /etc/shadow 2>>"$ERR_DIR/s3_creds.err" || true
    awk -F: 'length($2) < 4 && $2 != "!" && $2 != "*" && $2 != "x" {print $1}' \
        /etc/shadow 2>>"$ERR_DIR/s3_creds.err" || true

    echo
    echo "=== Recently added accounts ==="
    awk -F: '$3 >= 1000 && $3 != 65534 {print}' /etc/passwd 2>>"$ERR_DIR/s3_creds.err"

    echo
    echo "=== Accounts with interactive shells ==="
    grep -vE '(/nologin|/false|/sync)$' /etc/passwd 2>>"$ERR_DIR/s3_creds.err"

} > "$OUTPUT_DIR/account_anomalies.txt"
_section_err "Section 3 account anomalies" "$ERR_DIR/s3_creds.err"

{
    echo "=== /etc/sudoers NOPASSWD entries ==="
    grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>>"$ERR_DIR/s3_sudo.err"

    echo
    echo "=== Sudo rights for all users ==="
    grep -rE '^\s*[^#].*ALL\s*=.*ALL' /etc/sudoers /etc/sudoers.d/ 2>>"$ERR_DIR/s3_sudo.err"

    echo
    echo "=== sudoers.d directory ==="
    ls -la /etc/sudoers.d/ 2>>"$ERR_DIR/s3_sudo.err"

} > "$OUTPUT_DIR/sudo_privilege_escalation.txt"
_section_err "Section 3 sudo" "$ERR_DIR/s3_sudo.err"

echo "[*] Searching for exposed credential files..."
find /home /root /var/www /opt /etc -type f 2>"$ERR_DIR/s3_credfiles.err" \
    \( -name ".netrc" -o -name ".pgpass" -o -name "credentials" \
       -o -name "*.credentials" -o -name ".aws/credentials" \
       -o -name ".docker/config.json" -o -name "*.kubeconfig" \
       -o -name "kubeconfig" -o -name "*.token" \) \
    -ls >> "$OUTPUT_DIR/credential_files.txt" \
    || _note_err "credential file search" $?
_section_err "Section 3 credential files" "$ERR_DIR/s3_credfiles.err"

echo "[*] Checking shell history for credentials..."
find /home /root -name ".*history" -type f 2>"$ERR_DIR/s3_histcreds.err" \
| while read -r hist; do
    echo "=== $hist ===" >> "$OUTPUT_DIR/history_credential_exposure.txt"
    grep -iE '(password|passwd|secret|token|key|curl.*-u|wget.*--user|mysql.*-p|sshpass)' \
        "$hist" 2>>"$ERR_DIR/s3_histcreds.err" | head -20 \
        >> "$OUTPUT_DIR/history_credential_exposure.txt"
done
_section_err "Section 3 history credentials" "$ERR_DIR/s3_histcreds.err"

echo "[*] Checking for credential-dumping tools..."
for tool in mimikatz pypykatz impacket-secretsdump crackmapexec bloodhound \
            ldapdomaindump kerbrute hashcat john hydra medusa ncrack; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool found at: $(which "$tool")" \
            >> "$OUTPUT_DIR/credential_dumping_tools.txt"
    fi
done
find /home /root /tmp /opt \( -name "mimikatz*" -o -name "pypykatz*" -o -name "lazagne*" \) \
    2>"$ERR_DIR/s3_dumptools.err" \
    >> "$OUTPUT_DIR/credential_dumping_tools.txt" || true
_section_err "Section 3 credential dumping tools" "$ERR_DIR/s3_dumptools.err"

# SECTION 4 — NETWORK SHARE & SMB ENUMERATION

echo "[*] Checking for network share access..."

{
    echo "=== Network mounts ==="
    mount 2>>"$ERR_DIR/s4_shares.err" | grep -E 'type (nfs|cifs|smbfs|glusterfs|cephfs)'

    echo
    echo "=== /etc/fstab network entries ==="
    grep -E '(nfs|cifs|smbfs)' /etc/fstab 2>>"$ERR_DIR/s4_shares.err" || echo "(none)"

    echo
    echo "=== autofs maps ==="
    [ -r /etc/auto.master ] && cat /etc/auto.master
    find /etc -name "auto.*" -type f 2>>"$ERR_DIR/s4_shares.err" | xargs cat 2>>"$ERR_DIR/s4_shares.err"

} > "$OUTPUT_DIR/network_mounts.txt"
_section_err "Section 4 network mounts" "$ERR_DIR/s4_shares.err"

{
    echo "=== SMB connections from this host ==="
    ss -tnp state established 2>>"$ERR_DIR/s4_smb.err" | awk '$5 ~ /:445$/ || $5 ~ /:139$/ {print}'

    echo
    echo "=== Samba/CIFS client processes ==="
    pgrep -a -x "smbd\|nmbd\|winbindd\|smbclient\|mount\.cifs" 2>>"$ERR_DIR/s4_smb.err" \
        || echo "(none)"

} > "$OUTPUT_DIR/smb_activity.txt"
_section_err "Section 4 SMB" "$ERR_DIR/s4_smb.err"

showmount -e localhost > "$OUTPUT_DIR/nfs_exports.txt" 2>"$ERR_DIR/s4_nfs.err" \
    || { echo "(showmount unavailable)" > "$OUTPUT_DIR/nfs_exports.txt"; _note_err "showmount" $?; }
_section_err "Section 4 NFS" "$ERR_DIR/s4_nfs.err"

cat /proc/net/rpc/nfs > "$OUTPUT_DIR/nfs_stats.txt" 2>"$ERR_DIR/s4_nfsstats.err" \
    || { echo "(NFS RPC stats unavailable)" > "$OUTPUT_DIR/nfs_stats.txt"; }
_section_err "Section 4 NFS stats" "$ERR_DIR/s4_nfsstats.err"

# SECTION 5 — RPC / WMI / DCOM

echo "[*] Checking RPC/WMI lateral movement indicators..."

{
    echo "=== rpcinfo -p ==="
    rpcinfo -p localhost 2>>"$ERR_DIR/s5_rpc.err" || echo "(rpcinfo unavailable)"

    echo
    echo "=== RPC-related processes ==="
    pgrep -al "rpcbind\|rpc\.\|dbus-daemon\|systemd-logind" 2>>"$ERR_DIR/s5_rpc.err" || true

} > "$OUTPUT_DIR/rpc_services.txt"
_section_err "Section 5 RPC" "$ERR_DIR/s5_rpc.err"

{
    echo "=== Polkit rules ==="
    find /etc/polkit-1 /usr/share/polkit-1 -name "*.rules" 2>>"$ERR_DIR/s5_polkit.err" \
    | while read -r r; do echo "--- $r ---" ; cat "$r"; done

    echo
    echo "=== Active D-Bus system sessions ==="
    busctl list 2>>"$ERR_DIR/s5_polkit.err" | head -30 \
        || dbus-send --system --print-reply \
            --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames \
            2>>"$ERR_DIR/s5_polkit.err" || echo "(dbus unavailable)"

} > "$OUTPUT_DIR/dbus_polkit_analysis.txt"
_section_err "Section 5 DBus/Polkit" "$ERR_DIR/s5_polkit.err"

# SECTION 6 — PORT FORWARDING & TUNNELLING

echo "[*] Detecting port forwarding and tunnelling..."

{
    echo "=== iptables port forwarding rules ==="
    iptables -t nat -L -n -v 2>>"$ERR_DIR/s6_tunnel.err" | grep -E "DNAT|REDIRECT|SNAT" \
        || echo "(no iptables NAT rules or insufficient privilege)"

    echo
    echo "=== nftables port forwarding ==="
    nft list ruleset 2>>"$ERR_DIR/s6_tunnel.err" | grep -E "dnat|redirect|snat" \
        || echo "(no nft rules or nft not installed)"

    echo
    echo "=== SSH tunnel/forward processes ==="
    ps auxww 2>>"$ERR_DIR/s6_tunnel.err" \
        | grep -E '\-[LRD] [0-9]|ssh.*-N|ssh.*-w|autossh' | grep -v grep

    echo
    echo "=== socat / ncat tunnel processes ==="
    ps auxww 2>>"$ERR_DIR/s6_tunnel.err" \
        | grep -E '(socat|ncat|nc |netcat).*:[0-9]' | grep -v grep

    echo
    echo "=== Chisel / ligolo / frp tunnel tools ==="
    for tool in chisel ligolo ligolo-ng frp frpc frps; do
        pgrep -a "$tool" 2>>"$ERR_DIR/s6_tunnel.err" && echo "$tool is running" || true
        find /tmp /opt /home /root -name "$tool" -type f 2>>"$ERR_DIR/s6_tunnel.err" \
            && echo "$tool binary found on disk" || true
    done

    echo
    echo "=== Unexpected LISTEN sockets on high ports ==="
    ss -tlnp 2>>"$ERR_DIR/s6_tunnel.err" | awk 'NR>1 && $4 ~ /:[0-9]+$/ {
        split($4, a, ":"); port=a[length(a)]+0;
        if (port > 1024 && port != 3306 && port != 5432 && port != 6379 \
            && port != 8080 && port != 8443 && port != 9200) print $0
    }'

} > "$OUTPUT_DIR/port_forwarding_tunnels.txt"
_section_err "Section 6 tunnelling" "$ERR_DIR/s6_tunnel.err"

# SECTION 7 — PTRACE / PROCESS INJECTION

echo "[*] Checking for process injection indicators..."

{
    echo "=== ptrace_scope ==="
    cat /proc/sys/kernel/yama/ptrace_scope 2>>"$ERR_DIR/s7_inject.err" \
        && echo "(0=permissive, 1=restricted, 2=admin-only, 3=disabled)"

    echo
    echo "=== Processes ptracing others ==="
    ps auxww 2>>"$ERR_DIR/s7_inject.err" \
        | grep -E '\-\-pid|gdb|strace|ltrace|ptrace' | grep -v grep

    echo
    echo "=== /proc/*/status TracerPid (non-zero = being traced) ==="
    grep -l "TracerPid:[^0]" /proc/*/status 2>>"$ERR_DIR/s7_inject.err" | while read -r s; do
        pid=$(echo "$s" | grep -oE '[0-9]+')
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        tracer=$(grep "TracerPid" "$s" 2>/dev/null)
        echo "PID $pid ($exe): $tracer"
    done || echo "(none)"

    echo
    echo "=== LD_PRELOAD in process environments ==="
    grep -rl "LD_PRELOAD" /proc/*/environ 2>>"$ERR_DIR/s7_inject.err" | while read -r env_f; do
        pid=$(echo "$env_f" | grep -oE '[0-9]+' | head -1)
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        val=$(tr '\0' '\n' < "$env_f" 2>/dev/null | grep "LD_PRELOAD")
        echo "PID $pid ($exe): $val"
    done || echo "(none)"

} > "$OUTPUT_DIR/process_injection_indicators.txt"
_section_err "Section 7 process injection" "$ERR_DIR/s7_inject.err"

# SECTION 8 — NETWORK RECON SIGNS

echo "[*] Checking for internal network reconnaissance signs..."

{
    echo "=== ARP table ==="
    arp_count=$(ip neigh show 2>>"$ERR_DIR/s8_recon.err" | wc -l)
    echo "Total ARP entries: $arp_count"
    [ "$arp_count" -gt 100 ] && echo "WARNING: High ARP entry count — possible ARP scan"
    ip neigh show 2>>"$ERR_DIR/s8_recon.err" | head -30

    echo
    echo "=== Recent nmap / masscan processes ==="
    ps auxww 2>>"$ERR_DIR/s8_recon.err" \
        | grep -E 'nmap|masscan|zmap|rustscan|naabu' | grep -v grep

    echo
    echo "=== nmap output files (recent) ==="
    find /home /root /tmp /opt \( -name "*.xml" -o -name "nmap_*" -o -name "masscan*" \) \
        -mtime -7 -type f 2>>"$ERR_DIR/s8_recon.err" | head -20

    echo
    echo "=== TCP connection bursts to sequential IPs ==="
    ss -tnp state established 2>>"$ERR_DIR/s8_recon.err" \
        | awk 'NR>1{print $5}' \
        | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' \
        | sort | uniq -c | sort -rn | head -10

} > "$OUTPUT_DIR/network_recon_indicators.txt"
_section_err "Section 8 network recon" "$ERR_DIR/s8_recon.err"

# SECTION 9 — WTMP / UTMP / BTMP ANALYSIS

echo "[*] Analysing login record databases..."

{
    echo "=== last (successful logins) ==="
    last -n 100 -i 2>>"$ERR_DIR/s9_logins.err" || last -n 100 2>>"$ERR_DIR/s9_logins.err" || true

    echo
    echo "=== lastb (failed logins — requires root) ==="
    lastb -n 50 2>>"$ERR_DIR/s9_logins.err" || echo "(requires root access)"

    echo
    echo "=== Currently logged-in users ==="
    who -a 2>>"$ERR_DIR/s9_logins.err" || w 2>>"$ERR_DIR/s9_logins.err" || true

    echo
    echo "=== lastlog (last login per account) ==="
    lastlog 2>>"$ERR_DIR/s9_logins.err" | grep -v "Never logged in" | head -30 || true

} > "$OUTPUT_DIR/login_records.txt"
_section_err "Section 9 login records" "$ERR_DIR/s9_logins.err"

# SECTION 10 — SUMMARY

echo "[*] Generating lateral movement summary report..."

{
    echo "========================================================"
    echo "  Lateral Movement Detection — Summary Report"
    echo "  Generated: $(date)"
    echo "  Host:      $(hostname)"
    echo "========================================================"

    echo
    echo "--- High-Priority Findings ---"

    root_eq=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
    [ -n "$root_eq" ] && echo "[!] CRITICAL: Extra UID 0 accounts: $root_eq"

    nopasswd=$(grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -3)
    [ -n "$nopasswd" ] && echo "[!] HIGH: NOPASSWD sudo entries found"

    [ -s "$OUTPUT_DIR/ssh_agent_forwarding.txt" ] && \
        echo "[!] MEDIUM: SSH agent forwarding detected in running processes"

    grep -qE 'DNAT|ssh.*-[LRD]' "$OUTPUT_DIR/port_forwarding_tunnels.txt" 2>/dev/null \
        && echo "[!] MEDIUM: Port forwarding or tunnelling detected"

    grep -q "LD_PRELOAD" "$OUTPUT_DIR/process_injection_indicators.txt" 2>/dev/null \
        && echo "[!] HIGH: LD_PRELOAD library injection detected"

    [ -s "$OUTPUT_DIR/recently_modified_authorized_keys.txt" ] && \
        echo "[!] HIGH: authorized_keys files modified in last 7 days"

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

    echo
    echo "--- Script Errors ---"
    if [ -s "$ERRORS_FILE" ]; then
        cat "$ERRORS_FILE"
    else
        echo "[OK] No section errors recorded."
    fi

} > "$OUTPUT_DIR/lateral_movement_summary.txt"

cat "$OUTPUT_DIR/lateral_movement_summary.txt"

tar -czf lateral_movement_archive.tar.gz "$OUTPUT_DIR" 2>/dev/null || true
echo
echo "[+] Detection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: lateral_movement_archive.tar.gz"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors were recorded — see $OUTPUT_DIR/errors_summary.txt and $ERR_DIR/"