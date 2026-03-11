#!/usr/bin/env bash
# /modules/forensics/forensic_collect.sh
# Work on all Linux computers independent of distro
# Linux forensic artifact collection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"
log_init "forensic_collect"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/forensic_collect"
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

# SYSTEM & HOST INFORMATION

log_section "System and Host Information"
echo "[*] Collecting system information..."

uname -a                   > "$OUTPUT_DIR/uname.txt"       2>"$ERR_DIR/uname.err"    || _note_err "uname" $?
hostnamectl                > "$OUTPUT_DIR/hostnamectl.txt"  2>"$ERR_DIR/host.err" \
    || hostname            > "$OUTPUT_DIR/hostname.txt"     2>>"$ERR_DIR/host.err"   || _note_err "hostname" $?
whoami                     > "$OUTPUT_DIR/whoami.txt"       2>"$ERR_DIR/whoami.err"   || _note_err "whoami" $?
id                         > "$OUTPUT_DIR/id.txt"           2>"$ERR_DIR/id.err"       || _note_err "id" $?
uptime                     > "$OUTPUT_DIR/uptime.txt"       2>"$ERR_DIR/uptime.err"   || _note_err "uptime" $?

for f in "$ERR_DIR/uname.err" "$ERR_DIR/host.err" "$ERR_DIR/whoami.err" \
          "$ERR_DIR/id.err"   "$ERR_DIR/uptime.err"; do
    [ -s "$f" ] \
        && { echo "[WARN] $(basename "$f" .err): see errors/$(basename "$f")" >> "$ERRORS_FILE"
             log_warning "$(basename "$f" .err) had errors"; } \
        || rm -f "$f"
done

# KERNEL & BOOT MESSAGES

log_section "Kernel and Boot Messages"
echo "[*] Collecting kernel messages..."

dmesg --ctime > "$OUTPUT_DIR/dmesg.txt" 2>"$ERR_DIR/dmesg.err" \
    || dmesg  > "$OUTPUT_DIR/dmesg.txt" 2>>"$ERR_DIR/dmesg.err" \
    || _note_err "dmesg" $?
_section_err "dmesg" "$ERR_DIR/dmesg.err"

# SYSTEMD JOURNAL LOGS

log_section "Systemd Journal Collection"
echo "[*] Collecting journal logs..."

journalctl --no-pager --output=short-precise \
    > "$OUTPUT_DIR/journalctl_all.txt"    2>"$ERR_DIR/jctl_all.err"    || _note_err "journalctl all" $?
journalctl -u ssh --no-pager \
    > "$OUTPUT_DIR/journalctl_ssh.txt"    2>"$ERR_DIR/jctl_ssh.err"    || _note_err "journalctl ssh" $?
journalctl -k --no-pager \
    > "$OUTPUT_DIR/journalctl_kernel.txt" 2>"$ERR_DIR/jctl_kernel.err" || _note_err "journalctl kernel" $?

for f in "$ERR_DIR/jctl_all.err" "$ERR_DIR/jctl_ssh.err" "$ERR_DIR/jctl_kernel.err"; do
    [ -s "$f" ] \
        && { echo "[WARN] $(basename "$f" .err): see errors/$(basename "$f")" >> "$ERRORS_FILE"
             log_warning "$(basename "$f" .err) had errors"; } \
        || rm -f "$f"
done

# TRADITIONAL LOG FILES

log_section "Traditional Log File Collection"
echo "[*] Copying log files..."

cp /var/log/auth.log "$OUTPUT_DIR/"  2>/dev/null \
    || cp /var/log/secure "$OUTPUT_DIR/" 2>/dev/null || true
cp /var/log/syslog   "$OUTPUT_DIR/"  2>/dev/null || true
cp /var/log/messages "$OUTPUT_DIR/"  2>/dev/null || true

ls -l /var/log > "$OUTPUT_DIR/var_log_listing.txt" 2>"$ERR_DIR/varlog.err" \
    || _note_err "ls /var/log" $?
_section_err "var_log listing" "$ERR_DIR/varlog.err"

# Detect and flag any zero-byte core auth/syslog files (possible wiping)
for logfile in /var/log/auth.log /var/log/secure /var/log/syslog; do
    if [ -f "$logfile" ] && [ ! -s "$logfile" ]; then
        log_finding "high" "Core log file is zero bytes — possible log wiping" \
            "file=$logfile"
    fi
done

# AUTHENTICATION & LOGIN RECORDS

log_section "Authentication and Login Records"
echo "[*] Collecting authentication records..."

lastlog > "$OUTPUT_DIR/lastlog.txt"    2>"$ERR_DIR/lastlog.err"    || _note_err "lastlog" $?
faillog -v > "$OUTPUT_DIR/faillog.txt" 2>"$ERR_DIR/faillog.err"    || _note_err "faillog" $?

_section_err "lastlog" "$ERR_DIR/lastlog.err"
_section_err "faillog" "$ERR_DIR/faillog.err"

# LINUX AUDIT FRAMEWORK

log_section "Audit Framework"
echo "[*] Collecting audit framework data..."

ausearch --start today > "$OUTPUT_DIR/ausearch_today.log"     2>"$ERR_DIR/ausearch.err" \
    || ausearch        > "$OUTPUT_DIR/ausearch_all.log"        2>>"$ERR_DIR/ausearch.err" \
    || _note_err "ausearch" $?
auditctl -l            > "$OUTPUT_DIR/audit_rules.txt"         2>"$ERR_DIR/auditctl.err" \
    || _note_err "auditctl" $?
ausearch -m USER_LOGIN -ts today \
                       > "$OUTPUT_DIR/ausearch_user_login.txt" 2>"$ERR_DIR/ausearch_login.err" \
    || _note_err "ausearch user_login" $?
cp /var/log/audit/audit.log "$OUTPUT_DIR/" 2>/dev/null || true

for f in "$ERR_DIR/ausearch.err" "$ERR_DIR/auditctl.err" "$ERR_DIR/ausearch_login.err"; do
    [ -s "$f" ] \
        && { echo "[WARN] $(basename "$f" .err): see errors/$(basename "$f")" >> "$ERRORS_FILE"
             log_warning "$(basename "$f" .err) had errors"; } \
        || rm -f "$f"
done

# PROCESS INFORMATION

log_section "Process Information"
echo "[*] Collecting process information..."

ps auxww > "$OUTPUT_DIR/ps_aux.txt" 2>"$ERR_DIR/ps_aux.err" \
    || _note_err "ps auxww" $?
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -200 \
    > "$OUTPUT_DIR/top_procs.txt" 2>"$ERR_DIR/top_procs.err" \
    || _note_err "ps top procs" $?
lsmod > "$OUTPUT_DIR/lsmod.txt" 2>"$ERR_DIR/lsmod.err" \
    || _note_err "lsmod" $?

_section_err "ps_aux"     "$ERR_DIR/ps_aux.err"
_section_err "top_procs"  "$ERR_DIR/top_procs.err"
_section_err "lsmod"      "$ERR_DIR/lsmod.err"

proc_count=$(ps auxww 2>/dev/null | wc -l 2>/dev/null)
proc_count=${proc_count:-0}
log_metric "running_processes" "$proc_count" "count"

# NETWORK CONNECTIONS & INTERFACES

log_section "Network Connections and Interfaces"
echo "[*] Collecting network state..."

{
    ss -tunap 2>>"$ERR_DIR/ss.err" || netstat -tulpen 2>>"$ERR_DIR/ss.err"
} > "$OUTPUT_DIR/ss_tunap.txt"
_section_err "ss_tunap" "$ERR_DIR/ss.err"

lsof -i > "$OUTPUT_DIR/lsof_network.txt" 2>"$ERR_DIR/lsof.err" \
    || _note_err "lsof -i" $?
_section_err "lsof_network" "$ERR_DIR/lsof.err"

{
    ip -s link 2>/dev/null || ip link 2>/dev/null
} > "$OUTPUT_DIR/ip_stats.txt"

ip -4 addr show  > "$OUTPUT_DIR/ip_addr.txt"  2>/dev/null || true
ip route show    > "$OUTPUT_DIR/ip_route.txt" 2>/dev/null || true

# Count established connections and emit as a metric
if command -v ss >/dev/null; then
    estab_count=$(ss -tunap 2>/dev/null | grep -c ESTAB)
else
    estab_count=$(netstat -tunap 2>/dev/null | grep -c ESTABLISHED)
fi
log_metric "established_connections" "$estab_count" "count"

# FIREWALL & CONNECTION TRACKING

log_section "Firewall Rules and Connection Tracking"
echo "[*] Collecting firewall rules..."

{
    iptables-save 2>/dev/null || nft list ruleset 2>/dev/null || echo "(no iptables/nft)"
} > "$OUTPUT_DIR/firewall_rules.txt"

conntrack -L > "$OUTPUT_DIR/conntrack.txt" 2>/dev/null || true

# PACKET CAPTURE (limited)

log_section "Packet Capture"
echo "[*] Attempting packet capture..."

pcap_captured=false
if timeout 10 tcpdump -nn -s 0 -c 1000 -w "$OUTPUT_DIR/tcpdump_capture.pcap" 2>/dev/null; then
    pcap_captured=true
    log_metric "pcap_tool" "tcpdump" "label"
elif tshark -i any -c 1000 -w "$OUTPUT_DIR/tshark_capture.pcap" 2>/dev/null; then
    pcap_captured=true
    log_metric "pcap_tool" "tshark" "label"
fi

if $pcap_captured; then
    log_info "Packet capture completed successfully"
else
    log_warning "No packet capture tool available (tcpdump/tshark not found or failed)"
fi

# NETWORK STATISTICS
ss -s > "$OUTPUT_DIR/ss_summary.txt" 2>/dev/null \
    || netstat -s > "$OUTPUT_DIR/netstat_summary.txt" 2>/dev/null || true
cat /proc/net/tcp > "$OUTPUT_DIR/proc_net_tcp.txt"    2>/dev/null || true
cat /proc/net/udp > "$OUTPUT_DIR/proc_net_udp.txt"    2>/dev/null || true
cat /proc/net/arp > "$OUTPUT_DIR/proc_net_arp.txt"    2>/dev/null || true
netstat -s        > "$OUTPUT_DIR/netstat_s.txt"       2>/dev/null || true

# FILESYSTEMS & MOUNTS

log_section "Filesystems and Mounts"
echo "[*] Collecting filesystem info..."

mount  > "$OUTPUT_DIR/mounts.txt" 2>/dev/null || true
df -h  > "$OUTPUT_DIR/df.txt"     2>/dev/null || true

find /var/log -type f -maxdepth 2 \
    -printf "%p %s %TY-%Tm-%Td %TH:%TM:%TS\n" \
    > "$OUTPUT_DIR/varlog_files_listing.txt" 2>/dev/null || true

# CONFIGURATION FILES

log_section "Configuration Files"
echo "[*] Collecting configuration files..."

cp /etc/ssh/sshd_config "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/hosts           "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/passwd          "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/group           "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/issue           "$OUTPUT_DIR/" 2>/dev/null || true

# PACKAGE MANAGEMENT HISTORY

cp /var/log/apt/history.log "$OUTPUT_DIR/" 2>/dev/null \
    || cp /var/log/dpkg.log "$OUTPUT_DIR/" 2>/dev/null \
    || cp /var/log/yum.log  "$OUTPUT_DIR/" 2>/dev/null || true

# LISTENING PORTS

log_section "Listening Ports"
echo "[*] Collecting listening ports..."

ss -ltnp > "$OUTPUT_DIR/listening_tcp.txt" 2>/dev/null \
    || netstat -ltnp > "$OUTPUT_DIR/listening_tcp.txt" 2>/dev/null || true

ss -lunp > "$OUTPUT_DIR/listening_udp.txt" 2>/dev/null \
    || netstat -lunp > "$OUTPUT_DIR/listening_udp.txt" 2>/dev/null || true

if command -v ss >/dev/null; then
    tcp_listen_count=$(ss -ltnp 2>/dev/null | tail -n +2 | wc -l)
else
    tcp_listen_count=$(netstat -ltnp 2>/dev/null | tail -n +3 | wc -l)
fi
if command -v ss >/dev/null; then
    udp_listen_count=$(ss -lunp 2>/dev/null | tail -n +2 | wc -l)
else
    udp_listen_count=$(netstat -lunp 2>/dev/null | tail -n +3 | wc -l)
fi
log_metric "tcp_listening_ports" "$tcp_listen_count" "count"
log_metric "udp_listening_ports" "$udp_listen_count" "count"

# SCHEDULED TASKS

log_section "Scheduled Tasks"
echo "[*] Collecting scheduled tasks..."

crontab -l > "$OUTPUT_DIR/crontab_current.txt" 2>/dev/null || true
ls -la /etc/cron* > "$OUTPUT_DIR/cron_dirs.txt" 2>/dev/null || true

# LOG KEYWORD HUNTING

log_section "Log Keyword Hunting"
echo "[*] Hunting keywords in logs..."

grep -R "ssh" /var/log -nH --binary-files=without-match \
    | head -500 > "$OUTPUT_DIR/ssh_related_logs_snippet.txt" 2>/dev/null || true
grep -R "sudo" /var/log -nH 2>/dev/null | head -500 \
    > "$OUTPUT_DIR/sudo_related_logs_snippet.txt" || true

ssh_hits=$(wc -l  < "$OUTPUT_DIR/ssh_related_logs_snippet.txt"  2>/dev/null || echo 0)
sudo_hits=$(wc -l < "$OUTPUT_DIR/sudo_related_logs_snippet.txt" 2>/dev/null || echo 0)
log_metric "ssh_log_hits"  "$ssh_hits"  "count"
log_metric "sudo_log_hits" "$sudo_hits" "count"

# ARCHIVE & OWNERSHIP

ARCHIVE="$OUTPUT_DIR/forensic_archive.tar.gz"
tar --exclude="forensic_archive.tar.gz" \
    -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

log_metric "output_files_collected" \
    "$(find "$OUTPUT_DIR" -maxdepth 1 -type f | wc -l)" "count"

# Fall back to the current user if SUDO_USER is empty or unset.
REAL_USER="${SUDO_USER:-}"
if [ -z "$REAL_USER" ] || ! id "$REAL_USER" >/dev/null 2>&1; then
    REAL_USER="$(whoami)"
fi
chown -R "$REAL_USER" "$OUTPUT_DIR" 2>/dev/null || true

echo
echo "[+] Forensic collection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"