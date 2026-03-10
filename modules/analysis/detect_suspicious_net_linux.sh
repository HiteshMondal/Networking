#!/usr/bin/env bash
# /modules/analysis/detect_suspicious_net_linux.sh
# Suspicious network activity detection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"
log_init "detect_suspicious_net"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/suspicious_net"
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

# SECTION 1 — PROCESS & NETWORK OVERVIEW

log_section "Process and Network Overview"
echo "[*] Collecting process and network overview..."

ps aux --sort=-%mem > "$OUTPUT_DIR/ps_aux.txt" 2>"$ERR_DIR/s1_ps.err" \
    || _note_err "ps aux" $?
_section_err "Section 1 ps" "$ERR_DIR/s1_ps.err"

{
    ss -tunap 2>>"$ERR_DIR/s1_ss.err" || netstat -tulpen 2>>"$ERR_DIR/s1_ss.err"
} > "$OUTPUT_DIR/ss_tunap_raw.txt"
_section_err "Section 1 ss" "$ERR_DIR/s1_ss.err"

ss -tunapH 2>"$ERR_DIR/s1_conns.err" \
    | awk '{print $1" "$5" "$6" "$7}' \
    > "$OUTPUT_DIR/ss_connections.txt" || _note_err "ss connections" $?
_section_err "Section 1 connections" "$ERR_DIR/s1_conns.err"

# Extract remote addresses; strip port suffix after the last colon to handle
# both IPv4 (1.2.3.4:port) and IPv6 ([::1]:port) forms correctly.
ss -tunapH 2>"$ERR_DIR/s1_ips.err" \
    | awk '{print $5}' \
    | sed -E 's/(\]?):[0-9]+$/\1/' \
    | sed -E 's/^\[([^]]+)\]$/\1/' \
    | sed '/^$/d' \
    | sort -u \
    > "$OUTPUT_DIR/remote_ips.txt" || _note_err "remote ips" $?
_section_err "Section 1 remote IPs" "$ERR_DIR/s1_ips.err"

log_metric "remote_ip_count" "$(wc -l < "$OUTPUT_DIR/remote_ips.txt" 2>/dev/null || echo 0)" "count"

# SECTION 2 — PUBLIC IP ENRICHMENT

log_section "Public IP Enrichment"
echo "[*] Enriching public IPs..."

if [ -s "$OUTPUT_DIR/remote_ips.txt" ]; then
    grep -vE '^(127\.|::1$|localhost|fe80:|fc00:|fd00:|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
        "$OUTPUT_DIR/remote_ips.txt" \
        | sort -u \
        > "$OUTPUT_DIR/remote_ips_public.txt" 2>"$ERR_DIR/s2_filter.err" \
        || cp "$OUTPUT_DIR/remote_ips.txt" "$OUTPUT_DIR/remote_ips_public.txt"
    _section_err "Section 2 IP filter" "$ERR_DIR/s2_filter.err"

    public_count=$(wc -l < "$OUTPUT_DIR/remote_ips_public.txt" 2>/dev/null || echo 0)
    log_metric "public_ip_count" "$public_count" "count"

    if [ -s "$OUTPUT_DIR/remote_ips_public.txt" ]; then
        # Pass the output directory as an env var to avoid unsafe $(...) interpolation
        # inside the sh -c body.  Each IP is passed via stdin and referenced as $ip
        # — no unquoted variable expansion from the outer shell.
        OUT_DIR="$OUTPUT_DIR" xargs -P5 -I{} sh -c '
            ip="$1"
            safe_ip=$(printf "%s" "$ip" | tr ":/" "__")
            outfile="${OUT_DIR}/whois_${safe_ip}.txt"
            printf "=== %s ===\n" "$ip" > "$outfile"
            timeout 10 whois "$ip" >> "$outfile" 2>/dev/null || true
            timeout 5  nslookup "$ip" >> "$outfile" 2>/dev/null || true
            curl -m 8 -sS "https://ipinfo.io/${ip}/json" >> "$outfile" 2>/dev/null || true
        ' -- {} < "$OUTPUT_DIR/remote_ips_public.txt" 2>"$ERR_DIR/s2_enrich.err" || true
        _section_err "Section 2 enrichment" "$ERR_DIR/s2_enrich.err"
    fi
fi

# SECTION 3 — LOW-LEVEL NETWORK STATE

log_section "Low-Level Network State"
echo "[*] Collecting low-level network state..."

lsof -i -P -n    > "$OUTPUT_DIR/lsof_i.txt"       2>"$ERR_DIR/s3_lsof.err"  || _note_err "lsof" $?
netstat -s        > "$OUTPUT_DIR/netstat_s.txt"    2>"$ERR_DIR/s3_ns.err"    || _note_err "netstat -s" $?
cat /proc/net/tcp > "$OUTPUT_DIR/proc_net_tcp.txt" 2>"$ERR_DIR/s3_tcp.err"   || _note_err "/proc/net/tcp" $?
cat /proc/net/udp > "$OUTPUT_DIR/proc_net_udp.txt" 2>"$ERR_DIR/s3_udp.err"   || _note_err "/proc/net/udp" $?

_section_err "Section 3 lsof"      "$ERR_DIR/s3_lsof.err"
_section_err "Section 3 netstat"   "$ERR_DIR/s3_ns.err"
_section_err "Section 3 proc/tcp"  "$ERR_DIR/s3_tcp.err"
_section_err "Section 3 proc/udp"  "$ERR_DIR/s3_udp.err"

if command -v ss >/dev/null 2>&1; then
    ss -o state established '( sport != :22 )' \
        > "$OUTPUT_DIR/established_not_ssh.txt" 2>"$ERR_DIR/s3_estab.err" \
        || _note_err "established not ssh" $?
    _section_err "Section 3 established" "$ERR_DIR/s3_estab.err"
fi

# SECTION 4 — INTERESTING CONNECTIONS & PID EXTRACTION

log_section "Interesting Connections and PID Extraction"
echo "[*] Extracting interesting connections..."

awk '/LISTEN|ESTAB|ESTABLISHED/' "$OUTPUT_DIR/ss_tunap_raw.txt" \
    > "$OUTPUT_DIR/interesting_connections.txt" 2>"$ERR_DIR/s4_int.err" || true
_section_err "Section 4 interesting" "$ERR_DIR/s4_int.err"

awk '{if($7 ~ /^[0-9]+,/) print $0}' "$OUTPUT_DIR/ss_tunap_raw.txt" \
    > "$OUTPUT_DIR/connections_with_pid.txt" 2>"$ERR_DIR/s4_pid.err" || true
_section_err "Section 4 with-pid" "$ERR_DIR/s4_pid.err"

# Extract the numeric PID that precedes the comma-separated program name.
# The ss users: field has the form:  users:(("prog",pid=NNN,fd=M))
# This pattern is more reliable than stripping all alpha chars from $7.
awk '{print $7}' "$OUTPUT_DIR/connections_with_pid.txt" \
    | grep -oE 'pid=[0-9]+' \
    | grep -oE '[0-9]+' \
    | sort -u \
    > "$OUTPUT_DIR/pids_with_network.txt" 2>"$ERR_DIR/s4_pids.err" || true
_section_err "Section 4 pids" "$ERR_DIR/s4_pids.err"

pid_count=$(wc -l < "$OUTPUT_DIR/pids_with_network.txt" 2>/dev/null || echo 0)
log_metric "pids_with_network" "$pid_count" "count"

# SECTION 5 — PER-PID FORENSICS

log_section "Per-PID Forensics"
echo "[*] Running per-PID forensics..."

# Locations that are commonly associated with malware / living-off-the-land drops.
# A process executable in one of these paths warrants a HIGH finding.
_suspicious_path_re='^(/tmp|/dev/shm|/var/tmp|/run/|/proc/self)'

if [ -s "$OUTPUT_DIR/pids_with_network.txt" ]; then
    while IFS= read -r pid; do
        [ -d "/proc/$pid" ] || continue

        readlink -f "/proc/$pid/exe" \
            > "$OUTPUT_DIR/pid_${pid}_exe.txt"  2>"$ERR_DIR/s5_pid${pid}.err" || true
        ls -l "/proc/$pid/fd" \
            > "$OUTPUT_DIR/pid_${pid}_fds.txt"  2>>"$ERR_DIR/s5_pid${pid}.err" || true
        ps -p "$pid" -o pid,ppid,uid,gid,etimes,cmd \
            > "$OUTPUT_DIR/pid_${pid}_ps.txt"   2>>"$ERR_DIR/s5_pid${pid}.err" || true

        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        if [ -n "$exe" ] && [ -f "$exe" ]; then
            {
                md5sum    "$exe" 2>/dev/null
                sha256sum "$exe" 2>/dev/null
            } > "$OUTPUT_DIR/pid_${pid}_exe_hash.txt" || true

            # Flag processes running from suspicious filesystem locations
            if echo "$exe" | grep -qE "$_suspicious_path_re"; then
                log_finding "high" \
                    "Network-active process running from suspicious path" \
                    "pid=$pid exe=$exe"
            fi

            # Flag deleted executables still running (fileless / replaced binary)
            if [ ! -e "$exe" ] || grep -q '(deleted)' "/proc/$pid/exe" 2>/dev/null; then
                log_finding "high" \
                    "Network-active process executable is deleted/replaced" \
                    "pid=$pid exe=$exe"
            fi
        fi

        _section_err "Section 5 PID $pid" "$ERR_DIR/s5_pid${pid}.err"
    done < "$OUTPUT_DIR/pids_with_network.txt"
fi

# SECTION 6 — PERSISTENCE CHECKS

log_section "Persistence Checks"
echo "[*] Checking persistence mechanisms..."

{
    echo "=== User crontab ==="
    crontab -l 2>>"$ERR_DIR/s6_cron.err" || echo "(no crontab or not available)"

    echo
    echo "=== Root crontab ==="
    crontab -u root -l 2>>"$ERR_DIR/s6_cron.err" || echo "(no root crontab or insufficient privilege)"

    echo
    echo "=== /etc/cron* directories ==="
    ls -la /etc/cron* 2>>"$ERR_DIR/s6_cron.err" || echo "(no cron dirs)"

} > "$OUTPUT_DIR/crontab_persistence.txt"
_section_err "Section 6 cron" "$ERR_DIR/s6_cron.err"

systemctl list-timers --all \
    > "$OUTPUT_DIR/systemd_timers.txt"        2>"$ERR_DIR/s6_timers.err" \
    || _note_err "systemd timers" $?
systemctl list-unit-files --state=enabled \
    > "$OUTPUT_DIR/systemd_enabled_units.txt" 2>"$ERR_DIR/s6_units.err" \
    || _note_err "systemd units" $?
_section_err "Section 6 timers" "$ERR_DIR/s6_timers.err"
_section_err "Section 6 units"  "$ERR_DIR/s6_units.err"

grep -R "curl -s" /etc 2>"$ERR_DIR/s6_curl.err" \
    > "$OUTPUT_DIR/curl_exec_in_etc.txt" || true
_section_err "Section 6 curl in etc" "$ERR_DIR/s6_curl.err"

find /etc/systemd/system /lib/systemd/system \
    -type f -name '*.service' \
    -exec grep -I -nH 'ExecStart' {} \; 2>"$ERR_DIR/s6_execstart.err" \
    | head -200 \
    > "$OUTPUT_DIR/systemd_execstarts.txt" || true
_section_err "Section 6 ExecStart" "$ERR_DIR/s6_execstart.err"

# Flag ExecStart lines pointing to temp/shm paths
if grep -qE 'ExecStart=(/tmp|/dev/shm|/var/tmp)' \
        "$OUTPUT_DIR/systemd_execstarts.txt" 2>/dev/null; then
    log_finding "high" \
        "Systemd unit ExecStart references temporary/volatile path" \
        "review output/suspicious_net/systemd_execstarts.txt"
fi

# SECTION 7 — FILESYSTEM & PRIVILEGE ABUSE

log_section "Filesystem and Privilege Abuse Indicators"
echo "[*] Checking filesystem and privilege abuse indicators..."

timeout 300 find /home /tmp /var/tmp /dev/shm \
    -type f -mtime -7 -ls 2>"$ERR_DIR/s7_recent.err" \
    > "$OUTPUT_DIR/recent_tmp_files.txt" || _note_err "recent tmp files" $?
_section_err "Section 7 recent files" "$ERR_DIR/s7_recent.err"

recent_count=$(wc -l < "$OUTPUT_DIR/recent_tmp_files.txt" 2>/dev/null || echo 0)
log_metric "recent_tmp_files" "$recent_count" "count"
if [ "$recent_count" -gt 50 ]; then
    log_finding "medium" "Elevated count of recently modified files in temp directories" \
        "count=$recent_count — review recent_tmp_files.txt"
fi

timeout 600 find / \
    -path /proc -prune -o -path /sys  -prune -o \
    -path /dev  -prune -o -path /run  -prune -o \
    -type f \( -perm -4000 -o -perm -2000 \) -ls 2>"$ERR_DIR/s7_suid.err" \
    > "$OUTPUT_DIR/suid_sgid_files.txt" || true
_section_err "Section 7 SUID/SGID" "$ERR_DIR/s7_suid.err"

suid_count=$(wc -l < "$OUTPUT_DIR/suid_sgid_files.txt" 2>/dev/null || echo 0)
log_metric "suid_sgid_files" "$suid_count" "count"

# SECTION 8 — PROCESS AGE & ROOTKIT CHECKS

log_section "Process Age and Rootkit Checks"
echo "[*] Checking process age and rootkit indicators..."

ps -eo pid,user,group,etime,cmd --sort=-etime 2>"$ERR_DIR/s8_procs.err" \
    | head -200 \
    > "$OUTPUT_DIR/top_old_procs.txt" || _note_err "ps etime" $?
_section_err "Section 8 process age" "$ERR_DIR/s8_procs.err"

if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit > "$OUTPUT_DIR/chkrootkit.txt" 2>"$ERR_DIR/s8_chkrootkit.err" || true
    _section_err "Section 8 chkrootkit" "$ERR_DIR/s8_chkrootkit.err"
    if grep -qiE '^INFECTED' "$OUTPUT_DIR/chkrootkit.txt" 2>/dev/null; then
        infected=$(grep -iE '^INFECTED' "$OUTPUT_DIR/chkrootkit.txt" | head -5 | paste -sd';')
        log_finding "critical" "chkrootkit reports INFECTED status" "$infected"
    fi
else
    echo "(chkrootkit not installed)" > "$OUTPUT_DIR/chkrootkit.txt"
fi

if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --checkall --sk --nolog > "$OUTPUT_DIR/rkhunter.txt" 2>"$ERR_DIR/s8_rkhunter.err" || true
    _section_err "Section 8 rkhunter" "$ERR_DIR/s8_rkhunter.err"
    if grep -qiE 'Warning|Infected' "$OUTPUT_DIR/rkhunter.txt" 2>/dev/null; then
        log_finding "high" "rkhunter reported warnings or infections" \
            "review output/suspicious_net/rkhunter.txt"
    fi
else
    echo "(rkhunter not installed)" > "$OUTPUT_DIR/rkhunter.txt"
fi

# SECTION 9 — NETWORK STATISTICS & MISC

log_section "Network Statistics"
echo "[*] Collecting network statistics..."

ss -tunap 2>"$ERR_DIR/s9_counts.err" \
    | awk '{print $5}' \
    | sed -E 's/(\]?):[0-9]+$/\1/' \
    | sort | uniq -c | sort -nr \
    > "$OUTPUT_DIR/remote_ip_counts.txt" || _note_err "remote ip counts" $?
_section_err "Section 9 IP counts" "$ERR_DIR/s9_counts.err"

timeout 300 find /etc /home /root \
    -iname "*ssh*" -type f -mtime -7 -ls 2>"$ERR_DIR/s9_ssh.err" \
    > "$OUTPUT_DIR/recent_ssh_related_files.txt" || true
_section_err "Section 9 SSH files" "$ERR_DIR/s9_ssh.err"

grep -R "wget " /etc /home /root 2>"$ERR_DIR/s9_wget.err" \
    | head -200 \
    > "$OUTPUT_DIR/wget_exec_in_configs.txt" || true
_section_err "Section 9 wget" "$ERR_DIR/s9_wget.err"

ps -eo pid,cmd > "$OUTPUT_DIR/all_pids_cmds.txt" 2>"$ERR_DIR/s9_allpids.err" \
    || _note_err "all pids" $?
_section_err "Section 9 all pids" "$ERR_DIR/s9_allpids.err"

# SECTION 10 — SUMMARY

log_section "Summary"
echo "[*] Generating summary..."

total_remote=$(wc -l < "$OUTPUT_DIR/remote_ips.txt"        2>/dev/null || echo 0)
total_public=$(wc -l < "$OUTPUT_DIR/remote_ips_public.txt" 2>/dev/null || echo 0)
total_pids=$(wc -l   < "$OUTPUT_DIR/pids_with_network.txt" 2>/dev/null || echo 0)

log_metric "total_remote_ips"  "$total_remote" "count"
log_metric "total_public_ips"  "$total_public" "count"
log_metric "total_network_pids" "$total_pids"  "count"

{
    echo "========================================================"
    echo "  Suspicious Network Detection — Summary"
    echo "  Generated: $(date)"
    echo "  Host:      $(hostname)"
    echo "========================================================"
    echo

    echo "--- Counts ---"
    echo "  Remote IPs (total):  $total_remote"
    echo "  Remote IPs (public): $total_public"
    echo "  PIDs w/ network:     $total_pids"

    echo
    echo "--- Interesting Connections ---"
    head -20 "$OUTPUT_DIR/interesting_connections.txt" 2>/dev/null || echo "(none)"

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

} > "$OUTPUT_DIR/suspicious_net_summary.txt"

cat "$OUTPUT_DIR/suspicious_net_summary.txt"

# ARCHIVE (contents only, no embedded absolute path)
ARCHIVE="$OUTPUT_DIR/suspicious_net_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] Scan complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"