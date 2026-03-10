#!/usr/bin/env bash
# /modules/analysis/log_analysis.sh
# Log analysis and threat hunting

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"
log_init "log_analysis"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/log_analysis"
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

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a >> "$OUTPUT_DIR/run_timestamp.txt"
whoami   >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — LOG INVENTORY

log_section "Log Inventory"
echo "[*] Inventorying log files..."

{
    echo "=== /var/log directory listing ==="
    find /var/log -type f -ls 2>>"$ERR_DIR/s1_inventory.err" | sort -k11

    echo
    echo "=== Log sizes summary ==="
    du -sh /var/log/* 2>>"$ERR_DIR/s1_inventory.err" | sort -rh | head -30

    echo
    echo "=== Journald disk usage ==="
    journalctl --disk-usage 2>>"$ERR_DIR/s1_inventory.err" \
        || echo "(journald unavailable)"

    echo
    echo "=== Log rotation config ==="
    head -30 /etc/logrotate.conf 2>>"$ERR_DIR/s1_inventory.err" || true
    ls -la /etc/logrotate.d/ 2>>"$ERR_DIR/s1_inventory.err" || true

} > "$OUTPUT_DIR/log_inventory.txt"

[ -s "$ERR_DIR/s1_inventory.err" ] \
    && { echo "[WARN] Section 1 (Log Inventory): see errors/s1_inventory.err" >> "$ERRORS_FILE"
         log_warning "Section 1 (Log Inventory) had errors"; } \
    || rm -f "$ERR_DIR/s1_inventory.err"

# SECTION 2 — LOG TAMPERING DETECTION

log_section "Log Tampering Detection"
echo "[*] Checking for log tampering indicators..."

{
    echo "=== Log file modification times ==="
    ls -la /var/log/auth.log /var/log/syslog /var/log/messages \
           /var/log/secure /var/log/kern.log 2>>"$ERR_DIR/s2_tamper.err" || true

    echo
    echo "=== Gaps in log timestamps (possible truncation/wiping) ==="
    for logfile in /var/log/auth.log /var/log/syslog /var/log/secure; do
        [ -r "$logfile" ] || { echo "(not readable: $logfile)"; continue; }
        echo "--- $logfile ---"
        head -1 "$logfile" 2>>"$ERR_DIR/s2_tamper.err" | awk '{print "First:", $1, $2, $3}'
        tail -1 "$logfile" 2>>"$ERR_DIR/s2_tamper.err" | awk '{print "Last: ", $1, $2, $3}'
        total_lines=$(wc -l < "$logfile" 2>>"$ERR_DIR/s2_tamper.err")
        echo "Total lines: $total_lines"
        echo
    done

    echo
    echo "=== Journald integrity check ==="
    journalctl --verify 2>>"$ERR_DIR/s2_tamper.err" \
        || echo "(journald verification unavailable)"

    echo
    echo "=== Files with ctime newer than mtime ==="
    find /var/log -type f -newer /etc/passwd 2>>"$ERR_DIR/s2_tamper.err" \
    | while IFS= read -r f; do
        mtime=$(stat -c '%Y' "$f" 2>>"$ERR_DIR/s2_tamper.err" || continue)
        ctime=$(stat -c '%Z' "$f" 2>>"$ERR_DIR/s2_tamper.err" || continue)
        [ "$ctime" -gt "$mtime" ] && echo "$f (ctime=$ctime > mtime=$mtime)"
    done

    echo
    echo "=== Cleared utmp/wtmp/btmp ==="
    for f in /var/log/wtmp /var/log/btmp /var/run/utmp; do
        [ -f "$f" ] && echo "$(ls -la "$f") $(du -sh "$f" | cut -f1)"
    done

    echo
    echo "=== Log deletion commands in history ==="
    find /home /root -name ".*history" -type f 2>>"$ERR_DIR/s2_tamper.err" \
    | while IFS= read -r hist; do
        grep -iE '(rm.*\.log|shred.*log|> /var/log|truncate.*log|unlink.*log|echo.*>/var/log)' \
            "$hist" 2>>"$ERR_DIR/s2_tamper.err" \
        | while IFS= read -r line; do
            echo "$hist: $line"
        done
    done

} > "$OUTPUT_DIR/log_tampering_detection.txt"

[ -s "$ERR_DIR/s2_tamper.err" ] \
    && { echo "[WARN] Section 2 (Log Tampering): see errors/s2_tamper.err" >> "$ERRORS_FILE"
         log_warning "Section 2 (Log Tampering) had errors"; } \
    || rm -f "$ERR_DIR/s2_tamper.err"

# Emit a finding if any zero-byte core log files are detected (sign of wiping)
for logfile in /var/log/auth.log /var/log/syslog /var/log/secure; do
    if [ -f "$logfile" ] && [ ! -s "$logfile" ]; then
        log_finding "high" "Core log file is zero bytes — possible wiping" \
            "file=$logfile"
    fi
done

# SECTION 3 — AUTHENTICATION TIMELINE

log_section "Authentication Timeline"
echo "[*] Building authentication timeline..."

# The Python script writes its own output directly to auth_timeline.txt.
# On Python failure we fall back to journalctl — both paths write to the same
# destination, so we open the file once and redirect inside each branch.

python3 - > "$OUTPUT_DIR/auth_timeline.txt" 2>"$ERR_DIR/s3_auth.err" << 'PYEOF'
import os, re, sys

auth_logs = ['/var/log/auth.log', '/var/log/secure']
events = []

patterns = [
    (re.compile(r'(\w+ \d+ \d+:\d+:\d+).*sshd.*Accepted (\w+) for (\S+) from ([\d.]+)'),
     'SSH_SUCCESS'),
    (re.compile(r'(\w+ \d+ \d+:\d+:\d+).*sshd.*Failed (\w+) for (?:invalid user )?(\S+) from ([\d.]+)'),
     'SSH_FAILURE'),
    (re.compile(r'(\w+ \d+ \d+:\d+:\d+).*sudo.*?(\S+)\s*:.*COMMAND=(.+)'),
     'SUDO_EXEC'),
    (re.compile(r'(\w+ \d+ \d+:\d+:\d+).*su.*switched.*to (\S+)'),
     'SU_SWITCH'),
    (re.compile(r'(\w+ \d+ \d+:\d+:\d+).*useradd.*new user.*name=(\S+)'),
     'USER_CREATED'),
    (re.compile(r'(\w+ \d+ \d+:\d+:\d+).*passwd.*password changed for (\S+)'),
     'PASSWD_CHANGED'),
]

for log_path in auth_logs:
    if not os.path.isfile(log_path):
        continue
    try:
        with open(log_path, errors='replace') as f:
            for line in f:
                for pat, event_type in patterns:
                    m = pat.search(line)
                    if m:
                        events.append((m.group(1), event_type, list(m.groups()[1:])))
                        break
    except Exception as e:
        print(f"[ERROR] Could not read {log_path}: {e}", file=sys.stderr)

print(f"{'Timestamp':<18}  {'Event':<16}  Details")
print("-" * 80)
for ts, etype, details in events[-300:]:
    detail_str = ' | '.join(str(d) for d in details)
    flag = ""
    if etype == 'SSH_FAILURE':
        flag = " [ALERT]"
    elif etype == 'USER_CREATED':
        flag = " [MONITOR]"
    elif etype == 'SUDO_EXEC' and ('passwd' in detail_str or 'shadow' in detail_str):
        flag = " [HIGH]"
    print(f"{ts:<18}  {etype:<16}  {detail_str}{flag}")
PYEOF

# If Python wrote nothing meaningful (empty or only the header), fall back to journalctl
if [ ! -s "$OUTPUT_DIR/auth_timeline.txt" ] || \
        ! grep -q "SSH_\|SUDO_\|SU_\|USER_\|PASSWD_" "$OUTPUT_DIR/auth_timeline.txt" 2>/dev/null; then
    journalctl -u ssh -u sshd --no-pager --output=short-precise 2>>"$ERR_DIR/s3_auth.err" \
        | grep -E "Accepted|Failed|sudo|su\[" | tail -300 \
        >> "$OUTPUT_DIR/auth_timeline.txt" \
        || _note_err "auth_timeline journald fallback" $?
fi

[ -s "$ERR_DIR/s3_auth.err" ] \
    && { echo "[WARN] Section 3 (Auth Timeline): see errors/s3_auth.err" >> "$ERRORS_FILE"
         log_warning "Section 3 (Auth Timeline) had errors"; } \
    || rm -f "$ERR_DIR/s3_auth.err"

# Metrics from auth timeline
ssh_fail_count=$(grep -c "\[ALERT\]" "$OUTPUT_DIR/auth_timeline.txt" 2>/dev/null || echo 0)
user_created_count=$(grep -c "\[MONITOR\]" "$OUTPUT_DIR/auth_timeline.txt" 2>/dev/null || echo 0)
log_metric "ssh_failures" "$ssh_fail_count" "count"
log_metric "users_created" "$user_created_count" "count"

if [ "$ssh_fail_count" -gt 20 ]; then
    log_finding "high" "Elevated SSH failure count in auth logs" \
        "count=$ssh_fail_count — possible brute-force or password spray"
fi
if [ "$user_created_count" -gt 0 ]; then
    log_finding "medium" "User account creation events detected" \
        "count=$user_created_count — verify legitimacy"
fi

# SECTION 4 — PRIVILEGE ESCALATION EVENTS

log_section "Privilege Escalation Events"
echo "[*] Detecting privilege escalation events..."

{
    echo "=== sudo command history ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep "sudo" "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -100
    done
    journalctl _COMM=sudo --no-pager -n 100 2>>"$ERR_DIR/s4_privesc.err" \
        || echo "(journald sudo query unavailable)"

    echo
    echo "=== su (switch user) events ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep '\bsu\b' "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -50
    done

    echo
    echo "=== setuid/setgid execution events (auditd) ==="
    ausearch -m EXECVE -ts today 2>>"$ERR_DIR/s4_privesc.err" | head -50 \
        || echo "(auditd not available)"

    echo
    echo "=== Polkit / pkexec events ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] \
            && grep -iE "polkit|pkexec" "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -20
    done
    journalctl _COMM=pkexec --no-pager -n 20 2>>"$ERR_DIR/s4_privesc.err" || true

    echo
    echo "=== doas events ==="
    for logfile in /var/log/auth.log /var/log/messages; do
        [ -r "$logfile" ] && grep '\bdoas\b' "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -20
    done

    echo
    echo "=== Capability-related anomalies ==="
    find /proc -maxdepth 2 -name "status" 2>>"$ERR_DIR/s4_privesc.err" \
    | while IFS= read -r s; do
        caps_eff=$(grep "^CapEff:" "$s" 2>/dev/null | awk '{print $2}')
        if [ -n "$caps_eff" ] && [ "$caps_eff" != "0000000000000000" ]; then
            pid=$(echo "$s" | grep -oE '[0-9]+')
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            echo "PID $pid ($exe): CapEff=$caps_eff"
        fi
    done | head -20

} > "$OUTPUT_DIR/privilege_escalation_events.txt"

[ -s "$ERR_DIR/s4_privesc.err" ] \
    && { echo "[WARN] Section 4 (Privilege Escalation): see errors/s4_privesc.err" >> "$ERRORS_FILE"
         log_warning "Section 4 (Privilege Escalation) had errors"; } \
    || rm -f "$ERR_DIR/s4_privesc.err"

# SECTION 5 — WEB SERVER LOG HUNTING

log_section "Web Server Log Hunting"
echo "[*] Hunting webshell and injection patterns in web logs..."

WEB_LOGS=""
for candidate in \
    /var/log/apache2/access.log  /var/log/apache2/access_log \
    /var/log/nginx/access.log    /var/log/httpd/access_log \
    /var/log/apache2/*.log       /var/log/nginx/*.log; do
    [ -r "$candidate" ] && WEB_LOGS="$WEB_LOGS $candidate"
done

if [ -n "$WEB_LOGS" ]; then

    declare -A _pattern _outfile
    _pattern[webshell]='(cmd=|shell=|exec=|system\(|passthru\(|eval\(|base64_decode|assert\(|phpinfo\(\))'
    _outfile[webshell]="$OUTPUT_DIR/webshell_access.txt"

    _pattern[sqli]="(UNION\s+SELECT|SELECT\s.*FROM|INSERT\s+INTO|DROP\s+TABLE|'; |%27|%3B|'--|0x[0-9a-f]{10,})"
    _outfile[sqli]="$OUTPUT_DIR/sqli_patterns.txt"

    _pattern[xss]='(<script|%3Cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)'
    _outfile[xss]="$OUTPUT_DIR/xss_patterns.txt"

    _pattern[path_traversal]='(\.\./|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|/proc/self|/windows/system32)'
    _outfile[path_traversal]="$OUTPUT_DIR/path_traversal_patterns.txt"

    _pattern[log4shell]='(\$\{jndi:|jndi:ldap|jndi:rmi|jndi:dns|jndi:iiop|%24%7Bjndi|\\u0024\\u007bjndi)'
    _outfile[log4shell]="$OUTPUT_DIR/log4shell_attempts.txt"

    _pattern[ssrf]='(169\.254\.169\.254|metadata\.google|instance-data|localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\..*:)'
    _outfile[ssrf]="$OUTPUT_DIR/ssrf_attempts.txt"

    for name in webshell sqli xss path_traversal log4shell ssrf; do
        # shellcheck disable=SC2086
        grep -ihE "${_pattern[$name]}" $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
            | head -200 > "${_outfile[$name]}" \
            || _note_err "web grep $name" $?

        hit_count=$(wc -l < "${_outfile[$name]}" 2>/dev/null || echo 0)
        if [ "$hit_count" -gt 0 ]; then
            log_metric "web_hits_${name}" "$hit_count" "count"
        fi
    done

    # Emit structured findings for any web attack patterns found
    if [ -s "$OUTPUT_DIR/log4shell_attempts.txt" ]; then
        log_finding "critical" "Log4Shell (CVE-2021-44228) exploitation attempts in web logs" \
            "count=$(wc -l < "$OUTPUT_DIR/log4shell_attempts.txt") — review log4shell_attempts.txt"
    fi
    if [ -s "$OUTPUT_DIR/webshell_access.txt" ] && \
            grep -qv '^\[\-\]' "$OUTPUT_DIR/webshell_access.txt" 2>/dev/null; then
        log_finding "high" "Webshell access patterns in web logs" \
            "count=$(wc -l < "$OUTPUT_DIR/webshell_access.txt") — review webshell_access.txt"
    fi
    if [ -s "$OUTPUT_DIR/sqli_patterns.txt" ]; then
        log_finding "high" "SQL injection patterns in web logs" \
            "count=$(wc -l < "$OUTPUT_DIR/sqli_patterns.txt") — review sqli_patterns.txt"
    fi
    if [ -s "$OUTPUT_DIR/ssrf_attempts.txt" ]; then
        log_finding "high" "SSRF attempts targeting metadata endpoints in web logs" \
            "count=$(wc -l < "$OUTPUT_DIR/ssrf_attempts.txt") — review ssrf_attempts.txt"
    fi
    if [ -s "$OUTPUT_DIR/path_traversal_patterns.txt" ]; then
        log_finding "medium" "Path traversal attempts in web logs" \
            "count=$(wc -l < "$OUTPUT_DIR/path_traversal_patterns.txt") — review path_traversal_patterns.txt"
    fi

    # shellcheck disable=SC2086
    grep -iE \
        '(nmap|nikto|nessus|qualys|acunetix|burpsuite|zaproxy|sqlmap|nuclei|masscan|dirbuster|gobuster|ffuf|wfuzz|hydra|metasploit|python-requests|go-http|curl/7\.)' \
        $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | awk '{print $1}' | sort | uniq -c | sort -rn | head -30 \
        > "$OUTPUT_DIR/scanner_user_agents.txt" || _note_err "web scanner agents" $?

    # shellcheck disable=SC2086
    awk '{print $9}' $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | sort | uniq -c | sort -rn | head -20 \
        > "$OUTPUT_DIR/http_status_distribution.txt" || _note_err "web http status" $?

    # shellcheck disable=SC2086
    awk '{print $1}' $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | sort | uniq -c | sort -rn | head -30 \
        > "$OUTPUT_DIR/web_top_ips.txt" || _note_err "web top IPs" $?

    # shellcheck disable=SC2086
    awk '{print $4}' $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | cut -d: -f1-2 | sort | uniq -c \
        > "$OUTPUT_DIR/web_requests_per_hour.txt" || _note_err "web requests/hour" $?

    [ -s "$ERR_DIR/s5_web.err" ] \
        && { echo "[WARN] Section 5 (Web Log Hunting): see errors/s5_web.err" >> "$ERRORS_FILE"
             log_warning "Section 5 (Web Log Hunting) had errors"; } \
        || rm -f "$ERR_DIR/s5_web.err"
else
    echo "[-] No web access logs found." > "$OUTPUT_DIR/webshell_access.txt"
    echo "[INFO] Section 5: No web logs present on this host." >> "$ERRORS_FILE"
    log_info "Section 5: no web access logs found on this host"
fi

# SECTION 6 — KERNEL LOG ANALYSIS

log_section "Kernel Log Analysis"
echo "[*] Analysing kernel logs for security events..."

{
    echo "=== Kernel OOM kills ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "oom[_-]|killed process" | tail -20
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" \
        | grep -iE "oom|killed process" | tail -20

    echo
    echo "=== Kernel module loads ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "module.*load|insmod|rmmod" | tail -20
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" \
        | grep -iE "module.*load|insmod|rmmod" | tail -20

    echo
    echo "=== Firewall/netfilter drop events ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "nf_|iptables|DROPPED|BLOCKED" | tail -20
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" \
        | grep -iE "nf_|iptables|DROPPED|BLOCKED" | tail -20

    echo
    echo "=== Segfaults / crashes ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "segfault|general protection|trap" | tail -30
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" \
        | grep -iE "segfault|general protection|trap" | tail -30

    echo
    echo "=== Hardware errors ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "edac|mce|machine check|hardware error" | tail -10

} > "$OUTPUT_DIR/kernel_log_analysis.txt"

[ -s "$ERR_DIR/s6_kernel.err" ] \
    && { echo "[WARN] Section 6 (Kernel Logs): see errors/s6_kernel.err" >> "$ERRORS_FILE"
         log_warning "Section 6 (Kernel Logs) had errors"; } \
    || rm -f "$ERR_DIR/s6_kernel.err"

# SECTION 7 — COMMAND EXECUTION AUDIT

log_section "Shell History Forensics"
echo "[*] Forensicating shell histories..."

{
    echo "=== High-risk commands executed (all users) ==="
    find /home /root -name ".*history" -type f 2>>"$ERR_DIR/s7_history.err" \
    | while IFS= read -r hist; do
        echo "--- $hist ---"
        grep -nE '(wget|curl|scp|rsync|nc |netcat|base64).*(http|ftp|:/)' \
            "$hist" 2>>"$ERR_DIR/s7_history.err" | head -10
        grep -nE '(id|whoami|cat /etc/passwd|cat /etc/shadow|ifconfig|ip addr|ss -|nmap)' \
            "$hist" 2>>"$ERR_DIR/s7_history.err" | head -10
        grep -nE '(sudo|su -|chmod [+]?[47]|chown root|passwd|pkexec)' \
            "$hist" 2>>"$ERR_DIR/s7_history.err" | head -10
        grep -nE '(rm.*log|> /var/log|shred|history -c|unset HISTFILE)' \
            "$hist" 2>>"$ERR_DIR/s7_history.err" | head -10
        grep -nE '(curl.*\|.*sh|wget.*-O.*|python.*urllib|bash <\(|/tmp/.*)' \
            "$hist" 2>>"$ERR_DIR/s7_history.err" | head -10
        echo
    done

    echo
    echo "=== Commands that disabled history recording ==="
    find /home /root -name ".*history" -type f 2>>"$ERR_DIR/s7_history.err" \
    | while IFS= read -r hist; do
        if grep -qE '(HISTFILE|HISTSIZE=0|HISTFILESIZE=0|history -c|set +o history)' "$hist" 2>/dev/null; then
            grep -nE '(HISTFILE|HISTSIZE=0|HISTFILESIZE=0|history -c|set +o history)' "$hist"
            echo "  (in $hist)"
        fi
    done

} > "$OUTPUT_DIR/shell_history_forensics.txt"

[ -s "$ERR_DIR/s7_history.err" ] \
    && { echo "[WARN] Section 7 (Shell History): see errors/s7_history.err" >> "$ERRORS_FILE"
         log_warning "Section 7 (Shell History) had errors"; } \
    || rm -f "$ERR_DIR/s7_history.err"

# Flag if anyone disabled history recording
if grep -q "HISTFILE\|HISTSIZE=0\|history -c" "$OUTPUT_DIR/shell_history_forensics.txt" 2>/dev/null; then
    log_finding "medium" "Shell history suppression commands detected in user histories" \
        "review shell_history_forensics.txt — attacker may have attempted anti-forensics"
fi

# Flag curl|sh / wget pipe-to-bash patterns
if grep -qE 'curl.*\|.*sh|wget.*\|.*bash|bash <\(' \
        "$OUTPUT_DIR/shell_history_forensics.txt" 2>/dev/null; then
    log_finding "high" "Remote code execution pattern in shell history" \
        "curl/wget pipe-to-shell detected — review shell_history_forensics.txt"
fi

# NOTE: log_info / log_warning etc. are now available here because log_init
# was called at the top of this script, before any section executes.
ausearch -m EXECVE --start today 2>"$ERR_DIR/s7_auditd.err" \
    | head -300 > "$OUTPUT_DIR/auditd_execve.txt" \
    || { _note_err "auditd execve" $?
         echo "(auditd not available)" > "$OUTPUT_DIR/auditd_execve.txt"; }

[ -s "$ERR_DIR/s7_auditd.err" ] \
    && { echo "[INFO] Section 7 (auditd): see errors/s7_auditd.err" >> "$ERRORS_FILE"
         log_info "Section 7: auditd not available or produced errors"; } \
    || rm -f "$ERR_DIR/s7_auditd.err"

# SECTION 8 — CRON / TIMER ANOMALY LOG HUNT

log_section "Cron and Timer Anomaly Hunt"
echo "[*] Checking cron and timer execution logs..."

{
    echo "=== Cron execution logs ==="
    for logfile in /var/log/syslog /var/log/cron /var/log/messages; do
        [ -r "$logfile" ] \
            && grep "CRON\|crond" "$logfile" 2>>"$ERR_DIR/s8_cron.err" | tail -50
    done
    journalctl _COMM=cron -n 50 --no-pager 2>>"$ERR_DIR/s8_cron.err" \
        || echo "(journald cron query unavailable)"

    echo
    echo "=== Systemd timer executions (last 24h) ==="
    journalctl --since "24 hours ago" --no-pager 2>>"$ERR_DIR/s8_cron.err" \
        | grep -E "timer|service.*Start" | head -50 \
        || echo "(journald unavailable)"

    echo
    echo "=== Cron jobs modified recently ==="
    find /var/spool/cron /etc/cron.d /etc/cron.hourly /etc/cron.daily \
         /etc/cron.weekly /etc/cron.monthly \
         -type f -mtime -7 -ls 2>>"$ERR_DIR/s8_cron.err" || true

} > "$OUTPUT_DIR/cron_timer_logs.txt"

[ -s "$ERR_DIR/s8_cron.err" ] \
    && { echo "[WARN] Section 8 (Cron/Timer): see errors/s8_cron.err" >> "$ERRORS_FILE"
         log_warning "Section 8 (Cron/Timer) had errors"; } \
    || rm -f "$ERR_DIR/s8_cron.err"

# SECTION 9 — CORRELATION ENGINE

log_section "Multi-Source Event Correlation"
echo "[*] Running multi-source event correlation..."

python3 - > "$OUTPUT_DIR/correlation_report.txt" 2>"$ERR_DIR/s9_correlate.err" << 'PYEOF'
import os, re, sys

auth_events = []
auth_logs = ['/var/log/auth.log', '/var/log/secure']
for log_path in auth_logs:
    if not os.path.isfile(log_path):
        continue
    try:
        with open(log_path, errors='replace') as f:
            for line in f:
                m = re.search(r'(\w+ \d+ \d+:\d+:\d+).*?(Accepted|Failed).*?from ([\d.]+)', line)
                if m:
                    auth_events.append({
                        'ts': m.group(1), 'type': m.group(2), 'ip': m.group(3), 'raw': line.strip()
                    })
    except Exception as e:
        print(f"[ERROR] {log_path}: {e}", file=sys.stderr)

failed_ips  = {e['ip'] for e in auth_events if e['type'] == 'Failed'}
success_ips = {e['ip'] for e in auth_events if e['type'] == 'Accepted'}
spray_success = failed_ips & success_ips

print("=" * 60)
print("CORRELATION REPORT")
print("=" * 60)
print()

if spray_success:
    print("[CRITICAL] Password spray success detected:")
    for ip in sorted(spray_success):
        fails   = sum(1 for e in auth_events if e['ip'] == ip and e['type'] == 'Failed')
        success = sum(1 for e in auth_events if e['ip'] == ip and e['type'] == 'Accepted')
        print(f"  {ip:<20} Failures: {fails:<6} Successes: {success}")
else:
    print("[OK] No password spray success patterns detected")

print()

ip_times = {}
for e in auth_events:
    if e['type'] == 'Accepted':
        ip_times.setdefault(e['ip'], []).append(e['ts'])

rapid = {ip: ts for ip, ts in ip_times.items() if len(ts) > 5}
if rapid:
    print("[ALERT] IPs with many successful logins (possible session reuse/pivoting):")
    for ip, ts_list in rapid.items():
        print(f"  {ip:<20} {len(ts_list)} successful logins")
else:
    print("[OK] No rapid login sequences detected")

print()
print(f"Total auth events analysed: {len(auth_events)}")
print(f"Unique source IPs: {len(set(e['ip'] for e in auth_events))}")
PYEOF

if [ $? -ne 0 ]; then
    _note_err "correlation engine" $?
fi

[ -s "$ERR_DIR/s9_correlate.err" ] \
    && { echo "[WARN] Section 9 (Correlation): see errors/s9_correlate.err" >> "$ERRORS_FILE"
         log_warning "Section 9 (Correlation Engine) had errors"; } \
    || rm -f "$ERR_DIR/s9_correlate.err"

# Emit structured findings from correlation output
if grep -q "^\[CRITICAL\] Password spray success" "$OUTPUT_DIR/correlation_report.txt" 2>/dev/null; then
    spray_ips=$(grep -A5 "Password spray success" "$OUTPUT_DIR/correlation_report.txt" \
        | grep -E '^\s+[0-9]+\.' | awk '{print $1}' | paste -sd,)
    log_finding "critical" "Password spray followed by successful login" \
        "source_ips=$spray_ips — same IP had both failed and successful auth events"
fi
if grep -q "^\[ALERT\] IPs with many successful logins" "$OUTPUT_DIR/correlation_report.txt" 2>/dev/null; then
    log_finding "high" "IPs with unusually high successful login counts" \
        "possible credential reuse or session pivoting — review correlation_report.txt"
fi

# SECTION 10 — SUMMARY

log_section "Summary"
echo "[*] Generating log analysis summary..."

{
    echo "========================================================"
    echo "  Log Analysis & Threat Hunting — Summary"
    echo "  Generated: $(date)"
    echo "  Host:      $(hostname)"
    echo "========================================================"
    echo

    echo "--- Findings Requiring Immediate Review ---"

    [ -s "$OUTPUT_DIR/log4shell_attempts.txt" ] && \
        echo "[CRITICAL] Log4Shell (CVE-2021-44228) exploitation attempts detected!"

    if [ -s "$OUTPUT_DIR/webshell_access.txt" ] && \
            grep -qv '^\[\-\]' "$OUTPUT_DIR/webshell_access.txt" 2>/dev/null; then
        echo "[HIGH] Webshell access patterns detected in web logs"
    fi

    [ -s "$OUTPUT_DIR/sqli_patterns.txt" ] && \
        echo "[HIGH] SQL injection patterns detected in web logs"

    [ -s "$OUTPUT_DIR/path_traversal_patterns.txt" ] && \
        echo "[MEDIUM] Path traversal attempts detected"

    grep -q "CRITICAL\|HIGH\|ALERT" "$OUTPUT_DIR/correlation_report.txt" 2>/dev/null && \
        echo "[HIGH] Correlation engine detected suspicious event patterns"

    echo
    echo "--- Log Tampering Indicators ---"
    grep -qiE "zero.*byte|Cleared|deleted|manipulat" \
        "$OUTPUT_DIR/log_tampering_detection.txt" 2>/dev/null \
        && echo "[MEDIUM] Possible log tampering indicators — review log_tampering_detection.txt" \
        || echo "[OK] No obvious log tampering detected"

    echo
    echo "--- Script Errors ---"
    if [ -s "$ERRORS_FILE" ]; then
        cat "$ERRORS_FILE"
    else
        echo "[OK] No section errors recorded."
    fi

    echo
    echo "--- File List ---"
    ls -lh "$OUTPUT_DIR/"*.txt 2>/dev/null

} > "$OUTPUT_DIR/log_analysis_summary.txt"

cat "$OUTPUT_DIR/log_analysis_summary.txt"

# ARCHIVE (contents only, no embedded absolute path)
ARCHIVE="$OUTPUT_DIR/log_analysis_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] Log analysis complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"