#!/bin/bash
# Log Analysis & Threat Hunting Script
# Purpose : Parse, correlate, and hunt threats across system logs.
#           Detects: auth attacks, privilege escalation, log tampering,
#           webshell access, Log4Shell/Log4j patterns, anomalous commands,
#           and generates a structured timeline of security events.
# Output  : log_analysis/ directory + archive

set -eo pipefail

OUTPUT_DIR="log_analysis"
mkdir -p "$OUTPUT_DIR"

# ── Error capture infrastructure ─────────────────────────────────────────────
# Every section records its stderr to a per-section file. Non-zero exits are
# noted in ERRORS_FILE so they appear in the summary without being swallowed.

ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"   # truncate/create

# _run_section <label> <output_file> <command...>
# Runs a command, redirecting stdout to output_file and stderr to the error
# log. On failure records the exit code and stderr snippet.
_run_section() {
    local label="$1"
    local outfile="$2"
    shift 2
    local errfile="$ERR_DIR/${label// /_}.err"

    if ! "$@" > "$outfile" 2>"$errfile"; then
        local ec=$?
        {
            echo "[ERROR] Section '$label' exited $ec"
            echo "        stderr: $(head -5 "$errfile" 2>/dev/null | tr '\n' '|')"
        } >> "$ERRORS_FILE"
        # Keep the error file only if non-empty
        [ -s "$errfile" ] || rm -f "$errfile"
        return 0   # don't abort the whole script on a section failure
    fi
    [ -s "$errfile" ] || rm -f "$errfile"
}

# _note_err <label> <exit_code>
# Record that a command inside a compound block failed.
_note_err() {
    local label="$1" ec="${2:-?}"
    echo "[ERROR] '$label' failed (exit $ec)" >> "$ERRORS_FILE"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a >> "$OUTPUT_DIR/run_timestamp.txt"
whoami   >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — LOG INVENTORY

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
        || echo "(journald unavailable)" >> "$ERRORS_FILE"

    echo
    echo "=== Log rotation config ==="
    cat /etc/logrotate.conf 2>>"$ERR_DIR/s1_inventory.err" | head -30
    ls -la /etc/logrotate.d/ 2>>"$ERR_DIR/s1_inventory.err"

} > "$OUTPUT_DIR/log_inventory.txt"
[ -s "$ERR_DIR/s1_inventory.err" ] \
    && echo "[WARN] Section 1 (Log Inventory): see errors/s1_inventory.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s1_inventory.err"

# SECTION 2 — LOG TAMPERING DETECTION

echo "[*] Checking for log tampering indicators..."

{
    echo "=== Log file modification times (suspicious if very recent or missing) ==="
    ls -la /var/log/auth.log /var/log/syslog /var/log/messages \
            /var/log/secure /var/log/kern.log 2>>"$ERR_DIR/s2_tamper.err"

    echo
    echo "=== Gaps in log timestamps (possible truncation/wiping) ==="
    for logfile in /var/log/auth.log /var/log/syslog /var/log/secure; do
        [ -r "$logfile" ] || { echo "(not readable: $logfile)" ; continue; }
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
    find /var/log -type f -newer /etc/passwd 2>>"$ERR_DIR/s2_tamper.err" | while read -r f; do
        mtime=$(stat -c '%Y' "$f" 2>>"$ERR_DIR/s2_tamper.err")
        ctime=$(stat -c '%Z' "$f" 2>>"$ERR_DIR/s2_tamper.err")
        [ "$ctime" -gt "$mtime" ] && echo "$f (ctime=$ctime > mtime=$mtime)"
    done

    echo
    echo "=== Cleared utmp/wtmp/btmp (zero-byte files indicate wiping) ==="
    for f in /var/log/wtmp /var/log/btmp /var/run/utmp; do
        [ -f "$f" ] && echo "$(ls -la "$f") $(du -sh "$f" | cut -f1)"
    done

    echo
    echo "=== Log deletion commands in history ==="
    find /home /root -name ".*history" -type f 2>>"$ERR_DIR/s2_tamper.err" | while read -r hist; do
        grep -iE '(rm.*\.log|shred.*log|> /var/log|truncate.*log|unlink.*log|echo.*>/var/log)' \
            "$hist" 2>>"$ERR_DIR/s2_tamper.err" | while read -r line; do
            echo "$hist: $line"
        done
    done

} > "$OUTPUT_DIR/log_tampering_detection.txt"
[ -s "$ERR_DIR/s2_tamper.err" ] \
    && echo "[WARN] Section 2 (Log Tampering): see errors/s2_tamper.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s2_tamper.err"

# SECTION 3 — AUTHENTICATION TIMELINE

echo "[*] Building authentication timeline..."

python3 - << 'PYEOF' > "$OUTPUT_DIR/auth_timeline.txt" 2>>"$ERR_DIR/s3_auth.err" || {
    _note_err "auth_timeline python3" $?
    # Journald fallback
    journalctl -u ssh -u sshd --no-pager --output=short-precise 2>>"$ERR_DIR/s3_auth.err" \
        | grep -E "Accepted|Failed|sudo|su\[" | tail -300 \
        > "$OUTPUT_DIR/auth_timeline.txt" \
        || _note_err "auth_timeline journald fallback" $?
}
import os, re, datetime

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

year = datetime.datetime.now().year

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
        import sys
        print(f"[ERROR] Could not read {log_path}: {e}", file=sys.stderr)
        continue

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

[ -s "$ERR_DIR/s3_auth.err" ] \
    && echo "[WARN] Section 3 (Auth Timeline): see errors/s3_auth.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s3_auth.err"

# SECTION 4 — PRIVILEGE ESCALATION EVENTS

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
        [ -r "$logfile" ] && grep "\bsu\b" "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -50
    done

    echo
    echo "=== setuid/setgid execution events (auditd) ==="
    ausearch -m EXECVE -ts today 2>>"$ERR_DIR/s4_privesc.err" | head -50 \
        || echo "(auditd not available)"

    echo
    echo "=== Polkit / pkexec events ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep -iE "polkit|pkexec" "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -20
    done
    journalctl _COMM=pkexec --no-pager -n 20 2>>"$ERR_DIR/s4_privesc.err" \
        || true

    echo
    echo "=== doas events ==="
    for logfile in /var/log/auth.log /var/log/messages; do
        [ -r "$logfile" ] && grep "\bdoas\b" "$logfile" 2>>"$ERR_DIR/s4_privesc.err" | tail -20
    done

    echo
    echo "=== Capability-related anomalies ==="
    find /proc -maxdepth 2 -name "status" 2>>"$ERR_DIR/s4_privesc.err" | while read -r s; do
        caps_eff=$(grep "^CapEff:" "$s" 2>/dev/null | awk '{print $2}')
        if [ -n "$caps_eff" ] && [ "$caps_eff" != "0000000000000000" ]; then
            pid=$(echo "$s" | grep -oE '[0-9]+')
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            echo "PID $pid ($exe): CapEff=$caps_eff"
        fi
    done | head -20

} > "$OUTPUT_DIR/privilege_escalation_events.txt"
[ -s "$ERR_DIR/s4_privesc.err" ] \
    && echo "[WARN] Section 4 (Privilege Escalation): see errors/s4_privesc.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s4_privesc.err"

# SECTION 5 — WEB SERVER LOG HUNTING

echo "[*] Hunting webshell and injection patterns in web logs..."

WEB_LOGS=""
for candidate in /var/log/apache2/access.log /var/log/apache2/access_log \
                  /var/log/nginx/access.log /var/log/httpd/access_log \
                  /var/log/apache2/*.log /var/log/nginx/*.log; do
    [ -r "$candidate" ] && WEB_LOGS="$WEB_LOGS $candidate"
done

if [ -n "$WEB_LOGS" ]; then

    for pattern_name in webshell sqli xss path_traversal log4shell ssrf; do
        case "$pattern_name" in
            webshell)
                regex='(cmd=|shell=|exec=|system\(|passthru\(|eval\(|base64_decode\|assert\(|phpinfo\(\))'
                outfile="$OUTPUT_DIR/webshell_access.txt" ;;
            sqli)
                regex="(UNION\s+SELECT|SELECT\s.*FROM|INSERT\s+INTO|DROP\s+TABLE|'; |%27|%3B|'--|0x[0-9a-f]{10,})"
                outfile="$OUTPUT_DIR/sqli_patterns.txt" ;;
            xss)
                regex="(<script|%3Cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)"
                outfile="$OUTPUT_DIR/xss_patterns.txt" ;;
            path_traversal)
                regex="(\.\./|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|/proc/self|/windows/system32)"
                outfile="$OUTPUT_DIR/path_traversal_patterns.txt" ;;
            log4shell)
                regex='(\$\{jndi:|jndi:ldap|jndi:rmi|jndi:dns|jndi:iiop|%24%7Bjndi|\\u0024\\u007bjndi)'
                outfile="$OUTPUT_DIR/log4shell_attempts.txt" ;;
            ssrf)
                regex='(169\.254\.169\.254|metadata\.google|instance-data|localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\..*:)'
                outfile="$OUTPUT_DIR/ssrf_attempts.txt" ;;
        esac
        grep -ihE "$regex" $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" | head -200 > "$outfile" \
            || _note_err "web grep $pattern_name" $?
    done

    grep -iE \
        '(nmap|nikto|nessus|qualys|acunetix|burpsuite|zaproxy|sqlmap|nuclei|masscan|dirbuster|gobuster|ffuf|wfuzz|hydra|metasploit|python-requests|go-http|curl/7\.)' \
        $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" | awk '{print $1}' | sort | uniq -c | sort -rn | head -30 \
        > "$OUTPUT_DIR/scanner_user_agents.txt" || _note_err "web scanner agents" $?

    awk '{print $9}' $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | sort | uniq -c | sort -rn | head -20 \
        > "$OUTPUT_DIR/http_status_distribution.txt" || _note_err "web http status" $?

    awk '{print $1}' $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | sort | uniq -c | sort -rn | head -30 \
        > "$OUTPUT_DIR/web_top_ips.txt" || _note_err "web top IPs" $?

    awk '{print $4}' $WEB_LOGS 2>>"$ERR_DIR/s5_web.err" \
        | cut -d: -f1-2 | sort | uniq -c \
        > "$OUTPUT_DIR/web_requests_per_hour.txt" || _note_err "web requests/hour" $?

    [ -s "$ERR_DIR/s5_web.err" ] \
        && echo "[WARN] Section 5 (Web Log Hunting): see errors/s5_web.err" >> "$ERRORS_FILE" \
        || rm -f "$ERR_DIR/s5_web.err"
else
    echo "[-] No web access logs found." > "$OUTPUT_DIR/webshell_access.txt"
    echo "[INFO] Section 5: No web logs present on this host." >> "$ERRORS_FILE"
fi

# SECTION 6 — KERNEL LOG ANALYSIS

echo "[*] Analysing kernel logs for security events..."

{
    echo "=== Kernel OOM kills ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "oom[_-]|killed process" | tail -20
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "oom|killed process" | tail -20

    echo
    echo "=== Kernel module loads ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "module.*load|insmod|rmmod" | tail -20
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "module.*load\|insmod\|rmmod" | tail -20

    echo
    echo "=== Firewall/netfilter drop events ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "nf_|iptables|DROPPED|BLOCKED" | tail -20
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "nf_|iptables|DROPPED|BLOCKED" | tail -20

    echo
    echo "=== Segfaults / crashes ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "segfault|general protection|trap" | tail -30
    journalctl -k --no-pager 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "segfault|general protection|trap" | tail -30

    echo
    echo "=== Hardware errors ==="
    dmesg 2>>"$ERR_DIR/s6_kernel.err" | grep -iE "edac|mce|machine check|hardware error" | tail -10

} > "$OUTPUT_DIR/kernel_log_analysis.txt"
[ -s "$ERR_DIR/s6_kernel.err" ] \
    && echo "[WARN] Section 6 (Kernel Logs): see errors/s6_kernel.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s6_kernel.err"

# SECTION 7 — COMMAND EXECUTION AUDIT

echo "[*] Forensicating shell histories..."

{
    echo "=== High-risk commands executed (all users) ==="
    find /home /root -name ".*history" -type f 2>>"$ERR_DIR/s7_history.err" | while read -r hist; do
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
    find /home /root -name ".*history" -type f 2>>"$ERR_DIR/s7_history.err" | while read -r hist; do
        grep -nE '(HISTFILE|HISTSIZE=0|HISTFILESIZE=0|history -c|set +o history)' \
            "$hist" 2>>"$ERR_DIR/s7_history.err" && echo "$hist"
    done

} > "$OUTPUT_DIR/shell_history_forensics.txt"
[ -s "$ERR_DIR/s7_history.err" ] \
    && echo "[WARN] Section 7 (Shell History): see errors/s7_history.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s7_history.err"

ausearch -m EXECVE --start today 2>"$ERR_DIR/s7_auditd.err" \
    | head -300 > "$OUTPUT_DIR/auditd_execve.txt" \
    || { _note_err "auditd execve" $?; echo "(auditd not available)" > "$OUTPUT_DIR/auditd_execve.txt"; }
[ -s "$ERR_DIR/s7_auditd.err" ] \
    && echo "[INFO] Section 7 (auditd): see errors/s7_auditd.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s7_auditd.err"

# SECTION 8 — CRON / TIMER ANOMALY LOG HUNT

echo "[*] Checking cron and timer execution logs..."

{
    echo "=== Cron execution logs ==="
    for logfile in /var/log/syslog /var/log/cron /var/log/messages; do
        [ -r "$logfile" ] && grep "CRON\|crond" "$logfile" 2>>"$ERR_DIR/s8_cron.err" | tail -50
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
         /etc/cron.weekly /etc/cron.monthly -type f -mtime -7 -ls 2>>"$ERR_DIR/s8_cron.err"

} > "$OUTPUT_DIR/cron_timer_logs.txt"
[ -s "$ERR_DIR/s8_cron.err" ] \
    && echo "[WARN] Section 8 (Cron/Timer): see errors/s8_cron.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s8_cron.err"

# SECTION 9 — CORRELATION ENGINE

echo "[*] Running multi-source event correlation..."

python3 - << 'PYEOF' > "$OUTPUT_DIR/correlation_report.txt" 2>"$ERR_DIR/s9_correlate.err" \
    || _note_err "correlation engine" $?
import os, re, datetime, sys

output_dir = "log_analysis"
year = datetime.datetime.now().year

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
        continue

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

[ -s "$ERR_DIR/s9_correlate.err" ] \
    && echo "[WARN] Section 9 (Correlation): see errors/s9_correlate.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s9_correlate.err"

# SECTION 10 — LOG ANALYSIS SUMMARY

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

    [ -s "$OUTPUT_DIR/webshell_access.txt" ] && \
        grep -qv '^\[\-\]' "$OUTPUT_DIR/webshell_access.txt" && \
        echo "[HIGH] Webshell access patterns detected in web logs"

    [ -s "$OUTPUT_DIR/sqli_patterns.txt" ] && \
        echo "[HIGH] SQL injection patterns detected in web logs"

    [ -s "$OUTPUT_DIR/path_traversal_patterns.txt" ] && \
        echo "[MEDIUM] Path traversal attempts detected"

    grep -q "CRITICAL\|HIGH" "$OUTPUT_DIR/correlation_report.txt" 2>/dev/null && \
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

# ARCHIVE

tar -czf log_analysis_archive.tar.gz "$OUTPUT_DIR" 2>/dev/null || true
echo
echo "[+] Log analysis complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: log_analysis_archive.tar.gz"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors were recorded — see $OUTPUT_DIR/errors_summary.txt and $ERR_DIR/"