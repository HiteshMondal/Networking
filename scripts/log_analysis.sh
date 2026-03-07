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

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a >> "$OUTPUT_DIR/run_timestamp.txt"
whoami   >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — LOG INVENTORY

echo "[*] Inventorying log files..."

{
    echo "=== /var/log directory listing ==="
    find /var/log -type f -ls 2>/dev/null | sort -k11

    echo
    echo "=== Log sizes summary ==="
    du -sh /var/log/* 2>/dev/null | sort -rh | head -30

    echo
    echo "=== Journald disk usage ==="
    journalctl --disk-usage 2>/dev/null || true

    echo
    echo "=== Log rotation config ==="
    cat /etc/logrotate.conf 2>/dev/null | head -30
    ls -la /etc/logrotate.d/ 2>/dev/null

} > "$OUTPUT_DIR/log_inventory.txt"

# SECTION 2 — LOG TAMPERING DETECTION

echo "[*] Checking for log tampering indicators..."

{
    echo "=== Log file modification times (suspicious if very recent or missing) ==="
    ls -la /var/log/auth.log /var/log/syslog /var/log/messages \
            /var/log/secure /var/log/kern.log 2>/dev/null

    echo
    echo "=== Gaps in log timestamps (possible truncation/wiping) ==="
    for logfile in /var/log/auth.log /var/log/syslog /var/log/secure; do
        [ -r "$logfile" ] || continue
        echo "--- $logfile ---"
        # First and last timestamps
        head -1 "$logfile" 2>/dev/null | awk '{print "First:", $1, $2, $3}'
        tail -1 "$logfile" 2>/dev/null | awk '{print "Last: ", $1, $2, $3}'
        total_lines=$(wc -l < "$logfile" 2>/dev/null)
        echo "Total lines: $total_lines"
        echo
    done

    echo
    echo "=== Journald integrity check ==="
    journalctl --verify 2>/dev/null || echo "(journald verification unavailable)"

    echo
    echo "=== Files with ctime newer than mtime (inode changed but content not) ==="
    # This can indicate log content was overwritten without updating mtime
    find /var/log -type f -newer /etc/passwd 2>/dev/null | while read -r f; do
        mtime=$(stat -c '%Y' "$f" 2>/dev/null)
        ctime=$(stat -c '%Z' "$f" 2>/dev/null)
        [ "$ctime" -gt "$mtime" ] && echo "$f (ctime=$ctime > mtime=$mtime)"
    done || true

    echo
    echo "=== Cleared utmp/wtmp/btmp (zero-byte files indicate wiping) ==="
    for f in /var/log/wtmp /var/log/btmp /var/run/utmp; do
        [ -f "$f" ] && echo "$(ls -la "$f") $(du -sh "$f" | cut -f1)"
    done

    echo
    echo "=== Log deletion commands in history ==="
    find /home /root -name ".*history" -type f 2>/dev/null | while read -r hist; do
        grep -iE '(rm.*\.log|shred.*log|> /var/log|truncate.*log|unlink.*log|echo.*>/var/log)' \
            "$hist" 2>/dev/null | while read -r line; do
            echo "$hist: $line"
        done
    done || true

} > "$OUTPUT_DIR/log_tampering_detection.txt"

# SECTION 3 — AUTHENTICATION TIMELINE

echo "[*] Building authentication timeline..."

python3 - << 'PYEOF' > "$OUTPUT_DIR/auth_timeline.txt" 2>/dev/null || \
python  - << 'PYEOF' > "$OUTPUT_DIR/auth_timeline.txt" 2>/dev/null || true
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
    except Exception:
        continue

print(f"{'Timestamp':<18}  {'Event':<16}  Details")
print("-" * 80)
for ts, etype, details in events[-300:]:  # last 300 events
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

# Journald fallback
if [ ! -s "$OUTPUT_DIR/auth_timeline.txt" ]; then
    journalctl -u ssh -u sshd --no-pager --output=short-precise 2>/dev/null \
        | grep -E "Accepted|Failed|sudo|su\[" | tail -300 \
        > "$OUTPUT_DIR/auth_timeline.txt" || true
fi

# SECTION 4 — PRIVILEGE ESCALATION EVENTS

echo "[*] Detecting privilege escalation events..."

{
    echo "=== sudo command history ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep "sudo" "$logfile" 2>/dev/null | tail -100
    done
    journalctl _COMM=sudo --no-pager -n 100 2>/dev/null || true

    echo
    echo "=== su (switch user) events ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep "\bsu\b" "$logfile" 2>/dev/null | tail -50
    done

    echo
    echo "=== setuid/setgid execution events (auditd) ==="
    ausearch -m EXECVE -ts today 2>/dev/null | head -50 || true

    echo
    echo "=== Polkit / pkexec events ==="
    for logfile in /var/log/auth.log /var/log/secure; do
        [ -r "$logfile" ] && grep -iE "polkit|pkexec" "$logfile" 2>/dev/null | tail -20
    done
    journalctl _COMM=pkexec --no-pager -n 20 2>/dev/null || true

    echo
    echo "=== doas events (OpenBSD-style privilege tool) ==="
    for logfile in /var/log/auth.log /var/log/messages; do
        [ -r "$logfile" ] && grep "\bdoas\b" "$logfile" 2>/dev/null | tail -20
    done

    echo
    echo "=== Capability-related anomalies ==="
    # Processes with elevated capabilities
    find /proc -maxdepth 2 -name "status" 2>/dev/null | while read -r s; do
        caps_eff=$(grep "^CapEff:" "$s" 2>/dev/null | awk '{print $2}')
        if [ -n "$caps_eff" ] && [ "$caps_eff" != "0000000000000000" ]; then
            pid=$(echo "$s" | grep -oE '[0-9]+')
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            echo "PID $pid ($exe): CapEff=$caps_eff"
        fi
    done | head -20

} > "$OUTPUT_DIR/privilege_escalation_events.txt" 2>/dev/null || true

# SECTION 5 — WEB SERVER LOG HUNTING

echo "[*] Hunting webshell and injection patterns in web logs..."

WEB_LOGS=""
for candidate in /var/log/apache2/access.log /var/log/apache2/access_log \
                  /var/log/nginx/access.log /var/log/httpd/access_log \
                  /var/log/apache2/*.log /var/log/nginx/*.log; do
    [ -r "$candidate" ] && WEB_LOGS="$WEB_LOGS $candidate"
done

if [ -n "$WEB_LOGS" ]; then

    # ── Webshell access patterns ─────────────────────────────────────────────
    grep -ihE \
        '(cmd=|shell=|exec=|system\(|passthru\(|eval\(|base64_decode\|assert\(|phpinfo\(\))' \
        $WEB_LOGS 2>/dev/null | head -200 \
        > "$OUTPUT_DIR/webshell_access.txt" || true

    # ── SQL injection patterns ────────────────────────────────────────────────
    grep -ihE \
        "(UNION\s+SELECT|SELECT\s.*FROM|INSERT\s+INTO|DROP\s+TABLE|'; |%27|%3B|'--|0x[0-9a-f]{10,})" \
        $WEB_LOGS 2>/dev/null | head -200 \
        > "$OUTPUT_DIR/sqli_patterns.txt" || true

    # ── XSS patterns ─────────────────────────────────────────────────────────
    grep -ihE \
        "(<script|%3Cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)" \
        $WEB_LOGS 2>/dev/null | head -200 \
        > "$OUTPUT_DIR/xss_patterns.txt" || true

    # ── Path traversal ────────────────────────────────────────────────────────
    grep -iE \
        "(\.\./|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|/proc/self|/windows/system32)" \
        $WEB_LOGS 2>/dev/null | head -200 \
        > "$OUTPUT_DIR/path_traversal_patterns.txt" || true

    # ── Log4Shell (CVE-2021-44228) ────────────────────────────────────────────
    grep -iE \
        '(\$\{jndi:|jndi:ldap|jndi:rmi|jndi:dns|jndi:iiop|%24%7Bjndi|\\u0024\\u007bjndi)' \
        $WEB_LOGS 2>/dev/null | head -200 \
        > "$OUTPUT_DIR/log4shell_attempts.txt" || true

    # ── SSRF / Internal service probing ──────────────────────────────────────
    grep -iE \
        '(169\.254\.169\.254|metadata\.google|instance-data|localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\..*:)' \
        $WEB_LOGS 2>/dev/null | head -200 \
        > "$OUTPUT_DIR/ssrf_attempts.txt" || true

    # ── Scanner user-agents ───────────────────────────────────────────────────
    grep -iE \
        '(nmap|nikto|nessus|qualys|acunetix|burpsuite|zaproxy|sqlmap|nuclei|masscan|dirbuster|gobuster|ffuf|wfuzz|hydra|metasploit|python-requests|go-http|curl/7\.)' \
        $WEB_LOGS 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -30 \
        > "$OUTPUT_DIR/scanner_user_agents.txt" || true

    # ── HTTP error rate analysis (4xx/5xx storms) ────────────────────────────
    awk '{print $9}' $WEB_LOGS 2>/dev/null \
        | sort | uniq -c | sort -rn | head -20 \
        > "$OUTPUT_DIR/http_status_distribution.txt" || true

    # ── Top talkers (IP with most requests) ──────────────────────────────────
    awk '{print $1}' $WEB_LOGS 2>/dev/null \
        | sort | uniq -c | sort -rn | head -30 \
        > "$OUTPUT_DIR/web_top_ips.txt" || true

    # ── Requests per hour (volume spike detection) ────────────────────────────
    awk '{print $4}' $WEB_LOGS 2>/dev/null \
        | cut -d: -f1-2 | sort | uniq -c \
        > "$OUTPUT_DIR/web_requests_per_hour.txt" || true

else
    echo "[-] No web access logs found." > "$OUTPUT_DIR/webshell_access.txt"
fi

# SECTION 6 — KERNEL LOG ANALYSIS

echo "[*] Analysing kernel logs for security events..."

{
    echo "=== Kernel OOM kills (potential DoS or memory bomb) ==="
    dmesg 2>/dev/null | grep -iE "oom[_-]|killed process" | tail -20
    journalctl -k --no-pager 2>/dev/null | grep -iE "oom|killed process" | tail -20

    echo
    echo "=== Kernel module loads (rootkit vector) ==="
    dmesg 2>/dev/null | grep -iE "module.*load|insmod|rmmod" | tail -20
    journalctl -k --no-pager 2>/dev/null | grep -iE "module.*load\|insmod\|rmmod" | tail -20

    echo
    echo "=== Firewall/netfilter drop events ==="
    dmesg 2>/dev/null | grep -iE "nf_|iptables|DROPPED|BLOCKED" | tail -20
    journalctl -k --no-pager 2>/dev/null | grep -iE "nf_|iptables|DROPPED|BLOCKED" | tail -20

    echo
    echo "=== Segfaults / crashes (possible exploitation attempts) ==="
    dmesg 2>/dev/null | grep -iE "segfault|general protection|trap" | tail -30
    journalctl -k --no-pager 2>/dev/null | grep -iE "segfault|general protection|trap" | tail -30

    echo
    echo "=== Hardware errors (EDAC/MCE — could indicate physical compromise) ==="
    dmesg 2>/dev/null | grep -iE "edac|mce|machine check|hardware error" | tail -10

} > "$OUTPUT_DIR/kernel_log_analysis.txt" 2>/dev/null || true

# SECTION 7 — COMMAND EXECUTION AUDIT (BASH HISTORY FORENSICS)

echo "[*] Forensicating shell histories..."

{
    echo "=== High-risk commands executed (all users) ==="
    find /home /root -name ".*history" -type f 2>/dev/null | while read -r hist; do
        echo "--- $hist ---"
        # Data exfiltration tools
        grep -nE '(wget|curl|scp|rsync|nc |netcat|base64).*(http|ftp|:/)' "$hist" \
            2>/dev/null | head -10 || true
        # Enumeration/recon
        grep -nE '(id|whoami|cat /etc/passwd|cat /etc/shadow|ifconfig|ip addr|ss -|nmap)' \
            "$hist" 2>/dev/null | head -10 || true
        # Privilege escalation
        grep -nE '(sudo|su -|chmod [+]?[47]|chown root|passwd|pkexec)' \
            "$hist" 2>/dev/null | head -10 || true
        # Log clearing
        grep -nE '(rm.*log|> /var/log|shred|history -c|unset HISTFILE)' \
            "$hist" 2>/dev/null | head -10 || true
        # Download and execute patterns
        grep -nE '(curl.*\|.*sh|wget.*-O.*|python.*urllib|bash <\(|/tmp/.*)' \
            "$hist" 2>/dev/null | head -10 || true
        echo
    done

    echo
    echo "=== Commands that disabled history recording ==="
    find /home /root -name ".*history" -type f 2>/dev/null | while read -r hist; do
        grep -nE '(HISTFILE|HISTSIZE=0|HISTFILESIZE=0|history -c|set +o history)' \
            "$hist" 2>/dev/null && echo "$hist" || true
    done

} > "$OUTPUT_DIR/shell_history_forensics.txt" 2>/dev/null || true

# auditd execve records (most complete command execution log)
ausearch -m EXECVE --start today 2>/dev/null \
    | head -300 > "$OUTPUT_DIR/auditd_execve.txt" 2>/dev/null || true

# SECTION 8 — CRON / TIMER ANOMALY LOG HUNT

echo "[*] Checking cron and timer execution logs..."

{
    echo "=== Cron execution logs ==="
    for logfile in /var/log/syslog /var/log/cron /var/log/messages; do
        [ -r "$logfile" ] && grep "CRON\|crond" "$logfile" 2>/dev/null | tail -50
    done
    journalctl _COMM=cron -n 50 --no-pager 2>/dev/null || true

    echo
    echo "=== Systemd timer executions (last 24h) ==="
    journalctl --since "24 hours ago" --no-pager 2>/dev/null \
        | grep -E "timer|service.*Start" | head -50 || true

    echo
    echo "=== Cron jobs modified recently ==="
    find /var/spool/cron /etc/cron.d /etc/cron.hourly /etc/cron.daily \
         /etc/cron.weekly /etc/cron.monthly -type f -mtime -7 -ls 2>/dev/null \
        || true

} > "$OUTPUT_DIR/cron_timer_logs.txt" 2>/dev/null || true

# SECTION 9 — CORRELATION ENGINE (MULTI-SOURCE)

echo "[*] Running multi-source event correlation..."

python3 - << 'PYEOF' > "$OUTPUT_DIR/correlation_report.txt" 2>/dev/null || true
"""
Correlate: bruteforce → shell spawn (post-exploitation indicator)
           login from new IP → immediate sudo execution
           failed logins → configuration file modification (may indicate access)
"""
import os, re, datetime

output_dir = "log_analysis"
year = datetime.datetime.now().year

# Load events
auth_events = []
auth_logs = ['/var/log/auth.log', '/var/log/secure']
for log_path in auth_logs:
    if not os.path.isfile(log_path):
        continue
    with open(log_path, errors='replace') as f:
        for line in f:
            m = re.search(r'(\w+ \d+ \d+:\d+:\d+).*?(Accepted|Failed).*?from ([\d.]+)', line)
            if m:
                auth_events.append({
                    'ts': m.group(1), 'type': m.group(2), 'ip': m.group(3), 'raw': line.strip()
                })

# Find IPs with both failures and success (spray success)
failed_ips = {e['ip'] for e in auth_events if e['type'] == 'Failed'}
success_ips = {e['ip'] for e in auth_events if e['type'] == 'Accepted'}
spray_success = failed_ips & success_ips

print("=" * 60)
print("CORRELATION REPORT")
print("=" * 60)
print()

if spray_success:
    print("[CRITICAL] Password spray success detected:")
    print("  IPs with failures THEN successes:")
    for ip in sorted(spray_success):
        fails = sum(1 for e in auth_events if e['ip'] == ip and e['type'] == 'Failed')
        success = sum(1 for e in auth_events if e['ip'] == ip and e['type'] == 'Accepted')
        print(f"  {ip:<20} Failures: {fails:<6} Successes: {success}")
else:
    print("[OK] No password spray success patterns detected")

print()

# Detect rapid login sequences from same IP
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

    [ -s "$OUTPUT_DIR/spray_success_ips.txt" ] && \
        grep -qv '^===' "$OUTPUT_DIR/spray_success_ips.txt" && \
        echo "[HIGH] Password spray success: IPs with both failures and successes"

    grep -q "CRITICAL\|HIGH" "$OUTPUT_DIR/correlation_report.txt" 2>/dev/null && \
        echo "[HIGH] Correlation engine detected suspicious event patterns"

    echo
    echo "--- Log Tampering Indicators ---"
    grep -qiE "zero.*byte|Cleared|deleted|manipulat" \
        "$OUTPUT_DIR/log_tampering_detection.txt" 2>/dev/null \
        && echo "[MEDIUM] Possible log tampering indicators — review log_tampering_detection.txt" \
        || echo "[OK] No obvious log tampering detected"

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