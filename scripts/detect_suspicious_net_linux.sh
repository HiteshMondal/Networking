#!/bin/sh
# Script: detect_suspicious_net_linux.sh
# Purpose:
#   Perform a broad suspicious activity scan focused on:
#   - Network connections
#   - Processes with network access
#   - Persistence mechanisms (cron, systemd, SUID)
#   - Recently modified files
#
# Output:
#   All artifacts are written to ./suspicious_scan/
#   A compressed archive is created at the end.
#
# Notes:
#   - Designed for incident response / threat hunting
#   - Best run as root for maximum visibility

# Setup

mkdir -p suspicious_scan

# Record execution timestamp (ISO format preferred)
date --iso-8601=seconds > suspicious_scan/run_timestamp.txt 2>/dev/null \
  || date > suspicious_scan/run_timestamp.txt

# Basic system identity
uname -a > suspicious_scan/uname.txt
whoami  > suspicious_scan/whoami.txt
id      > suspicious_scan/id.txt


# Process & Network Overview

# Top processes by memory usage
ps aux --sort=-%mem > suspicious_scan/ps_aux.txt

# Full socket listing with PID/program info
ss -tunap > suspicious_scan/ss_tunap_raw.txt 2>/dev/null \
  || netstat -tulpen > suspicious_scan/netstat_raw.txt 2>/dev/null

# Condensed connection view: proto, remote addr, state, process
ss -tunapH | awk '{print $1" "$5" "$6" "$7}' \
  > suspicious_scan/ss_connections.txt 2>/dev/null || true

# Extract remote IPs (strip ports, remove blanks)
ss -tunapH | awk '{print $5}' \
  | sed -E 's/:[0-9]+$//' \
  | sed '/^$/d' \
  | sort -u \
  > suspicious_scan/remote_ips.txt 2>/dev/null || true


# Public IP Identification & Enrichment

if [ -s suspicious_scan/remote_ips.txt ]; then
  # Filter out private / loopback ranges
  grep -vE '^(127\.|::1|localhost|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
    suspicious_scan/remote_ips.txt \
    > suspicious_scan/remote_ips_public.txt 2>/dev/null \
    || cp suspicious_scan/remote_ips.txt suspicious_scan/remote_ips_public.txt

  # Enrich public IPs with whois, DNS, and IP info
  xargs -n1 -P10 -I{} sh -c '
    echo "=== {} ===" > suspicious_scan/whois_{}
    whois {} >> suspicious_scan/whois_{} 2>/dev/null
    nslookup {} >> suspicious_scan/whois_{} 2>/dev/null
    curl -m 8 -sS "http://ipinfo.io/{}/json" >> suspicious_scan/whois_{} 2>/dev/null
  ' < suspicious_scan/remote_ips_public.txt || true
fi


# Low-level Network State

lsof -i -P -n > suspicious_scan/lsof_i.txt 2>/dev/null || true
netstat -s     > suspicious_scan/netstat_s.txt 2>/dev/null || true

# Kernel socket tables (raw)
cat /proc/net/tcp > suspicious_scan/proc_net_tcp.txt 2>/dev/null || true
cat /proc/net/udp > suspicious_scan/proc_net_udp.txt 2>/dev/null || true

# Established connections excluding SSH (common pivot point)
if command -v ss >/dev/null 2>&1; then
  ss -o state established '( sport != :22 )' \
    > suspicious_scan/established_not_ssh.txt 2>/dev/null || true
fi


# Interesting / Suspicious Connections

# Filter for listening and established sockets
awk '/LISTEN|ESTAB|ESTABLISHED/' suspicious_scan/ss_tunap_raw.txt \
  > suspicious_scan/interesting_connections.txt 2>/dev/null || true

# Extract entries that include PID information
awk '{if($7 ~ /^[0-9]+,/) print $0}' suspicious_scan/ss_tunap_raw.txt \
  > suspicious_scan/connections_with_pid.txt 2>/dev/null || true

# Extract unique PIDs with network activity
awk '{print $7}' suspicious_scan/connections_with_pid.txt \
  | sed 's/,.*$//' \
  | sed -E 's/[a-zA-Z\/]//g' \
  | tr -d '[]' \
  | sort -u \
  > suspicious_scan/pids_with_network.txt 2>/dev/null || true


# Per-PID Forensics (Processes with Network Access)

if [ -s suspicious_scan/pids_with_network.txt ]; then
  for pid in $(cat suspicious_scan/pids_with_network.txt); do
    [ -d "/proc/$pid" ] || continue

    # Binary path and file descriptors
    readlink -f /proc/$pid/exe > suspicious_scan/pid_${pid}_exe 2>/dev/null || true
    ls -l /proc/$pid/fd        > suspicious_scan/pid_${pid}_fds 2>/dev/null || true

    # Process metadata
    ps -p "$pid" -o pid,ppid,uid,gid,etimes,cmd \
      > suspicious_scan/pid_${pid}_ps.txt 2>/dev/null || true

    # Hash executable (useful for malware identification)
    exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
    if [ -n "$exe" ]; then
      md5sum "$exe"    > suspicious_scan/pid_${pid}_exe_hash.txt 2>/dev/null || true
      sha256sum "$exe" >> suspicious_scan/pid_${pid}_exe_hash.txt 2>/dev/null || true
    fi
  done
fi


# Persistence Checks

# Cron jobs
cron -l > suspicious_scan/crontab_root.txt 2>/dev/null \
  || crontab -l > suspicious_scan/crontab.txt 2>/dev/null || true

ls -la /etc/cron* > suspicious_scan/cron_dirs.txt 2>/dev/null || true

# Systemd persistence
systemctl list-timers --all \
  > suspicious_scan/systemd_timers.txt 2>/dev/null || true

systemctl list-unit-files --state=enabled \
  > suspicious_scan/systemd_enabled_units.txt 2>/dev/null || true

# Look for suspicious download-and-execute patterns
grep -R "curl -s" /etc -nH 2>/dev/null | head -n 200 \
  > suspicious_scan/curl_exec_in_etc.txt || true

find /etc/systemd/system /lib/systemd/system -type f -name '*.service' \
  -exec grep -I -nH 'ExecStart' {} \; 2>/dev/null | head -n 200 \
  > suspicious_scan/systemd_execstarts.txt || true


# File System & Privilege Abuse

# Recently modified files in common attacker locations
find /home /tmp /var/tmp /dev/shm -type f -mtime -7 -ls \
  > suspicious_scan/recent_tmp_files.txt 2>/dev/null || true

# SUID / SGID binaries (privilege escalation vectors)
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null \
  > suspicious_scan/suid_sgid_files.txt || true


# Process Age & Rootkit Checks

# Long-running processes
ps -eo pid,user,group,etime,cmd --sort=-etime | head -n 200 \
  > suspicious_scan/top_old_procs.txt

# Rootkit scanners (if installed)
command -v chkrootkit >/dev/null 2>&1 \
  && chkrootkit > suspicious_scan/chkrootkit.txt 2>/dev/null || true

command -v rkhunter >/dev/null 2>&1 \
  && rkhunter --checkall --sk --nolog > suspicious_scan/rkhunter.txt 2>/dev/null || true


# Network Statistics & Misc

# Count frequency of remote IP connections
ss -tunap | awk '{print $5}' \
  | sed -E 's/:[0-9]+$//' \
  | sort | uniq -c | sort -nr \
  > suspicious_scan/remote_ip_counts.txt 2>/dev/null || true

# Recently modified SSH-related files
find / -iname "*ssh*" -type f -mtime -7 -ls 2>/dev/null \
  > suspicious_scan/recent_ssh_related_files.txt || true

# Look for wget usage in configs (dropper behavior)
grep -R "wget " /etc /home /root 2>/dev/null | head -n 200 \
  > suspicious_scan/wget_exec_in_configs.txt || true

# Full PID → command mapping
ps -eo pid,cmd > suspicious_scan/all_pids_cmds.txt


# Archive Results

tar -czf suspicious_scan_archive.tar.gz suspicious_scan 2>/dev/null || true
