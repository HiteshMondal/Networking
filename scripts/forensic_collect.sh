#!/bin/sh
###############################################################################
# Linux Forensic Collection Script
# Purpose : Collect system, user, process, network, and log artifacts
# Output  : forensic_output/ directory
# Notes   : Commands may fail silently if not available or permission denied
###############################################################################

# Create output directory
OUTPUT_DIR="forensic_output"
mkdir -p "$OUTPUT_DIR"

# System & Host Information
uname -a > "$OUTPUT_DIR/uname.txt"

hostnamectl > "$OUTPUT_DIR/hostnamectl.txt" 2>/dev/null \
  || hostname > "$OUTPUT_DIR/hostname.txt"

whoami > "$OUTPUT_DIR/whoami.txt"
id > "$OUTPUT_DIR/id.txt"
uptime > "$OUTPUT_DIR/uptime.txt"

# Kernel & Boot Messages
dmesg --ctime > "$OUTPUT_DIR/dmesg.txt" 2>/dev/null \
  || dmesg > "$OUTPUT_DIR/dmesg.txt"

# Systemd Journal Logs
journalctl --no-pager --output=short-precise \
  > "$OUTPUT_DIR/journalctl_all.txt" 2>/dev/null || true

journalctl -u ssh --no-pager \
  > "$OUTPUT_DIR/journalctl_ssh.txt" 2>/dev/null || true

journalctl -k --no-pager \
  > "$OUTPUT_DIR/journalctl_kernel.txt" 2>/dev/null || true

# Traditional Log Files
cp /var/log/auth.log "$OUTPUT_DIR/" 2>/dev/null \
  || cp /var/log/secure "$OUTPUT_DIR/" 2>/dev/null || true

cp /var/log/syslog "$OUTPUT_DIR/" 2>/dev/null || true
cp /var/log/messages "$OUTPUT_DIR/" 2>/dev/null || true

ls -l /var/log > "$OUTPUT_DIR/var_log_listing.txt" 2>/dev/null || true

# Authentication & Login Records
lastlog > "$OUTPUT_DIR/lastlog.txt" 2>/dev/null || true
faillog -v > "$OUTPUT_DIR/faillog.txt" 2>/dev/null || true

# Linux Audit Framework (auditd)
ausearch --start today \
  > "$OUTPUT_DIR/ausearch_today.log" 2>/dev/null \
  || ausearch > "$OUTPUT_DIR/ausearch_all.log" 2>/dev/null || true

auditctl -l > "$OUTPUT_DIR/audit_rules.txt" 2>/dev/null || true

ausearch -m USER_LOGIN -ts today \
  > "$OUTPUT_DIR/ausearch_user_login.txt" 2>/dev/null || true

cp /var/log/audit/audit.log "$OUTPUT_DIR/" 2>/dev/null || true

# ---------------------------------------------------------------------------
ps auxww > "$OUTPUT_DIR/ps_aux.txt"

ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 200 \
  > "$OUTPUT_DIR/top_procs.txt"

lsmod > "$OUTPUT_DIR/lsmod.txt" 2>/dev/null || true

# Network Connections & Interfaces
ss -tunap > "$OUTPUT_DIR/ss_tunap.txt" 2>/dev/null \
  || netstat -tulpen > "$OUTPUT_DIR/netstat_tulpen.txt" 2>/dev/null || true

lsof -i > "$OUTPUT_DIR/lsof_network.txt" 2>/dev/null || true

ip -s link > "$OUTPUT_DIR/ip_stats.txt" 2>/dev/null \
  || ip link > "$OUTPUT_DIR/ip_link.txt" 2>/dev/null || true

ip -4 addr show > "$OUTPUT_DIR/ip_addr.txt"
ip route show > "$OUTPUT_DIR/ip_route.txt"

# Firewall & Connection Tracking
iptables-save > "$OUTPUT_DIR/iptables_rules.txt" 2>/dev/null \
  || nft list ruleset > "$OUTPUT_DIR/nft_rules.txt" 2>/dev/null || true

conntrack -L > "$OUTPUT_DIR/conntrack.txt" 2>/dev/null || true

# Packet Capture (limited)
tcpdump -nn -s 0 -c 1000 -w "$OUTPUT_DIR/tcpdump_capture.pcap" 2>/dev/null \
  || tshark -i any -c 1000 -w "$OUTPUT_DIR/tshark_capture.pcap" 2>/dev/null || true

# Network Statistics (Kernel View)
ss -s > "$OUTPUT_DIR/ss_summary.txt" 2>/dev/null || true

cat /proc/net/tcp > "$OUTPUT_DIR/proc_net_tcp.txt" 2>/dev/null || true
cat /proc/net/udp > "$OUTPUT_DIR/proc_net_udp.txt" 2>/dev/null || true
cat /proc/net/arp > "$OUTPUT_DIR/proc_net_arp.txt" 2>/dev/null || true

netstat -s > "$OUTPUT_DIR/netstat_s.txt" 2>/dev/null || true

# Filesystems & Mounts
mount > "$OUTPUT_DIR/mounts.txt"
df -h > "$OUTPUT_DIR/df.txt"

find /var/log -type f -maxdepth 2 \
  -printf "%p %s %TY-%Tm-%Td %TH:%TM:%TS\n" \
  > "$OUTPUT_DIR/varlog_files_listing.txt" 2>/dev/null || true

# Configuration Files
cp /etc/ssh/sshd_config "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/hosts "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/issue* "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/passwd "$OUTPUT_DIR/" 2>/dev/null || true
cp /etc/group "$OUTPUT_DIR/" 2>/dev/null || true

# Package Management History
cp /var/log/apt/history.log "$OUTPUT_DIR/" 2>/dev/null \
  || cp /var/log/dpkg.log* "$OUTPUT_DIR/" 2>/dev/null \
  || cp /var/log/yum.log* "$OUTPUT_DIR/" 2>/dev/null || true

# Listening Ports
ss -ltnp > "$OUTPUT_DIR/listening_tcp.txt" 2>/dev/null \
  || netstat -ltnp > "$OUTPUT_DIR/listening_tcp_netstat.txt" 2>/dev/null || true

ss -lunp > "$OUTPUT_DIR/listening_udp.txt" 2>/dev/null \
  || netstat -lunp > "$OUTPUT_DIR/listening_udp_netstat.txt" 2>/dev/null || true

# Scheduled Tasks (Cron)
crontab -l > "$OUTPUT_DIR/crontab_current.txt" 2>/dev/null || true
ls -la /etc/cron* > "$OUTPUT_DIR/cron_dirs.txt" 2>/dev/null || true

# Log Keyword Hunting (Quick Triage)
grep -R "ssh" /var/log -nH 2>/dev/null | head -n 500 \
  > "$OUTPUT_DIR/ssh_related_logs_snippet.txt" || true

grep -R "sudo" /var/log -nH 2>/dev/null | head -n 500 \
  > "$OUTPUT_DIR/sudo_related_logs_snippet.txt" || true

# Archive & Permissions
tar -czf forensic_output_varlog.tar.gz -C "$OUTPUT_DIR" . 2>/dev/null || true

chown -R "$(id -u)":"$(id -g)" "$OUTPUT_DIR" 2>/dev/null || true
