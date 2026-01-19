#!/bin/sh
mkdir -p forensic_output
uname -a > forensic_output/uname.txt
hostnamectl > forensic_output/hostnamectl.txt 2>/dev/null || hostname > forensic_output/hostname.txt
whoami > forensic_output/whoami.txt
id > forensic_output/id.txt
uptime > forensic_output/uptime.txt
dmesg --ctime > forensic_output/dmesg.txt 2>/dev/null || dmesg > forensic_output/dmesg.txt
journalctl --no-pager --output=short-precise > forensic_output/journalctl_all.txt 2>/dev/null || true
journalctl -u ssh --no-pager > forensic_output/journalctl_ssh.txt 2>/dev/null || true
journalctl -k --no-pager > forensic_output/journalctl_kernel.txt 2>/dev/null || true
cp /var/log/auth.log forensic_output/ 2>/dev/null || cp /var/log/secure forensic_output/ 2>/dev/null || true
cp -r /var/log/forensic_varlog 2>/dev/null || true
cp /var/log/syslog forensic_output/ 2>/dev/null || true
cp /var/log/messages forensic_output/ 2>/dev/null || true
ls -l /var/log > forensic_output/var_log_listing.txt 2>/dev/null || true
lastlog > forensic_output/lastlog.txt 2>/dev/null || true
faillog -v > forensic_output/faillog.txt 2>/dev/null || true
ausearch --start today > forensic_output/ausearch_today.log 2>/dev/null || ausearch > forensic_output/ausearch_all.log 2>/dev/null || true
auditctl -l > forensic_output/audit_rules.txt 2>/dev/null || true
ausearch -m USER_LOGIN -ts today > forensic_output/ausearch_user_login.txt 2>/dev/null || true
cp /var/log/audit/audit.log forensic_output/ 2>/dev/null || true
ps auxww > forensic_output/ps_aux.txt
ss -tunap > forensic_output/ss_tunap.txt 2>/dev/null || netstat -tulpen > forensic_output/netstat_tulpen.txt 2>/dev/null || true
lsof -i > forensic_output/lsof_network.txt 2>/dev/null || true
ip -s link > forensic_output/ip_stats.txt 2>/dev/null || ip link > forensic_output/ip_link.txt 2>/dev/null || true
ip -4 addr show > forensic_output/ip_addr.txt
ip route show > forensic_output/ip_route.txt
iptables-save > forensic_output/iptables_rules.txt 2>/dev/null || nft list ruleset > forensic_output/nft_rules.txt 2>/dev/null || true
conntrack -L > forensic_output/conntrack.txt 2>/dev/null || true
tcpdump -nn -s 0 -c 1000 -w forensic_output/tcpdump_capture.pcap 2>/dev/null || tshark -i any -c 1000 -w forensic_output/tshark_capture.pcap 2>/dev/null || true
ss -s > forensic_output/ss_summary.txt 2>/dev/null || true
cat /proc/net/tcp > forensic_output/proc_net_tcp.txt 2>/dev/null || true
cat /proc/net/udp > forensic_output/proc_net_udp.txt 2>/dev/null || true
cat /proc/net/arp > forensic_output/proc_net_arp.txt 2>/dev/null || true
netstat -s > forensic_output/netstat_s.txt 2>/dev/null || true
lsmod > forensic_output/lsmod.txt 2>/dev/null || true
mount > forensic_output/mounts.txt
df -h > forensic_output/df.txt
find /var/log -type f -maxdepth 2 -printf "%p %s %TY-%Tm-%Td %TH:%TM:%TS\n" > forensic_output/varlog_files_listing.txt 2>/dev/null || true
cp /etc/ssh/sshd_config forensic_output/ 2>/dev/null || true
cp /etc/hosts forensic_output/ 2>/dev/null || true
cp /etc/issue* forensic_output/ 2>/dev/null || true
cp /etc/passwd forensic_output/ 2>/dev/null || true
cp /etc/group forensic_output/ 2>/dev/null || true
cp /var/log/apt/history.log forensic_output/ 2>/dev/null || cp /var/log/dpkg.log* forensic_output/ 2>/dev/null || cp /var/log/yum.log* forensic_output/ 2>/dev/null || true
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 200 > forensic_output/top_procs.txt
ss -ltnp > forensic_output/listening_tcp.txt 2>/dev/null || netstat -ltnp > forensic_output/listening_tcp_netstat.txt 2>/dev/null || true
ss -lunp > forensic_output/listening_udp.txt 2>/dev/null || netstat -lunp > forensic_output/listening_udp_netstat.txt 2>/dev/null || true
crontab -l > forensic_output/crontab_current.txt 2>/dev/null || true
ls -la /etc/cron* > forensic_output/cron_dirs.txt 2>/dev/null || true
grep -R "ssh" /var/log -nH 2>/dev/null | head -n 500 > forensic_output/ssh_related_logs_snippet.txt 2>/dev/null || true
grep -R "sudo" /var/log -nH 2>/dev/null | head -n 500 > forensic_output/sudo_related_logs_snippet.txt 2>/dev/null || true
tar -czf forensic_output_varlog.tar.gz -C forensic_output . 2>/dev/null || true
chown -R $(id -u):$(id -g) forensic_output 2>/dev/null || true
