#!/bin/sh
mkdir -p suspicious_scan
date --iso-8601=seconds > suspicious_scan/run_timestamp.txt 2>/dev/null || date > suspicious_scan/run_timestamp.txt
uname -a > suspicious_scan/uname.txt
whoami > suspicious_scan/whoami.txt
id > suspicious_scan/id.txt
ps aux --sort=-%mem > suspicious_scan/ps_aux.txt
ss -tunap > suspicious_scan/ss_tunap_raw.txt 2>/dev/null || netstat -tulpen > suspicious_scan/netstat_raw.txt 2>/dev/null
ss -tunapH | awk '{print $1" "$5" "$6" "$7}' > suspicious_scan/ss_connections.txt 2>/dev/null || true
ss -tunapH | awk '{print $5}' | sed -E 's/:[0-9]+$//' | sed '/^$/d' | sort -u > suspicious_scan/remote_ips.txt 2>/dev/null || true
if [ -s suspicious_scan/remote_ips.txt ]; then
  cat suspicious_scan/remote_ips.txt | grep -vE '^(127\.|::1|localhost|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' > suspicious_scan/remote_ips_public.txt 2>/dev/null || cp suspicious_scan/remote_ips.txt suspicious_scan/remote_ips_public.txt 2>/dev/null
  cat suspicious_scan/remote_ips_public.txt | xargs -n1 -P10 -I{} sh -c 'echo "=== {} ===" > suspicious_scan/whois_{} 2>/dev/null; whois {} >> suspicious_scan/whois_{} 2>/dev/null; nslookup {} >> suspicious_scan/whois_{} 2>/dev/null; curl -m 8 -sS "http://ipinfo.io/{}/json" >> suspicious_scan/whois_{} 2>/dev/null' || true
fi
lsof -i -P -n > suspicious_scan/lsof_i.txt 2>/dev/null || true
netstat -s > suspicious_scan/netstat_s.txt 2>/dev/null || true
cat /proc/net/tcp > suspicious_scan/proc_net_tcp.txt 2>/dev/null || true
cat /proc/net/udp > suspicious_scan/proc_net_udp.txt 2>/dev/null || true
if command -v ss >/dev/null 2>&1; then
  ss -o state established '( sport != :22 )' > suspicious_scan/established_not_ssh.txt 2>/dev/null || true
fi
awk '/LISTEN|ESTAB|ESTABLISHED/{print $0}' suspicious_scan/ss_tunap_raw.txt > suspicious_scan/interesting_connections.txt 2>/dev/null || true
awk '{if($7 ~ /^[0-9]+,/) print $0}' suspicious_scan/ss_tunap_raw.txt > suspicious_scan/connections_with_pid.txt 2>/dev/null || true
cat suspicious_scan/connections_with_pid.txt | awk '{print $7}' | sed 's/,.*$//' | sed -E 's/[a-zA-Z\/]//g' | tr -d '[]' | sort -u > suspicious_scan/pids_with_network.txt 2>/dev/null || true
if [ -s suspicious_scan/pids_with_network.txt ]; then
  for pid in $(cat suspicious_scan/pids_with_network.txt); do
    if [ -d "/proc/$pid" ]; then
      readlink -f /proc/$pid/exe > suspicious_scan/pid_${pid}_exe 2>/dev/null || true
      ls -l /proc/$pid/fd > suspicious_scan/pid_${pid}_fds 2>/dev/null || true
      ps -p $pid -o pid,ppid,uid,gid,etimes,cmd > suspicious_scan/pid_${pid}_ps.txt 2>/dev/null || true
      exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
      if [ -n "$exe" ]; then
        md5sum "$exe" 2>/dev/null > suspicious_scan/pid_${pid}_exe_hash.txt || true
        sha256sum "$exe" 2>/dev/null >> suspicious_scan/pid_${pid}_exe_hash.txt || true
      fi
    fi
  done
fi
cron -l > suspicious_scan/crontab_root.txt 2>/dev/null || crontab -l > suspicious_scan/crontab.txt 2>/dev/null || true
ls -la /etc/cron* > suspicious_scan/cron_dirs.txt 2>/dev/null || true
systemctl list-timers --all > suspicious_scan/systemd_timers.txt 2>/dev/null || true
systemctl list-unit-files --state=enabled > suspicious_scan/systemd_enabled_units.txt 2>/dev/null || true
grep -R "curl -s" /etc -nH 2>/dev/null | head -n 200 > suspicious_scan/curl_exec_in_etc.txt 2>/dev/null || true
find /etc/systemd/system /lib/systemd/system -type f -name '*.service' -exec grep -I -nH 'ExecStart' {} \; 2>/dev/null | head -n 200 > suspicious_scan/systemd_execstarts.txt || true
find /home /tmp /var/tmp /dev/shm -type f -mtime -7 -ls > suspicious_scan/recent_tmp_files.txt 2>/dev/null || true
find / -type f -perm -4000 -o -perm -2000 -ls 2>/dev/null > suspicious_scan/suid_sgid_files.txt || true
ps -eo pid,user,group,etime,cmd --sort=-etime | head -n 200 > suspicious_scan/top_old_procs.txt
if command -v chkrootkit >/dev/null 2>&1; then
  chkrootkit > suspicious_scan/chkrootkit.txt 2>/dev/null || true
fi
if command -v rkhunter >/dev/null 2>&1; then
  rkhunter --checkall --sk --nolog > suspicious_scan/rkhunter.txt 2>/dev/null || true
fi
ss -tunap | awk '{print $5}' | sed -E 's/:[0-9]+$//' | sort | uniq -c | sort -nr > suspicious_scan/remote_ip_counts.txt 2>/dev/null || true
find / -iname "*ssh*" -type f -mtime -7 -ls 2>/dev/null > suspicious_scan/recent_ssh_related_files.txt || true
grep -R "wget " /etc /home /root 2>/dev/null | head -n 200 > suspicious_scan/wget_exec_in_configs.txt || true
ps -eo pid,cmd > suspicious_scan/all_pids_cmds.txt
tar -czf suspicious_scan_archive.tar.gz suspicious_scan 2>/dev/null || true
