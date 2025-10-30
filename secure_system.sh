#!/bin/sh
sudo sysctl -w kernel.dmesg_restrict=1
sudo sysctl -w kernel.kptr_restrict=2
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w vm.mmap_min_addr=65536
sudo sysctl -p 2>/dev/null || true
sudo chmod 600 /etc/issue /etc/issue.net 2>/dev/null || true
sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
sudo chmod 600 /etc/ssh/ssh_host_* 2>/dev/null || true
sudo chown root:root /etc/ssh/ssh_host_* 2>/dev/null || true
sudo setfacl -m o::--- /etc/ssh/ssh_host_* 2>/dev/null || true
sudo systemctl stop snmpd 2>/dev/null || true
sudo systemctl disable snmpd 2>/dev/null || true
sudo systemctl stop rpcbind 2>/dev/null || true
sudo systemctl disable rpcbind 2>/dev/null || true
sudo systemctl stop nfs-server 2>/dev/null || true
sudo systemctl disable nfs-server 2>/dev/null || true
sudo systemctl stop avahi-daemon 2>/dev/null || true
sudo systemctl disable avahi-daemon 2>/dev/null || true
sudo systemctl stop smb smbd nmbd 2>/dev/null || true
sudo systemctl disable smb smbd nmbd 2>/dev/null || true
sudo systemctl stop cups 2>/dev/null || true
sudo systemctl disable cups 2>/dev/null || true
command -v ufw >/dev/null 2>&1 && sudo ufw --force enable
command -v ufw >/dev/null 2>&1 && sudo ufw default deny incoming
command -v ufw >/dev/null 2>&1 && sudo ufw default allow outgoing
command -v ufw >/dev/null 2>&1 && sudo ufw deny proto tcp from any to any port 137,138,139,445,111,2049,161,162
sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP 2>/dev/null || true
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
sudo iptables -P INPUT DROP 2>/dev/null || true
sudo iptables -P FORWARD DROP 2>/dev/null || true
sudo iptables -P OUTPUT ACCEPT 2>/dev/null || true
sudo iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
sudo iptables-save | sudo tee /etc/iptables.rules 2>/dev/null || true
command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --permanent --add-service=http --add-service=https >/dev/null 2>&1 || true
command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --permanent --remove-service=snmp >/dev/null 2>&1 || true
command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --reload >/dev/null 2>&1 || true
sudo apt-get install -y --no-install-recommends auditd 2>/dev/null || true
sudo systemctl enable auditd 2>/dev/null || true
sudo systemctl start auditd 2>/dev/null || true
sudo auditctl -e 1 2>/dev/null || true
sudo auditctl -w /etc/ssh/sshd_config -p wa -k ssh_config_changes 2>/dev/null || true
sudo chmod 700 /root 2>/dev/null || true
sudo find /home -maxdepth 2 -type f -name "id_rsa" -exec chmod 600 {} \; 2>/dev/null || true
sudo find / -xdev -type f -perm -u=s -exec chmod u-s {} \; 2>/dev/null || true
sudo chmod o-rwx /etc/shadow /etc/gshadow 2>/dev/null || true
sudo usermod -L guest 2>/dev/null || true
sudo usermod -L daemon 2>/dev/null || true
sudo passwd -l root 2>/dev/null || true
command -v apparmor_parser >/dev/null 2>&1 && sudo systemctl enable apparmor 2>/dev/null || true
command -v selinuxenabled >/dev/null 2>&1 && sudo setenforce 1 2>/dev/null || true
sudo rm -f /etc/cron.d/unused_* 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true
sudo journalctl --rotate 2>/dev/null || true
sudo journalctl --vacuum-time=7d 2>/dev/null || true

