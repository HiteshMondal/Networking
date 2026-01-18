#!/bin/sh
echo "Reverting system hardening changes..."

# --- Revert sysctl changes ---
sudo sysctl -w kernel.dmesg_restrict=0
sudo sysctl -w kernel.kptr_restrict=0
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.accept_source_route=1
sudo sysctl -w net.ipv4.conf.default.accept_source_route=1
sudo sysctl -w net.ipv4.conf.all.accept_redirects=1
sudo sysctl -w net.ipv4.conf.default.accept_redirects=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=1
sudo sysctl -w net.ipv4.conf.default.send_redirects=1
sudo sysctl -w vm.mmap_min_addr=0

sudo sysctl -p || true

# --- Restore default permissions ---
sudo chmod u+s /usr/lib/polkit-1/polkit-agent-helper-1
sudo systemctl restart polkit
sudo chmod u+s /bin/ping
sudo chmod u+s /bin/mount
sudo chmod u+s /bin/umount
sudo chmod u+s /usr/bin/sudo
sudo chmod u+s /usr/bin/passwd
sudo chmod u+s /usr/bin/chsh
sudo chmod u+s /usr/bin/chfn
sudo chmod u+s /usr/bin/gpasswd
sudo chmod u+s /usr/lib/dbus-1.0/dbus-daemon-launch-helper
sudo chmod u+s /usr/lib/polkit-1/polkit-agent-helper-1
sudo chmod 644 /etc/issue /etc/issue.net 2>/dev/null || true
sudo chmod 644 /boot/grub/grub.cfg 2>/dev/null || true
sudo chmod 644 /etc/ssh/ssh_host_* 2>/dev/null || true
sudo chown root:root /etc/ssh/ssh_host_* 2>/dev/null || true
sudo setfacl -b /etc/ssh/ssh_host_* 2>/dev/null || true
sudo chmod 755 /root 2>/dev/null || true

# --- Re-enable services that were disabled ---
for svc in snmpd rpcbind nfs-server avahi-daemon smb smbd nmbd cups; do
  sudo systemctl enable $svc 2>/dev/null || true
  sudo systemctl start $svc 2>/dev/null || true
done

# --- Reset firewall / iptables ---
if command -v ufw >/dev/null 2>&1; then
  sudo ufw --force disable
fi

sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables-save | sudo tee /etc/iptables.rules >/dev/null

# --- Revert auditd, AppArmor, SELinux changes ---
sudo systemctl disable auditd 2>/dev/null || true
sudo systemctl stop auditd 2>/dev/null || true
command -v apparmor_parser >/dev/null 2>&1 && sudo systemctl disable apparmor 2>/dev/null || true
command -v selinuxenabled >/dev/null 2>&1 && sudo setenforce 0 2>/dev/null || true

# --- Re-enable locked users ---
sudo usermod -U guest 2>/dev/null || true
sudo usermod -U daemon 2>/dev/null || true
sudo passwd -u root 2>/dev/null || true

sudo apt update
sudo apt install --reinstall pkexec polkitd sudo passwd mount util-linux dbus -y
sudo systemctl restart polkit

echo "System hardening reverted. Please reboot."
