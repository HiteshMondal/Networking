#!/bin/sh
###############################################################################
# System Hardening Revert Script
# Purpose : Roll back previously applied Linux hardening measures
# WARNING : This script significantly reduces system security.
#           Use ONLY in lab, recovery, or controlled environments.
###############################################################################

echo "Reverting system hardening changes..."

# ===========================================================================
# Revert sysctl (Kernel & Network) Hardening
# ===========================================================================
# Restore permissive kernel and network defaults

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

# Reload sysctl configuration files (if present)
sudo sysctl -p 2>/dev/null || true

# ===========================================================================
# Restore Default Permissions & SUID Bits
# ===========================================================================
# NOTE: Restoring SUID binaries increases privilege escalation risk

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

# Restore standard file permissions
sudo chmod 644 /etc/issue /etc/issue.net 2>/dev/null || true
sudo chmod 644 /boot/grub/grub.cfg 2>/dev/null || true

# SSH host keys: permissions, ownership, ACLs
sudo chmod 644 /etc/ssh/ssh_host_* 2>/dev/null || true
sudo chown root:root /etc/ssh/ssh_host_* 2>/dev/null || true
sudo setfacl -b /etc/ssh/ssh_host_* 2>/dev/null || true

# Restore root home permissions
sudo chmod 755 /root 2>/dev/null || true

# ===========================================================================
# Re-enable Services Previously Disabled
# ===========================================================================
# WARNING: These services may expose network attack surfaces

SERVICES="
snmpd
rpcbind
nfs-server
avahi-daemon
smb
smbd
nmbd
cups
"

for svc in $SERVICES; do
  sudo systemctl enable "$svc" 2>/dev/null || true
  sudo systemctl start "$svc" 2>/dev/null || true
done

# ===========================================================================
# Reset Firewall & iptables
# ===========================================================================
# WARNING: This fully opens inbound, outbound, and forwarded traffic

# Disable UFW if present
if command -v ufw >/dev/null 2>&1; then
  sudo ufw --force disable
fi

# Flush all iptables rules and chains
sudo iptables -F
sudo iptables -X

# Set default policies to ACCEPT
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Save empty rule set (distribution-dependent)
sudo iptables-save | sudo tee /etc/iptables.rules >/dev/null

# ===========================================================================
# Disable Security Frameworks
# ===========================================================================
# Auditd
sudo systemctl disable auditd 2>/dev/null || true
sudo systemctl stop auditd 2>/dev/null || true

# AppArmor
if command -v apparmor_parser >/dev/null 2>&1; then
  sudo systemctl disable apparmor 2>/dev/null || true
fi

# SELinux (if present)
if command -v selinuxenabled >/dev/null 2>&1; then
  sudo setenforce 0 2>/dev/null || true
fi

# ===========================================================================
# Re-enable Locked System Accounts
# ===========================================================================
# WARNING: Unlocking system accounts may be unsafe

sudo usermod -U guest 2>/dev/null || true
sudo usermod -U daemon 2>/dev/null || true
sudo passwd -u root 2>/dev/null || true

# ===========================================================================
# Reinstall Core Privilege & Policy Packages
# ===========================================================================
sudo apt update
sudo apt install --reinstall \
  pkexec \
  polkitd \
  sudo \
  passwd \
  mount \
  util-linux \
  dbus \
  -y

sudo systemctl restart polkit

# ===========================================================================
# Final Notice
# ===========================================================================
echo "System hardening reverted."
echo "A reboot is strongly recommended."
