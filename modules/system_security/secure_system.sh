#!/bin/sh
# ==============================================================================
# Linux System Hardening Script
# Purpose : Reduce attack surface via kernel hardening, service lockdown,
#           firewall rules, audit logging, and permission tightening
# WARNING : May break legacy apps, remote access, container workloads, or IR
# Requires: Root privileges
# ==============================================================================

echo "[*] Applying system hardening settings..."

# Kernel & Network Hardening (sysctl)

# Restrict access to kernel logs and symbols
sudo sysctl -w kernel.dmesg_restrict=1
sudo sysctl -w kernel.kptr_restrict=2

# Disable ICMP echo replies (anti-recon)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Enable reverse path filtering (anti-spoofing)
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1

# Disable source routing
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0

# Prevent NULL pointer dereference exploits
sudo sysctl -w vm.mmap_min_addr=65536

# Reload persistent sysctl settings if present
sudo sysctl -p 2>/dev/null || true

# File & Configuration Permissions Hardening

# Restrict OS banner files (info leakage)
sudo chmod 600 /etc/issue /etc/issue.net 2>/dev/null || true

# Restrict GRUB configuration (boot tampering)
sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# Protect SSH host private keys
sudo chmod 600 /etc/ssh/ssh_host_* 2>/dev/null || true
sudo chown root:root /etc/ssh/ssh_host_* 2>/dev/null || true
sudo setfacl -m o::--- /etc/ssh/ssh_host_* 2>/dev/null || true

# Disable High-Risk or Unused Network Services

# SNMP
sudo systemctl stop snmpd 2>/dev/null || true
sudo systemctl disable snmpd 2>/dev/null || true

# RPC / NFS
sudo systemctl stop rpcbind nfs-server 2>/dev/null || true
sudo systemctl disable rpcbind nfs-server 2>/dev/null || true

# Zeroconf / Multicast
sudo systemctl stop avahi-daemon 2>/dev/null || true
sudo systemctl disable avahi-daemon 2>/dev/null || true

# SMB / CIFS
sudo systemctl stop smb smbd nmbd 2>/dev/null || true
sudo systemctl disable smb smbd nmbd 2>/dev/null || true

# Printing services
sudo systemctl stop cups 2>/dev/null || true
sudo systemctl disable cups 2>/dev/null || true

# Firewall Configuration (UFW + iptables)

# Enable UFW if available
command -v ufw >/dev/null 2>&1 && sudo ufw --force enable
command -v ufw >/dev/null 2>&1 && sudo ufw default deny incoming
command -v ufw >/dev/null 2>&1 && sudo ufw default allow outgoing

# Block common lateral movement ports
command -v ufw >/dev/null 2>&1 && \
sudo ufw deny proto tcp from any to any port 137,138,139,445,111,2049,161,162

# iptables hardening (fallback / additive)
sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP 2>/dev/null || true
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
sudo iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true

sudo iptables -P INPUT DROP 2>/dev/null || true
sudo iptables -P FORWARD DROP 2>/dev/null || true
sudo iptables -P OUTPUT ACCEPT 2>/dev/null || true

# Persist firewall rules
sudo iptables-save | sudo tee /etc/iptables.rules 2>/dev/null || true

# firewalld (RHEL-based systems)

command -v firewall-cmd >/dev/null 2>&1 && \
sudo firewall-cmd --permanent --add-service=http --add-service=https >/dev/null 2>&1 || true

command -v firewall-cmd >/dev/null 2>&1 && \
sudo firewall-cmd --permanent --remove-service=snmp >/dev/null 2>&1 || true

command -v firewall-cmd >/dev/null 2>&1 && \
sudo firewall-cmd --reload >/dev/null 2>&1 || true

# Audit & Logging Hardening

# Install and enable auditd
sudo apt-get install -y --no-install-recommends auditd 2>/dev/null || true
sudo systemctl enable auditd 2>/dev/null || true
sudo systemctl start auditd 2>/dev/null || true

# Lock audit configuration
sudo auditctl -e 1 2>/dev/null || true

# Watch SSH configuration for changes
sudo auditctl -w /etc/ssh/sshd_config -p wa -k ssh_config_changes 2>/dev/null || true

# Account & Credential Protection

# Restrict root home directory
sudo chmod 700 /root 2>/dev/null || true

# Protect private SSH keys
sudo find /home -maxdepth 2 -type f -name "id_rsa" -exec chmod 600 {} \; 2>/dev/null || true

# Remove all SUID binaries (⚠ aggressive)
sudo find / -xdev -type f -perm -u=s -exec chmod u-s {} \; 2>/dev/null || true

# Protect shadow files
sudo chmod o-rwx /etc/shadow /etc/gshadow 2>/dev/null || true

# Lock non-interactive/system accounts
sudo usermod -L guest 2>/dev/null || true
sudo usermod -L daemon 2>/dev/null || true

# Lock root password (forces sudo-only access)
sudo passwd -l root 2>/dev/null || true

# Mandatory Access Control

# Enable AppArmor (Debian/Ubuntu)
command -v apparmor_parser >/dev/null 2>&1 && \
sudo systemctl enable apparmor 2>/dev/null || true

# Enforce SELinux (RHEL-based)
command -v selinuxenabled >/dev/null 2>&1 && \
sudo setenforce 1 2>/dev/null || true

# Cleanup & Log Management

# Remove unused cron jobs
sudo rm -f /etc/cron.d/unused_* 2>/dev/null || true

# Reload systemd units
sudo systemctl daemon-reload 2>/dev/null || true

# Rotate and prune logs (retain 7 days)
sudo journalctl --rotate 2>/dev/null || true
sudo journalctl --vacuum-time=7d 2>/dev/null || true

echo "[+] System hardening complete."

sleep 10
# ===========================================================================
# ===========================================================================
#
# Revert system hardening and make everything Normal
#
# ===========================================================================
# ===========================================================================

echo "Reverting system hardening changes..."

# ===========================================================================
# Revert sysctl (Kernel & Network) Hardening
# ===========================================================================
# Restore permissive kernel and network defaults

sysctl -w kernel.dmesg_restrict=0
sysctl -w kernel.kptr_restrict=0

sysctl -w net.ipv4.icmp_echo_ignore_all=0
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0

sysctl -w net.ipv4.conf.all.accept_source_route=1
sysctl -w net.ipv4.conf.default.accept_source_route=1

sysctl -w net.ipv4.conf.all.accept_redirects=1
sysctl -w net.ipv4.conf.default.accept_redirects=1
sysctl -w net.ipv4.conf.all.send_redirects=1
sysctl -w net.ipv4.conf.default.send_redirects=1

sysctl -w vm.mmap_min_addr=0

# Reload sysctl configuration files (if present)
sysctl --system 2>/dev/null || true

# ===========================================================================
# Restore Default Permissions & SUID Bits
# ===========================================================================
# NOTE: Restoring SUID binaries increases privilege escalation risk

chmod u+s /usr/lib/polkit-1/polkit-agent-helper-1
systemctl restart polkit

chmod u+s /bin/ping
chmod u+s /bin/mount
chmod u+s /bin/umount
chmod u+s /usr/bin/sudo
chmod u+s /usr/bin/passwd
chmod u+s /usr/bin/chsh
chmod u+s /usr/bin/chfn
chmod u+s /usr/bin/gpasswd
chmod u+s /usr/lib/dbus-1.0/dbus-daemon-launch-helper

# Restore standard file permissions
chmod 644 /etc/issue /etc/issue.net 2>/dev/null || true
chmod 644 /boot/grub/grub.cfg 2>/dev/null || true

# SSH host keys: permissions, ownership, ACLs
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chown root:root /etc/ssh/ssh_host_* 2>/dev/null || true
if command -v setfacl >/dev/null 2>&1; then
    setfacl -b /etc/ssh/ssh_host_* 2>/dev/null
fi

# Restore root home permissions
chmod 755 /root 2>/dev/null || true

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
  if command -v systemctl >/dev/null 2>&1; then
      systemctl enable "$svc" 2>/dev/null || true
      systemctl start "$svc" 2>/dev/null || true
  fi
done

# ===========================================================================
# Reset Firewall & iptables
# ===========================================================================
# WARNING: This fully opens inbound, outbound, and forwarded traffic

# Disable UFW if present
if command -v ufw >/dev/null 2>&1; then
  ufw --force disable
fi

# Flush all iptables rules and chains
if command -v iptables >/dev/null 2>&1; then
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
fi

# Save empty rule set (distribution-dependent)
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

# ===========================================================================
# Disable Security Frameworks
# ===========================================================================
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable auditd 2>/dev/null || true
    systemctl stop auditd 2>/dev/null || true
    systemctl restart polkit 2>/dev/null || true
fi

# AppArmor
if command -v systemctl >/dev/null 2>&1 && \
   systemctl list-unit-files 2>/dev/null | grep -q apparmor; then
    systemctl disable apparmor
fi

# SELinux (if present)
if command -v selinuxenabled >/dev/null 2>&1; then
  setenforce 0 2>/dev/null || true
fi

# ===========================================================================
# Re-enable Locked System Accounts
# ===========================================================================
# WARNING: Unlocking system accounts may be unsafe

usermod -U guest 2>/dev/null || true
usermod -U daemon 2>/dev/null || true

# ===========================================================================
# Reinstall Core Privilege & Policy Packages
# ===========================================================================
if command -v apt-get >/dev/null 2>&1; then
    apt update
    apt install --reinstall -y passwd util-linux dbus
elif command -v dnf >/dev/null; then
    dnf reinstall -y util-linux dbus
elif command -v pacman >/dev/null; then
    pacman -S --noconfirm util-linux dbus
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart polkit 2>/dev/null || true
fi

# ===========================================================================
# Final Notice
# ===========================================================================
echo "System hardening reverted."
echo "A reboot is strongly recommended."
