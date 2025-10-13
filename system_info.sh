#!/bin/bash
echo "=== Hostname & OS ==="
uname -a
lsb_release -a 2>/dev/null || cat /etc/os-release 2>/dev/null || true
echo "=== Uptime & Load ==="
uptime
echo "=== CPU ==="
lscpu 2>/dev/null || cat /proc/cpuinfo
echo "=== Memory ==="
free -h 2>/dev/null || head -n 5 /proc/meminfo
echo "=== Disks & Filesystems ==="
lsblk -a
df -hT
echo "=== Block device models ==="
for d in /sys/block/*/device/model 2>/dev/null; do echo "$d:"; cat "$d" 2>/dev/null; done || true
echo "=== PCI devices ==="
lspci 2>/dev/null || true
echo "=== USB devices ==="
lsusb 2>/dev/null || true
echo "=== DMI / BIOS (requires sudo) ==="
sudo dmidecode -t system 2>/dev/null || true
echo "=== Hardware summary (may require sudo) ==="
sudo lshw -short 2>/dev/null || true
echo "=== Kernel & Modules ==="
uname -r
lsmod
echo "=== Network interfaces & addresses ==="
ip -br addr
echo "=== Routes ==="
ip route show
echo "=== ARP / Neighbor cache ==="
ip neigh show
echo "=== Listening sockets / open ports ==="
ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true
echo "=== DNS configuration ==="
systemd-resolve --status 2>/dev/null || resolvectl status 2>/dev/null || cat /etc/resolv.conf 2>/dev/null || true
echo "=== Wireless info (if applicable) ==="
iwconfig 2>/dev/null || nmcli device wifi list 2>/dev/null || true
echo "=== Link settings for interfaces ==="
for iface in $(ls /sys/class/net); do echo "----- $iface -----"; ethtool "$iface" 2>/dev/null || true; done
echo "=== PCI drivers / kernel driver in use ==="
lspci -k 2>/dev/null || true
echo "=== ARP table ==="
arp -n 2>/dev/null || ip neigh show
echo "=== Temperature / sensors (if lm-sensors installed) ==="
sensors 2>/dev/null || true
echo "=== SMART status for disks (requires smartmontools & sudo) ==="
for dev in /dev/sd?; do echo "=== $dev ==="; sudo smartctl -a "$dev" 2>/dev/null || true; done
echo "=== Active network connections (summary) ==="
netstat -tunap 2>/dev/null || ss -tunap 2>/dev/null || true
echo "=== Top processes by CPU / Memory ==="
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 15
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 15
