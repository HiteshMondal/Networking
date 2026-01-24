#!/bin/sh
###############################################################################
# Universal Unix / Linux / macOS Enumeration Script
# Purpose : Host inventory, network state, security posture, and optional
#           penetration-testing style enumeration against a target
# Usage   : ./enum.sh [TARGET]
# WARNING : Contains noisy scans and privilege-requiring commands
###############################################################################

# BASIC SYSTEM IDENTIFICATION

uname -a
cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null || true
hostnamectl 2>/dev/null || true
uptime
arch 2>/dev/null || uname -m

# PLATFORM-SPECIFIC ENUMERATION

if [ "$(uname -s)" = "Darwin" ]; then
  # macOS ENUMERATION

  system_profiler SPHardwareDataType SPNetworkDataType
  networksetup -listallhardwareports
  scutil --get ComputerName 2>/dev/null || true

  ifconfig -a
  route -n get default 2>/dev/null || netstat -rn

  # CPU & memory details
  sysctl -a | grep machdep.cpu 2>/dev/null || true
  sysctl hw.memsize 2>/dev/null || true

else
  # LINUX ENUMERATION

  lscpu 2>/dev/null || cat /proc/cpuinfo
  lsblk -a 2>/dev/null
  blkid 2>/dev/null || true

  lspci -vmm 2>/dev/null || true
  lsusb 2>/dev/null || true

  # Hardware / firmware info (requires root)
  sudo dmidecode -t system 2>/dev/null || true
  sudo dmidecode -t baseboard 2>/dev/null || true
  sudo dmidecode -t memory 2>/dev/null || true

  cat /proc/meminfo 2>/dev/null
  free -h 2>/dev/null || true

  df -h
  mount
fi

# NETWORK ENUMERATION (COMMON)

ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null
ip -br link 2>/dev/null || true
ip route show 2>/dev/null || netstat -rn
ip neigh show 2>/dev/null || arp -a

# Listening ports + owning processes
ss -tunap 2>/dev/null || netstat -tulpen 2>/dev/null

# NetworkManager (if present)
nmcli device status 2>/dev/null || true
nmcli connection show 2>/dev/null || true

# Wireless
iw dev 2>/dev/null || iwconfig 2>/dev/null || true

# Ethernet driver & capabilities
ethtool $(ip -o -4 addr show | awk '{print $2; exit}') 2>/dev/null || true
ethtool -i $(ip -o link show | awk -F: '$0!~/lo/ {gsub(/ /,"",$2); print $2; exit}') 2>/dev/null || true

# USERS, LOGS & KERNEL

getent passwd root 2>/dev/null || true
dmesg | head -n 60 2>/dev/null || true
journalctl -n 50 --no-pager 2>/dev/null || true

# PENETRATION TESTING / DEEP ENUMERATION SECTION
# NOTE: This section is intentionally noisy

uname -a
cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null || true
hostname
id
whoami
uptime

# USER ACTIVITY & AUTH

w
last -n 10 2>/dev/null || true

# NETWORK STATE (AGGRESSIVE)

ip -o -4 addr show scope global
ip addr show
ip route show

ss -tunap 2>/dev/null || netstat -tulpen 2>/dev/null || true

iptables -L 2>/dev/null || nft list ruleset 2>/dev/null || true

arp -an
ip neigh show
route -n 2>/dev/null || true

# STORAGE & HARDWARE (REPEAT FOR STANDALONE EXECUTION)

lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null || blkid 2>/dev/null || true
lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null || true
free -h 2>/dev/null || cat /proc/meminfo 2>/dev/null || true
df -h

sudo dmidecode -t system 2>/dev/null || true
sudo dmidecode -t memory 2>/dev/null || true
cat /etc/fstab 2>/dev/null || true

# PROCESS, SERVICES & PERSISTENCE

ps aux --forest
ss -ltnp 2>/dev/null || true
netstat -tulpen 2>/dev/null || true

crontab -l 2>/dev/null || true
ls -la /home 2>/dev/null || true

# USERS & CREDENTIAL HUNTING (HIGH SIGNAL)

getent passwd
cat /etc/passwd

grep -R "password" /etc 2>/dev/null || true

find / -type f \( -name "id_rsa" -o -name "*.pem" -o -name "*.key" \) 2>/dev/null || true
find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null || true

sudo -l 2>/dev/null || true
grep -R "ssh" /etc/ssh 2>/dev/null || true
ss -tunap | grep ssh || true

# TARGET SELECTION

TARGET="$1"

# Default to local interface network if no target supplied
if [ -z "$TARGET" ]; then
  TARGET=$(ip -o -4 addr show scope global | awk '{print $4; exit}')
fi

echo "Target: $TARGET"

# ACTIVE SCANNING (TOOLS MUST BE INSTALLED)

command -v nmap >/dev/null 2>&1 && \
  nmap -Pn -sS -sV -O -p- --script "default,safe,discovery" -oA nmap_full "$TARGET" || true

command -v masscan >/dev/null 2>&1 && \
  masscan -p1-65535 --rate=1000 "$TARGET" -oL masscan.out || true

# SMB / WINDOWS ENUMERATION

command -v enum4linux >/dev/null 2>&1 && enum4linux -a "$TARGET" > enum4linux.out || true
command -v smbclient >/dev/null 2>&1 && smbclient -L "//$TARGET" -N > smbclient.out 2>&1 || true
command -v smbmap >/dev/null 2>&1 && smbmap -H "$TARGET" -o smbmap.out || true

# SNMP / LDAP

command -v snmpwalk >/dev/null 2>&1 && \
  snmpwalk -v2c -c public "$TARGET" > snmpwalk.out 2>/dev/null || true

command -v ldapsearch >/dev/null 2>&1 && \
  ldapsearch -x -h "$TARGET" -b "" -s base "(objectclass=*)" > ldapsearch.out 2>/dev/null || true

# WEB ENUMERATION

command -v curl >/dev/null 2>&1 && \
  curl -I --max-time 10 "http://$TARGET" > curl_head.out 2>/dev/null || true

command -v nikto >/dev/null 2>&1 && \
  nikto -h "http://$TARGET" -o nikto.out || true

command -v gobuster >/dev/null 2>&1 && \
  gobuster dir -u "http://$TARGET" \
  -w /usr/share/wordlists/dirb/common.txt -o gobuster.out || true

# SERVICE-SPECIFIC NMAP

command -v nmap >/dev/null 2>&1 && \
  nmap -Pn -p 80,443,8080 --script http-enum,http-vuln* -oN nmap_http "$TARGET" || true

command -v nmap >/dev/null 2>&1 && \
  nmap -Pn -p 22 --script ssh-auth-methods,ssh-hostkey -oN nmap_ssh "$TARGET" || true

command -v nmap >/dev/null 2>&1 && \
  nmap -Pn -p 445 --script smb* -oN nmap_smb "$TARGET" || true

# DNS & TLS

command -v dig >/dev/null 2>&1 && dig any "$TARGET" +noall +answer > dig_any.out || true
command -v host >/dev/null 2>&1 && host "$TARGET" > host.out || true

command -v openssl >/dev/null 2>&1 && \
  openssl s_client -connect "$TARGET:443" -servername "$TARGET" -brief \
  < /dev/null > openssl_443.out 2>/dev/null || true

# ENVIRONMENT & LOGS

env > env.out
dmesg | head -n 200 2>/dev/null || true
journalctl -n 200 --no-pager 2>/dev/null || true
