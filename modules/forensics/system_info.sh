#!/usr/bin/env bash
# /modules/forensics/system_info.sh
# Comprehensive host enumeration
# Usage: system_info.sh [TARGET_IP_OR_HOST]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/system_info"
mkdir -p "$OUTPUT_DIR"

ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"

_note_err() {
    local label="$1" ec="${2:-?}"
    echo "[ERROR] '$label' failed (exit $ec)" >> "$ERRORS_FILE"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"

TARGET="${1:-}"

# SECTION 1 — BASIC SYSTEM IDENTIFICATION

echo "[*] Collecting system identification..."

{
    uname -a
    echo
    cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null || true
    echo
    hostnamectl 2>/dev/null || true
    echo
    uptime
    echo
    arch 2>/dev/null || uname -m

} > "$OUTPUT_DIR/system_identity.txt" 2>"$ERR_DIR/s1_identity.err"
[ -s "$ERR_DIR/s1_identity.err" ] || rm -f "$ERR_DIR/s1_identity.err"

# SECTION 2 — PLATFORM-SPECIFIC HARDWARE ENUMERATION

echo "[*] Enumerating hardware..."

if [ "$(uname -s)" = "Darwin" ]; then

    {
        system_profiler SPHardwareDataType SPNetworkDataType 2>/dev/null || true
        networksetup -listallhardwareports 2>/dev/null || true
        scutil --get ComputerName 2>/dev/null || true
        ifconfig -a
        route -n get default 2>/dev/null || netstat -rn
        sysctl -a 2>/dev/null | grep machdep.cpu || true
        sysctl hw.memsize 2>/dev/null || true
    } > "$OUTPUT_DIR/hardware_macos.txt" 2>"$ERR_DIR/s2_hw.err"

else

    {
        lscpu 2>/dev/null || cat /proc/cpuinfo
        echo
        lsblk -a 2>/dev/null || true
        blkid 2>/dev/null    || true
        echo
        lspci -vmm 2>/dev/null || true
        lsusb 2>/dev/null      || true
        echo
        dmidecode -t system   2>/dev/null || true
        dmidecode -t baseboard 2>/dev/null || true
        dmidecode -t memory    2>/dev/null || true
        echo
        cat /proc/meminfo 2>/dev/null
        free -h 2>/dev/null || true
        echo
        df -h
        mount
    } > "$OUTPUT_DIR/hardware_linux.txt" 2>"$ERR_DIR/s2_hw.err"

fi

[ -s "$ERR_DIR/s2_hw.err" ] \
    && echo "[WARN] Section 2 (Hardware): see errors/s2_hw.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s2_hw.err"

# SECTION 3 — NETWORK ENUMERATION

echo "[*] Enumerating network state..."

{
    echo "=== Interface addresses ==="
    ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null

    echo
    echo "=== Link state ==="
    ip -br link 2>/dev/null || true

    echo
    echo "=== Routes ==="
    ip route show 2>/dev/null || netstat -rn

    echo
    echo "=== ARP / neighbours ==="
    ip neigh show 2>/dev/null || arp -a

    echo
    echo "=== Active sockets ==="
    ss -tunap 2>/dev/null || netstat -tulpen 2>/dev/null

    echo
    echo "=== NetworkManager ==="
    nmcli device status  2>/dev/null || true
    nmcli connection show 2>/dev/null || true

    echo
    echo "=== Wireless ==="
    iw dev 2>/dev/null || iwconfig 2>/dev/null || true

    echo
    echo "=== Ethernet details ==="
    FIRST_IFACE=$(ip -o -4 addr show | awk '{print $2; exit}' 2>/dev/null)
    [ -n "$FIRST_IFACE" ] && ethtool "$FIRST_IFACE" 2>/dev/null || true
    FIRST_LINK=$(ip -o link show 2>/dev/null \
        | awk -F: '$0 !~ /lo/ { gsub(/ /,"",$2); print $2; exit }')
    [ -n "$FIRST_LINK" ] && ethtool -i "$FIRST_LINK" 2>/dev/null || true

} > "$OUTPUT_DIR/network_state.txt" 2>"$ERR_DIR/s3_net.err"
[ -s "$ERR_DIR/s3_net.err" ] \
    && echo "[WARN] Section 3 (Network): see errors/s3_net.err" >> "$ERRORS_FILE" \
    || rm -f "$ERR_DIR/s3_net.err"

# SECTION 4 — USERS, ACTIVITY & AUTH

echo "[*] Enumerating users and activity..."

{
    echo "=== Current users ==="
    w
    echo
    echo "=== Recent logins ==="
    last -n 10 2>/dev/null || true
    echo
    echo "=== /etc/passwd (all accounts) ==="
    getent passwd
    echo
    echo "=== Root-equivalent accounts ==="
    getent passwd root 2>/dev/null || true

} > "$OUTPUT_DIR/users_activity.txt" 2>"$ERR_DIR/s4_users.err"
[ -s "$ERR_DIR/s4_users.err" ] || rm -f "$ERR_DIR/s4_users.err"

# SECTION 5 — PROCESS, SERVICES & PERSISTENCE

echo "[*] Enumerating processes and persistence..."

{
    echo "=== Process tree ==="
    ps aux --forest 2>/dev/null || ps aux

    echo
    echo "=== Listening TCP sockets ==="
    ss -ltnp 2>/dev/null || true

    echo
    echo "=== User crontab ==="
    crontab -l 2>/dev/null || echo "(none)"

    echo
    echo "=== Home directories ==="
    ls -la /home 2>/dev/null || true

    echo
    echo "=== Storage ==="
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null \
        || blkid 2>/dev/null || true
    df -h

    echo
    echo "=== /etc/fstab ==="
    cat /etc/fstab 2>/dev/null || true

} > "$OUTPUT_DIR/processes_persistence.txt" 2>"$ERR_DIR/s5_procs.err"
[ -s "$ERR_DIR/s5_procs.err" ] || rm -f "$ERR_DIR/s5_procs.err"

# SECTION 6 — CREDENTIAL HUNTING

echo "[*] Hunting credentials and sensitive files..."

{
    echo "=== Password strings in /etc ==="
    grep -R "password" /etc 2>/dev/null | head -30 || true

    echo
    echo "=== Private keys and PEM files ==="
    find / -type f \( -name "id_rsa" -o -name "*.pem" -o -name "*.key" \) \
        2>/dev/null | head -20 || true

    echo
    echo "=== SUID binaries ==="
    find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null | head -30 || true

    echo
    echo "=== sudo -l ==="
    sudo -l 2>/dev/null || true

    echo
    echo "=== SSH config ==="
    grep -R "ssh" /etc/ssh 2>/dev/null || true

    echo
    echo "=== SSH established connections ==="
    ss -tunap 2>/dev/null | grep ssh || true

} > "$OUTPUT_DIR/credential_hunting.txt" 2>"$ERR_DIR/s6_creds.err"
[ -s "$ERR_DIR/s6_creds.err" ] || rm -f "$ERR_DIR/s6_creds.err"

# SECTION 7 — KERNEL & RECENT LOGS

echo "[*] Collecting kernel and journal entries..."

{
    echo "=== dmesg (first 60 lines) ==="
    dmesg 2>/dev/null | head -60 || true

    echo
    echo "=== Recent journal (last 50 lines) ==="
    journalctl -n 50 --no-pager 2>/dev/null || true

} > "$OUTPUT_DIR/kernel_journal.txt" 2>"$ERR_DIR/s7_logs.err"
[ -s "$ERR_DIR/s7_logs.err" ] || rm -f "$ERR_DIR/s7_logs.err"

# SECTION 8 — ACTIVE SCANNING (optional, if target supplied)

# Default target to local network if not supplied
if [ -z "$TARGET" ]; then
    TARGET=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4; exit}')
fi

if [ -n "$TARGET" ]; then

    echo "[*] Running active scans against target: $TARGET"
    echo "Target: $TARGET" > "$OUTPUT_DIR/scan_target.txt"

    command -v nmap >/dev/null 2>&1 && \
        nmap -Pn -sS -sV -O -p- \
            --script "default,safe,discovery" \
            -oA "$OUTPUT_DIR/nmap_full" \
            "$TARGET" 2>"$ERR_DIR/s8_nmap.err" \
        || _note_err "nmap full" $?
    [ -s "$ERR_DIR/s8_nmap.err" ] || rm -f "$ERR_DIR/s8_nmap.err"

    command -v masscan >/dev/null 2>&1 && \
        masscan -p1-65535 --rate=1000 "$TARGET" \
            -oL "$OUTPUT_DIR/masscan.out" 2>"$ERR_DIR/s8_masscan.err" \
        || _note_err "masscan" $?
    [ -s "$ERR_DIR/s8_masscan.err" ] || rm -f "$ERR_DIR/s8_masscan.err"

    # SMB / Windows enumeration
    command -v enum4linux >/dev/null 2>&1 && \
        enum4linux -a "$TARGET" > "$OUTPUT_DIR/enum4linux.out" 2>/dev/null || true
    command -v smbclient >/dev/null 2>&1 && \
        smbclient -L "//$TARGET" -N > "$OUTPUT_DIR/smbclient.out" 2>/dev/null || true

    # DNS & TLS
    command -v dig >/dev/null 2>&1 && \
        dig any "$TARGET" +noall +answer > "$OUTPUT_DIR/dig_any.out" 2>/dev/null || true
    command -v openssl >/dev/null 2>&1 && \
        openssl s_client -connect "$TARGET:443" \
            -servername "$TARGET" -brief \
            < /dev/null > "$OUTPUT_DIR/openssl_443.out" 2>/dev/null || true

    # HTTP banner
    command -v curl >/dev/null 2>&1 && \
        curl -I --max-time 10 "http://$TARGET" \
            > "$OUTPUT_DIR/curl_head.out" 2>/dev/null || true

    # Service-specific nmap scripts
    command -v nmap >/dev/null 2>&1 && \
        nmap -Pn -p 80,443,8080 \
            --script http-enum,http-vuln* \
            -oN "$OUTPUT_DIR/nmap_http" \
            "$TARGET" 2>/dev/null || true
    command -v nmap >/dev/null 2>&1 && \
        nmap -Pn -p 22 \
            --script ssh-auth-methods,ssh-hostkey \
            -oN "$OUTPUT_DIR/nmap_ssh" \
            "$TARGET" 2>/dev/null || true
    command -v nmap >/dev/null 2>&1 && \
        nmap -Pn -p 445 \
            --script smb* \
            -oN "$OUTPUT_DIR/nmap_smb" \
            "$TARGET" 2>/dev/null || true

else
    echo "[INFO] No target specified — active scanning skipped." \
        > "$OUTPUT_DIR/scan_target.txt"
fi

# ENVIRONMENT CAPTURE

env > "$OUTPUT_DIR/env.txt" 2>/dev/null || true

# ARCHIVE (contents only, no embedded absolute path)

ARCHIVE="$OUTPUT_DIR/system_info_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] System info collection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"