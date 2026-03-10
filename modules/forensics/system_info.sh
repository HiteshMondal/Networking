#!/usr/bin/env bash
# /modules/forensics/system_info.sh
# Comprehensive host enumeration
# Usage: system_info.sh [TARGET_IP_OR_HOST]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"
log_init "system_info"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/system_info"
mkdir -p "$OUTPUT_DIR"

ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"

_note_err() {
    local label="$1" ec="${2:-?}"
    local msg="[ERROR] '$label' failed (exit $ec)"
    echo "$msg" >> "$ERRORS_FILE"
    log_error "$msg"
}

_section_err() {
    local sec="$1" errfile="$2"
    if [ -s "$errfile" ]; then
        local msg="[WARN] $sec: see errors/$(basename "$errfile")"
        echo "$msg" >> "$ERRORS_FILE"
        log_warning "$msg"
    else
        rm -f "$errfile"
    fi
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"

TARGET="${1:-}"

# SECTION 1 — BASIC SYSTEM IDENTIFICATION

log_section "System Identification"
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
_section_err "Section 1 identity" "$ERR_DIR/s1_identity.err"

os_info=$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || uname -s)
log_metric "os" "$os_info" "label"
log_metric "hostname" "$(hostname 2>/dev/null || echo unknown)" "label"

# SECTION 2 — PLATFORM-SPECIFIC HARDWARE ENUMERATION

log_section "Hardware Enumeration"
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
        dmidecode -t system    2>/dev/null || true
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

_section_err "Section 2 hardware" "$ERR_DIR/s2_hw.err"

# Emit memory metric from /proc/meminfo if available
mem_total=$(awk '/^MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
log_metric "mem_total_kb" "$mem_total" "kb"

# SECTION 3 — NETWORK ENUMERATION

log_section "Network Enumeration"
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
    nmcli device status   2>/dev/null || true
    nmcli connection show 2>/dev/null || true

    echo
    echo "=== Wireless ==="
    iw dev 2>/dev/null || iwconfig 2>/dev/null || true

    echo
    echo "=== Ethernet details ==="
    FIRST_IFACE=$(ip -o -4 addr show 2>/dev/null | awk '{print $2; exit}')
    [ -n "$FIRST_IFACE" ] && ethtool "$FIRST_IFACE" 2>/dev/null || true
    FIRST_LINK=$(ip -o link show 2>/dev/null \
        | awk -F: '$0 !~ /lo/ { gsub(/ /,"",$2); print $2; exit }')
    [ -n "$FIRST_LINK" ] && ethtool -i "$FIRST_LINK" 2>/dev/null || true

} > "$OUTPUT_DIR/network_state.txt" 2>"$ERR_DIR/s3_net.err"
_section_err "Section 3 network" "$ERR_DIR/s3_net.err"

iface_count=$(ip -o link show 2>/dev/null | wc -l || echo 0)
log_metric "network_interfaces" "$iface_count" "count"

# SECTION 4 — USERS, ACTIVITY & AUTH

log_section "Users and Activity"
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
_section_err "Section 4 users" "$ERR_DIR/s4_users.err"

# Count local user accounts (UID >= 1000, non-system)
user_count=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null | wc -l || echo 0)
log_metric "local_user_accounts" "$user_count" "count"

# Flag any UID-0 accounts beyond root
uid0_extras=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
if [ -n "$uid0_extras" ]; then
    log_finding "critical" "Non-root account with UID 0 detected" \
        "accounts=$uid0_extras — possible backdoor account"
fi

# SECTION 5 — PROCESS, SERVICES & PERSISTENCE

log_section "Processes, Services and Persistence"
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
_section_err "Section 5 processes" "$ERR_DIR/s5_procs.err"

# SECTION 6 — CREDENTIAL HUNTING

log_section "Credential Hunting"
echo "[*] Hunting credentials and sensitive files..."

{
    echo "=== Password strings in /etc ==="
    grep -Rn "password" /etc 2>/dev/null | head -30 || true

    echo
    echo "=== Private keys and PEM files ==="
    find / -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
                   -o -name "*.pem" -o -name "*.key" \) \
        2>/dev/null | head -20 || true

    echo
    echo "=== SUID binaries ==="
    find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null | head -30 || true

    echo
    # Run sudo -l non-interactively; -n prevents password prompt (exits 1 if
    # a password would be required, rather than blocking on stdin).
    echo "=== sudo -l (non-interactive) ==="
    sudo -nl 2>/dev/null || echo "(sudo -l not available or requires password)"

    echo
    echo "=== SSH config ==="
    grep -R "ssh" /etc/ssh 2>/dev/null || true

    echo
    echo "=== SSH established connections ==="
    ss -tunap 2>/dev/null | grep ssh || true

} > "$OUTPUT_DIR/credential_hunting.txt" 2>"$ERR_DIR/s6_creds.err"
_section_err "Section 6 credentials" "$ERR_DIR/s6_creds.err"

# Emit findings for discovered private keys
key_count=$(find / -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
    -o -name "*.pem" -o -name "*.key" \) 2>/dev/null | wc -l | tr -d ' \n' || echo 0)
log_metric "private_key_files" "$key_count" "count"
if [ "$key_count" -gt 0 ]; then
    log_finding "high" "Private key / PEM files found on filesystem" \
        "count=$key_count — review credential_hunting.txt"
fi

# Count world-readable private key files as a higher severity
world_readable_keys=$(find / -type f \( -name "id_rsa" -o -name "id_ed25519" \
    -o -name "*.pem" -o -name "*.key" \) -perm /o+r 2>/dev/null | wc -l | tr -d ' \n' || echo 0)

if [ "$world_readable_keys" -gt 0 ]; then
    log_finding "critical" "World-readable private key / PEM files" \
        "count=$world_readable_keys — immediate remediation required"
fi

# SUID count metric
suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' \n' || echo 0)
log_metric "suid_binaries" "$suid_count" "count"
if [ "$suid_count" -gt 30 ]; then
    log_finding "medium" "Elevated SUID binary count" \
        "count=$suid_count — review credential_hunting.txt for unexpected entries"
fi

# SECTION 7 — KERNEL & RECENT LOGS

log_section "Kernel and Journal Entries"
echo "[*] Collecting kernel and journal entries..."

{
    echo "=== dmesg (first 60 lines) ==="
    dmesg 2>/dev/null | head -60 || true

    echo
    echo "=== Recent journal (last 50 lines) ==="
    journalctl -n 50 --no-pager 2>/dev/null || true

} > "$OUTPUT_DIR/kernel_journal.txt" 2>"$ERR_DIR/s7_logs.err"
_section_err "Section 7 kernel/journal" "$ERR_DIR/s7_logs.err"

# SECTION 8 — ACTIVE SCANNING (optional, if target supplied)

# Resolve TARGET to a plain host/IP — strip any CIDR prefix that might be
# returned when falling back to the interface address.
if [ -z "$TARGET" ]; then
    # ip -o -4 addr returns lines like:  2 eth0  inet 192.168.1.5/24 ...
    # We want only the address, not the prefix length.
    TARGET=$(ip -o -4 addr show scope global 2>/dev/null \
        | awk '{print $4; exit}' \
        | cut -d/ -f1)
fi

if [ -n "$TARGET" ]; then

    log_section "Active Scanning — $TARGET"
    echo "[*] Running active scans against target: $TARGET"
    echo "Target: $TARGET" > "$OUTPUT_DIR/scan_target.txt"

    if command -v nmap >/dev/null 2>&1; then
        # OS detection (-O) requires raw socket access.  Check for root or
        # the CAP_NET_RAW capability before enabling it so nmap doesn't error.
        NMAP_OS_FLAG=""
        if [ "$EUID" -eq 0 ] || \
                grep -q "^CapEff:.*[1-9]" /proc/self/status 2>/dev/null; then
            NMAP_OS_FLAG="-O"
        else
            log_warning "nmap: -O (OS detection) requires root/CAP_NET_RAW — skipped"
        fi

        # shellcheck disable=SC2086
        nmap -Pn -sS -sV $NMAP_OS_FLAG -p- \
            --script "default,safe,discovery" \
            -oA "$OUTPUT_DIR/nmap_full" \
            "$TARGET" 2>"$ERR_DIR/s8_nmap.err" \
            || _note_err "nmap full" $?
        _section_err "Section 8 nmap" "$ERR_DIR/s8_nmap.err"
    fi

    if command -v masscan >/dev/null 2>&1; then
        masscan -p1-65535 --rate=1000 "$TARGET" \
            -oL "$OUTPUT_DIR/masscan.out" 2>"$ERR_DIR/s8_masscan.err" \
            || _note_err "masscan" $?
        _section_err "Section 8 masscan" "$ERR_DIR/s8_masscan.err"
    fi

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
    if command -v nmap >/dev/null 2>&1; then
        nmap -Pn -p 80,443,8080 \
            --script http-enum,http-vuln* \
            -oN "$OUTPUT_DIR/nmap_http" \
            "$TARGET" 2>/dev/null || true
        nmap -Pn -p 22 \
            --script ssh-auth-methods,ssh-hostkey \
            -oN "$OUTPUT_DIR/nmap_ssh" \
            "$TARGET" 2>/dev/null || true
        nmap -Pn -p 445 \
            --script smb* \
            -oN "$OUTPUT_DIR/nmap_smb" \
            "$TARGET" 2>/dev/null || true
    fi

    log_metric "scan_target" "$TARGET" "label"

else
    echo "[INFO] No target specified — active scanning skipped." \
        > "$OUTPUT_DIR/scan_target.txt"
    log_info "Active scanning skipped — no target resolved"
fi

# ENVIRONMENT CAPTURE

env > "$OUTPUT_DIR/env.txt" 2>/dev/null || true

# ARCHIVE

output_file_count=$(find "$OUTPUT_DIR" -maxdepth 1 -type f | wc -l)
log_metric "output_files_collected" "$output_file_count" "count"

ARCHIVE="$OUTPUT_DIR/system_info_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] System info collection complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
if [ -s "$ERRORS_FILE" ]; then
    echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"
fi