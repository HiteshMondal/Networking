#!/bin/bash

# /tools/wireless_security.sh
# Topic: Wireless Security — Interactive Lab
# Covers: WiFi Standards, 802.11, WEP/WPA/WPA2/WPA3, Attacks, Monitor Mode, Live Analysis

# Bootstrap
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$_SELF_DIR")"}"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"
: "${OUTPUT_DIR:="${PROJECT_ROOT}/output"}"
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

#  IEEE 802.11 STANDARDS
check_80211_standards() {
    header "IEEE 802.11 — WiFi Standards"

    cat << 'INFO'
  WiFi operates on the IEEE 802.11 family of standards.
  Each generation improves throughput, range, and efficiency.
INFO

    echo
    printf "  ${BOLD}%-10s %-8s %-12s %-12s %-16s %-18s${NC}\n" \
        "Standard" "Alias" "Frequency" "Max Speed" "Modulation" "Notes"
    printf "  ${DARK_GRAY}%-10s %-8s %-12s %-12s %-16s %-18s${NC}\n" \
        "─────────" "───────" "───────────" "───────────" "───────────────" "─────────────────"

    while IFS='|' read -r std alias freq speed mod notes; do
        printf "  ${CYAN}%-10s${NC} ${GOLD}%-8s${NC} ${GREEN}%-12s${NC} ${YELLOW}%-12s${NC} ${MUTED}%-16s${NC} %s\n" \
            "$std" "$alias" "$freq" "$speed" "$mod" "$notes"
    done << 'TABLE'
802.11b|WiFi 1|2.4 GHz|11 Mbps|DSSS/CCK|Legacy, 1999
802.11a|WiFi 2|5 GHz|54 Mbps|OFDM|1999, less interference
802.11g|WiFi 3|2.4 GHz|54 Mbps|OFDM|2003, backward compat
802.11n|WiFi 4|2.4/5 GHz|600 Mbps|OFDM/MIMO|2009, MIMO introduced
802.11ac|WiFi 5|5 GHz|3.5 Gbps|MU-MIMO|2013, beamforming
802.11ax|WiFi 6|2.4/5/6 GHz|9.6 Gbps|OFDMA|2019, high density
802.11be|WiFi 7|2.4/5/6 GHz|46 Gbps|MLO|2024, multi-link
TABLE

    echo
    section "Key 802.11 Concepts"
    echo
    kv "SSID"        "Service Set Identifier — the network name (up to 32 bytes)"
    kv "BSSID"       "Basic SSID — the AP's MAC address uniquely identifying the BSS"
    kv "Channel"     "2.4GHz: ch 1-14 (1,6,11 non-overlapping)  5GHz: ch 36-177"
    kv "BSS"         "Basic Service Set — one AP + its clients"
    kv "ESS"         "Extended Service Set — multiple APs, same SSID (roaming)"
    kv "IBSS"        "Independent BSS — ad-hoc, peer-to-peer (no AP)"
    kv "Beacon"      "Management frame broadcast by AP every 100ms with SSID, caps"
    kv "Probe Req"   "Client broadcasts to discover available networks"
    kv "Association" "Client ↔ AP handshake to join the BSS"
    kv "DTIM"        "Delivery Traffic Indication Message — wakes sleeping clients"

    echo
    section "2.4 GHz Channel Overlap"
    echo
    echo -e "  ${MUTED}Ch 1  ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${NC}"
    echo -e "  ${MUTED}Ch 6  ░░░░░░░░░░░░████████░░░░░░░░░░░░░░░░░░${NC}"
    echo -e "  ${MUTED}Ch 11 ░░░░░░░░░░░░░░░░░░░░░░░░████████░░░░░░${NC}"
    echo -e "  ${SUCCESS}Ch 1, 6, 11 are the only non-overlapping channels in 2.4 GHz${NC}"
}

#  SECURITY PROTOCOLS: WEP → WPA3
check_wifi_security_protocols() {
    header "WiFi Security — WEP, WPA, WPA2, WPA3"

    section "WEP — Wired Equivalent Privacy (1999) — BROKEN"
    cat << 'INFO'
  Encryption : RC4 stream cipher
  Key size   : 40-bit or 104-bit (effectively 64/128-bit with 24-bit IV)
  Auth       : Open or Shared Key
  Weakness   : 24-bit IV is reused too quickly → statistical attack
               ICV (CRC-32) is linear → bitflipping attacks
               No per-packet replay protection
  Attack time: Crackable in < 1 minute with enough traffic (aircrack-ng)
  Status     : DEPRECATED — never use
INFO

    section "WPA — WiFi Protected Access (2003) — WEAK"
    cat << 'INFO'
  Encryption : TKIP (Temporal Key Integrity Protocol) over RC4
  Key mgmt   : 4-way handshake, PTK/GTK per session
  Auth       : PSK (Personal) or 802.1X (Enterprise)
  Weakness   : TKIP is RC4-based; Michael MIC is 64-bit → brute-forceable
               TKIP deprecated in 802.11n standard
  Status     : DEPRECATED — disable on all APs
INFO

    section "WPA2 — WiFi Protected Access 2 (2004) — CURRENT STANDARD"
    cat << 'INFO'
  Encryption : AES-CCMP (Counter Mode CBC-MAC Protocol)
  Key mgmt   : 4-way handshake, PMKID caching, pre-auth roaming
  Auth       : PSK (Personal) or 802.1X/EAP (Enterprise)
  Strength   : AES-128 block cipher, per-packet MIC, replay counters
  Weakness   : PSK offline dictionary attack on captured 4-way handshake
               PMKID attack (no handshake needed, from EAPOL frame)
               KRACK (Key Reinstallation Attack, CVE-2017-13077)
               Deauthentication frames are unauthenticated → DoS
  Status     : Still widely deployed; use strong PSK (20+ chars)
INFO

    section "WPA3 — WiFi Protected Access 3 (2018) — RECOMMENDED"
    cat << 'INFO'
  Encryption : AES-GCMP-256 (WPA3-Enterprise), AES-CCMP-128 (WPA3-Personal)
  Key mgmt   : SAE (Simultaneous Authentication of Equals) replaces PSK
               — Dragonfly handshake, immune to offline dictionary attacks
               — Forward secrecy per session
  Auth       : SAE (Personal), 802.1X with 192-bit Suite B (Enterprise)
  OWE        : Opportunistic Wireless Encryption — encrypts open networks
  DPP        : Device Provisioning Protocol — QR code / NFC onboarding
  Strength   : No offline cracking possible even with captured handshake
               Protected Management Frames (PMF) mandatory → no deauth DoS
  Weakness   : Dragonblood vulnerabilities (2019, side-channel); mostly patched
               Transition mode (WPA2/WPA3 mix) weakens security to WPA2 level
  Status     : Use WPA3-only when all devices support it
INFO

    echo
    section "Protocol Comparison at a Glance"
    printf "\n  ${BOLD}%-12s %-12s %-14s %-12s %-8s${NC}\n" \
        "Protocol" "Cipher" "Handshake" "Dict Attack" "Status"
    printf "  ${DARK_GRAY}%-12s %-12s %-14s %-12s %-8s${NC}\n" \
        "───────────" "───────────" "─────────────" "───────────" "───────"
    while IFS='|' read -r proto cipher hs dict stat; do
        local sc; case "$stat" in
            SECURE)    sc="$SUCCESS" ;;
            CURRENT)   sc="$YELLOW"  ;;
            BROKEN*)   sc="$FAILURE" ;;
            DEPRECATED) sc="$WARNING" ;;
        esac
        printf "  ${CYAN}%-12s${NC} %-12s %-14s %-12s ${sc}%-8s${NC}\n" \
            "$proto" "$cipher" "$hs" "$dict" "$stat"
    done << 'TABLE'
WEP|RC4/ICV|Open/Shared|Trivial|BROKEN
WPA|TKIP/RC4|4-way|Possible|DEPRECATED
WPA2-PSK|AES-CCMP|4-way|Offline|CURRENT
WPA2-EAP|AES-CCMP|802.1X/EAP|Hard|CURRENT
WPA3-SAE|AES-CCMP|SAE|Impossible|SECURE
WPA3-Ent|AES-GCMP|Suite-B|Impossible|SECURE
TABLE
}

#  WPA2 4-WAY HANDSHAKE (DEEP DIVE)
check_4way_handshake() {
    header "WPA2 4-Way Handshake — Key Derivation"

    cat << 'INFO'
  Purpose: Derive fresh PTK (Pairwise Transient Key) each session.
           Confirm both sides possess the correct PMK without revealing it.

  PMK (Pairwise Master Key):
    WPA2-PSK: PMK = PBKDF2-SHA1(passphrase, SSID, 4096, 256-bit)
    WPA2-EAP: PMK derived from EAP authentication

  PTK derivation (PRF-512):
    PTK = PRF(PMK | "Pairwise key expansion" | min(AA,SPA) | max(AA,SPA) | min(ANonce,SNonce) | max(ANonce,SNonce))

  PTK components (for AES-CCMP):
    KCK (Key Confirmation Key) — 128-bit  — MIC on EAPOL frames
    KEK (Key Encryption Key)   — 128-bit  — encrypts GTK in message 3
    TK  (Temporal Key)         — 128-bit  — encrypts data frames

  GTK (Group Temporal Key): shared key for broadcast/multicast traffic
INFO

    echo
    echo -e "  ${BOLD}${YELLOW}4-Way Handshake Flow:${NC}"
    echo
    printf "  ${GREEN}%-20s${NC}                          ${BLUE}%-20s${NC}\n" "Client (Supplicant)" "AP (Authenticator)"
    printf "  ${DARK_GRAY}%-20s${NC}                          ${DARK_GRAY}%-20s${NC}\n" "────────────────────" "────────────────────"
    echo
    echo -e "  ${MUTED}                          ◄── [Msg 1] ANonce ───────────────${NC}"
    echo -e "  ${MUTED}  (Client derives PTK)${NC}"
    echo -e "  ${MUTED}                          ─── [Msg 2] SNonce + MIC ────────►${NC}"
    echo -e "  ${MUTED}                                         (AP derives PTK)${NC}"
    echo -e "  ${MUTED}                          ◄── [Msg 3] GTK (enc) + MIC ──────${NC}"
    echo -e "  ${MUTED}  (Client installs PTK)${NC}"
    echo -e "  ${MUTED}                          ─── [Msg 4] ACK + MIC ───────────►${NC}"
    echo -e "  ${MUTED}                                         (AP installs PTK)${NC}"
    echo
    echo -e "  ${SUCCESS}→ Encrypted data transfer begins (TK active)${NC}"
    echo
    echo -e "  ${WARNING}Attack surface:${NC}"
    echo -e "  ${MUTED}  Message 2 contains SNonce + MIC over EAPOL data${NC}"
    echo -e "  ${MUTED}  Attacker captures msgs 1+2 (or 2+3), runs offline dictionary${NC}"
    echo -e "  ${MUTED}  PMKID attack: PMKID = HMAC-SHA1(PMK, \"PMK Name\" + AA + SPA)${NC}"
    echo -e "  ${MUTED}  — Captured from EAPOL msg 1, no full handshake needed${NC}"
}

#  WIRELESS ATTACKS
check_wireless_attacks() {
    header "Wireless Attack Techniques"

    section "1. Deauthentication Attack (DoS)"
    cat << 'INFO'
  IEEE 802.11 management frames (including deauth) are unauthenticated.
  Attacker spoofs AP MAC → sends deauth frames to client → client disconnects.

  aireplay-ng --deauth 0 -a <BSSID> -c <ClientMAC> wlan0mon

  Defence:
    - WPA3 with PMF (Protected Management Frames) mandatory
    - 802.11w PMF on WPA2 networks
    - Wireless IDS to alert on deauth floods
INFO

    section "2. Evil Twin / Rogue AP"
    cat << 'INFO'
  Attacker creates a WiFi AP with the same SSID as a legitimate network.
  Client associates with rogue AP → attacker is the MITM.

  Variants:
    - Karma attack: responds to ANY probe request SSID
    - Captive portal attack: force credentials via fake login page

  Tools: hostapd-wpe, airbase-ng, Wi-Fi Pineapple

  Defence:
    - 802.1X/EAP with certificate validation (client verifies server cert)
    - WIDS (Wireless IDS) — detect duplicate BSSIDs on different radios
    - Avoid auto-connecting to open/known networks
INFO

    section "3. PMKID / Handshake Capture & Crack"
    cat << 'INFO'
  Capture:  hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1
  Convert:  hcxpcapngtool capture.pcapng -o hashes.hc22000
  Crack:    hashcat -m 22000 hashes.hc22000 wordlist.txt

  PMKID (no client needed):
    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || BSSID || ClientMAC)
    Embedded in EAPOL RSN IE of beacon/association frames

  Defence:
    - Use WPA3-SAE (immune to offline dictionary attack)
    - WPA2: use long, random PSK (20+ chars, not dictionary words)
    - Monitor for capture tools (hcxdumptool sends probe floods)
INFO

    section "4. WPS PIN Attack"
    cat << 'INFO'
  WPS (WiFi Protected Setup) PIN is split into two 4-digit halves.
  Brute force requires only 10^4 + 10^4 = 20,000 attempts (not 10^8).
  Some APs have no lockout → Reaver/Bully can recover PSK in hours.

  pixie-dust attack: offline WPS PIN recovery from nonce values.

  Defence:
    - Disable WPS entirely on all APs
    - Use APs that implement WPS lockout after 3 failures
INFO

    section "5. Wardriving & SSID Harvesting"
    cat << 'INFO'
  Scanning for WiFi networks while in motion (car, drone, walking).
  Tools: Kismet, Wigle.net, airodump-ng, NetStumbler

  Collected data: SSID, BSSID, channel, signal, encryption, GPS coords.
  Wigle.net database: >1 billion networks globally.

  Defence:
    - SSID hiding provides minimal security (SSIDs appear in probe reqs)
    - Ensure correct security mode is advertised (WPA3)
    - Unique SSIDs reduce correlation attacks
INFO

    section "6. Bluetooth Attacks (Adjacent Wireless)"
    cat << 'INFO'
  BlueSnarfing  — Unauthorized data read from BT device (contacts, SMS)
  BlueJacking   — Sending unsolicited messages via BT
  Bluebugging   — Full command access to a BT device
  KNOB attack   — Force weak entropy in BT key negotiation (CVE-2019-9506)
  BIAS attack   — Impersonate bonded BT device (CVE-2020-10135)

  Defence:
    - Disable BT when not in use
    - Non-discoverable mode
    - Apply firmware patches promptly
    - Use BT 5.x with SC (Secure Connections) only
INFO
}

#  LIVE WIRELESS ANALYSIS
check_live_wireless() {
    header "Live Wireless Interface Analysis"

    section "Detected Wireless Interfaces"

    local found=0
    if cmd_exists iw; then
        iw dev 2>/dev/null | while read -r line; do
            echo -e "  ${CYAN}${line}${NC}"
        done
        found=1
    fi

    if cmd_exists iwconfig; then
        echo -e "${INFO}iwconfig output:${NC}"
        iwconfig 2>/dev/null | grep -v "^$" | while IFS= read -r line; do
            if echo "$line" | grep -qE "^[a-zA-Z]"; then
                echo -e "\n  ${BOLD}${WHITE}${line}${NC}"
            else
                echo -e "  ${MUTED}${line}${NC}"
            fi
        done
        found=1
    fi

    [[ $found -eq 0 ]] && status_line neutral "No wireless tools available (install iw / wireless-tools)"

    section "Interface Capabilities"
    if cmd_exists iw; then
        for wif in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
            echo -e "  ${GOLD}${BOLD}Interface: ${wif}${NC}"
            iw dev "$wif" info 2>/dev/null | sed 's/^/    /'
            echo
            echo -e "  ${INFO}Supported modes for ${wif}:${NC}"
            iw phy "$(iw dev "$wif" info 2>/dev/null | awk '/wiphy/{print $2}')" info 2>/dev/null \
                | grep -A20 "Supported interface modes" | head -15 | sed 's/^/    /'
            echo
        done
    fi

    section "Current Connections"
    if cmd_exists nmcli; then
        echo -e "${INFO}NetworkManager connections:${NC}"
        nmcli -c no dev wifi 2>/dev/null | head -20 | sed 's/^/  /' \
            || echo -e "  ${MUTED}Not available${NC}"
    fi

    if cmd_exists iwgetid; then
        echo
        echo -e "${INFO}Current association:${NC}"
        for wif in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
            local ssid bssid
            ssid=$(iwgetid  "$wif" --raw 2>/dev/null)
            bssid=$(iwgetid "$wif" --ap  2>/dev/null)
            [[ -n "$ssid" ]] && kv "$wif SSID"  "$ssid"
            [[ -n "$bssid" ]] && kv "$wif BSSID" "$bssid"
        done
    fi

    section "Scan for Networks (Passive)"
    local wif
    wif=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
    if [[ -n "$wif" ]]; then
        echo -e "  ${MUTED}Scanning on ${wif} (requires sudo)...${NC}"
        echo
        sudo iw dev "$wif" scan 2>/dev/null \
            | grep -E "^BSS|SSID:|signal:|DS Parameter|RSN|WPA" \
            | while IFS= read -r line; do
            if echo "$line" | grep -q "^BSS"; then
                echo -e "\n  ${BOLD}${CYAN}${line}${NC}"
            elif echo "$line" | grep -qiE "RSN|WPA"; then
                echo -e "  ${SUCCESS}  ${line}${NC}"
            elif echo "$line" | grep -qi "signal"; then
                echo -e "  ${GOLD}  ${line}${NC}"
            else
                echo -e "  ${MUTED}  ${line}${NC}"
            fi
        done | head -60 \
            || echo -e "  ${MUTED}Scan not available (no wireless interface or insufficient privilege)${NC}"
    else
        status_line neutral "No wireless interface detected"
    fi

    section "Monitor Mode Check"
    echo -e "  ${MUTED}Monitor mode allows capture of all 802.11 frames (not just associated).${NC}"
    echo
    for wif in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
        local mode
        mode=$(iw dev "$wif" info 2>/dev/null | awk '/type/{print $2}')
        if [[ "$mode" == "monitor" ]]; then
            status_line ok "${wif} is in MONITOR MODE — can capture all frames"
        else
            status_line neutral "${wif} is in ${mode:-unknown} mode (managed/station mode)"
            echo -e "  ${MUTED}  Enable monitor mode: sudo ip link set ${wif} down && sudo iw ${wif} set monitor none && sudo ip link set ${wif} up${NC}"
        fi
    done

    section "Regulatory Domain"
    if cmd_exists iw; then
        echo -e "${INFO}Current regulatory domain:${NC}"
        iw reg get 2>/dev/null | head -6 | sed 's/^/  /'
    fi

    section "Signal Quality"
    if [[ -f /proc/net/wireless ]]; then
        echo -e "${INFO}/proc/net/wireless:${NC}"
        cat /proc/net/wireless | sed 's/^/  /'
        echo
        echo -e "  ${MUTED}Signal interpretation:${NC}"
        echo -e "  ${SUCCESS}   > -50 dBm  Excellent${NC}"
        echo -e "  ${GREEN}  -50 to -60  Good${NC}"
        echo -e "  ${YELLOW}  -60 to -70  Fair${NC}"
        echo -e "  ${FAILURE}   < -70 dBm  Poor${NC}"
    fi
}

#  WIRELESS HARDENING
check_wireless_hardening() {
    header "Wireless Network Hardening"

    section "AP Configuration Checklist"
    echo
    local items=(
        "Use WPA3-SAE or WPA3-Enterprise only"
        "Disable WPS (WiFi Protected Setup)"
        "Enable PMF (Protected Management Frames / 802.11w)"
        "Use strong PSK: 20+ chars, random, no dictionary words"
        "Separate guest VLAN from corporate LAN"
        "Disable legacy protocols: 802.11b/g where possible"
        "Enable AP isolation on guest networks"
        "Use 5GHz/6GHz for reduced signal bleed-through walls"
        "Disable SSID broadcast only if combined with other controls"
        "Implement WIDS (Wireless Intrusion Detection)"
        "Apply firmware updates to all APs regularly"
        "Use 802.1X/EAP + RADIUS for enterprise authentication"
        "Certificate-based EAP (EAP-TLS) prevents evil twin"
        "Configure rogue AP detection on WLAN controller"
        "Limit transmit power to minimum coverage needed"
    )

    for item in "${items[@]}"; do
        echo -e "  ${MUTED}○${NC}  ${VALUE}${item}${NC}"
    done

    section "EAP Methods Comparison"
    echo
    printf "  ${BOLD}%-14s %-14s %-10s %-10s %s${NC}\n" \
        "EAP Method" "Auth" "Cert(Client)" "Cert(Server)" "Security"
    printf "  ${DARK_GRAY}%-14s %-14s %-10s %-10s %s${NC}\n" \
        "─────────────" "─────────────" "───────────" "───────────" "────────"
    while IFS='|' read -r method auth cc cs sec; do
        local sc; [[ "$sec" == "HIGH" ]] && sc="$SUCCESS" || sc="$YELLOW"
        printf "  ${CYAN}%-14s${NC} %-14s %-10s %-10s ${sc}%s${NC}\n" \
            "$method" "$auth" "$cc" "$cs" "$sec"
    done << 'TABLE'
EAP-TLS|Certificate|Yes|Yes|HIGH
EAP-TTLS|Password|No|Yes|HIGH
PEAP|Password|No|Yes|MEDIUM
EAP-FAST|Password|No|Optional|MEDIUM
LEAP|Password|No|No|BROKEN
EAP-MD5|Password|No|No|BROKEN
TABLE

    section "RADIUS / 802.1X Architecture"
    cat << 'INFO'
  Supplicant (Client) ←→ Authenticator (AP/Switch) ←→ Auth Server (RADIUS)

  Flow:
    1. Client associates → AP puts port in "unauthorized" state
    2. AP relays EAP messages between client and RADIUS
    3. RADIUS validates credentials (LDAP, AD, cert store)
    4. On success: RADIUS sends Accept + MSK (Master Session Key)
    5. AP derives PMK from MSK → 4-way handshake → data path opens

  Ports: RADIUS UDP 1812 (auth), UDP 1813 (accounting)
  Software: FreeRADIUS, Cisco ISE, Aruba ClearPass, NPS (Windows)
INFO

    section "Wireless Client Hardening"
    cat << 'INFO'
  1. Forget unused WiFi profiles — prevent auto-association
  2. Disable auto-connect to open networks
  3. Use VPN on all untrusted WiFi (WPA3-OWE is encrypted but not authenticated)
  4. Validate server certificate on 802.1X connections
  5. Disable WiFi when not needed (reduce attack surface)
  6. Enable MAC address randomization (iOS, Android, Windows 10+)
  7. Disable WiFi Direct / P2P when not in use
INFO

    section "System WiFi Security Checks"
    echo -e "${INFO}Checking MAC randomization capability:${NC}"
    if cmd_exists iw; then
        for wif in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
            local rand
            rand=$(iw dev "$wif" info 2>/dev/null | grep -i "mac_randomization")
            if [[ -n "$rand" ]]; then
                status_line ok "${wif}: MAC randomization supported"
            else
                # Check via NetworkManager
                if nmcli -g WIFI-PROPERTIES.MAC-ADDRESS-RANDOMIZATION dev show "$wif" 2>/dev/null | grep -qi "yes\|random"; then
                    status_line ok "${wif}: MAC randomization active (NetworkManager)"
                else
                    status_line neutral "${wif}: MAC randomization status unknown"
                fi
            fi
        done
    fi

    echo
    echo -e "${INFO}Firewall on wireless interfaces:${NC}"
    if cmd_exists iptables; then
        local wif_rules
        wif_rules=$(sudo iptables -L -n 2>/dev/null | grep -c "wlan\|wifi\|wlp")
        if [[ "$wif_rules" -gt 0 ]]; then
            status_line ok "Firewall rules referencing wireless interfaces found ($wif_rules rules)"
        else
            status_line neutral "No wireless-specific firewall rules detected"
        fi
    fi
}

#  ROGUE NETWORK DETECTION
check_rogue_detection() {
    header "Rogue Network Detection"

    section "Unauthorised WiFi Adapters on This System"
    echo -e "${INFO}USB devices that may be wireless adapters:${NC}"
    if cmd_exists lsusb; then
        lsusb 2>/dev/null | grep -iE "wireless|wifi|wlan|802.11|ralink|realtek|atheros|broadcom|intel.*wifi" \
            | sed 's/^/  /' || echo -e "  ${MUTED}None identified (or lsusb not detailed enough)${NC}"
    fi

    echo
    echo -e "${INFO}PCI wireless devices:${NC}"
    if cmd_exists lspci; then
        lspci 2>/dev/null | grep -iE "wireless|wifi|wlan|802.11|network.*controller" \
            | sed 's/^/  /' || echo -e "  ${MUTED}None detected${NC}"
    fi

    section "Unexpected Listening Services"
    echo -e "${INFO}Hotspot / AP daemon processes:${NC}"
    for proc in hostapd create_ap wpa_supplicant dnsmasq; do
        if pgrep -x "$proc" &>/dev/null; then
            local pid
            pid=$(pgrep -x "$proc" | head -1)
            status_line warn "${proc} is running (PID: ${pid}) — verify this is intentional"
        fi
    done

    section "WiFi Pineapple / Attack Tool Detection"
    echo -e "  ${MUTED}Checking for known attack tool signatures...${NC}"
    echo
    local suspicious=0
    for tool in aircrack-ng aireplay-ng airodump-ng hostapd-wpe reaver bully pixiewps hcxdumptool hcxtools wifite; do
        if cmd_exists "$tool"; then
            echo -e "  ${WARNING}[~]${NC} ${YELLOW}${tool}${NC} is installed — verify authorization"
            suspicious=1
        fi
    done
    [[ $suspicious -eq 0 ]] && status_line ok "No known wireless attack tools detected"
}

main() {
    check_80211_standards
    check_wifi_security_protocols
    check_4way_handshake
    check_wireless_attacks
    check_live_wireless
    check_wireless_hardening
    check_rogue_detection

    pause
}

main