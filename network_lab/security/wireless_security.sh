#!/bin/bash

# /network_lab/security/wireless_security.sh
# Topic: Wireless Security — 802.11, WPA2/WPA3, Attacks & Hardening
# Covers: 802.11 standards, WEP/WPA/WPA2/WPA3, 4-way handshake, attacks, hardening

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# 802.11 STANDARDS
check_80211_standards() {
    header "IEEE 802.11 Standards — WiFi Generations"

    cat << 'INFO'
  ╔═══════════╦══════════╦════════════╦══════════╦════════════╦════════════════╗
  ║ Standard  ║ Wi-Fi    ║ Band (GHz) ║ Max Speed║ Year       ║ MIMO           ║
  ╠═══════════╬══════════╬════════════╬══════════╬════════════╬════════════════╣
  ║ 802.11b   ║ Wi-Fi 1  ║ 2.4        ║ 11 Mbps  ║ 1999       ║ No             ║
  ║ 802.11a   ║ Wi-Fi 2  ║ 5          ║ 54 Mbps  ║ 1999       ║ No             ║
  ║ 802.11g   ║ Wi-Fi 3  ║ 2.4        ║ 54 Mbps  ║ 2003       ║ No             ║
  ║ 802.11n   ║ Wi-Fi 4  ║ 2.4 / 5    ║ 600 Mbps ║ 2009       ║ 4×4            ║
  ║ 802.11ac  ║ Wi-Fi 5  ║ 5          ║ 3.5 Gbps ║ 2013       ║ MU-MIMO 8×8    ║
  ║ 802.11ax  ║ Wi-Fi 6  ║ 2.4 / 5    ║ 9.6 Gbps ║ 2019       ║ MU-MIMO + OFDMA║
  ║ 802.11ax  ║ Wi-Fi 6E ║ 2.4/5/6    ║ 9.6 Gbps ║ 2021       ║ Adds 6 GHz band║
  ║ 802.11be  ║ Wi-Fi 7  ║ 2.4/5/6    ║ 46 Gbps  ║ 2024       ║ MLO, 320 MHz   ║
  ╚═══════════╩══════════╩════════════╩══════════╩════════════╩════════════════╝

  Key technologies:
    OFDM    — Orthogonal Frequency Division Multiplexing (multi-subcarrier)
    MIMO    — Multiple Input Multiple Output (spatial streams)
    OFDMA   — Multiple users share one OFDM channel (Wi-Fi 6)
    Beamforming — directional signal focus toward client
    BSS Coloring — reuse channels in dense deployments (Wi-Fi 6)
    MLO     — Multi-Link Operation (Wi-Fi 7, simultaneous multi-band)

  Frequency bands:
    2.4 GHz — 11 channels (US) / 13 (EU); only 3 non-overlapping (1,6,11)
              Better range; more congestion; penetrates walls better
    5   GHz — 24+ non-overlapping 20 MHz channels; faster; shorter range
    6   GHz — 59 new non-overlapping channels; Wi-Fi 6E only; least congestion
INFO

    section "Local Wireless Interface"
    local wifi_iface
    wifi_iface=$(ip link show 2>/dev/null | grep -oP '^\d+: \K\w+' | \
        while read -r i; do
            [[ -d "/sys/class/net/${i}/wireless" ]] && echo "$i" && break
        done)

    if [[ -n "$wifi_iface" ]]; then
        status_line ok "Wireless interface: ${wifi_iface}"
        echo
        echo -e "${INFO}Interface details:${NC}"
        iw dev "$wifi_iface" info 2>/dev/null | sed 's/^/  /' \
            || iwconfig "$wifi_iface" 2>/dev/null | sed 's/^/  /'

        echo
        echo -e "${INFO}Associated AP:${NC}"
        iw dev "$wifi_iface" link 2>/dev/null | sed 's/^/  /' \
            || iwconfig "$wifi_iface" 2>/dev/null | grep -E "ESSID|Access Point|Bit Rate|Signal" | \
               sed 's/^/  /'

        echo
        echo -e "${INFO}Supported bands & capabilities:${NC}"
        iw phy 2>/dev/null | grep -E "Band|Frequencies|Capabilities" | head -15 | sed 's/^/  /'
    else
        status_line neutral "No wireless interface detected on this system"
        echo -e "  ${MUTED}(Physical or virtual machine without WiFi NIC)${NC}"
    fi
}

# WEP / WPA / WPA2 / WPA3
check_wifi_security_protocols() {
    header "WiFi Security Protocols — WEP to WPA3"

    section "Protocol Evolution"
    cat << 'INFO'
  WEP (Wired Equivalent Privacy) — 1999, BROKEN
    Cipher: RC4 stream cipher
    Key: 40-bit or 104-bit (often expressed as 64/128-bit with IV)
    Fatal flaws:
      • 24-bit IV reuse → keystream recovery in <60,000 packets
      • Weak IVs predictable (FMS attack, 2001)
      • No message integrity protection
    Tool: aircrack-ng, wesside-ng (crack in minutes/seconds)
    Status: NEVER USE — completely broken

  WPA (Wi-Fi Protected Access) — 2003, deprecated
    Cipher: TKIP (Temporal Key Integrity Protocol)
    Improvement over WEP: per-packet keying, MIC (Michael), key mixing
    Still RC4 underneath — vulnerable to TKIP-specific attacks
    Status: DEPRECATED — disable if possible

  WPA2 (Wi-Fi Protected Access 2) — 2004, widely used
    Cipher: AES-CCMP (128-bit AES in Counter Mode with CBC-MAC)
    Key exchange: 4-way handshake
    Modes:
      WPA2-Personal (PSK)  — pre-shared key, all users same key
      WPA2-Enterprise      — IEEE 802.1X + RADIUS authentication
    Vulnerabilities:
      KRACK (2017)          — key reinstallation attack (patched in most clients)
      PMKID attack (2018)   — offline dictionary attack without capturing handshake
      Offline dictionary    — weak PSKs crackable with captured handshake
    Status: ACCEPTABLE — use strong PSK (20+ chars), prefer WPA3 if available

  WPA3 — 2018, modern standard
    Personal: SAE (Simultaneous Authentication of Equals — Dragonfly KEx)
      • Forward secrecy — past sessions protected even if PSK later compromised
      • Offline dictionary attacks prevented (no capture-and-crack)
      • Transition mode: WPA2+WPA3 mixed for compatibility
    Enterprise: GCMP-256, HMAC-SHA-384, 192-bit security suite
    OWE (Enhanced Open): encryption without authentication (replaces open WiFi)
    Status: RECOMMENDED — deploy WPA3-SAE

  WPS (WiFi Protected Setup) — DISABLE IMMEDIATELY
    PIN brute-force: reduced to 10,000 → 1,100 guesses due to split verification
    Pixie Dust attack: offline crack of certain routers
    Tool: Reaver, Bully
INFO

    section "Local WiFi Security Assessment"
    if cmd_exists nmcli; then
        echo -e "${INFO}Known WiFi networks:${NC}"
        nmcli -t -f NAME,SECURITY,SIGNAL,BARS,ACTIVE connection show --active 2>/dev/null | \
            while IFS=: read -r name sec sig bars active; do
                local color="$MUTED"
                [[ "$active" == "yes" ]] && color="$SUCCESS"
                printf "  ${color}%-30s${NC} ${LABEL}%-12s${NC} ${MUTED}Signal: %s%s${NC}\n" \
                    "$name" "$sec" "$sig" "$bars"
            done

        echo
        echo -e "${INFO}Nearby access points:${NC}"
        nmcli dev wifi list 2>/dev/null | head -15 | sed 's/^/  /'
    elif cmd_exists iwlist; then
        local wifi_iface
        wifi_iface=$(ip link show 2>/dev/null | grep -oP '^\d+: \K\w+' | \
            while read -r i; do
                [[ -d "/sys/class/net/${i}/wireless" ]] && echo "$i" && break
            done)
        if [[ -n "$wifi_iface" ]]; then
            echo -e "${INFO}Scanning for APs (requires sudo):${NC}"
            sudo iwlist "$wifi_iface" scan 2>/dev/null | \
                grep -E "ESSID|Encryption|IE: WPA|WPA2|Channel:" | \
                head -20 | sed 's/^/  /'
        fi
    else
        status_line neutral "Network manager tools not available for WiFi scan"
    fi
}

# 4-WAY HANDSHAKE
check_4way_handshake() {
    header "WPA2 4-Way Handshake — Authentication Deep Dive"

    cat << 'INFO'
  The 4-way handshake establishes fresh encryption keys for each session.

  Pre-requisite: both parties know the PMK (Pairwise Master Key)
    PSK mode:  PMK = PBKDF2-SHA1(passphrase, SSID, 4096, 32)
    802.1X:    PMK derived from EAP authentication session

  From PMK → PTK (Pairwise Transient Key):
    PTK = PRF-512(PMK || "Pairwise key expansion" || min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
    Produces: KCK (Key Confirmation Key, 16 bytes)
              KEK (Key Encryption Key, 16 bytes)
              TK  (Temporal Key, 16 bytes for CCMP)

  ┌──────────────────────────────────────────────────────────────────────┐
  │  Authenticator (AP)                    Supplicant (Client)           │
  │  ─────────────────                     ────────────────────          │
  │  ANonce                ─M1────────►                                  │
  │                                        Generates SNonce              │
  │                                        Derives PTK                   │
  │                        ◄────M2───      SNonce + MIC (KCK)            │
  │  Derives PTK                                                         │
  │  Validates MIC                                                       │
  │  Installs PTK                                                        │
  │  GTK (encrypted w/ KEK) ─M3────────►                                │
  │                                        Installs PTK + GTK            │
  │                        ◄────M4───      ACK + MIC                     │
  │  Installs PTK + GTK                                                  │
  └──────────────────────────────────────────────────────────────────────┘

  KRACK Attack (Key Reinstallation):
    Retransmitting M3 causes client to reinstall PTK → resetting nonce/replay counter.
    Attacker can replay, decrypt, and potentially forge traffic.
    Fixed in client OS patches (2017 onwards).

  Offline Dictionary Attack:
    Capture M1+M2 (contains ANonce, SNonce, MAC addresses, MIC).
    MIC computed using KCK, which depends on PMK.
    If PMK is weak (short passphrase) → crack offline with hashcat/aircrack-ng.
    Format: hashcat -m 22000 hash.hc22000 wordlist.txt

  PMKID Attack (2018, Jens Steube):
    Extract PMKID from a single EAPOL frame (no full handshake needed).
    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
    Allows offline cracking without a connected client.
INFO
}

# WIRELESS ATTACKS
check_wireless_attacks() {
    header "Wireless Attacks — Classification & Defence"

    section "Attack Categories"
    cat << 'INFO'
  Passive Attacks (no injection — very hard to detect):
    ─────────────────────────────────────────────────────
    Eavesdropping  — capture cleartext traffic (WEP/Open networks)
    Traffic Analysis— infer activity from packet patterns (even on WPA2)
    Handshake Capture— record WPA2 4-way handshake for offline cracking
    Beacon Sniffing — enumerate APs, clients, probe requests (device tracking)

  Active Attacks (require injection — detectable with WIDS):
    ─────────────────────────────────────────────────────
    Deauthentication Flood
        Send spoofed 802.11 deauth frames to disconnect clients.
        Forces client to re-associate → capture 4-way handshake.
        WPA3 protects: Management Frame Protection (MFP/PMF) mandatory.
        Tool: aireplay-ng -0 10 -a <AP_MAC> -c <CLIENT_MAC> mon0

    Evil Twin / Rogue AP
        Create fake AP with same SSID (higher power wins).
        Capture credentials via captive portal; perform MitM.
        Defence: 802.1X per-user auth (clients verify server cert).

    WPS PIN Attack
        Brute-force WPS PIN (Pixie Dust for offline cracking).
        Tool: reaver, bully
        Defence: DISABLE WPS.

    PMKID Attack
        Extract PMKID from EAPOL without client present.
        hcxdumptool + hcxtools → hashcat -m 22000.
        Defence: Strong (20+ char random) passphrase.

    Karma / MANA Attack
        Respond to ANY probe request with matching SSID.
        Clients auto-connect to attacker's AP.
        Defence: Disable auto-connect to open/unknown networks.

    RF Jamming
        Flood 2.4/5 GHz band with interference → DoS.
        Targeted: deauth flood on specific channel.
        Defence: 5 GHz / 6 GHz preferred (less crowded); WIDS alerting.
INFO

    section "Attack Tools Reference"
    echo
    printf "  ${BOLD}%-20s %-22s %s${NC}\n" "Tool" "Phase" "Function"
    printf "  ${DARK_GRAY}%-20s %-22s %s${NC}\n" "───────────────────" "─────────────────────" "──────────────────────────"
    while IFS='|' read -r tool phase func; do
        printf "  ${CYAN}%-20s${NC} ${LABEL}%-22s${NC} ${MUTED}%s${NC}\n" "$tool" "$phase" "$func"
    done << 'TABLE'
airmon-ng|Recon|Put NIC in monitor mode
airodump-ng|Recon|Capture packets, enumerate APs/clients
aireplay-ng|Attack|Inject frames (deauth, PMKID, etc.)
aircrack-ng|Cracking|WEP/WPA cracking (dictionary/brute)
hcxdumptool|Capture|PMKID + EAPOL capture
hcxtools|Conversion|Convert captures to hashcat format
hashcat|Cracking|GPU-based WPA2/WPA3-SAE cracking
hostapd-wpe|Evil Twin|Rogue AP with RADIUS capture
Wireshark|Analysis|Protocol analysis of .pcap captures
kismet|WIDS/Recon|Wireless IDS + passive scanning
TABLE

    section "Cracking Complexity Reference"
    cat << 'INFO'
  WPA2-PSK cracking speed (hashcat, mode 22000):
    GPU RTX 4090:  ~1,600,000 PMKIDs/second
    GPU RTX 3080:  ~700,000 PMKIDs/second

  Passphrase strength:
    8 lowercase chars   — crackable in hours (26^8 = 208 billion)
    12 mixed chars      — months to years
    20+ random chars    — effectively uncrackable (centuries)
    WPA3-SAE (any)     — offline cracking impossible by design

  Recommendation: Use 20+ char random passphrase. Enable WPA3.
INFO
}

# LIVE WIRELESS ANALYSIS
check_live_wireless() {
    header "Live Wireless Analysis"

    section "Wireless Interface Status"
    local wifi_iface
    wifi_iface=$(ip link show 2>/dev/null | grep -oP '^\d+: \K\w+' | \
        while read -r i; do
            [[ -d "/sys/class/net/${i}/wireless" ]] && echo "$i" && break
        done)

    if [[ -z "$wifi_iface" ]]; then
        status_line neutral "No wireless interface found — skipping live analysis"
        return
    fi

    status_line ok "Wireless interface: ${wifi_iface}"

    echo
    echo -e "${INFO}Interface details:${NC}"
    iw dev "$wifi_iface" info 2>/dev/null | sed 's/^/  /'

    echo
    echo -e "${INFO}Current connection:${NC}"
    iw dev "$wifi_iface" link 2>/dev/null | sed 's/^/  /'

    echo
    echo -e "${INFO}RF kill status:${NC}"
    rfkill list 2>/dev/null | sed 's/^/  /'

    section "Channel Utilisation"
    if cmd_exists iw; then
        echo -e "${INFO}Available channels:${NC}"
        iw phy 2>/dev/null | grep -E "MHz" | head -20 | sed 's/^/  /'
    fi

    section "WiFi Signal Quality"
    if cmd_exists nmcli; then
        echo -e "${INFO}Access points in range:${NC}"
        nmcli dev wifi list 2>/dev/null | head -12 | sed 's/^/  /'
    fi

    echo
    echo -e "${INFO}Quality statistics (from /proc/net/wireless):${NC}"
    if [[ -r /proc/net/wireless ]]; then
        cat /proc/net/wireless | sed 's/^/  /'
    else
        echo -e "  ${MUTED}Not available${NC}"
    fi
}

# WIRELESS HARDENING
check_wireless_hardening() {
    header "Wireless Network Hardening"

    section "AP Security Checklist"
    echo
    local checks=(
        "Enable WPA3-SAE (or WPA2+WPA3 transition mode)"
        "Use 20+ character random passphrase (PSK)"
        "DISABLE WPS (WiFi Protected Setup) — permanently vulnerable"
        "Enable Management Frame Protection (PMF/MFP — 802.11w)"
        "Disable SSID broadcast? Optional; security through obscurity only"
        "Segregate Guest WiFi to isolated VLAN (no access to LAN)"
        "Use 802.1X + RADIUS for enterprise (per-user credentials)"
        "Disable legacy protocols: WEP, WPA(TKIP), 802.11b"
        "Enable client isolation (prevent client-to-client communication)"
        "Monitor with WIDS (kismet, Meraki CMX, Cisco CleanAir)"
        "Log all associations and deauthentications"
        "Use 5 GHz or 6 GHz bands (less congestion, harder to jam)"
        "Regular firmware updates for AP hardware"
        "Physical security — APs in locked enclosures where possible"
        "Rogue AP detection — compare authorised AP list against scan"
    )
    for i in "${!checks[@]}"; do
        printf "  ${MUTED}○${NC}  ${VALUE}%s${NC}\n" "${checks[$i]}"
    done

    section "Client-Side Hardening"
    echo
    local client_checks=(
        "Disable auto-connect to open/unknown WiFi networks"
        "Use VPN on all untrusted networks (coffee shops, hotels)"
        "Enable firewall on device when on public WiFi"
        "Prefer HTTPS-only connections (HSTS)"
        "Disable WiFi when not in use (prevents probe request tracking)"
        "Forget old WiFi networks you no longer use"
        "Use HTTPS Everywhere / Strict HTTPS mode in browser"
        "Do not use open WiFi for sensitive transactions (banking, email)"
    )
    for item in "${client_checks[@]}"; do
        printf "  ${MUTED}○${NC}  ${VALUE}%s${NC}\n" "$item"
    done

    section "System WiFi Security Check"
    if cmd_exists nmcli; then
        echo -e "${INFO}Saved WiFi profiles:${NC}"
        nmcli connection show 2>/dev/null | grep "wifi" | while read -r name _ type _; do
            local sec
            sec=$(nmcli -g 802-11-wireless-security.key-mgmt \
                  connection show "$name" 2>/dev/null)
            local color
            case "$sec" in
                wpa-psk)     color="$YELLOW" ;;
                sae)         color="$SUCCESS" ;;
                wpa-eap)     color="$SUCCESS" ;;
                "")          color="$FAILURE" ;;
                *)           color="$MUTED"   ;;
            esac
            printf "  ${LABEL}%-30s${NC} ${color}%s${NC}\n" "$name" "${sec:-open/unknown}"
        done
    fi
}

# ROGUE AP DETECTION
check_rogue_detection() {
    header "Rogue Access Point Detection"

    section "Detection Methods"
    cat << 'INFO'
  Rogue AP: an unauthorised access point connected to a network.
  Evil Twin: a fake AP impersonating a legitimate SSID.

  Detection approaches:
    1. WIDS (Wireless IDS)
       Dedicated sensors or AP-based monitoring.
       Compare seen APs against authorised AP list.
       Alert on: unknown BSSIDs, unauthorised channels, signal anomalies.

    2. Wired-side correlation
       Monitor switch port MAC tables.
       If AP MAC appears on unexpected port → rogue connected.

    3. RF fingerprinting
       Each radio has unique transmission characteristics.
       Legitimate AP fingerprints stored; deviations flagged.

    4. Passive scanning
       Tools: kismet (continuous passive scan, no injection)
       Map all BSSIDs → compare against approved inventory.

    5. Client probe analysis
       Clients probing for known SSIDs can reveal evil twins.
       If a client probes for "CorpWiFi" and connects to unknown BSSID → alert.
INFO

    section "Local Rogue Detection Scan"
    local wifi_iface
    wifi_iface=$(ip link show 2>/dev/null | grep -oP '^\d+: \K\w+' | \
        while read -r i; do
            [[ -d "/sys/class/net/${i}/wireless" ]] && echo "$i" && break
        done)

    if [[ -z "$wifi_iface" ]]; then
        status_line neutral "No wireless interface — cannot scan"
        return
    fi

    if cmd_exists nmcli; then
        echo -e "${INFO}Visible access points with security detail:${NC}"
        echo
        printf "  ${BOLD}%-32s %-8s %-14s %-6s %s${NC}\n" \
            "SSID" "Signal" "Security" "Chan" "BSSID"
        printf "  ${DARK_GRAY}%-32s %-8s %-14s %-6s %s${NC}\n" \
            "$(printf '─%.0s' {1..31})" "───────" "─────────────" "─────" "─────────────────"

        nmcli -f SSID,SIGNAL,SECURITY,CHAN,BSSID dev wifi list 2>/dev/null | \
            tail -n +2 | head -20 | while read -r ssid signal sec chan bssid; do
            local color
            case "$sec" in
                *WPA3*)           color="$SUCCESS" ;;
                *WPA2*)           color="$YELLOW"  ;;
                *WPA*)            color="$WARNING" ;;
                "")               color="$FAILURE" ;;
                *)                color="$MUTED"   ;;
            esac
            printf "  ${LABEL}%-32s${NC} ${MUTED}%-8s${NC} ${color}%-14s${NC} ${MUTED}%-6s${NC} %s\n" \
                "${ssid:0:32}" "$signal" "$sec" "$chan" "$bssid"
        done

        echo
        echo -e "  ${MUTED}Tip: Compare BSSIDs above against your authorised AP inventory.${NC}"
        echo -e "  ${MUTED}Any unknown BSSID broadcasting your SSID = potential evil twin.${NC}"
    else
        status_line neutral "nmcli not available — install network-manager for WiFi scanning"
    fi

    section "WIDS Tools"
    for tool in kismet airodump-ng bettercap; do
        if cmd_exists "$tool"; then
            status_line ok "${tool} is available"
        else
            status_line neutral "${tool} not installed"
        fi
    done

    echo
    echo -e "  ${MUTED}Install kismet for continuous passive wireless monitoring:${NC}"
    echo -e "  ${CYAN}  sudo apt install kismet${NC}"
    echo -e "  ${CYAN}  sudo kismet -c ${wifi_iface}${NC}"
}

main() {
    check_80211_standards
    check_wifi_security_protocols
    check_4way_handshake
    check_wireless_attacks
    check_live_wireless
    check_wireless_hardening
    check_rogue_detection
}

main