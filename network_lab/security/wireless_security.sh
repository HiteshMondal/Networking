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
 
    #  1. STANDARDS REFERENCE TABLE 
    section "Standards Evolution"
    cat << 'INFO'
  ╔═══════════╦══════════╦════════════════╦═══════════╦══════╦══════════════════════════════╗
  ║ Standard  ║ Wi-Fi    ║ Band (GHz)     ║ Max Speed ║ Year ║ Key Technology               ║
  ╠═══════════╬══════════╬════════════════╬═══════════╬══════╬══════════════════════════════╣
  ║ 802.11    ║ —        ║ 2.4            ║ 2 Mbps    ║ 1997 ║ FHSS / DSSS — original spec  ║
  ║ 802.11b   ║ Wi-Fi 1  ║ 2.4            ║ 11 Mbps   ║ 1999 ║ DSSS, CCK modulation         ║
  ║ 802.11a   ║ Wi-Fi 2  ║ 5              ║ 54 Mbps   ║ 1999 ║ OFDM, 52 subcarriers         ║
  ║ 802.11g   ║ Wi-Fi 3  ║ 2.4            ║ 54 Mbps   ║ 2003 ║ OFDM on 2.4 GHz (b-compat)   ║
  ║ 802.11n   ║ Wi-Fi 4  ║ 2.4 / 5        ║ 600 Mbps  ║ 2009 ║ MIMO 4×4, 40 MHz channels    ║
  ║ 802.11ac  ║ Wi-Fi 5  ║ 5 only         ║ 3.5 Gbps  ║ 2013 ║ MU-MIMO 8×8, 80/160 MHz      ║
  ║ 802.11ax  ║ Wi-Fi 6  ║ 2.4 / 5        ║ 9.6 Gbps  ║ 2019 ║ OFDMA, BSS Color, TWT        ║
  ║ 802.11ax  ║ Wi-Fi 6E ║ 2.4 / 5 / 6    ║ 9.6 Gbps  ║ 2021 ║ Wi-Fi 6 + 6 GHz spectrum     ║
  ║ 802.11be  ║ Wi-Fi 7  ║ 2.4 / 5 / 6    ║ 46 Gbps   ║ 2024 ║ MLO, 320 MHz, 4096-QAM       ║
  ╚═══════════╩══════════╩════════════════╩═══════════╩══════╩══════════════════════════════╝
 
  Note: "Max Speed" is theoretical PHY throughput under ideal lab conditions.
  Real-world TCP throughput is typically 40–60% of the advertised maximum.
INFO
 
    #  2. KEY TECHNOLOGIES 
    section "Key Technologies Explained"
    cat << 'INFO'
  Modulation & multiplexing:
    DSSS  (Direct Sequence Spread Spectrum) — 802.11b; spreads signal across
          wide band using chipping code; simple but slow
    OFDM  (Orthogonal Frequency Division Multiplexing) — 802.11a/g/n/ac/ax;
          splits channel into many narrow orthogonal subcarriers; efficient,
          handles multipath interference well
    OFDMA (Orthogonal Frequency Division Multiple Access) — Wi-Fi 6+; divides
          subcarriers among multiple clients simultaneously (like LTE); reduces
          latency in dense environments
    QAM   (Quadrature Amplitude Modulation) — encodes bits per symbol;
          Wi-Fi 5: 256-QAM  Wi-Fi 6: 1024-QAM  Wi-Fi 7: 4096-QAM
          Higher QAM → more bits/symbol → higher throughput (needs better SNR)
 
  Antenna technologies:
    SISO  — Single Input Single Output (one antenna each side)
    MIMO  — Multiple Input Multiple Output; multiple spatial streams
    SU-MIMO — Single User MIMO; one client uses all spatial streams
    MU-MIMO — Multi-User MIMO (Wi-Fi 5 downlink, Wi-Fi 6 uplink+downlink);
              AP transmits to multiple clients simultaneously
    Beamforming — phased array focuses signal toward specific client;
              improves SNR at range; requires CSI feedback from client
 
  Wi-Fi 6 / 6E specific:
    BSS Coloring  — tags frames with a color ID to identify overlapping BSS;
                    allows spatial reuse (ignore frames from other color)
    TWT (Target Wake Time) — client negotiates sleep schedule with AP;
                    dramatically reduces IoT device power consumption
    UL-MU-MIMO    — uplink multi-user MIMO (new in Wi-Fi 6; Wi-Fi 5 was DL only)
    6 GHz band    — Wi-Fi 6E only; 59 new 20 MHz channels (US: 1200 MHz of spectrum);
                    WPA3 mandatory; no legacy devices; least interference
 
  Wi-Fi 7 specific:
    MLO  (Multi-Link Operation) — client and AP simultaneously use 2–3 bands;
         aggregates bandwidth and enables seamless failover across bands
    320 MHz channels — doubles Wi-Fi 6E's 160 MHz maximum channel width
    4096-QAM — 20% more bits/symbol vs Wi-Fi 6's 1024-QAM
    MRU  (Multi-Resource Unit) — flexible subcarrier allocation per client
 
  Frequency bands:
    2.4 GHz — 11 channels (US) / 13 (EU); only 3 non-overlapping (1, 6, 11)
              longest range; best wall penetration; most congested
              avoid for throughput-sensitive applications on dense networks
 
    5 GHz   — 24+ non-overlapping 20 MHz channels (varies by region/DFS)
              DFS channels (52–144) require radar avoidance; AP may vacate
              better throughput; moderate range
 
    6 GHz   — 59 non-overlapping 20 MHz channels (US); Wi-Fi 6E / 7 only
              WPA3 required; no legacy device interference; best for dense
              high-throughput deployments; shortest range
INFO
 
    #  3. WIRELESS INTERFACE DETECTION 
    section "Wireless Interface Detection"
 
    # Collect all wireless interfaces via sysfs — distro-independent
    local wifi_ifaces=()
    while IFS= read -r iface; do
        [[ -d "/sys/class/net/${iface}/wireless" ]] && wifi_ifaces+=("$iface")
    done < <(ls /sys/class/net/ 2>/dev/null)
 
    if [[ ${#wifi_ifaces[@]} -eq 0 ]]; then
        status_line neutral "No wireless interfaces detected on this system"
        echo -e "  ${MUTED}  (physical machine without WiFi NIC, or running in a VM/container)${NC}"
        echo
        return 0
    fi
 
    echo -e "  ${SUCCESS}[+] Found ${#wifi_ifaces[@]} wireless interface(s): ${GOLD}${wifi_ifaces[*]}${NC}"
 
    #  4. PER-INTERFACE DEEP AUDIT 
    for wifi_iface in "${wifi_ifaces[@]}"; do
        echo
        echo -e "  ${BORDER}$(printf '%*s' 60 '' | tr ' ' '')${NC}"
        echo -e "  ${TITLE}  Interface: ${BOLD}${GOLD}${wifi_iface}${NC}"
        echo -e "  ${BORDER}$(printf '%*s' 60 '' | tr ' ' '')${NC}"
        echo
 
        #  4a. Basic interface state 
        local mac state driver
        mac=$(cat "/sys/class/net/${wifi_iface}/address" 2>/dev/null || echo "unknown")
        state=$(cat "/sys/class/net/${wifi_iface}/operstate" 2>/dev/null || echo "unknown")
        driver=$(readlink "/sys/class/net/${wifi_iface}/device/driver" 2>/dev/null \
                 | xargs basename 2>/dev/null || echo "unknown")
 
        local state_col
        [[ "$state" == "up" ]] && state_col="$SUCCESS" || state_col="$MUTED"
 
        kv "  MAC Address"  "$mac"
        kv "  State"        "$(echo -e "${state_col}${state}${NC}")"
        kv "  Driver"       "$driver"
 
        #  4b. iw dev info — mode, channel, freq, txpower 
        if command -v iw &>/dev/null; then
            local iw_info
            iw_info=$(iw dev "$wifi_iface" info 2>/dev/null)
 
            if [[ -n "$iw_info" ]]; then
                local iface_type channel freq txpower width
                iface_type=$(echo "$iw_info" | grep -oP 'type \K\S+')
                channel=$(echo   "$iw_info" | grep -oP 'channel \K[0-9]+')
                freq=$(echo      "$iw_info" | grep -oP '\(\K[0-9.]+ MHz' | head -1)
                txpower=$(echo   "$iw_info" | grep -oP 'txpower \K[^\n]+')
                width=$(echo     "$iw_info" | grep -oP 'width: \K[^\n]+')
 
                echo
                echo -e "  ${LABEL}Interface mode & radio:${NC}"
                kv "  Mode"          "${iface_type:---}"
                kv "  Channel"       "${channel:---}"
                kv "  Frequency"     "${freq:---}"
                kv "  Channel width" "${width:---}"
                kv "  TX power"      "${txpower:---}"
 
                # Flag monitor mode
                if [[ "${iface_type,,}" == "monitor" ]]; then
                    echo -e "  ${FAILURE}  ⚠ Interface is in MONITOR mode — may indicate active capture/attack tooling${NC}"
                fi
            fi
        elif command -v iwconfig &>/dev/null; then
            echo
            echo -e "  ${LABEL}iwconfig output:${NC}"
            iwconfig "$wifi_iface" 2>/dev/null | grep -v "^$" | sed 's/^/    /'
        fi
 
        #  4c. Associated AP (link info) 
        echo
        echo -e "  ${LABEL}Associated AP / current link:${NC}"
 
        if command -v iw &>/dev/null; then
            local link_info
            link_info=$(iw dev "$wifi_iface" link 2>/dev/null)
 
            if echo "$link_info" | grep -q "Not connected"; then
                echo -e "  ${MUTED}    Not currently associated with any AP${NC}"
            else
                local bssid essid bitrate signal freq_link
                bssid=$(echo    "$link_info" | grep -oP 'Connected to \K[0-9a-f:]+')
                essid=$(echo    "$link_info" | grep -oP 'SSID: \K.*')
                bitrate=$(echo  "$link_info" | grep -oP 'tx bitrate: \K[^\n]+')
                signal=$(echo   "$link_info" | grep -oP 'signal: \K[^\n]+')
                freq_link=$(echo "$link_info" | grep -oP 'freq: \K[0-9]+')
 
                kv "  BSSID"      "${bssid:---}"
                kv "  SSID"       "${essid:---}"
                kv "  TX bitrate" "${bitrate:---}"
                kv "  Signal"     "${signal:---}"
                kv "  Frequency"  "${freq_link:+${freq_link} MHz}"
 
                # Signal strength interpretation
                if [[ -n "$signal" ]]; then
                    local sig_val
                    sig_val=$(echo "$signal" | grep -oP '\-?[0-9]+')
                    local sig_col sig_label
                    if   (( sig_val >= -50 )); then sig_col="$SUCCESS"; sig_label="Excellent"
                    elif (( sig_val >= -65 )); then sig_col="$SUCCESS"; sig_label="Good"
                    elif (( sig_val >= -75 )); then sig_col="$WARNING"; sig_label="Fair — consider relocating"
                    elif (( sig_val >= -85 )); then sig_col="$FAILURE"; sig_label="Weak — significant packet loss likely"
                    else                            sig_col="$FAILURE"; sig_label="Very weak — unreliable connection"
                    fi
                    echo -e "  ${MUTED}    Signal quality: ${sig_col}${sig_label} (${sig_val} dBm)${NC}"
                fi
 
                # Determine likely 802.11 generation from frequency + bitrate
                local inferred_gen=""
                if [[ -n "$freq_link" ]]; then
                    if (( freq_link >= 5925 )); then
                        inferred_gen="Wi-Fi 6E or Wi-Fi 7 (6 GHz)"
                    elif (( freq_link >= 5180 )); then
                        # Infer from max bitrate if available
                        local rate_num
                        rate_num=$(echo "$bitrate" | grep -oP '^[0-9.]+')
                        if   [[ -n "$rate_num" ]] && (( $(echo "$rate_num > 1000" | bc -l 2>/dev/null) )); then
                            inferred_gen="Likely Wi-Fi 5 (ac) or Wi-Fi 6 (ax) — 5 GHz"
                        else
                            inferred_gen="Wi-Fi 4/5/6 — 5 GHz band"
                        fi
                    elif (( freq_link >= 2412 )); then
                        inferred_gen="2.4 GHz band (Wi-Fi 4/6 possible; could be legacy b/g/n)"
                    fi
                fi
                [[ -n "$inferred_gen" ]] && \
                    echo -e "  ${MUTED}    Inferred generation: ${GOLD}${inferred_gen}${NC}"
            fi
        fi
 
        #  4d. PHY capabilities 
        echo
        echo -e "  ${LABEL}PHY capabilities (supported standards & features):${NC}"
 
        if command -v iw &>/dev/null; then
            # Get phy name from sysfs
            local phy_name
            phy_name=$(cat "/sys/class/net/${wifi_iface}/phy80211/name" 2>/dev/null)
 
            if [[ -n "$phy_name" ]]; then
                local phy_info
                phy_info=$(iw phy "$phy_name" info 2>/dev/null)
 
                # Supported bands summary
                local bands_supported=()
                echo "$phy_info" | grep -qP 'Band 1:' && bands_supported+=("2.4 GHz")
                echo "$phy_info" | grep -qP 'Band 2:' && bands_supported+=("5 GHz")
                echo "$phy_info" | grep -qP 'Band 3:' && bands_supported+=("6 GHz")
 
                [[ ${#bands_supported[@]} -gt 0 ]] && \
                    kv "  Supported bands" "${bands_supported[*]}"
 
                # Feature flags
                local features=()
                echo "$phy_info" | grep -qi "HT capable"   && features+=("HT/802.11n")
                echo "$phy_info" | grep -qi "VHT capable"  && features+=("VHT/802.11ac")
                echo "$phy_info" | grep -qi "HE capable"   && features+=("HE/802.11ax(Wi-Fi 6)")
                echo "$phy_info" | grep -qi "EHT capable"  && features+=("EHT/802.11be(Wi-Fi 7)")
 
                if [[ ${#features[@]} -gt 0 ]]; then
                    kv "  Detected generations" "${features[*]}"
                fi
 
                # Max supported channel widths
                local widths=""
                echo "$phy_info" | grep -q "160 MHz" && widths="160 MHz"
                echo "$phy_info" | grep -q "80 MHz"  && widths="${widths:+$widths, }80 MHz"
                echo "$phy_info" | grep -q "40 MHz"  && widths="${widths:+$widths, }40 MHz"
                echo "$phy_info" | grep -q "20 MHz"  && widths="${widths:+$widths, }20 MHz"
                [[ -n "$widths" ]] && kv "  Channel widths" "$widths"
 
                # MIMO: count spatial streams from antenna info
                local num_antennas
                num_antennas=$(echo "$phy_info" | grep -oP 'Configured Antennas.*TX.*\K[0-9]+' | head -1)
                [[ -n "$num_antennas" ]] && kv "  Antenna streams" "$num_antennas"
 
                # Key feature flags from capabilities
                local cap_flags=()
                echo "$phy_info" | grep -qi "MFP"        && cap_flags+=("MFP/802.11w")
                echo "$phy_info" | grep -qi "TDLS"       && cap_flags+=("TDLS")
                echo "$phy_info" | grep -qi "mesh"       && cap_flags+=("Mesh/802.11s")
                echo "$phy_info" | grep -qi "AP/VLAN"    && cap_flags+=("AP-VLAN")
                echo "$phy_info" | grep -qi "monitor"    && cap_flags+=("Monitor mode")
                echo "$phy_info" | grep -qi "P2P"        && cap_flags+=("Wi-Fi Direct/P2P")
                [[ ${#cap_flags[@]} -gt 0 ]] && \
                    kv "  Capability flags" "${cap_flags[*]}"
 
                # Supported interface modes
                local supported_modes
                supported_modes=$(echo "$phy_info" \
                    | awk '/Supported interface modes/,/^[^ \t]/' \
                    | grep -oE '\* \S+' | awk '{print $2}' | tr '\n' ' ')
                [[ -n "$supported_modes" ]] && \
                    kv "  Interface modes" "$supported_modes"
 
                # Frequency list — first 8 per band, deduplicated
                echo
                echo -e "  ${LABEL}Available frequencies (first 8 per band):${NC}"
                local current_band=""
                local band_count=0
                while IFS= read -r phy_line; do
                    if [[ "$phy_line" =~ Band\ ([0-9]+): ]]; then
                        current_band="${BASH_REMATCH[1]}"
                        band_count=0
                        local band_ghz
                        case "$current_band" in
                            1) band_ghz="2.4 GHz" ;;
                            2) band_ghz="5 GHz"   ;;
                            3) band_ghz="6 GHz"   ;;
                            *) band_ghz="Band ${current_band}" ;;
                        esac
                        echo -e "  ${AMBER}  ${band_ghz}:${NC}"
                    elif [[ "$phy_line" =~ \*\ ([0-9.]+)\ MHz.*channel\ ([0-9]+) && $band_count -lt 8 ]]; then
                        local freq_val="${BASH_REMATCH[1]}"
                        local chan_val="${BASH_REMATCH[2]}"
                        local disabled=""
                        echo "$phy_line" | grep -qi "disabled" && disabled=" ${FAILURE}[disabled]${NC}"
                        printf "  ${MUTED}    ch %-4s  %s MHz%b${NC}\n" \
                            "$chan_val" "$freq_val" "$disabled"
                        (( band_count++ ))
                        [[ $band_count -eq 8 ]] && \
                            echo -e "  ${MUTED}    ... (use: iw phy $phy_name info for full list)${NC}"
                    fi
                done <<< "$phy_info"
 
            else
                echo -e "  ${MUTED}  Could not determine phy name from sysfs${NC}"
                iw dev "$wifi_iface" info 2>/dev/null | sed 's/^/    /'
            fi
        else
            echo -e "  ${MUTED}  iw not available — limited capability info${NC}"
            if command -v iwconfig &>/dev/null; then
                iwconfig "$wifi_iface" 2>/dev/null | sed 's/^/    /'
            fi
        fi
 
    done  # end per-interface loop
 
    #  5. STANDARDS QUICK REFERENCE 
    section "Practical Deployment Guidance"
    cat << 'INFO'
  Choosing the right standard for your deployment:
 
  Legacy hardware / maximum compatibility
    → 802.11n (Wi-Fi 4): 2.4+5 GHz, adequate for most tasks, universal support
    → Avoid 802.11b/g: too slow, pollutes airspace with long preambles
 
  Home / SOHO — modern deployment (2023+)
    → Wi-Fi 6 (802.11ax): best price/performance; WPA3 support; wide device compat
    → Enable WPA3-SAE; disable 2.4 GHz legacy rates; enable 80 MHz channels on 5 GHz
 
  Dense environments (offices, stadiums, universities)
    → Wi-Fi 6 / 6E mandatory: OFDMA + BSS Coloring handle hundreds of clients
    → Deploy 6 GHz SSIDs for modern clients; keep 5 GHz for transitional devices
    → Use 20 MHz channels on 2.4 GHz to maximise non-overlapping cell count
 
  High-throughput / low-latency (AV, gaming, VDI)
    → Wi-Fi 6E or Wi-Fi 7: 6 GHz band, 160/320 MHz channels, MLO
    → Minimise client count per AP; use 5/6 GHz band steering
 
  IoT / battery-constrained devices
    → Wi-Fi 6 TWT (Target Wake Time) reduces IoT power consumption by up to 7×
    → Segment IoT onto dedicated 2.4 GHz SSID / VLAN
 
  Security requirements:
    → WPA3 is mandatory on 6 GHz band (Wi-Fi 6E / 7)
    → 802.11w (PMF) should be required (not just capable) for WPA3
    → Disable WPS on all APs regardless of standard
INFO
    echo
}

# WEP / WPA / WPA2 / WPA3
check_wifi_security_protocols() {
    header "WiFi Security Protocols — WEP to WPA3"
 
    #  1. PROTOCOL EVOLUTION 
    section "Protocol Evolution & Vulnerability Reference"
    cat << 'INFO'
  ┌
  │  WEP (Wired Equivalent Privacy) — 1999                       BROKEN ✘  │
  └
  Cipher:      RC4 stream cipher
  Key sizes:   40-bit or 104-bit static key + 24-bit IV (64/128-bit total)
  Auth:        Open System or Shared Key (both broken)
 
  Fatal flaws:
    • 24-bit IV space (16 million values) — reuse after ~5,000 packets at
      typical traffic rates; keystream fully recoverable
    • Weak IVs predictable → FMS attack (2001); aircrack-ng optimised in 2004
    • CRC-32 integrity check is linear — packets can be forged bit-by-bit
    • No replay protection; no per-user keying
    • Crack time: <60 seconds with ~50,000 IVs (aircrack-ng / wesside-ng)
 
  Attack tools:  aircrack-ng, wesside-ng, airmon-ng
  Status:        ✘ NEVER USE — completely and trivially broken
 
  ┌
  │  WPA (Wi-Fi Protected Access) — 2003                      DEPRECATED ⚠ │
  └
  Cipher:      TKIP (Temporal Key Integrity Protocol) over RC4
  Auth:        PSK (personal) or 802.1X (enterprise)
  Improvements over WEP:
    • Per-packet key mixing (128-bit per-packet key)
    • Michael MIC (Message Integrity Code) — replay counter
    • 48-bit TKIP Sequence Counter (TSC) prevents replay
 
  Remaining flaws:
    • RC4 is the underlying primitive — inherently weak
    • Beck-Tews / Ohigashi-Moriii (2008/2009): TKIP MIC forgery in ~60 sec
    • ChopChop-style decryption of short packets
    • PSK mode still vulnerable to offline dictionary attacks on 4-way handshake
    • WPA with TKIP was always a stopgap; vendors dropped it ~2013
 
  Status:        ⚠ DEPRECATED — disable entirely; no new deployments
 
  ┌
  │  WPA2 (Wi-Fi Protected Access 2) — 2004               ACCEPTABLE (★★★) │
  └
  Cipher:      AES-CCMP (128-bit AES, Counter Mode + CBC-MAC integrity)
  Auth:        PSK (personal) or IEEE 802.1X + RADIUS (enterprise)
  Key exchange: 4-way handshake (PTK/GTK derivation from PMK)
 
  Modes:
    WPA2-Personal (PSK)
      • All users share a single pre-shared key
      • PMK = PBKDF2-HMAC-SHA1(PSK, SSID, 4096 iter) — deliberately slow
      • Rogue AP with same PSK can MITM any client
 
    WPA2-Enterprise (802.1X)
      • Per-user credentials via EAP (PEAP, EAP-TLS, EAP-TTLS)
      • RADIUS server issues per-session PMK — no shared secret
      • Protects against insider credential theft
 
  Vulnerabilities:
    KRACK (2017) — CVE-2017-13077 to 13088
      Key reinstallation via nonce reuse in 4-way / group handshake
      All clients affected; patched in most OS updates by late 2017
      Unpatched IoT devices remain vulnerable indefinitely
 
    PMKID attack (2018) — Jens Steube (hashcat author)
      PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || client MAC)
      Captured from a single EAPOL frame — no client association needed
      Enables offline PSK dictionary attack without sniffing a full handshake
      Tool: hcxdumptool + hcxtools + hashcat (mode 22000)
 
    Offline dictionary / PMKID
      Weak PSKs (<12 chars or common words) crackable in minutes with GPU
      Rule of thumb: PSK should be ≥20 random chars
 
    Dragonblood (WPA3 transition mode — affects WPA2-mixed APs)
      Side-channel and DoS attacks when WPA3 SAE falls back to WPA2
 
  Status:        ★ ACCEPTABLE — require strong PSK (20+ random chars);
                   prefer WPA3-SAE wherever hardware supports it
 
  ┌
  │  WPA3 — 2018                                         RECOMMENDED (★★★★) │
  └
  WPA3-Personal (SAE — Simultaneous Authentication of Equals)
    • Dragonfly key exchange (IETF RFC 7664) — zero-knowledge proof
    • Offline dictionary attacks eliminated: attacker must be online per guess
    • Forward secrecy: compromise of PSK does NOT expose past sessions
    • Anti-clogging tokens resist DoS amplification
    • Transition mode (WPA2+WPA3) preserves backward compat — some risk
 
  WPA3-Enterprise (192-bit security suite)
    • GCMP-256 cipher (Galois/Counter Mode)
    • HMAC-SHA-384 for key derivation
    • ECDH/ECDSA-384 for key establishment
    • Meets NSA CNSA suite requirements for sensitive environments
 
  OWE (Opportunistic Wireless Encryption — Enhanced Open)
    • Unauthenticated Diffie-Hellman: encrypts open WiFi sessions
    • Prevents passive eavesdropping in cafes / airports (no passphrase)
    • Does NOT provide mutual authentication — still vulnerable to active MITM
 
  Dragonblood (2019) — partial attacks on early WPA3 implementations
    • Side-channel timing leaks on some curves (mitigated in updated firmware)
    • Downgrade to WPA2 in transition mode (design trade-off)
    • Cache-based side channels on certain ECC implementations
 
  Status:        ★★★ RECOMMENDED — deploy WPA3-SAE; disable transition mode
                   on new hardware; use WPA3-Enterprise for sensitive nets
 
  ┌
  │  WPS (WiFi Protected Setup)                            DISABLE NOW ✘✘✘  │
  └
  Design flaw:
    • 8-digit PIN split into two independent 4-digit halves for verification
    • Effective keyspace: 10^4 + 10^3 = 11,000 guesses (not 10^8)
    • Online brute-force: ~4 hours worst case (Viehbock, 2011)
 
  Pixie Dust attack (2014)
    • Offline crack against routers using weak nonce generation (E-S1/E-S2)
    • Many older Realtek, Ralink, Broadcom chipsets affected
    • Crack in seconds with pixiewps tool
 
  Attack tools:  Reaver, Bully, pixiewps, wpscan
  Status:        ✘ DISABLE IMMEDIATELY — no legitimate use case justifies the risk
 
  ┌
  │  Protocol Comparison Summary                                             │
  └
  Protocol  Year  Cipher        Key Bits  Fwd Secrecy  MIC/AEAD  Verdict
              
  WEP       1999  RC4           40/104    No           CRC-32    BROKEN
  WPA       2003  RC4+TKIP      128       No           Michael   DEPRECATED
  WPA2-PSK  2004  AES-CCMP      128       No           CCMP      ACCEPTABLE
  WPA2-Ent  2004  AES-CCMP      128       No           CCMP      GOOD
  WPA3-SAE  2018  AES-CCMP      128       Yes          CCMP      RECOMMENDED
  WPA3-Ent  2018  AES-GCMP      256       Yes          GCMP-256  BEST
  OWE       2018  AES-CCMP      128       Yes          CCMP      GOOD (open)
INFO
 
    #  2. INTERFACE DISCOVERY 
    section "Wireless Interface Discovery"
 
    # Detect all wireless interfaces via sysfs (distro-independent)
    local wifi_ifaces=()
    while IFS= read -r iface; do
        [[ -d "/sys/class/net/${iface}/wireless" ]] && wifi_ifaces+=("$iface")
    done < <(ls /sys/class/net/ 2>/dev/null)
 
    if [[ ${#wifi_ifaces[@]} -eq 0 ]]; then
        echo -e "  ${MUTED}  No wireless interfaces detected on this system${NC}"
    else
        for iface in "${wifi_ifaces[@]}"; do
            local state driver chipset phy
            state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "unknown")
            driver=$(readlink "/sys/class/net/${iface}/device/driver" 2>/dev/null \
                     | xargs basename 2>/dev/null || echo "unknown")
            phy=$(ls "/sys/class/net/${iface}/phy80211/" 2>/dev/null | head -1 || echo "")
 
            local state_col
            [[ "$state" == "up" ]] && state_col="$SUCCESS" || state_col="$MUTED"
 
            printf "  ${LABEL}Interface:${NC}  ${BOLD}${VALUE}%-12s${NC}  " "$iface"
            printf "state: ${state_col}%-8s${NC}  " "$state"
            printf "driver: ${GOLD}%-14s${NC}  " "$driver"
            [[ -n "$phy" ]] && printf "phy: ${MUTED}%s${NC}" "$phy"
            echo
 
            # Show MAC address
            local mac
            mac=$(cat "/sys/class/net/${iface}/address" 2>/dev/null || echo "")
            [[ -n "$mac" ]] && printf "  ${MUTED}  MAC: %s${NC}\n" "$mac"
 
            # Check monitor mode capability
            if command -v iw &>/dev/null; then
                local modes
                modes=$(iw phy "$(cat "/sys/class/net/${iface}/phy80211/name" 2>/dev/null)" \
                        info 2>/dev/null | grep -A5 "Supported interface modes" \
                        | grep -oE "monitor|AP|managed|mesh point" | tr '\n' ' ')
                [[ -n "$modes" ]] && printf "  ${MUTED}  Supported modes: %s${NC}\n" "$modes"
            fi
        done
    fi
 
    #  3. ACTIVE CONNECTION AUDIT 
    section "Active WiFi Connection Audit"
 
    if command -v nmcli &>/dev/null; then
 
        # Active connections
        echo -e "  ${LABEL}Currently active wireless connections:${NC}"
        echo
 
        local active_found=0
        while IFS=: read -r name iface type security signal; do
            [[ "$type" != "wifi" ]] && continue
            (( active_found++ ))
 
            # Security rating
            local sec_col sec_note
            case "${security^^}" in
                *WPA3*)   sec_col="$SUCCESS";  sec_note="[RECOMMENDED]" ;;
                *WPA2*)   sec_col="$WARNING";  sec_note="[ACCEPTABLE — upgrade to WPA3 if possible]" ;;
                *WPA*)    sec_col="$FAILURE";  sec_note="[DEPRECATED — migrate immediately]" ;;
                *WEP*)    sec_col="$FAILURE";  sec_note="[BROKEN — replace immediately]" ;;
                "")       sec_col="$FAILURE";  sec_note="[OPEN — no encryption]" ;;
                *)        sec_col="$MUTED";    sec_note="" ;;
            esac
 
            printf "  ${SUCCESS}●${NC}  ${BOLD}${VALUE}%s${NC}\n" "$name"
            printf "  ${MUTED}   Interface: %-10s  Security: ${sec_col}%-10s${NC} %s\n" \
                "${iface:-n/a}" "${security:-OPEN}" "$sec_note"
            [[ -n "$signal" ]] && printf "  ${MUTED}   Signal:   %s%%${NC}\n" "$signal"
            echo
 
        done < <(nmcli -t -f NAME,DEVICE,TYPE,SECURITY,SIGNAL connection show --active 2>/dev/null)
 
        [[ $active_found -eq 0 ]] && echo -e "  ${MUTED}  No active WiFi connections${NC}"
 
        # Saved connection security audit
        echo -e "  ${LABEL}Saved WiFi profile security summary:${NC}"
        echo
 
        local profiles_found=0 profiles_insecure=0
        while IFS=: read -r name security; do
            [[ -z "$name" ]] && continue
            (( profiles_found++ ))
 
            local sec_col rating
            case "${security^^}" in
                *WPA3*)   sec_col="$SUCCESS"; rating="★★★ WPA3"     ;;
                *WPA2*)   sec_col="$WARNING"; rating="★★  WPA2"     ;;
                *WPA*)    sec_col="$FAILURE"; rating="★   WPA (old)"; (( profiles_insecure++ )) ;;
                *WEP*)    sec_col="$FAILURE"; rating="✘   WEP";       (( profiles_insecure++ )) ;;
                "")       sec_col="$FAILURE"; rating="✘   OPEN";      (( profiles_insecure++ )) ;;
                *)        sec_col="$MUTED";   rating="?   Unknown"    ;;
            esac
 
            printf "  ${sec_col}%-4s${NC}  ${VALUE}%-35s${NC}  ${MUTED}%s${NC}\n" \
                "$rating" "$name" "$security"
 
        done < <(nmcli -t -f NAME,SECURITY connection show 2>/dev/null \
                 | grep -v '^--' | head -20)
 
        [[ $profiles_found -eq 0 ]] && echo -e "  ${MUTED}  No saved profiles found${NC}"
 
        echo
        if [[ $profiles_insecure -gt 0 ]]; then
            echo -e "  ${FAILURE}[!] $profiles_insecure saved profile(s) use deprecated or missing security${NC}"
        else
            [[ $profiles_found -gt 0 ]] && \
                echo -e "  ${SUCCESS}[+] All $profiles_found saved profiles use WPA2 or better${NC}"
        fi
 
    elif command -v iwconfig &>/dev/null || [[ ${#wifi_ifaces[@]} -gt 0 ]]; then
        # Fallback: use iwconfig / proc for environments without NetworkManager
        echo -e "  ${MUTED}  NetworkManager (nmcli) not available — using iwconfig fallback${NC}"
        echo
 
        local scan_iface="${wifi_ifaces[0]:-wlan0}"
        local enc_info
        enc_info=$(iwconfig "$scan_iface" 2>/dev/null | grep -i "encryption\|essid\|access point")
 
        if [[ -n "$enc_info" ]]; then
            echo "$enc_info" | sed 's/^/  /'
        else
            echo -e "  ${MUTED}  No iwconfig data available for $scan_iface${NC}"
        fi
    else
        status_line neutral "No WiFi management tools available (nmcli / iwconfig not found)"
    fi
 
    #  4. NEARBY ACCESS POINT SCAN 
    section "Nearby Access Point Security Scan"
 
    if command -v nmcli &>/dev/null; then
        echo -e "  ${LABEL}Scanning for visible access points...${NC}"
        echo
 
        # Trigger a rescan (best-effort, may require sudo)
        nmcli dev wifi rescan 2>/dev/null
 
        # Header
        printf "  ${BOLD}${TITLE}%-3s  %-32s %-10s %-8s %-7s %-6s %s${NC}\n" \
            "Str" "SSID" "Security" "Mode" "Band" "Ch" "BSSID"
        printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '%.0s' {1..90})"
 
        local ap_count=0 insecure_count=0 open_count=0
        while IFS= read -r line; do
            # Skip header lines
            [[ "$line" =~ ^IN-USE ]] && continue
            [[ -z "$line" ]] && continue
 
            # nmcli fields: IN-USE BSSID SSID MODE CHAN RATE SIGNAL BARS SECURITY
            local in_use bssid ssid mode chan rate signal bars security
            read -r in_use bssid ssid mode chan rate signal bars security <<< "$line"
 
            [[ -z "$ssid" || "$ssid" == "--" ]] && ssid="[hidden]"
            (( ap_count++ ))
 
            # Security colour + verdict
            local sec_col verdict
            case "${security^^}" in
                *WPA3*)    sec_col="$SUCCESS"; verdict="" ;;
                *WPA2*)    sec_col="$WARNING"; verdict="" ;;
                *WPA1*|*WPA\ *) sec_col="$FAILURE"; verdict="⚠ OLD"; (( insecure_count++ )) ;;
                *WEP*)     sec_col="$FAILURE"; verdict="✘ BROKEN"; (( insecure_count++ )) ;;
                "--"|"")   sec_col="$FAILURE"; verdict="✘ OPEN";   (( open_count++ )); (( insecure_count++ )) ;;
                *)         sec_col="$MUTED";   verdict="" ;;
            esac
 
            # Active connection marker
            local active_marker=""
            [[ "$in_use" == "*" ]] && active_marker="${SUCCESS}◀ connected${NC}"
 
            # Signal bar colour
            local sig_col
            (( signal >= 70 )) && sig_col="$SUCCESS" \
                || { (( signal >= 40 )) && sig_col="$WARNING" || sig_col="$FAILURE"; }
 
            printf "  ${sig_col}%3s%%${NC}  ${VALUE}%-32.32s${NC} ${sec_col}%-10s${NC} %-8s %-7s %-6s ${MUTED}%s${NC}" \
                "$signal" "$ssid" "${security:---}" "$mode" "$chan" "$bars" "$bssid"
 
            [[ -n "$verdict" ]] && printf "  ${FAILURE}%s${NC}" "$verdict"
            [[ -n "$active_marker" ]] && printf "  $active_marker"
            echo
 
        done < <(nmcli -f IN-USE,BSSID,SSID,MODE,CHAN,RATE,SIGNAL,BARS,SECURITY \
                       dev wifi list 2>/dev/null | tail -n +2 | sort -k7 -rn | head -25)
 
        echo
        printf "  Visible APs: ${GOLD}%d${NC}   " "$ap_count"
        printf "Insecure/Open: ${FAILURE}%d${NC}   " "$insecure_count"
        printf "Open (no auth): ${FAILURE}%d${NC}\n" "$open_count"
 
        if [[ $open_count -gt 0 ]]; then
            echo -e "  ${FAILURE}[!] Open APs detected — avoid connecting; susceptible to passive eavesdropping${NC}"
        fi
        if [[ $insecure_count -gt 0 ]]; then
            echo -e "  ${WARNING}[~] $insecure_count AP(s) use deprecated or absent encryption${NC}"
        fi
 
    elif [[ ${#wifi_ifaces[@]} -gt 0 ]]; then
        local scan_iface="${wifi_ifaces[0]}"
        echo -e "  ${LABEL}Using iwlist scan on ${scan_iface}...${NC}"
        echo
 
        local scan_output
        scan_output=$(iwlist "$scan_iface" scan 2>/dev/null)
 
        if [[ -z "$scan_output" ]]; then
            echo -e "  ${MUTED}  No scan results (may require sudo / interface up)${NC}"
        else
            # Extract SSID + encryption info per cell
            local current_ssid=""
            while IFS= read -r scan_line; do
                if [[ "$scan_line" =~ ESSID:\"(.+)\" ]]; then
                    current_ssid="${BASH_REMATCH[1]}"
                fi
                if [[ "$scan_line" =~ (IE:\ WPA|WPA2|WPA\ Version|Encryption\ key:(on|off)) ]]; then
                    printf "  ${VALUE}%-35s${NC}  ${MUTED}%s${NC}\n" \
                        "$current_ssid" "$(echo "$scan_line" | xargs)"
                fi
            done <<< "$scan_output"
        fi
    else
        status_line neutral "No wireless interfaces available for AP scan"
    fi
 
    #  5. WPS STATUS CHECK 
    section "WPS Status Check"
 
    # iw can report WPS in BSS info; also check saved NM profiles
    if command -v nmcli &>/dev/null; then
        echo -e "  ${LABEL}Checking connected AP for WPS beacon flag...${NC}"
 
        local active_bssid
        active_bssid=$(nmcli -t -f ACTIVE,BSSID dev wifi list 2>/dev/null \
            | grep '^yes' | cut -d: -f2- | head -1)
 
        if [[ -n "$active_bssid" ]] && command -v iw &>/dev/null; then
            local wps_info
            wps_info=$(iw dev "${wifi_ifaces[0]:-wlan0}" scan 2>/dev/null \
                | awk "/BSS ${active_bssid//:/\\:}/,/^BSS /" \
                | grep -i "WPS\|WSC" | head -5)
 
            if [[ -n "$wps_info" ]]; then
                echo -e "  ${FAILURE}[!] WPS advertised by connected AP — recommend disabling WPS on the router${NC}"
                echo "$wps_info" | sed 's/^/    /'
            else
                echo -e "  ${SUCCESS}[+] No WPS advertisement detected on connected AP${NC}"
            fi
        else
            echo -e "  ${MUTED}  Cannot verify WPS remotely — check your router admin panel${NC}"
        fi
    fi
 
    echo
    echo -e "  ${FAILURE}[!] WPS should be DISABLED on all access points regardless of scan results${NC}"
    echo -e "  ${MUTED}     Even if not currently advertising WPS, router firmware may re-enable it${NC}"
    echo -e "  ${MUTED}     after updates. Verify in router settings manually.${NC}"
 
    #  6. HARDENING RECOMMENDATIONS 
    section "WiFi Hardening Recommendations"
 
    local checks=(
        "Deploy WPA3-SAE (Personal) or WPA3-Enterprise on all APs|critical"
        "Disable WEP and WPA/TKIP entirely on all hardware|critical"
        "Disable WPS (WiFi Protected Setup) on all access points|critical"
        "Use PSK ≥ 20 characters (random, not passphrase-based)|high"
        "Enable Management Frame Protection (802.11w / PMF required in WPA3)|high"
        "Segment IoT devices onto a separate SSID / VLAN|high"
        "Disable SSID broadcast for sensitive networks (minor obscurity benefit)|medium"
        "Rotate PSK periodically or use WPA2/3-Enterprise with per-user creds|medium"
        "Enable client isolation to prevent peer-to-peer attacks on guest nets|medium"
        "Audit authorized devices via RADIUS or MAC filtering (defence-in-depth)|low"
        "Monitor for rogue APs using WIDS (Wireless Intrusion Detection)|low"
        "Use VPN over all WiFi — especially public / open networks|high"
    )
 
    for entry in "${checks[@]}"; do
        local rec risk
        IFS='|' read -r rec risk <<< "$entry"
 
        local risk_col marker
        case "$risk" in
            critical) risk_col="$FAILURE"; marker="✘" ;;
            high)     risk_col="$WARNING"; marker="!" ;;
            medium)   risk_col="$AMBER";   marker="~" ;;
            low)      risk_col="$MUTED";   marker="i" ;;
        esac
 
        printf "  ${risk_col}[%s]${NC}  %-60s ${DARK_GRAY}(%s)${NC}\n" \
            "$marker" "$rec" "$risk"
    done
 
    echo
    echo -e "  ${LABEL}Further reading:${NC}"
    echo -e "  ${MUTED}  • Wi-Fi Alliance WPA3 Specification: https://www.wi-fi.org/discover-wi-fi/security${NC}"
    echo -e "  ${MUTED}  • NIST SP 800-97: Establishing Wireless Robust Security Networks${NC}"
    echo -e "  ${MUTED}  • Dragonblood: https://dragonbloodattack.com${NC}"
    echo -e "  ${MUTED}  • KRACK:       https://www.krackattacks.com${NC}"
    echo
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

  │  Authenticator (AP)                    Supplicant (Client)           │
  │                                                                      │
  │  ANonce                M1►                                           │
  │                                        Generates SNonce              │
  │                                        Derives PTK                   │
  │                        ◄M2      SNonce + MIC (KCK)                   │
  │  Derives PTK                                                         │
  │  Validates MIC                                                       │
  │  Installs PTK                                                        │
  │  GTK (encrypted w/ KEK) M3►                                          │
  │                                        Installs PTK + GTK            │
  │                        ◄M4      ACK + MIC                            │
  │  Installs PTK + GTK                                                  │

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
    
    Eavesdropping  — capture cleartext traffic (WEP/Open networks)
    Traffic Analysis— infer activity from packet patterns (even on WPA2)
    Handshake Capture— record WPA2 4-way handshake for offline cracking
    Beacon Sniffing — enumerate APs, clients, probe requests (device tracking)

  Active Attacks (require injection — detectable with WIDS):
    
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
    printf "  ${DARK_GRAY}%-20s %-22s %s${NC}\n" "-" "-" "-"
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
 
    #  1. AP SECURITY CHECKLIST 
    section "Access Point Security Checklist"
    echo
 
    # Format: "description|risk_level|category"
    # Risk levels: critical / high / medium / low
    # Categories used to group output
    local ap_checks=(
        "Enable WPA3-SAE (Personal) or WPA3-Enterprise; disable WEP and WPA/TKIP entirely|critical|Encryption"
        "Disable WPS (WiFi Protected Setup) permanently — no legitimate use case justifies the risk|critical|Authentication"
        "Use a PSK of 20+ random characters (not a passphrase or dictionary word)|high|Authentication"
        "Enable Management Frame Protection (PMF — IEEE 802.11w, required for WPA3)|high|Protocol"
        "Enable client isolation: prevent direct client-to-client Layer 2 communication|high|Segmentation"
        "Segregate IoT and guest traffic onto isolated VLANs with no LAN access|high|Segmentation"
        "Deploy 802.1X + RADIUS for enterprise environments (per-user credentials, no shared PSK)|high|Authentication"
        "Disable legacy rates and protocols: 802.11b, 802.11g-only APs, TKIP ciphers|medium|Protocol"
        "Prefer 5 GHz or 6 GHz bands (Wi-Fi 6E); disable 2.4 GHz where not required|medium|Protocol"
        "Enable Opportunistic Wireless Encryption (OWE) on guest/open SSIDs|medium|Encryption"
        "SSID broadcast: disabling is obscurity only — do not rely on it as a security control|low|Protocol"
        "Deploy WIDS/WIPS: monitor for rogue APs, deauth floods, evil-twin attacks|medium|Monitoring"
        "Perform regular rogue AP audits: compare authorised AP inventory vs live scan|medium|Monitoring"
        "Log all associations, deauthentications, and authentication failures to SIEM|medium|Monitoring"
        "Apply AP firmware updates promptly — WPA3 Dragonblood was patched via firmware|high|Maintenance"
        "Physical security: mount APs in tamper-resistant enclosures; disable console ports|low|Physical"
        "Disable unused AP features: Telnet, HTTP management, UPnP, legacy SNMP (v1/v2c)|medium|Hardening"
        "Set AP management interface to a dedicated out-of-band VLAN; enforce MFA on admin UI|high|Hardening"
    )
 
    local current_cat=""
    for entry in "${ap_checks[@]}"; do
        local rec risk category
        IFS='|' read -r rec risk category <<< "$entry"
 
        # Print category heading when it changes
        if [[ "$category" != "$current_cat" ]]; then
            current_cat="$category"
            echo -e "  ${AMBER}${category}${NC}"
        fi
 
        local risk_col marker
        case "$risk" in
            critical) risk_col="$FAILURE"; marker="✘" ;;
            high)     risk_col="$WARNING"; marker="!" ;;
            medium)   risk_col="$AMBER";   marker="~" ;;
            low)      risk_col="$MUTED";   marker="i" ;;
        esac
 
        printf "  ${risk_col}[%s]${NC}  ${VALUE}%s${NC}  ${DARK_GRAY}(%s)${NC}\n" \
            "$marker" "$rec" "$risk"
    done
    echo
 
    #  2. CLIENT-SIDE HARDENING 
    section "Client-Side Hardening"
    echo
 
    local client_checks=(
        "Disable auto-connect to open or unknown WiFi networks|critical|Connection Hygiene"
        "Forget saved profiles for networks you no longer use (each is a passive probe beacon)|high|Connection Hygiene"
        "Use a VPN with kill-switch on all untrusted and public networks|high|Privacy"
        "Enable MAC address randomisation per-network to prevent probe request tracking|high|Privacy"
        "Disable WiFi radio when not in use — prevents probe request leakage and tracking|medium|Privacy"
        "Enable host-based firewall when connected to public or guest WiFi|high|Host Security"
        "Prefer HTTPS-only mode in browser (HSTS preloading); reject mixed-content pages|high|Host Security"
        "Never perform sensitive transactions (banking, auth) over untrusted WiFi without VPN|critical|Host Security"
        "Disable 802.11 Probe Requests for known SSIDs (varies by OS — check WiFi privacy settings)|medium|Privacy"
        "On Linux: use iwd or NetworkManager with private address generation enabled|low|Host Security"
    )
 
    local current_cat=""
    for entry in "${client_checks[@]}"; do
        local rec risk category
        IFS='|' read -r rec risk category <<< "$entry"
 
        if [[ "$category" != "$current_cat" ]]; then
            current_cat="$category"
            echo -e "  ${AMBER}${category}${NC}"
        fi
 
        local risk_col marker
        case "$risk" in
            critical) risk_col="$FAILURE"; marker="✘" ;;
            high)     risk_col="$WARNING"; marker="!" ;;
            medium)   risk_col="$AMBER";   marker="~" ;;
            low)      risk_col="$MUTED";   marker="i" ;;
        esac
 
        printf "  ${risk_col}[%s]${NC}  ${VALUE}%s${NC}  ${DARK_GRAY}(%s)${NC}\n" \
            "$marker" "$rec" "$risk"
    done
    echo
 
    #  3. SAVED PROFILE SECURITY AUDIT 
    section "System WiFi Profile Security Audit"
 
    if ! command -v nmcli &>/dev/null; then
        echo -e "  ${MUTED}  nmcli not available — install NetworkManager for profile auditing${NC}"
    else
        echo -e "  ${LABEL}Saved WiFi connection profiles:${NC}"
        echo
        printf "  ${BOLD}${TITLE}%-35s %-18s %-12s %s${NC}\n" \
            "Profile Name" "Key Management" "Security" "Status"
        printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '%*s' 80 '' | tr ' ' '-')"
 
        local total=0 secure=0 insecure=0 open_count=0
 
        while IFS= read -r profile_line; do
            local name
            name=$(echo "$profile_line" | awk '{print $1}')
            [[ -z "$name" || "$name" == "NAME" ]] && continue
 
            # Only process WiFi profiles
            local conn_type
            conn_type=$(nmcli -g connection.type connection show "$name" 2>/dev/null)
            [[ "$conn_type" != "802-11-wireless" ]] && continue
 
            (( total++ ))
 
            # Key management method
            local key_mgmt
            key_mgmt=$(nmcli -g 802-11-wireless-security.key-mgmt \
                       connection show "$name" 2>/dev/null)
            key_mgmt="${key_mgmt:-none}"
 
            # Cipher details
            local pairwise_cipher group_cipher
            pairwise_cipher=$(nmcli -g 802-11-wireless-security.pairwise \
                              connection show "$name" 2>/dev/null)
            group_cipher=$(nmcli -g 802-11-wireless-security.group \
                           connection show "$name" 2>/dev/null)
 
            # PMF (Management Frame Protection) status
            local pmf_status
            pmf_status=$(nmcli -g 802-11-wireless-security.pmf \
                         connection show "$name" 2>/dev/null)
 
            # Auto-connect setting
            local autoconnect
            autoconnect=$(nmcli -g connection.autoconnect connection show "$name" 2>/dev/null)
 
            # Security rating and colour
            local sec_label sec_col status_sym verdict
            case "$key_mgmt" in
                sae)
                    sec_label="WPA3-SAE"
                    sec_col="$SUCCESS"
                    status_sym="✔"
                    verdict="Secure"
                    (( secure++ ))
                    ;;
                wpa-psk)
                    # Check if pairwise is CCMP (AES) vs TKIP
                    if [[ "${pairwise_cipher^^}" == *"TKIP"* ]]; then
                        sec_label="WPA2-TKIP"
                        sec_col="$FAILURE"
                        status_sym="✘"
                        verdict="Insecure — TKIP"
                        (( insecure++ ))
                    else
                        sec_label="WPA2-PSK"
                        sec_col="$WARNING"
                        status_sym="~"
                        verdict="Acceptable"
                        (( secure++ ))
                    fi
                    ;;
                wpa-eap)
                    sec_label="WPA2-Enterprise"
                    sec_col="$SUCCESS"
                    status_sym="✔"
                    verdict="Secure"
                    (( secure++ ))
                    ;;
                wpa-eap-suite-b-192)
                    sec_label="WPA3-Enterprise"
                    sec_col="$SUCCESS"
                    status_sym="✔"
                    verdict="Secure"
                    (( secure++ ))
                    ;;
                owe)
                    sec_label="OWE (Enh. Open)"
                    sec_col="$WARNING"
                    status_sym="~"
                    verdict="Encrypted, no auth"
                    (( secure++ ))
                    ;;
                none|"")
                    sec_label="OPEN"
                    sec_col="$FAILURE"
                    status_sym="✘"
                    verdict="No encryption"
                    (( insecure++ ))
                    (( open_count++ ))
                    ;;
                *)
                    sec_label="$key_mgmt"
                    sec_col="$MUTED"
                    status_sym="?"
                    verdict="Unknown"
                    ;;
            esac
 
            printf "  ${sec_col}%s${NC}  ${VALUE}%-35.35s${NC} ${sec_col}%-18s${NC} %-12s ${sec_col}%s${NC}\n" \
                "$status_sym" "$name" "$sec_label" "${pairwise_cipher:---}" "$verdict"
 
            # Per-profile warnings
            local warnings=()
 
            [[ "$pmf_status" == "0" || "$pmf_status" == "disable" ]] && \
                warnings+=("PMF/802.11w disabled — management frames unprotected")
 
            [[ "$pmf_status" == "" && "$key_mgmt" != "sae" ]] && \
                warnings+=("PMF status unknown — verify 802.11w is enabled in AP config")
 
            [[ "$autoconnect" == "yes" && ( "$key_mgmt" == "none" || "$key_mgmt" == "" ) ]] && \
                warnings+=("Auto-connect enabled on open network — disable to prevent silent association")
 
            [[ "${pairwise_cipher^^}" == *"TKIP"* ]] && \
                warnings+=("TKIP cipher in use — replace with CCMP (AES)")
 
            for warn in "${warnings[@]}"; do
                printf "    ${WARNING}⚠${NC}  ${MUTED}%s${NC}\n" "$warn"
            done
 
        done < <(nmcli connection show 2>/dev/null)
 
        echo
        if [[ $total -eq 0 ]]; then
            echo -e "  ${MUTED}  No saved WiFi profiles found${NC}"
        else
            printf "  Profiles audited: ${GOLD}%d${NC}   " "$total"
            printf "Secure/Acceptable: ${SUCCESS}%d${NC}   " "$secure"
            printf "Insecure: ${FAILURE}%d${NC}   " "$insecure"
            printf "Open (no encryption): ${FAILURE}%d${NC}\n" "$open_count"
 
            [[ $insecure -gt 0 ]] && \
                echo -e "\n  ${FAILURE}[!] $insecure profile(s) use no encryption or deprecated ciphers — review immediately${NC}"
            [[ $open_count -gt 0 ]] && \
                echo -e "  ${FAILURE}[!] $open_count open profile(s) detected — consider removing or replacing with OWE${NC}"
            [[ $insecure -eq 0 && $open_count -eq 0 ]] && \
                echo -e "\n  ${SUCCESS}[+] All $total saved profiles use acceptable or strong security${NC}"
        fi
    fi
 
    #  4. LIVE INTERFACE HARDENING STATE 
    section "Live Interface Hardening State"
 
    # Collect wireless interfaces via sysfs (distro-independent)
    local wifi_ifaces=()
    while IFS= read -r iface; do
        [[ -d "/sys/class/net/${iface}/wireless" ]] && wifi_ifaces+=("$iface")
    done < <(ls /sys/class/net/ 2>/dev/null)
 
    if [[ ${#wifi_ifaces[@]} -eq 0 ]]; then
        echo -e "  ${MUTED}  No wireless interfaces detected${NC}"
    else
        for iface in "${wifi_ifaces[@]}"; do
            echo -e "  ${LABEL}Interface: ${BOLD}${VALUE}${iface}${NC}"
 
            # MAC randomisation — check via NetworkManager or iw
            local mac_rand="unknown"
            if command -v nmcli &>/dev/null; then
                local rand_setting
                rand_setting=$(nmcli -g wifi.cloned-mac-address \
                               device show "$iface" 2>/dev/null)
                case "$rand_setting" in
                    random|stable) mac_rand="enabled (${rand_setting})" ;;
                    permanent|"") mac_rand="disabled (permanent MAC)" ;;
                    *)             mac_rand="${rand_setting}" ;;
                esac
            fi
 
            local rand_col
            [[ "$mac_rand" == *"enabled"* ]] && rand_col="$SUCCESS" || rand_col="$WARNING"
            printf "  ${MUTED}  %-30s${NC} ${rand_col}%s${NC}\n" "MAC randomisation:" "$mac_rand"
 
            # Power management state
            local pwr_mgmt="unknown"
            if command -v iwconfig &>/dev/null; then
                pwr_mgmt=$(iwconfig "$iface" 2>/dev/null \
                    | grep -oP 'Power Management:\K\S+' || echo "unknown")
            fi
 
            local pwr_col
            # Power management ON can cause deauth vulnerability in some drivers
            [[ "$pwr_mgmt" == "off" ]] && pwr_col="$SUCCESS" || pwr_col="$MUTED"
            printf "  ${MUTED}  %-30s${NC} ${pwr_col}%s${NC}\n" "Power management:" "$pwr_mgmt"
 
            # Current mode (managed / monitor / etc.)
            local iface_mode="unknown"
            if command -v iw &>/dev/null; then
                iface_mode=$(iw dev "$iface" info 2>/dev/null \
                    | grep -oP 'type \K\S+' || echo "unknown")
            elif command -v iwconfig &>/dev/null; then
                iface_mode=$(iwconfig "$iface" 2>/dev/null \
                    | grep -oP 'Mode:\K\S+' || echo "unknown")
            fi
 
            local mode_col
            [[ "$iface_mode" == "managed" ]] && mode_col="$SUCCESS" \
                || { [[ "$iface_mode" == "monitor" ]] && mode_col="$FAILURE" \
                || mode_col="$MUTED"; }
            printf "  ${MUTED}  %-30s${NC} ${mode_col}%s${NC}\n" "Interface mode:" "$iface_mode"
 
            [[ "$iface_mode" == "monitor" ]] && \
                echo -e "  ${FAILURE}  ⚠ Interface in monitor mode — may indicate active wireless attack tooling${NC}"
 
            echo
        done
    fi
 
    #  5. PROBE REQUEST PRIVACY CHECK -
    section "Probe Request & Privacy Exposure"
 
    echo -e "  ${LABEL}What are probe requests?${NC}"
    cat << 'INFO'
  When WiFi is enabled, your device broadcasts probe requests containing the
  SSIDs of every saved network to discover if any are nearby. These are
  visible to any passive listener within radio range — no association needed.
 
  Risk:  Saved SSIDs reveal location history (home, office, hotel, etc.)
         MAC address in probes enables persistent tracking across locations
         Evil-twin APs respond to probes and trigger auto-connect attempts
INFO
 
    echo
    if command -v nmcli &>/dev/null; then
        echo -e "  ${LABEL}Saved profiles that broadcast probe requests (non-hidden SSIDs):${NC}"
 
        local probe_count=0
        while IFS= read -r profile_line; do
            local name
            name=$(echo "$profile_line" | awk '{print $1}')
            [[ -z "$name" || "$name" == "NAME" ]] && continue
 
            local conn_type
            conn_type=$(nmcli -g connection.type connection show "$name" 2>/dev/null)
            [[ "$conn_type" != "802-11-wireless" ]] && continue
 
            local autoconnect hidden
            autoconnect=$(nmcli -g connection.autoconnect connection show "$name" 2>/dev/null)
            hidden=$(nmcli -g 802-11-wireless.hidden connection show "$name" 2>/dev/null)
 
            # Auto-connect + non-hidden = active probe broadcasting
            if [[ "$autoconnect" == "yes" && "$hidden" != "yes" ]]; then
                (( probe_count++ ))
                printf "  ${WARNING}⚠${NC}  ${VALUE}%s${NC}  ${MUTED}(auto-connect: yes, hidden: no)${NC}\n" "$name"
            fi
        done < <(nmcli connection show 2>/dev/null)
 
        if [[ $probe_count -eq 0 ]]; then
            echo -e "  ${SUCCESS}[+] No auto-connect non-hidden profiles found${NC}"
        else
            echo
            echo -e "  ${WARNING}[~] $probe_count profile(s) actively broadcast probe requests${NC}"
            echo -e "  ${MUTED}     Mitigate: disable auto-connect, enable MAC randomisation,${NC}"
            echo -e "  ${MUTED}     or remove profiles for networks you no longer use${NC}"
        fi
    else
        echo -e "  ${MUTED}  nmcli not available — cannot audit probe request exposure${NC}"
    fi
 
    echo
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
            "$(printf '-%.0s' {1..31})" "-" "-" "-" ""

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