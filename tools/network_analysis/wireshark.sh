#!/usr/bin/env bash
# tools/network_analysis/wireshark.sh
# Wireshark — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

_check_wireshark() {
    local wireshark_ok=false tshark_ok=false

    command -v wireshark &>/dev/null && wireshark_ok=true
    command -v tshark    &>/dev/null && tshark_ok=true

    if $wireshark_ok || $tshark_ok; then
        log_success "Wireshark is installed."
        echo
        $wireshark_ok && kv "  wireshark" "$(command -v wireshark)"
        $tshark_ok    && kv "  tshark"    "$(command -v tshark)"
        echo
        echo -e "  ${LABEL}How to run:${NC}"
        echo
        if $wireshark_ok; then
            echo -e "  ${CYAN}GUI:${NC}"
            echo -e "    wireshark"
            echo
        fi
        if $tshark_ok; then
            echo -e "  ${CYAN}CLI capture (examples):${NC}"
            echo -e "    tshark -i eth0 -w capture.pcap"
            echo -e "    tshark -i eth0 -a duration:30"
            echo -e "    tshark -i eth0 -f 'port 80'"
            echo
        fi
        echo -e "  ${MUTED}Tip: run 'ip link show' to list available interfaces.${NC}"
    else
        log_error "Wireshark is NOT installed."
        echo
        echo -e "  ${LABEL}Install Instructions:${NC}"
        echo
        echo -e "  ${CYAN}Debian / Ubuntu:${NC}"
        echo -e "    sudo apt install wireshark tshark"
        echo
        echo -e "  ${CYAN}Arch / Manjaro:${NC}"
        echo -e "    sudo pacman -S wireshark-qt"
        echo
        echo -e "  ${CYAN}RHEL / Fedora:${NC}"
        echo -e "    sudo dnf install wireshark"
        echo
        echo -e "  ${CYAN}After install — fix capture permissions:${NC}"
        echo -e "    sudo dpkg-reconfigure wireshark-common   # Debian/Ubuntu"
        echo -e "    sudo usermod -aG wireshark \$USER"
        echo -e "    newgrp wireshark"
    fi
}

clear; show_banner
echo -e "  ${LABEL}Wireshark — Packet Capture & Analysis${NC}"
echo
_check_wireshark
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"