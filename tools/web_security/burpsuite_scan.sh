#!/usr/bin/env bash
# tools/web_security/burpsuite_scan.sh
# Burp Suite — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

_find_burpsuite() {
    # PATH lookup
    for cmd in BurpSuiteCommunity BurpSuitePro burpsuite burpsuite_community burpsuite_pro; do
        command -v "$cmd" &>/dev/null && echo "$cmd" && return 0
    done

    # Desktop launcher lookup
    local desktop_exec
    desktop_exec=$(grep -rh "^Exec=.*[Bb]urp" \
        "$HOME/.local/share/applications/" \
        /usr/share/applications/ 2>/dev/null \
        | head -1 | cut -d= -f2- | awk '{print $1}') || true
    [[ -n "$desktop_exec" ]] && echo "$desktop_exec" && return 0

    # Filesystem lookup
    local found
    found=$(find "$HOME" /opt /usr/local /usr/bin -maxdepth 4 \
        \( -iname "*burpsuite*" -o -iname "*burp_suite*" \) \
        -type f 2>/dev/null | head -1) || true
    [[ -n "$found" ]] && echo "$found" && return 0

    return 1
}

_check_burpsuite() {
    local burp_path
    if burp_path=$(_find_burpsuite 2>/dev/null); then
        log_success "Burp Suite is installed."
        echo
        kv "  Location" "$burp_path"
        echo
        echo -e "  ${LABEL}How to run:${NC}"
        echo
        echo -e "  ${CYAN}From terminal:${NC}"
        echo -e "    burpsuite"
        echo -e "    # or the full path: $burp_path"
        echo
        echo -e "  ${CYAN}From desktop:${NC}"
        echo -e "    Search 'Burp Suite' in your application menu"
        echo
        echo -e "  ${LABEL}Quick-start tips:${NC}"
        echo
        echo -e "  1. Open Burp → Proxy → Intercept tab"
        echo -e "  2. Configure your browser to proxy through 127.0.0.1:8080"
        echo -e "  3. Browse the target app — requests appear in Intercept"
        echo -e "  4. Use Scanner (Pro) or Active Scan extension (Community)"
        echo
        echo -e "  ${MUTED}Docs: https://portswigger.net/burp/documentation${NC}"
    else
        log_error "Burp Suite is NOT installed."
        echo
        echo -e "  ${LABEL}Install Instructions:${NC}"
        echo
        echo -e "  ${CYAN}Community Edition (free):${NC}"
        echo -e "    https://portswigger.net/burp/communitydownload"
        echo
        echo -e "  ${CYAN}Steps:${NC}"
        echo -e "  1. Download the Linux installer (.sh) from the link above"
        echo -e "  2. chmod +x burpsuite_community_linux_*.sh"
        echo -e "  3. ./burpsuite_community_linux_*.sh"
        echo -e "  4. Follow the installer wizard"
        echo -e "  5. Launch from the Applications menu or run: burpsuite"
        echo
        echo -e "  ${CYAN}Kali Linux:${NC}"
        echo -e "    sudo apt install burpsuite"
    fi
}

clear; show_banner
echo -e "  ${LABEL}Burp Suite — Web Application Security Testing${NC}"
echo
_check_burpsuite
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"