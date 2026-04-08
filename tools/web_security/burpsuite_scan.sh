#!/usr/bin/env bash
# tools/web_security/burpsuite_scan.sh
# Burp Suite — presence checker (learning toolkit mode)

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"


detect_tool() {

    for tool in "$@"; do

        # PATH lookup
        if command -v "$tool" &>/dev/null; then
            command -v "$tool"
            return 0
        fi

    done


    # Desktop launcher lookup
    for tool in "$@"; do

        local desktop_exec

        desktop_exec=$(grep -h "^Exec=" \
            "$HOME/.local/share/applications/"*.desktop \
            /usr/share/applications/*.desktop 2>/dev/null \
            | grep -i "$tool" \
            | head -n1 \
            | cut -d= -f2 \
            | sed 's/%.//' \
            | awk '{print $1}')

        if [[ -n "$desktop_exec" ]]; then
            echo "$desktop_exec"
            return 0
        fi

    done


    # Filesystem lookup
    local search_paths=(
        "$HOME"
        /opt
        /usr/local/bin
        /usr/bin
    )

    for tool in "$@"; do

        for path in "${search_paths[@]}"; do

            local found

            found=$(find "$path" -maxdepth 3 -iname "*$tool*" 2>/dev/null | head -n1)

            if [[ -n "$found" ]]; then
                echo "$found"
                return 0
            fi

        done

    done


    return 1
}


check_burpsuite() {

    local burp_path

    if burp_path=$(detect_tool BurpSuiteCommunity burpsuite burpsuite_community); then

        log_success "Burp Suite is installed."
        echo
        echo -e "  ${INFO}Location:${NC} $burp_path"
        echo
        echo -e "  Open it manually from:"
        echo -e "  • Application Menu"
        echo -e "  • OR terminal command: ${CYAN}burpsuite${NC}"

    else

        log_error "Burp Suite is NOT installed."
        echo
        echo -e "  ${LABEL}Install Instructions:${NC}"
        echo
        echo -e "  1. Visit:"
        echo -e "     https://portswigger.net/burp/communitydownload"
        echo
        echo -e "  2. Download Linux installer (.sh)"
        echo
        echo -e "  3. Run:"
        echo -e "     ${CYAN}chmod +x burpsuite_community_linux.sh${NC}"
        echo -e "     ${CYAN}./burpsuite_community_linux.sh${NC}"
        echo
        echo -e "  4. Launch from Applications menu after install"

    fi

}


clear
show_banner

echo -e "  ${LABEL}Burp Suite — Web Application Security Testing${NC}"
echo

check_burpsuite

echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"