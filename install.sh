#!/usr/bin/env bash
# install.sh
# Networking & Cybersecurity Toolkit — Dependency Installer
# Supports: Debian/Ubuntu, Arch/Manjaro, RHEL/Fedora/CentOS, openSUSE, Alpine, Void

set -euo pipefail

#  Colours (degrade gracefully if unsupported)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    AMBER='\033[0;33m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN='' AMBER='' RED='' CYAN='' BOLD='' NC=''
fi

log_ok()   { printf "${GREEN}[OK]${NC}     %s\n" "$*"; }
log_warn() { printf "${AMBER}[WARN]${NC}   %s\n" "$*"; }
log_err()  { printf "${RED}[ERROR]${NC}  %s\n" "$*"; }
log_info() { printf "${CYAN}[*]${NC}      %s\n" "$*"; }
log_skip() { printf "${AMBER}[SKIP]${NC}   %s\n" "$*"; }

#  Root check
if [[ $EUID -ne 0 ]]; then
    log_err "Please run as root:"
    echo    "    sudo ./install.sh"
    exit 1
fi

#  Banner
echo
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  Networking & Cybersecurity Toolkit — Installer  ${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo

#  Detect distro & package manager
PM=""
PM_INSTALL=""
PM_UPDATE=""
DISTRO=""
DISTRO_FAMILY=""

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        DISTRO="${ID:-unknown}"
        DISTRO_FAMILY="${ID_LIKE:-$DISTRO}"
    elif command -v lsb_release &>/dev/null; then
        DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        DISTRO_FAMILY="$DISTRO"
    else
        DISTRO="unknown"
        DISTRO_FAMILY="unknown"
    fi

    if command -v apt-get &>/dev/null; then
        PM="apt"
        PM_UPDATE="apt-get update -qq"
        PM_INSTALL="apt-get install -y --no-install-recommends"
    elif command -v dnf &>/dev/null; then
        PM="dnf"
        PM_UPDATE="dnf makecache --quiet"
        PM_INSTALL="dnf install -y"
    elif command -v yum &>/dev/null; then
        PM="yum"
        PM_UPDATE="yum makecache --quiet"
        PM_INSTALL="yum install -y"
    elif command -v pacman &>/dev/null; then
        PM="pacman"
        PM_UPDATE="pacman -Sy --noconfirm"
        PM_INSTALL="pacman -S --noconfirm --needed"
    elif command -v zypper &>/dev/null; then
        PM="zypper"
        PM_UPDATE="zypper refresh"
        PM_INSTALL="zypper install -y --no-recommends"
    elif command -v apk &>/dev/null; then
        PM="apk"
        PM_UPDATE="apk update"
        PM_INSTALL="apk add --no-cache"
    elif command -v xbps-install &>/dev/null; then
        PM="xbps"
        PM_UPDATE="xbps-install -S"
        PM_INSTALL="xbps-install -y"
    else
        log_err "No supported package manager found."
        log_err "Detected distro: ${DISTRO}. Please install packages manually."
        exit 1
    fi

    log_info "Distro       : ${DISTRO} (family: ${DISTRO_FAMILY})"
    log_info "Package mgr  : ${PM}"
    echo
}

#  Map tool names per package manager
#  Format: "canonical_name:apt:dnf:pacman:zypper:apk:xbps"
#  Leave blank to skip a field (tool won't be installed on that PM)

# Each entry: "canonical|apt_pkg|dnf_pkg|pacman_pkg|zypper_pkg|apk_pkg|xbps_pkg"
declare -a PKG_MAP=(
    "curl|curl|curl|curl|curl|curl|curl"
    "wget|wget|wget|wget|wget|wget|wget"
    "git|git|git|git|git|git|git"
    "openssl|openssl|openssl|openssl|openssl|openssl|openssl"
    "jq|jq|jq|jq|jq|jq|jq"
    "dig|dnsutils|bind-utils|bind|bind-utils|bind-tools|bind"
    "nslookup|dnsutils|bind-utils|bind|bind-utils|bind-tools|bind"
    "host|dnsutils|bind-utils|bind|bind-utils|bind-tools|bind"
    "nmap|nmap|nmap|nmap|nmap|nmap|nmap"
    "masscan|masscan|masscan|masscan||masscan|"
    "traceroute|traceroute|traceroute|traceroute|traceroute|traceroute|traceroute"
    "whois|whois|whois|whois|whois|whois|whois"
    "nikto|nikto|nikto|nikto|||"
    "gobuster|gobuster|gobuster|gobuster|||"
    "whatweb|whatweb||||whatweb|"
    "sslscan|sslscan|sslscan||sslscan|sslscan|"
    "tcpdump|tcpdump|tcpdump|tcpdump|tcpdump|tcpdump|tcpdump"
    "netstat|net-tools|net-tools|net-tools|net-tools|net-tools|net-tools"
    "ss|iproute2|iproute|iproute2|iproute2|iproute2|iproute2"
    "awk|gawk|gawk|gawk|gawk|gawk|gawk"
    "python3|python3|python3|python|python3|python3|python3"
    "wireshark|wireshark-common|wireshark-cli|wireshark-cli|wireshark|wireshark|wireshark"
    "tshark|tshark|wireshark-cli|wireshark-cli|wireshark|tshark|tshark"
    "snort|snort|snort|snort|||"
    "semgrep|||||||"
    "strings|binutils|binutils|binutils|binutils|binutils|binutils"
    "readelf|binutils|binutils|binutils|binutils|binutils|binutils"
    "java|default-jdk|java-17-openjdk|jdk17-openjdk|java-17-openjdk|openjdk17|openjdk"
)

#  Resolve package name for current PM
resolve_pkg() {
    local entry="$1"
    local IFS='|'
    read -ra parts <<< "$entry"
    # parts: [0]=canonical [1]=apt [2]=dnf [3]=pacman [4]=zypper [5]=apk [6]=xbps
    case "$PM" in
        apt)    echo "${parts[1]:-}" ;;
        dnf|yum) echo "${parts[2]:-}" ;;
        pacman) echo "${parts[3]:-}" ;;
        zypper) echo "${parts[4]:-}" ;;
        apk)    echo "${parts[5]:-}" ;;
        xbps)   echo "${parts[6]:-}" ;;
        *)      echo "" ;;
    esac
}

get_canonical() {
    local entry="$1"
    echo "${entry%%|*}"
}

#  Update package index
update_index() {
    log_info "Updating package index..."
    if ! $PM_UPDATE 2>&1 | tail -3; then
        log_warn "Package index update failed — continuing anyway."
    fi
    echo
}

#  Install packages
install_packages() {
    log_info "Resolving packages for ${PM}..."
    echo

    local to_install=()
    local skipped=()

    for entry in "${PKG_MAP[@]}"; do
        local canonical pkg
        canonical=$(get_canonical "$entry")
        pkg=$(resolve_pkg "$entry")

        if [[ -z "$pkg" ]]; then
            skipped+=("$canonical")
            continue
        fi

        # Avoid duplicate packages (e.g. dnsutils covers dig/nslookup/host)
        if [[ ! " ${to_install[*]} " =~ " ${pkg} " ]]; then
            to_install+=("$pkg")
        fi
    done

    if [[ ${#skipped[@]} -gt 0 ]]; then
        log_warn "No package mapping for ${PM}: ${skipped[*]}"
        log_warn "You may need to install these manually."
        echo
    fi

    log_info "Installing: ${to_install[*]}"
    echo

    # Install all at once; fall back to one-by-one on failure
    if ! $PM_INSTALL "${to_install[@]}" 2>&1; then
        log_warn "Bulk install failed. Retrying one-by-one..."
        echo
        for pkg in "${to_install[@]}"; do
            if $PM_INSTALL "$pkg" 2>&1; then
                log_ok "$pkg"
            else
                log_warn "$pkg — install failed (may not exist in repos)"
            fi
        done
    fi
    echo
}

#  Install Python pip + psutil (optional)
install_python_deps() {
    log_info "Checking Python / pip for dashboard..."

    if ! command -v python3 &>/dev/null; then
        log_warn "python3 not found — dashboard system stats unavailable."
        return
    fi

    # Ensure pip is available
    if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
        case "$PM" in
            apt)    $PM_INSTALL python3-pip 2>/dev/null || true ;;
            dnf|yum) $PM_INSTALL python3-pip 2>/dev/null || true ;;
            pacman) $PM_INSTALL python-pip 2>/dev/null || true ;;
            zypper) $PM_INSTALL python3-pip 2>/dev/null || true ;;
            apk)    $PM_INSTALL py3-pip 2>/dev/null || true ;;
            xbps)   $PM_INSTALL python3-pip 2>/dev/null || true ;;
        esac
    fi

    if python3 -c "import psutil" &>/dev/null 2>&1; then
        log_ok "psutil already installed"
    else
        log_info "Installing psutil for dashboard system stats..."
        if python3 -m pip install psutil --break-system-packages --quiet 2>/dev/null ||
           python3 -m pip install psutil --quiet 2>/dev/null; then
            log_ok "psutil installed"
        else
            log_warn "psutil install failed — dashboard system stats will be unavailable."
            log_warn "Try manually: pip3 install psutil --break-system-packages"
        fi
    fi

    # Semgrep & GVM tools
    for pypkg in semgrep gvm-tools; do
        if python3 -c "import ${pypkg//-/_}" &>/dev/null 2>&1; then
            log_ok "$pypkg already installed"
        else
            log_info "Installing $pypkg..."
            if python3 -m pip install "$pypkg" --break-system-packages --quiet 2>/dev/null ||
               python3 -m pip install "$pypkg" --quiet 2>/dev/null; then
                log_ok "$pypkg installed"
            else
                log_warn "$pypkg install failed — install manually: pip3 install $pypkg"
            fi
        fi
    done
    echo
}

#  Verify tools after install
verify_tools() {
    log_info "Verifying installed tools..."
    echo

    local tools=(
        curl wget git openssl jq
        dig nslookup host
        nmap traceroute whois
        tcpdump ss awk python3
    )
    local optional_tools=(
        masscan nikto gobuster whatweb sslscan netstat wireshark tshark snort semgrep java ghidra kube-hunter
    )

    local ok=0 missing=0 optional_missing=0

    printf "  %-16s %s\n" "Tool" "Status"
    printf "  %-16s %s\n" "────────────────" "──────────"

    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            printf "  ${GREEN}%-16s OK${NC}\n" "$tool"
            (( ok++ )) || true
        else
            printf "  ${RED}%-16s MISSING${NC}\n" "$tool"
            (( missing++ )) || true
        fi
    done

    echo
    printf "  ${AMBER}%-16s %s${NC}\n" "Optional" "Status"
    printf "  %-16s %s\n" "────────────────" "──────────"

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            printf "  ${GREEN}%-16s OK${NC}\n" "$tool"
        else
            printf "  ${AMBER}%-16s not found${NC}\n" "$tool"
            (( optional_missing++ )) || true
        fi
    done

    echo
    log_info "Required: ${ok} installed, ${missing} missing"
    log_info "Optional: ${optional_missing} not found (non-critical)"
    echo
}

#  Make all toolkit scripts executable
set_permissions() {
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"

    log_info "Setting execute permissions on toolkit scripts..."
    find "$script_dir" -name "*.sh" -exec chmod +x {} \;
    log_ok "Permissions set."
    echo
}

#  Main
main() {
    detect_distro
    update_index
    install_packages
    install_python_deps
    verify_tools
    set_permissions

    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  Installation complete. Run: sudo ./run.sh        ${NC}"
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
    echo
}

main