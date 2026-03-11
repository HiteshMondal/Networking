#!/usr/bin/env bash
# install.sh
# Recon Framework Dependency Installer

set -euo pipefail

echo "======================================"
echo " Recon Framework Dependency Installer"
echo "======================================"
echo

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run as root:"
    echo "    sudo ./install.sh"
    exit 1
fi

# Detect package manager
detect_pm() {

    if command -v apt >/dev/null 2>&1; then
        PM="apt"

    elif command -v pacman >/dev/null 2>&1; then
        PM="pacman"

    elif command -v dnf >/dev/null 2>&1; then
        PM="dnf"

    elif command -v yum >/dev/null 2>&1; then
        PM="yum"

    elif command -v zypper >/dev/null 2>&1; then
        PM="zypper"

    else
        echo "[!] Unsupported Linux distribution"
        exit 1
    fi

    echo "[+] Detected package manager: $PM"
}

install_packages() {

    echo
    echo "[*] Installing required tools..."
    echo

    case "$PM" in

        apt)

            apt update || echo "[!] apt update failed, continuing..."

            apt install -y \
                curl wget git \
                dnsutils \
                whois \
                nmap masscan \
                traceroute \
                nikto \
                gobuster \
                whatweb \
                sslscan \
                openssl \
                jq || true
        ;;

        pacman)

            pacman -Syu --noconfirm

            pacman -S --noconfirm \
                curl wget git \
                bind \
                whois \
                nmap masscan \
                traceroute \
                nikto \
                gobuster \
                whatweb \
                sslscan \
                openssl \
                jq || true
        ;;

        dnf)

            dnf install -y \
                curl wget git \
                bind-utils \
                whois \
                nmap masscan \
                traceroute \
                nikto \
                gobuster \
                whatweb \
                sslscan \
                openssl \
                jq || true
        ;;

        yum)

            yum install -y \
                curl wget git \
                bind-utils \
                whois \
                nmap masscan \
                traceroute \
                nikto \
                gobuster \
                whatweb \
                sslscan \
                openssl \
                jq || true
        ;;

        zypper)

            zypper install -y \
                curl wget git \
                bind-utils \
                whois \
                nmap masscan \
                traceroute \
                nikto \
                gobuster \
                whatweb \
                sslscan \
                openssl \
                jq || true
        ;;

    esac
}

check_tools() {

    echo
    echo "[*] Verifying installed tools..."
    echo

    tools=(
        curl
        dig
        host
        nslookup
        whois
        nmap
        masscan
        traceroute
        nikto
        gobuster
        whatweb
        sslscan
        openssl
        jq
    )

    for tool in "${tools[@]}"; do

        if command -v "$tool" >/dev/null 2>&1; then
            printf "[OK] %-12s installed\n" "$tool"
        else
            printf "[MISSING] %-8s\n" "$tool"
        fi

    done
}

detect_pm
install_packages
check_tools

echo
echo "[+] Installation complete."
echo