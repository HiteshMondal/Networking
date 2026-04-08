#!/usr/bin/env bash
# lib/setup_wireshark_permissions.sh
# Configure Wireshark packet capture permissions automatically

set -euo pipefail

setup_wireshark_permissions() {

    echo "[*] Configuring Wireshark packet capture permissions..."

    if ! command -v dumpcap &>/dev/null; then
        echo "[!] dumpcap not found. Install wireshark first."
        return 1
    fi

    # Detect Linux distro family
    if command -v dpkg &>/dev/null; then
        DISTRO="debian"
    elif command -v pacman &>/dev/null; then
        DISTRO="arch"
    elif command -v rpm &>/dev/null; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi

    case "$DISTRO" in

        debian)
            echo "[*] Debian-based system detected"
            sudo dpkg-reconfigure wireshark-common || true
            ;;

        arch)
            echo "[*] Arch-based system detected"
            sudo gpasswd -a "$USER" wireshark || true
            ;;

        rhel)
            echo "[*] RHEL-based system detected"
            sudo groupadd -f wireshark
            sudo usermod -aG wireshark "$USER"
            ;;

        *)
            echo "[!] Unknown distro — applying capability fallback"
            ;;
    esac

    # Capability fallback (works almost everywhere)
    sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"

    echo "[✓] Wireshark permissions configured."
    echo "[!] Please log out and back in if capture still fails."
}