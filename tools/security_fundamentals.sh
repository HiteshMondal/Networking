#!/bin/bash

# /tools/security_fundamentals.sh
# Security Fundamentals – Practical Demonstration Toolkit
# Covers CIA Triad, AuthN/AuthZ, Encryption, Hashing, TLS, Certificates

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/output/security_fundamentals"
mkdir -p "$OUTPUT_DIR"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

pause() {
    echo
    read -p "Press Enter to continue..."
}

header() {
    clear
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN} Security Fundamentals – Practical Lab${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════${NC}"
    echo
}

# ---------------------------------------
cia_triad() {
    header
    echo -e "${YELLOW}CIA TRIAD DEMONSTRATION${NC}\n"

    echo -e "${GREEN}1. Confidentiality${NC}"
    echo "Encrypting a file so unauthorized users cannot read it."
    echo "Secret Data" > "$OUTPUT_DIR/secret.txt"

    openssl enc -aes-256-cbc -salt \
        -in "$OUTPUT_DIR/secret.txt" \
        -out "$OUTPUT_DIR/secret.enc"

    echo -e "Encrypted file: ${BLUE}secret.enc${NC}"

    echo -e "\n${GREEN}2. Integrity${NC}"
    echo "Generating SHA-256 hash to detect tampering."
    sha256sum "$OUTPUT_DIR/secret.txt" | tee "$OUTPUT_DIR/secret.sha256"

    echo -e "\n${GREEN}3. Availability${NC}"
    echo "Checking system uptime (system availability indicator):"
    uptime

    pause
}

auth_demo() {
    header
    echo -e "${YELLOW}Authentication & Authorization${NC}\n"

    USERNAME="admin"
    PASSWORD="password123"

    read -p "Username: " u
    read -s -p "Password: " p
    echo

    if [[ "$u" == "$USERNAME" && "$p" == "$PASSWORD" ]]; then
        echo -e "${GREEN}Authentication successful${NC}"
        echo "Authorized access granted."
    else
        echo -e "${RED}Authentication failed${NC}"
        echo "Access denied."
    fi

    pause
}

encryption_basics() {
    header
    echo -e "${YELLOW}Encryption Basics${NC}\n"

    echo "Encrypting with AES (Symmetric Encryption)"
    echo "Sensitive Info" > "$OUTPUT_DIR/data.txt"

    openssl enc -aes-256-cbc -salt \
        -in "$OUTPUT_DIR/data.txt" \
        -out "$OUTPUT_DIR/data.enc"

    echo -e "${GREEN}AES encryption completed${NC}"
    pause
}

hash_vs_encrypt() {
    header
    echo -e "${YELLOW}Hashing vs Encryption${NC}\n"

    echo "Password123" > "$OUTPUT_DIR/password.txt"

    echo -e "${GREEN}Hashing (SHA-256):${NC}"
    sha256sum "$OUTPUT_DIR/password.txt"

    echo -e "\n${GREEN}Encryption (AES):${NC}"
    openssl enc -aes-256-cbc -salt \
        -in "$OUTPUT_DIR/password.txt" \
        -out "$OUTPUT_DIR/password.enc"

    echo -e "\nHash = One-way\nEncryption = Reversible"
    pause
}

symmetric_asymmetric() {
    header
    echo -e "${YELLOW}Symmetric vs Asymmetric Encryption${NC}\n"

    echo -e "${GREEN}Generating RSA Key Pair${NC}"
    openssl genrsa -out "$OUTPUT_DIR/private.pem" 2048
    openssl rsa -in "$OUTPUT_DIR/private.pem" -pubout -out "$OUTPUT_DIR/public.pem"

    echo "Hello RSA" > "$OUTPUT_DIR/rsa.txt"

    openssl rsautl -encrypt \
        -inkey "$OUTPUT_DIR/public.pem" -pubin \
        -in "$OUTPUT_DIR/rsa.txt" \
        -out "$OUTPUT_DIR/rsa.enc"

    openssl rsautl -decrypt \
        -inkey "$OUTPUT_DIR/private.pem" \
        -in "$OUTPUT_DIR/rsa.enc" \
        -out "$OUTPUT_DIR/rsa.dec"

    echo -e "${GREEN}RSA encryption/decryption completed${NC}"
    pause
}

aes_rsa_ecc() {
    header
    echo -e "${YELLOW}AES, RSA, ECC${NC}\n"

    echo -e "${GREEN}AES:${NC} Fast, symmetric encryption"
    echo -e "${GREEN}RSA:${NC} Public/private key encryption"
    echo -e "${GREEN}ECC:${NC} Smaller keys, high security\n"

    echo "Generating ECC key"
    openssl ecparam -genkey -name prime256v1 \
        -out "$OUTPUT_DIR/ecc_private.pem"

    pause
}

tls_handshake() {
    header
    echo -e "${YELLOW}TLS / SSL Handshake${NC}\n"

    echo "Connecting to google.com using TLS"
    echo | openssl s_client -connect google.com:443 -servername google.com \
        2>/dev/null | head -n 20

    pause
}

certificates_ca() {
    header
    echo -e "${YELLOW}Certificates & Certificate Authority${NC}\n"

    echo "Fetching certificate chain from google.com"
    echo | openssl s_client -connect google.com:443 -showcerts \
        2>/dev/null | openssl x509 -noout -issuer -subject

    pause
}

hashing_demo() {
    header
    echo -e "${YELLOW}Hashing: SHA-256 & bcrypt${NC}\n"

    echo "password123" > "$OUTPUT_DIR/hash.txt"

    echo -e "${GREEN}SHA-256:${NC}"
    sha256sum "$OUTPUT_DIR/hash.txt"

    echo -e "\n${GREEN}bcrypt:${NC}"
    openssl passwd -bcrypt password123

    pause
}

main_menu() {
    while true; do
        header
        echo "1. CIA Triad"
        echo "2. Authentication & Authorization"
        echo "3. Encryption Basics"
        echo "4. Hashing vs Encryption"
        echo "5. Symmetric vs Asymmetric"
        echo "6. AES / RSA / ECC"
        echo "7. TLS / SSL Handshake"
        echo "8. Certificates & CA"
        echo "9. Hashing (SHA-256, bcrypt)"
        echo "0. Exit"
        echo
        read -p "Choose an option: " choice

        case $choice in
            1) cia_triad ;;
            2) auth_demo ;;
            3) encryption_basics ;;
            4) hash_vs_encrypt ;;
            5) symmetric_asymmetric ;;
            6) aes_rsa_ecc ;;
            7) tls_handshake ;;
            8) certificates_ca ;;
            9) hashing_demo ;;
            0) exit 0 ;;
            *) echo "Invalid option"; sleep 1 ;;
        esac
    done
}

main_menu
