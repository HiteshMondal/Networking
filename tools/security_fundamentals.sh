#!/bin/bash

# /tools/security_fundamentals.sh
# Security Fundamentals — Practical Demonstration Toolkit
# Covers: CIA Triad, AuthN/AuthZ, Encryption, Hashing, TLS, Certificates, JWT


# Bootstrap
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$_SELF_DIR")"}"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

# Directory paths (inherit from env if launched via tools.sh)
: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"
: "${OUTPUT_DIR:="${PROJECT_ROOT}/output"}"
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Per-run working directory inside output/ — keeps root output/ uncluttered
# and makes it easy to find all artefacts from a single session.
_SEC_RUN_DIR="${OUTPUT_DIR}/security_$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$_SEC_RUN_DIR"

#  CIA TRIAD
cia_triad() {
    header "CIA Triad" "$BOLD_CYAN"

    echo -e "${BOLD}The three pillars of information security:${NC}\n"

    section "Confidentiality"
    echo -e "  ${MUTED}Goal: Only authorised parties can access information.${NC}"
    echo -e "  ${MUTED}Demo: Encrypt a file with AES-256-CBC.${NC}"
    echo

    echo "This is confidential data — $(date)" > "$_SEC_RUN_DIR/secret.txt"
    log_step "Original file:"
    cat "$_SEC_RUN_DIR/secret.txt" | sed 's/^/    /'

    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in  "$_SEC_RUN_DIR/secret.txt" \
        -out "$_SEC_RUN_DIR/secret.enc" \
        -pass pass:"demo_key_$(hostname)" 2>/dev/null
    log_success "Encrypted → $_SEC_RUN_DIR/secret.enc"

    echo -e "  ${MUTED}Hex dump of ciphertext (first 4 lines):${NC}"
    xxd "$_SEC_RUN_DIR/secret.enc" 2>/dev/null | head -4 | sed 's/^/    /' \
        || od -A x -t x1z "$_SEC_RUN_DIR/secret.enc" | head -4 | sed 's/^/    /'

    echo
    log_step "Decrypting back to verify:"
    openssl enc -d -aes-256-cbc -salt -pbkdf2 \
        -in  "$_SEC_RUN_DIR/secret.enc" \
        -out "$_SEC_RUN_DIR/secret.dec" \
        -pass pass:"demo_key_$(hostname)" 2>/dev/null
    cat "$_SEC_RUN_DIR/secret.dec" | sed 's/^/    /'

    section "Integrity"
    echo -e "  ${MUTED}Goal: Detect any unauthorised modification of data.${NC}"
    echo

    echo "Original document content" > "$_SEC_RUN_DIR/doc.txt"
    local hash_orig
    hash_orig=$(sha256sum "$_SEC_RUN_DIR/doc.txt" | awk '{print $1}')
    echo -e "  ${LABEL}Original hash:${NC}  ${CYAN}${hash_orig}${NC}"
    sha256sum "$_SEC_RUN_DIR/doc.txt" > "$_SEC_RUN_DIR/doc.sha256"

    echo "Original document content (tampered!)" > "$_SEC_RUN_DIR/doc_tampered.txt"
    local hash_tampered
    hash_tampered=$(sha256sum "$_SEC_RUN_DIR/doc_tampered.txt" | awk '{print $1}')
    echo -e "  ${LABEL}Tampered hash:${NC}  ${RED}${hash_tampered}${NC}"
    echo
    if [[ "$hash_orig" != "$hash_tampered" ]]; then
        status_line fail "Tampering DETECTED — hashes differ"
    fi

    section "Availability"
    echo -e "  ${MUTED}Goal: Systems remain accessible when needed.${NC}"
    echo
    kv "System uptime"  "$(uptime -p 2>/dev/null || uptime)"
    kv "Load average"   "$(uptime | grep -oP 'load average: \K.*')"
    kv "Memory free"    "$(free -h 2>/dev/null | awk '/^Mem:/{print $4}' || echo 'N/A')"
    kv "Disk free (/)"  "$(df -h / 2>/dev/null | awk 'NR==2{print $4}' || echo 'N/A')"

    pause
}

#  AUTHENTICATION & AUTHORIZATION
auth_demo() {
    header "Authentication & Authorization" "$BOLD_CYAN"

    cat << 'INFO'
  Authentication (AuthN) — Proving you are who you claim to be
    Factors:
      Something you KNOW  — password, PIN
      Something you HAVE  — OTP token, smart card
      Something you ARE   — biometrics

  Authorization (AuthZ) — What you are allowed to do
    Models: DAC, MAC, RBAC, ABAC
INFO

    section "Live Authentication Demo"
    echo -e "  ${MUTED}Note: credentials are compared in memory only — not stored.${NC}"
    echo

    local stored_hash
    stored_hash=$(echo -n "password123" | sha256sum | awk '{print $1}')

    read -rp "  $(echo -e "${PROMPT}Username:${NC} ")" entered_user
    read -rsp "  $(echo -e "${PROMPT}Password:${NC} ")" entered_pass; echo

    local entered_hash
    entered_hash=$(echo -n "$entered_pass" | sha256sum | awk '{print $1}')

    if [[ "$entered_user" == "admin" && "$entered_hash" == "$stored_hash" ]]; then
        status_line ok "Authentication SUCCESSFUL"
        echo -e "  ${MUTED}Credential: admin / password123${NC}"
        echo
        echo -e "  ${INFO}Authorization (simulated RBAC):${NC}"
        echo -e "  ${SUCCESS}✔${NC} Role: administrator"
        echo -e "  ${SUCCESS}✔${NC} Can read logs"
        echo -e "  ${SUCCESS}✔${NC} Can modify configuration"
    else
        status_line fail "Authentication FAILED"
        echo -e "  ${MUTED}Hint: try admin / password123${NC}"
    fi

    section "Password Strength Checker"
    read -rsp "  $(echo -e "${PROMPT}Enter a password to analyse (not echoed):${NC} ")" check_pass; echo
    echo
    local score=0 warnings=()

    [[ ${#check_pass} -ge 8  ]] && (( score++ )) || warnings+=("Too short (< 8 chars)")
    [[ ${#check_pass} -ge 12 ]] && (( score++ )) || warnings+=("Short (< 12 chars recommended)")
    [[ "$check_pass" =~ [A-Z] ]] && (( score++ )) || warnings+=("No uppercase letters")
    [[ "$check_pass" =~ [a-z] ]] && (( score++ )) || warnings+=("No lowercase letters")
    [[ "$check_pass" =~ [0-9] ]] && (( score++ )) || warnings+=("No digits")
    [[ "$check_pass" =~ [^a-zA-Z0-9] ]] && (( score++ )) || warnings+=("No special characters")
    [[ ${#check_pass} -ge 16 ]] && (( score++ ))

    local label color
    if   (( score >= 6 )); then label="Strong"    color="$SUCCESS"
    elif (( score >= 4 )); then label="Moderate"  color="$YELLOW"
    else                        label="Weak"      color="$FAILURE"
    fi

    echo -e "  Strength score: ${color}${score}/7 — ${label}${NC}"
    for w in "${warnings[@]}"; do
        echo -e "  ${WARNING}⚠${NC} $w"
    done

    pause
}

#  SYMMETRIC ENCRYPTION (AES)
encryption_basics() {
    header "Symmetric Encryption (AES)" "$BOLD_CYAN"

    cat << 'INFO'
  Symmetric encryption uses THE SAME KEY to encrypt and decrypt.

  AES (Advanced Encryption Standard):
    AES-128 — 10 rounds   AES-192 — 12 rounds   AES-256 — 14 rounds ← recommended
  Modes: ECB (insecure), CBC (IV required), CTR (stream-like), GCM (authenticated)
INFO

    section "AES-256-CBC Demo"

    echo "AES encryption demonstration — $(date)" > "$_SEC_RUN_DIR/aes_data.txt"
    log_step "Plaintext:"; cat "$_SEC_RUN_DIR/aes_data.txt" | sed 's/^/    /'

    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in  "$_SEC_RUN_DIR/aes_data.txt" \
        -out "$_SEC_RUN_DIR/aes_data.enc" \
        -pass pass:"toolkit_aes_demo" 2>/dev/null
    log_success "Encrypted with AES-256-CBC"

    openssl enc -d -aes-256-cbc -salt -pbkdf2 \
        -in  "$_SEC_RUN_DIR/aes_data.enc" \
        -out "$_SEC_RUN_DIR/aes_data.dec" \
        -pass pass:"toolkit_aes_demo" 2>/dev/null
    log_success "Decrypted successfully"
    log_step "Recovered plaintext:"; cat "$_SEC_RUN_DIR/aes_data.dec" | sed 's/^/    /'

    section "AES Key Sizes"
    for keysize in 128 192 256; do
        printf "  ${CYAN}AES-%d${NC}  key bits: ${GOLD}%-4d${NC}  rounds: ${LABEL}%d${NC}\n" \
            "$keysize" "$keysize" $(( 6 + keysize / 32 ))
    done

    pause
}

#  HASHING vs ENCRYPTION
hash_vs_encrypt() {
    header "Hashing vs Encryption" "$BOLD_CYAN"

    cat << 'INFO'
  Hashing    — one-way, deterministic, avalanche effect; used for integrity / passwords
  Encryption — two-way (reversible with key); used for confidentiality
  Password storage: use bcrypt / scrypt / Argon2 / PBKDF2 (salted + stretched)
INFO

    section "Hash Algorithm Comparison"
    local test_input="The quick brown fox jumps over the lazy dog"
    echo -e "  ${MUTED}Input: \"${test_input}\"${NC}\n"

    for algo in md5 sha1 sha256 sha512 sha3-256; do
        local result
        result=$(echo -n "$test_input" | openssl dgst -"$algo" 2>/dev/null | awk '{print $2}')
        [[ -n "$result" ]] && printf "  ${LABEL}%-12s${NC} ${CYAN}%s${NC}\n" "$algo" "$result"
    done

    section "Avalanche Effect"
    local h1 h2
    h1=$(echo -n "Hello" | sha256sum | awk '{print $1}')
    h2=$(echo -n "hello" | sha256sum | awk '{print $1}')
    echo -e "  ${LABEL}\"Hello\":${NC} ${CYAN}${h1}${NC}"
    echo -e "  ${LABEL}\"hello\":${NC} ${RED}${h2}${NC}"
    echo -e "  ${MUTED}(One character change → completely different 256-bit hash)${NC}"

    section "Password Hashing"
    read -rsp "  $(echo -e "${PROMPT}Enter a password to hash:${NC} ")" pw; echo
    if [[ -n "$pw" ]]; then
        local h
        h=$(openssl passwd -6 "$pw" 2>/dev/null \
            || openssl passwd -apr1 "$pw" 2>/dev/null \
            || echo "not available in this openssl build")
        echo -e "  ${LABEL}SHA-512 crypt hash:${NC}"
        echo -e "  ${CYAN}${h}${NC}"
        echo -e "  ${MUTED}This is how passwords should be stored (salted + stretched).${NC}"
    fi

    pause
}

#  SYMMETRIC vs ASYMMETRIC
symmetric_asymmetric() {
    header "Symmetric vs Asymmetric Encryption" "$BOLD_CYAN"

    cat << 'INFO'
  Symmetric  — same key, fast, key distribution problem (AES, ChaCha20)
  Asymmetric — public/private pair, slow, no shared secret needed (RSA, ECC, Ed25519)
  Hybrid     — used in TLS: asymmetric for key exchange, symmetric for data
INFO

    section "RSA Key Generation & Encrypt/Decrypt"
    log_step "Generating 2048-bit RSA key pair…"
    openssl genrsa -out "$_SEC_RUN_DIR/rsa_private.pem" 2048 2>/dev/null
    openssl rsa -in "$_SEC_RUN_DIR/rsa_private.pem" \
        -pubout -out "$_SEC_RUN_DIR/rsa_public.pem" 2>/dev/null
    log_success "RSA key pair generated"
    echo -e "${INFO}Public key (first 3 lines):${NC}"
    head -3 "$_SEC_RUN_DIR/rsa_public.pem" | sed 's/^/  /'

    echo
    log_step "Encrypting with PUBLIC key (pkeyutl)…"
    echo -n "Secret message for RSA demo" > "$_SEC_RUN_DIR/rsa_plain.txt"
    openssl pkeyutl -encrypt \
        -pubin -inkey "$_SEC_RUN_DIR/rsa_public.pem" \
        -in  "$_SEC_RUN_DIR/rsa_plain.txt" \
        -out "$_SEC_RUN_DIR/rsa_cipher.bin" 2>/dev/null
    log_success "Encrypted → rsa_cipher.bin"

    log_step "Decrypting with PRIVATE key…"
    openssl pkeyutl -decrypt \
        -inkey "$_SEC_RUN_DIR/rsa_private.pem" \
        -in  "$_SEC_RUN_DIR/rsa_cipher.bin" \
        -out "$_SEC_RUN_DIR/rsa_decrypted.txt" 2>/dev/null
    local dec
    dec=$(cat "$_SEC_RUN_DIR/rsa_decrypted.txt" 2>/dev/null)
    [[ -n "$dec" ]] && log_success "Decrypted: ${dec}" \
        || log_warning "Decryption output unavailable (openssl version constraint)"

    section "RSA Digital Signing"
    echo "This document is authentic" > "$_SEC_RUN_DIR/doc_to_sign.txt"
    openssl dgst -sha256 -sign "$_SEC_RUN_DIR/rsa_private.pem" \
        -out "$_SEC_RUN_DIR/doc.sig" "$_SEC_RUN_DIR/doc_to_sign.txt" 2>/dev/null
    log_success "Signature created → doc.sig"
    if openssl dgst -sha256 -verify "$_SEC_RUN_DIR/rsa_public.pem" \
        -signature "$_SEC_RUN_DIR/doc.sig" \
        "$_SEC_RUN_DIR/doc_to_sign.txt" 2>/dev/null | grep -q "Verified OK"; then
        status_line ok "Signature VERIFIED — document is authentic"
    else
        log_warning "Signature verification returned unexpected output"
    fi

    section "ECC Key Generation"
    openssl ecparam -genkey -name prime256v1 -noout \
        -out "$_SEC_RUN_DIR/ecc_private.pem" 2>/dev/null
    openssl ec -in "$_SEC_RUN_DIR/ecc_private.pem" \
        -pubout -out "$_SEC_RUN_DIR/ecc_public.pem" 2>/dev/null
    log_success "ECC P-256 key pair generated"
    kv "ECC private key size" "$(wc -c < "$_SEC_RUN_DIR/ecc_private.pem") bytes"
    kv "RSA-2048 private size" "$(wc -c < "$_SEC_RUN_DIR/rsa_private.pem") bytes"

    pause
}

#  TLS / SSL HANDSHAKE
tls_handshake() {
    header "TLS / SSL Handshake" "$BOLD_CYAN"

    cat << 'INFO'
  TLS provides: Confidentiality + Integrity + Authentication
  TLS 1.3: 1 round-trip, removed weak ciphers, forward secrecy mandatory
  TLS 1.2: 2 round-trips, still widely deployed
INFO

    section "Live TLS Probe"
    read -rp "$(echo -e "  ${PROMPT}Enter domain [default: google.com]:${NC} ")" tls_host
    tls_host="${tls_host:-google.com}"
    is_valid_host "$tls_host" || { log_warning "Invalid hostname — using google.com"; tls_host="google.com"; }

    if cmd_exists openssl; then
        echo
        echo | openssl s_client -connect "${tls_host}:443" \
            -servername "$tls_host" 2>/dev/null | head -30 | sed 's/^/  /'

        section "Protocol Version Support"
        for proto in no_tls1 no_tls1_1 tls1_2 tls1_3; do
            local result
            result=$(echo | openssl s_client -connect "${tls_host}:443" \
                -servername "$tls_host" -"$proto" 2>/dev/null \
                | grep "Protocol\|Cipher is" | head -2)
            [[ -n "$result" ]] && printf "  ${CYAN}%-12s${NC} %s\n" "$proto" "$result"
        done

        section "Certificate Chain"
        echo | openssl s_client -connect "${tls_host}:443" \
            -showcerts -servername "$tls_host" 2>/dev/null \
            | openssl x509 -noout -subject -issuer -dates -serial 2>/dev/null \
            | sed 's/^/  /'
    else
        log_warning "openssl not available"
    fi

    pause
}

#  CERTIFICATES & CA
certificates_ca() {
    header "Certificates & Certificate Authorities" "$BOLD_CYAN"

    cat << 'INFO'
  X.509 Certificate: Version, Serial, Subject, Issuer, Validity, Public Key, Extensions, Signature
  Trust chain: Root CA → Intermediate CA → Leaf Certificate
  Self-signed: No chain of trust — for internal/dev use only
INFO

    section "Inspect a Live Certificate"
    read -rp "$(echo -e "  ${PROMPT}Enter domain [default: github.com]:${NC} ")" cert_host
    cert_host="${cert_host:-github.com}"
    is_valid_host "$cert_host" || { log_warning "Invalid hostname — using github.com"; cert_host="github.com"; }

    if cmd_exists openssl; then
        echo | openssl s_client -connect "${cert_host}:443" \
            -servername "$cert_host" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null \
            | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:|IP Address:" \
            | head -20 | sed 's/^[[:space:]]*/  /'
    fi

    section "Generate Self-Signed Certificate"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$_SEC_RUN_DIR/selfsigned.key" \
        -out    "$_SEC_RUN_DIR/selfsigned.crt" \
        -days 365 \
        -subj "/C=US/ST=Demo/L=Lab/O=Toolkit/CN=toolkit.local" 2>/dev/null
    log_success "Self-signed certificate: $_SEC_RUN_DIR/selfsigned.crt"
    openssl x509 -in "$_SEC_RUN_DIR/selfsigned.crt" -noout \
        -subject -issuer -dates 2>/dev/null | sed 's/^/  /'

    section "System Trust Store"
    for trust_dir in /etc/ssl/certs /etc/pki/tls/certs /usr/local/share/ca-certificates; do
        if [[ -d "$trust_dir" ]]; then
            local cnt
            cnt=$(find "$trust_dir" -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l)
            kv "Trust store" "$trust_dir ($cnt certs)"
        fi
    done

    pause
}

#  HASHING DEEP-DIVE
hashing_demo() {
    header "Hashing — SHA & HMAC" "$BOLD_CYAN"

    section "Algorithm Speed & Output Length"
    local testdata="The quick brown fox jumps over the lazy dog"
    echo -e "  ${MUTED}Input: \"$testdata\"${NC}\n"

    for algo in md5 sha1 sha224 sha256 sha384 sha512; do
        local hash result_len
        hash=$(echo -n "$testdata" | openssl dgst -"$algo" 2>/dev/null | awk '{print $2}')
        result_len=${#hash}
        printf "  ${LABEL}%-10s${NC} bits: ${GOLD}%-4d${NC}  ${CYAN}%s${NC}\n" \
            "$algo" "$(( result_len * 4 ))" "$hash"
    done

    section "HMAC Demo"
    local key="super_secret_key" message="important payload"
    kv "Key"     "$key"
    kv "Message" "$message"
    echo
    for algo in sha256 sha512; do
        local hmac
        hmac=$(echo -n "$message" | openssl dgst -"$algo" -hmac "$key" 2>/dev/null | awk '{print $2}')
        printf "  ${INFO}HMAC-%-8s${NC} ${CYAN}%s${NC}\n" "${algo^^}" "$hmac"
    done

    section "File Integrity Check"
    echo "Important file content" > "$_SEC_RUN_DIR/integrity_test.txt"
    sha256sum "$_SEC_RUN_DIR/integrity_test.txt" > "$_SEC_RUN_DIR/integrity_test.sha256"
    log_success "Checksum saved"
    sha256sum --check "$_SEC_RUN_DIR/integrity_test.sha256" &>/dev/null \
        && status_line ok "Integrity check PASSED — file unmodified"

    pause
}

#  JWT STRUCTURE DECODER
jwt_demo() {
    header "JWT — JSON Web Token Structure" "$BOLD_CYAN"

    cat << 'INFO'
  JWT = Header.Payload.Signature (base64url, dot-separated)
  Payload is ENCODED not ENCRYPTED — do NOT put secrets in it.
  Use JWE if confidentiality is needed.
INFO

    section "Decode a Sample JWT"
    local sample_jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    echo -e "  ${MUTED}Sample JWT: ${DIM}${sample_jwt:0:60}…${NC}\n"

    IFS='.' read -r jwt_header jwt_payload jwt_sig <<< "$sample_jwt"

    decode_b64url() {
        local input="$1"
        local pad=$(( 4 - ${#input} % 4 ))
        [[ $pad -ne 4 ]] && input+=$(printf '=%.0s' $(seq 1 $pad))
        echo "${input//-/+}" | tr '_' '/' | base64 -d 2>/dev/null
    }

    echo -e "  ${LABEL}Header:${NC}"
    decode_b64url "$jwt_header" | python3 -m json.tool 2>/dev/null \
        | sed 's/^/    /' || decode_b64url "$jwt_header" | sed 's/^/    /'

    echo -e "\n  ${LABEL}Payload:${NC}"
    decode_b64url "$jwt_payload" | python3 -m json.tool 2>/dev/null \
        | sed 's/^/    /' || decode_b64url "$jwt_payload" | sed 's/^/    /'

    echo -e "\n  ${LABEL}Signature:${NC}  ${MUTED}(verifiable only with the signing key)${NC}"
    echo -e "  ${GOLD}${jwt_sig:0:40}…${NC}"

    pause
}

#  MENU
show_menu() {
    clear
    show_banner
    echo -e "${BOLD_CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD_CYAN}║      Security Fundamentals — Practical       ║${NC}"
    echo -e "${BOLD_CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo
    echo -e "  ${GREEN} 1.${NC}  CIA Triad"
    echo -e "  ${GREEN} 2.${NC}  Authentication & Authorisation + Password Checker"
    echo -e "  ${GREEN} 3.${NC}  Symmetric Encryption (AES)"
    echo -e "  ${GREEN} 4.${NC}  Hashing vs Encryption"
    echo -e "  ${GREEN} 5.${NC}  Symmetric vs Asymmetric (RSA, ECC)"
    echo -e "  ${GREEN} 6.${NC}  TLS/SSL Handshake + Protocol Audit"
    echo -e "  ${GREEN} 7.${NC}  Certificates & CA"
    echo -e "  ${GREEN} 8.${NC}  Hashing Deep-Dive (SHA, HMAC, File Integrity)"
    echo -e "  ${GREEN} 9.${NC}  JWT Structure Decoder"
    echo -e "  ${GOLD}  A.${NC}  Run ALL non-interactive sections"
    echo -e "  ${RED}  0.${NC}  Back"
    echo
    echo -e "  ${MUTED}Output files → ${OUTPUT_DIR}/security_…${NC}"
    echo
}

main() {
    while true; do
        show_menu
        read -rp "$(echo -e "  ${PROMPT}Choice:${NC} ")" choice
        case "$choice" in
            1) cia_triad ;;
            2) auth_demo ;;
            3) encryption_basics ;;
            4) hash_vs_encrypt ;;
            5) symmetric_asymmetric ;;
            6) tls_handshake ;;
            7) certificates_ca ;;
            8) hashing_demo ;;
            9) jwt_demo ;;
            [aA])
                cia_triad
                encryption_basics
                hashing_demo
                symmetric_asymmetric
                ;;
            0) return 0 ;;
            *) log_warning "Invalid choice" ;;
        esac
    done
}

main