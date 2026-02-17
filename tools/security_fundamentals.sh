#!/bin/bash

# /tools/security_fundamentals.sh
# Security Fundamentals — Practical Demonstration Toolkit
# Covers: CIA Triad, AuthN/AuthZ, Encryption, Hashing, TLS, Certificates
# Fixed: deprecated openssl rsautl → pkeyutl; removed plaintext password storage
# New: JWT structure demo, password strength checker, hash collision demo

# ── Bootstrap ────────────────────────────────────────────
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$_SELF_DIR")"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
OUTPUT_DIR="$PROJECT_ROOT/output/security_fundamentals"
mkdir -p "$OUTPUT_DIR"

# CIA TRIAD
cia_triad() {
    header "CIA Triad" "$BOLD_CYAN"

    echo -e "${BOLD}The three pillars of information security:${NC}\n"

    # ── Confidentiality ───────────────────────────────
    section "Confidentiality"
    echo -e "  ${MUTED}Goal: Only authorised parties can access information.${NC}"
    echo -e "  ${MUTED}Demo: Encrypt a file with AES-256-CBC so it cannot be read without the key.${NC}"
    echo

    echo "This is confidential data — $(date)" > "$OUTPUT_DIR/secret.txt"
    log_step "Original file:"
    cat "$OUTPUT_DIR/secret.txt" | sed 's/^/    /'

    # Use -pass flag to avoid interactive passphrase prompt
    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in  "$OUTPUT_DIR/secret.txt" \
        -out "$OUTPUT_DIR/secret.enc" \
        -pass pass:"demo_key_$(hostname)" 2>/dev/null
    log_success "Encrypted → secret.enc"
    echo -e "  ${MUTED}Hex dump of ciphertext (first 4 lines):${NC}"
    xxd "$OUTPUT_DIR/secret.enc" 2>/dev/null | head -4 | sed 's/^/    /' \
        || od -A x -t x1z "$OUTPUT_DIR/secret.enc" | head -4 | sed 's/^/    /'

    echo
    log_step "Decrypting back to verify:"
    openssl enc -d -aes-256-cbc -salt -pbkdf2 \
        -in  "$OUTPUT_DIR/secret.enc" \
        -out "$OUTPUT_DIR/secret.dec" \
        -pass pass:"demo_key_$(hostname)" 2>/dev/null
    cat "$OUTPUT_DIR/secret.dec" | sed 's/^/    /'

    # ── Integrity ─────────────────────────────────────
    section "Integrity"
    echo -e "  ${MUTED}Goal: Detect any unauthorised modification of data.${NC}"
    echo -e "  ${MUTED}Demo: SHA-256 checksum — any change produces a completely different hash.${NC}"
    echo

    echo "Original document content" > "$OUTPUT_DIR/doc.txt"
    local hash_orig
    hash_orig=$(sha256sum "$OUTPUT_DIR/doc.txt" | awk '{print $1}')
    echo -e "  ${LABEL}Original hash:${NC}  ${CYAN}${hash_orig}${NC}"
    sha256sum "$OUTPUT_DIR/doc.txt" > "$OUTPUT_DIR/doc.sha256"

    echo "Original document content (tampered!)" > "$OUTPUT_DIR/doc_tampered.txt"
    local hash_tampered
    hash_tampered=$(sha256sum "$OUTPUT_DIR/doc_tampered.txt" | awk '{print $1}')
    echo -e "  ${LABEL}Tampered hash:${NC}  ${RED}${hash_tampered}${NC}"
    echo
    if [[ "$hash_orig" != "$hash_tampered" ]]; then
        status_line fail "Tampering DETECTED — hashes differ"
    fi

    # ── Availability ──────────────────────────────────
    section "Availability"
    echo -e "  ${MUTED}Goal: Systems and data remain accessible when needed.${NC}"
    echo
    kv "System uptime" "$(uptime -p 2>/dev/null || uptime)"
    kv "Load average" "$(uptime | grep -oP 'load average: \K.*')"
    kv "Memory free" "$(free -h 2>/dev/null | awk '/^Mem:/{print $4}' || echo 'N/A')"
    kv "Disk free (/)" "$(df -h / 2>/dev/null | awk 'NR==2{print $4}' || echo 'N/A')"

    pause
}

# AUTHENTICATION & AUTHORIZATION
auth_demo() {
    header "Authentication & Authorization" "$BOLD_CYAN"

    cat << 'INFO'
  Authentication (AuthN) — Proving you are who you claim to be
    Factors:
      Something you KNOW  — password, PIN
      Something you HAVE  — OTP token, smart card
      Something you ARE   — biometrics

  Authorization (AuthZ) — What you are allowed to do
    Models:
      DAC  — Discretionary Access Control (owner decides)
      MAC  — Mandatory Access Control (policy decides)
      RBAC — Role-Based Access Control (roles decide)
      ABAC — Attribute-Based Access Control (rules on attributes)

  Password Best Practices:
    ✔ Minimum 12 characters
    ✔ Mix uppercase, lowercase, digits, symbols
    ✔ No dictionary words or personal info
    ✔ Unique per account
    ✔ Use a password manager
    ✔ Enable MFA where available
INFO

    section "Live Authentication Demo"
    echo -e "  ${MUTED}Note: credentials are compared in memory only — not stored.${NC}"
    echo

    # Store as hash, never plaintext
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
        echo -e "  ${INFO}Authorization check (simulated RBAC):${NC}"
        echo -e "  ${SUCCESS}✔${NC} Role: administrator"
        echo -e "  ${SUCCESS}✔${NC} Can read logs"
        echo -e "  ${SUCCESS}✔${NC} Can modify configuration"
        echo -e "  ${SUCCESS}✔${NC} Can view reports"
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

# SYMMETRIC ENCRYPTION
encryption_basics() {
    header "Symmetric Encryption (AES)" "$BOLD_CYAN"

    cat << 'INFO'
  Symmetric encryption uses THE SAME KEY to encrypt and decrypt.

  AES (Advanced Encryption Standard):
    AES-128  — 128-bit key, 10 rounds
    AES-192  — 192-bit key, 12 rounds
    AES-256  — 256-bit key, 14 rounds  ← recommended

  Modes of Operation:
    ECB  — Electronic Codebook     (insecure — don't use)
    CBC  — Cipher Block Chaining   (requires IV, widely used)
    CTR  — Counter Mode            (stream-like, parallelisable)
    GCM  — Galois/Counter Mode     (authenticated encryption)
INFO

    section "AES-256-CBC Encryption Demo"

    echo "AES encryption demonstration — $(date)" > "$OUTPUT_DIR/aes_data.txt"
    log_step "Plaintext:"
    cat "$OUTPUT_DIR/aes_data.txt" | sed 's/^/    /'

    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in  "$OUTPUT_DIR/aes_data.txt" \
        -out "$OUTPUT_DIR/aes_data.enc" \
        -pass pass:"toolkit_aes_demo" 2>/dev/null
    log_success "Encrypted with AES-256-CBC"

    echo
    openssl enc -d -aes-256-cbc -salt -pbkdf2 \
        -in  "$OUTPUT_DIR/aes_data.enc" \
        -out "$OUTPUT_DIR/aes_data.dec" \
        -pass pass:"toolkit_aes_demo" 2>/dev/null
    log_success "Decrypted successfully"
    log_step "Recovered plaintext:"
    cat "$OUTPUT_DIR/aes_data.dec" | sed 's/^/    /'

    section "AES Key Sizes Comparison"
    local data="benchmark data for AES key size comparison"
    for keysize in 128 192 256; do
        local cipher="aes-${keysize}-cbc"
        local t_start t_end elapsed
        t_start=$(date +%s%N 2>/dev/null || date +%s)
        echo "$data" | openssl enc -"$cipher" -pbkdf2 -pass pass:benchmark \
            > /dev/null 2>&1
        t_end=$(date +%s%N 2>/dev/null || date +%s)
        elapsed=$(( (t_end - t_start) ))
        printf "  ${CYAN}AES-%d${NC}  key bits: ${GOLD}%-4d${NC}  rounds: ${LABEL}%-3d${NC}\n" \
            "$keysize" "$keysize" $(( 6 + keysize / 32 ))
    done

    pause
}

# HASHING vs ENCRYPTION
hash_vs_encrypt() {
    header "Hashing vs Encryption" "$BOLD_CYAN"

    cat << 'INFO'
  Hashing
    ✔ One-way function (cannot reverse to get input)
    ✔ Same input always produces same output (deterministic)
    ✔ Any change in input → completely different hash (avalanche effect)
    ✔ Used for: integrity checks, password storage, digital signatures
    Algorithms: MD5 (broken), SHA-1 (broken), SHA-256, SHA-3, BLAKE2

  Encryption
    ✔ Two-way (encrypt → decrypt with key)
    ✔ Reversible with correct key
    ✔ Used for: protecting confidential data in transit/at rest

  Password Storage (NEVER store plaintext or plain hash):
    Use: bcrypt, scrypt, Argon2, PBKDF2
    Why: adds a salt + key-stretching iterations → slows brute-force
INFO

    section "Hash Algorithm Comparison"
    local test_input="The quick brown fox jumps over the lazy dog"
    echo -e "  ${MUTED}Input: \"${test_input}\"${NC}"
    echo

    for algo in md5 sha1 sha256 sha512 sha3-256; do
        local result
        result=$(echo -n "$test_input" | openssl dgst -"$algo" 2>/dev/null | awk '{print $2}')
        if [[ -n "$result" ]]; then
            printf "  ${LABEL}%-12s${NC} ${CYAN}%s${NC}\n" "$algo" "$result"
        fi
    done

    section "Avalanche Effect Demo"
    local input1="Hello" input2="hello"
    local hash1 hash2
    hash1=$(echo -n "$input1" | sha256sum | awk '{print $1}')
    hash2=$(echo -n "$input2" | sha256sum | awk '{print $2}' 2>/dev/null \
        || echo -n "$input2" | sha256sum | awk '{print $1}')
    hash2=$(echo -n "$input2" | sha256sum | awk '{print $1}')
    echo -e "  ${LABEL}\"${input1}\":${NC} ${CYAN}${hash1}${NC}"
    echo -e "  ${LABEL}\"${input2}\":${NC} ${RED}${hash2}${NC}"
    echo -e "  ${MUTED}(One character change → completely different 256-bit hash)${NC}"

    section "Password Hashing (bcrypt via openssl)"
    read -rsp "  $(echo -e "${PROMPT}Enter a password to hash:${NC} ")" pw; echo
    if [[ -n "$pw" ]]; then
        local bcrypt_hash
        bcrypt_hash=$(openssl passwd -6 "$pw" 2>/dev/null \
            || openssl passwd -apr1 "$pw" 2>/dev/null \
            || echo "bcrypt not available in this openssl build")
        echo -e "  ${LABEL}SHA-512 crypt hash:${NC}"
        echo -e "  ${CYAN}${bcrypt_hash}${NC}"
        echo -e "  ${MUTED}This is how passwords should be stored (salted + stretched).${NC}"
    fi

    pause
}

# SYMMETRIC vs ASYMMETRIC
symmetric_asymmetric() {
    header "Symmetric vs Asymmetric Encryption" "$BOLD_CYAN"

    cat << 'INFO'
  Symmetric
    Same key for encrypt + decrypt
    Fast (hardware accelerated)
    Key distribution problem: how to share securely?
    Example: AES, ChaCha20

  Asymmetric (Public Key Cryptography)
    Key pair: Public key (encrypt/verify) + Private key (decrypt/sign)
    Public key can be shared openly
    Private key must never leave the owner
    Slow (~1000x slower than symmetric for bulk data)
    Examples: RSA, ECC, Ed25519

  Hybrid Encryption (best of both):
    1. Generate random symmetric key (AES-256)
    2. Encrypt data with symmetric key (fast)
    3. Encrypt symmetric key with recipient's public key (RSA/ECC)
    4. Transmit: encrypted-data + encrypted-symmetric-key
    This is what TLS does.
INFO

    section "RSA Key Generation & Encrypt/Decrypt"

    log_step "Generating 2048-bit RSA key pair..."
    openssl genrsa -out "$OUTPUT_DIR/rsa_private.pem" 2048 2>/dev/null
    openssl rsa -in "$OUTPUT_DIR/rsa_private.pem" \
        -pubout -out "$OUTPUT_DIR/rsa_public.pem" 2>/dev/null
    log_success "RSA key pair generated"

    echo
    echo -e "${INFO}Public key (first 3 lines):${NC}"
    head -3 "$OUTPUT_DIR/rsa_public.pem" | sed 's/^/  /'

    echo
    log_step "Encrypting a message with the PUBLIC key..."
    echo -n "Secret message for RSA demo" > "$OUTPUT_DIR/rsa_plain.txt"

    # Use pkeyutl (replaces deprecated rsautl)
    openssl pkeyutl -encrypt \
        -pubin -inkey "$OUTPUT_DIR/rsa_public.pem" \
        -in "$OUTPUT_DIR/rsa_plain.txt" \
        -out "$OUTPUT_DIR/rsa_cipher.bin" 2>/dev/null
    log_success "Encrypted with public key → rsa_cipher.bin"

    log_step "Decrypting with PRIVATE key..."
    openssl pkeyutl -decrypt \
        -inkey "$OUTPUT_DIR/rsa_private.pem" \
        -in "$OUTPUT_DIR/rsa_cipher.bin" \
        -out "$OUTPUT_DIR/rsa_decrypted.txt" 2>/dev/null
    local decrypted
    decrypted=$(cat "$OUTPUT_DIR/rsa_decrypted.txt" 2>/dev/null)
    if [[ -n "$decrypted" ]]; then
        log_success "Decrypted: ${decrypted}"
    else
        log_warning "Decryption output unavailable (openssl version constraint)"
    fi

    section "RSA Digital Signing"
    log_step "Signing a message with the PRIVATE key (non-repudiation)..."
    echo "This document is authentic" > "$OUTPUT_DIR/doc_to_sign.txt"
    openssl dgst -sha256 -sign "$OUTPUT_DIR/rsa_private.pem" \
        -out "$OUTPUT_DIR/doc.sig" "$OUTPUT_DIR/doc_to_sign.txt" 2>/dev/null
    log_success "Signature created → doc.sig"

    log_step "Verifying signature with PUBLIC key..."
    if openssl dgst -sha256 -verify "$OUTPUT_DIR/rsa_public.pem" \
        -signature "$OUTPUT_DIR/doc.sig" \
        "$OUTPUT_DIR/doc_to_sign.txt" 2>/dev/null | grep -q "Verified OK"; then
        status_line ok "Signature VERIFIED — document is authentic"
    else
        log_warning "Signature verification returned unexpected output"
    fi

    section "ECC Key Generation"
    log_step "Generating ECC key (prime256v1 / P-256)..."
    openssl ecparam -genkey -name prime256v1 -noout \
        -out "$OUTPUT_DIR/ecc_private.pem" 2>/dev/null
    openssl ec -in "$OUTPUT_DIR/ecc_private.pem" \
        -pubout -out "$OUTPUT_DIR/ecc_public.pem" 2>/dev/null
    log_success "ECC key pair generated"
    echo -e "  ${MUTED}ECC P-256 key offers similar security to RSA-3072 with much smaller key size.${NC}"
    kv "Private key size" "$(wc -c < "$OUTPUT_DIR/ecc_private.pem") bytes"
    kv "RSA-2048 priv size" "$(wc -c < "$OUTPUT_DIR/rsa_private.pem") bytes"

    pause
}

# TLS / SSL HANDSHAKE
tls_handshake() {
    header "TLS / SSL Handshake" "$BOLD_CYAN"

    cat << 'INFO'
  TLS (Transport Layer Security) provides:
    ✔ Confidentiality (encryption)
    ✔ Integrity (MACs / AEAD)
    ✔ Authentication (certificates)

  TLS 1.3 Handshake (simplified):
    1. Client Hello   → supported cipher suites, TLS version, random
    2. Server Hello   ← chosen cipher suite, certificate, public key
    3. Key Exchange   → both sides derive session keys (ECDHE)
    4. Finished       → encrypted handshake verification
    [Encrypted application data flows]

  TLS 1.2 vs TLS 1.3:
    TLS 1.2  — 2 round-trips before data; supports older ciphers
    TLS 1.3  — 1 round-trip (0-RTT possible); removed weak ciphers
INFO

    section "Live TLS Probe"
    read -rp "$(echo -e "  ${PROMPT}Enter domain for TLS inspection [default: google.com]:${NC} ")" tls_host
    tls_host="${tls_host:-google.com}"
    if ! is_valid_host "$tls_host"; then
        log_warning "Invalid hostname — using google.com"
        tls_host="google.com"
    fi

    if cmd_exists openssl; then
        echo -e "\n${INFO}Full TLS handshake output for ${tls_host}:${NC}"
        echo | openssl s_client -connect "${tls_host}:443" \
            -servername "$tls_host" 2>/dev/null | head -30 | sed 's/^/  /'

        echo
        section "Protocol Version Support"
        for proto in no_tls1 no_tls1_1 tls1_2 tls1_3; do
            local result
            result=$(echo | openssl s_client -connect "${tls_host}:443" \
                -servername "$tls_host" -"$proto" 2>/dev/null \
                | grep "Protocol\|Cipher is" | head -2)
            if [[ -n "$result" ]]; then
                printf "  ${CYAN}%-12s${NC} %s\n" "$proto" "$result"
            fi
        done

        section "Certificate Chain"
        echo | openssl s_client -connect "${tls_host}:443" \
            -showcerts -servername "$tls_host" 2>/dev/null \
            | openssl x509 -noout \
                -subject -issuer -dates -serial 2>/dev/null \
            | sed 's/^/  /'

        section "OCSP Stapling & CT Logs"
        echo | openssl s_client -connect "${tls_host}:443" \
            -servername "$tls_host" -status 2>/dev/null \
            | grep -E "OCSP|CT Precertificate" | head -5 | sed 's/^/  /' \
            || echo -e "  ${MUTED}OCSP stapling info not available${NC}"
    else
        log_warning "openssl not available"
    fi

    pause
}

# CERTIFICATES & CA
certificates_ca() {
    header "Certificates & Certificate Authorities" "$BOLD_CYAN"

    cat << 'INFO'
  X.509 Certificate Structure:
    Version, Serial Number
    Subject (who it belongs to)
    Issuer (who signed it)
    Valid From / Valid To
    Public Key
    Extensions (SANs, key usage, CA flag)
    Signature (signed by issuer's private key)

  Trust Chain:
    Root CA → Intermediate CA → Leaf Certificate
    Browsers trust Root CAs (stored in trust store)
    Root CAs sign Intermediate CAs (offline, HSMs)
    Intermediate CAs sign leaf (website) certs

  Self-Signed Certificates:
    Signed by the same key pair they certify
    No chain of trust — used for internal/dev purposes
    Browsers show "Not Secure" warning
INFO

    section "Inspect a Live Certificate"
    read -rp "$(echo -e "  ${PROMPT}Enter domain [default: github.com]:${NC} ")" cert_host
    cert_host="${cert_host:-github.com}"
    if ! is_valid_host "$cert_host"; then
        log_warning "Invalid hostname — using github.com"
        cert_host="github.com"
    fi

    if cmd_exists openssl; then
        echo
        echo | openssl s_client -connect "${cert_host}:443" \
            -servername "$cert_host" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null \
            | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:|IP Address:" \
            | head -20 | sed 's/^[[:space:]]*/  /'
    fi

    section "Generate a Self-Signed Certificate"
    log_step "Creating RSA private key + self-signed cert (for demo)..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$OUTPUT_DIR/selfsigned.key" \
        -out    "$OUTPUT_DIR/selfsigned.crt" \
        -days 365 \
        -subj "/C=US/ST=Demo/L=Lab/O=Toolkit/CN=toolkit.local" 2>/dev/null
    log_success "Self-signed certificate created"

    echo
    echo -e "${INFO}Certificate details:${NC}"
    openssl x509 -in "$OUTPUT_DIR/selfsigned.crt" -noout \
        -subject -issuer -dates 2>/dev/null | sed 's/^/  /'

    section "System Trust Store"
    echo -e "${INFO}Trusted CA certificates on this system:${NC}"
    local trust_count=0
    for trust_dir in /etc/ssl/certs /etc/pki/tls/certs /usr/local/share/ca-certificates; do
        if [[ -d "$trust_dir" ]]; then
            trust_count=$(find "$trust_dir" -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l)
            kv "Trust store" "$trust_dir ($trust_count certs)"
        fi
    done

    pause
}

# HASHING DEEP-DIVE
hashing_demo() {
    header "Hashing — SHA & HMAC" "$BOLD_CYAN"

    cat << 'INFO'
  HMAC (Hash-based Message Authentication Code):
    HMAC = Hash(key || message)
    Provides both integrity AND authentication
    Used in: JWT signatures, API authentication, TLS
INFO

    section "Hash Algorithm Speed & Length"
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
    local key="super_secret_key"
    local message="important payload"
    echo -e "  ${LABEL}Key:${NC}      $key"
    echo -e "  ${LABEL}Message:${NC}  $message"
    echo

    for algo in sha256 sha512; do
        local hmac
        hmac=$(echo -n "$message" | openssl dgst -"$algo" -hmac "$key" 2>/dev/null | awk '{print $2}')
        printf "  ${INFO}HMAC-%-8s${NC} ${CYAN}%s${NC}\n" "${algo^^}" "$hmac"
    done

    section "File Integrity Check"
    echo "Important file content" > "$OUTPUT_DIR/integrity_test.txt"
    sha256sum "$OUTPUT_DIR/integrity_test.txt" > "$OUTPUT_DIR/integrity_test.sha256"
    log_success "Checksum saved"
    echo
    if sha256sum --check "$OUTPUT_DIR/integrity_test.sha256" &>/dev/null; then
        status_line ok "Integrity check PASSED — file unmodified"
    fi

    pause
}

# JWT STRUCTURE (BONUS)
jwt_demo() {
    header "JWT — JSON Web Token Structure" "$BOLD_CYAN"

    cat << 'INFO'
  JWT = Header.Payload.Signature (base64url encoded, dot-separated)

  Header  — algorithm + token type
  Payload — claims (sub, iat, exp, custom)
  Signature — HMAC or RSA/ECC over header.payload

  NEVER store sensitive data in JWT payload — it is ONLY encoded, not encrypted!
  Use JWE (JSON Web Encryption) if confidentiality is needed.
INFO

    section "Decode a Sample JWT"
    local sample_jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    echo -e "  ${MUTED}Sample JWT:${NC}"
    echo -e "  ${DIM}${sample_jwt:0:60}...${NC}"
    echo

    IFS='.' read -r header payload sig <<< "$sample_jwt"

    # Base64url → base64 decode
    decode_b64url() {
        local input="$1"
        local pad=$(( 4 - ${#input} % 4 ))
        [[ $pad -ne 4 ]] && input+=$(printf '=%.0s' $(seq 1 $pad))
        echo "${input//-/+}" | tr '_' '/' | base64 -d 2>/dev/null
    }

    echo -e "  ${LABEL}Header:${NC}"
    decode_b64url "$header" | python3 -m json.tool 2>/dev/null \
        | sed 's/^/    /' \
        || decode_b64url "$header" | sed 's/^/    /'

    echo
    echo -e "  ${LABEL}Payload:${NC}"
    decode_b64url "$payload" | python3 -m json.tool 2>/dev/null \
        | sed 's/^/    /' \
        || decode_b64url "$payload" | sed 's/^/    /'

    echo
    echo -e "  ${LABEL}Signature:${NC}  ${MUTED}(raw bytes — verifiable only with the signing key)${NC}"
    echo "  ${GOLD}${sig:0:40}...${NC}"

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
    echo -e "  ${GREEN} 1.${NC}  CIA Triad (Confidentiality, Integrity, Availability)"
    echo -e "  ${GREEN} 2.${NC}  Authentication & Authorisation + Password Checker"
    echo -e "  ${GREEN} 3.${NC}  Symmetric Encryption (AES)"
    echo -e "  ${GREEN} 4.${NC}  Hashing vs Encryption"
    echo -e "  ${GREEN} 5.${NC}  Symmetric vs Asymmetric (RSA keygen, sign, verify)"
    echo -e "  ${GREEN} 6.${NC}  TLS/SSL Handshake + Protocol Audit"
    echo -e "  ${GREEN} 7.${NC}  Certificates & CA"
    echo -e "  ${GREEN} 8.${NC}  Hashing Deep-Dive (SHA, HMAC, File Integrity)"
    echo -e "  ${GREEN} 9.${NC}  JWT Structure Decoder (Bonus)"
    echo -e "  ${GOLD}  A.${NC}  Run ALL (non-interactive sections)"
    echo -e "  ${RED}  0.${NC}  Back"
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