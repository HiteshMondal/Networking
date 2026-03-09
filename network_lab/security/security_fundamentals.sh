#!/bin/bash

# /network_lab/security/security_fundamentals.sh
# Topic: Security Fundamentals
# Covers: CIA Triad, Auth/AuthZ, Encryption, Hashing, Symmetric/Asymmetric,
#         TLS Handshake, Certificates/CA, HMAC, JWT, Permission Audit, MitM

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# CIA TRIAD
cia_triad() {
    header "CIA Triad — Core Security Principles"

    cat << 'INFO'
  The three foundational goals of information security:

  C — CONFIDENTIALITY
        Only authorised parties can read the data.
        Controls: encryption, access control, MFA, need-to-know.
        Attack: eavesdropping, credential theft, data leaks.

  I — INTEGRITY
        Data has not been altered (accidentally or maliciously).
        Controls: hashing, digital signatures, checksums, WORM storage.
        Attack: man-in-the-middle tampering, SQL injection, ransomware.

  A — AVAILABILITY
        Systems and data are accessible when needed.
        Controls: redundancy, backups, DDoS mitigation, UPS, DR plans.
        Attack: DDoS, ransomware, hardware failure, misconfiguration.

  Extended: IAAA Model
    Identification   — who are you? (username)
    Authentication   — prove it (password, cert, biometric, MFA)
    Authorisation    — what can you do? (RBAC, ACL)
    Accountability   — what did you do? (audit logs, SIEM)
INFO

    section "CIA Assessment — This System"
    echo

    echo -e "  ${BOLD}CONFIDENTIALITY${NC}"
    local enc=0
    lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -qi "crypto_LUKS" && enc=1
    [[ $enc -eq 1 ]] && status_line ok   "Disk encryption (LUKS) detected" \
                     || status_line warn "No LUKS disk encryption found"

    if [[ -d /etc/ssh ]]; then
        local pw_auth
        pw_auth=$(grep -iE '^PasswordAuthentication\s' /etc/ssh/sshd_config 2>/dev/null \
                  | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
        [[ "$pw_auth" == "no" ]] \
            && status_line ok   "SSH: PasswordAuthentication = no (key-only)" \
            || status_line warn "SSH: PasswordAuthentication = ${pw_auth:-not set}"
    fi

    echo
    echo -e "  ${BOLD}INTEGRITY${NC}"
    if cmd_exists aide; then
        status_line ok   "AIDE (file integrity monitor) installed"
    elif cmd_exists tripwire; then
        status_line ok   "Tripwire (file integrity monitor) installed"
    else
        status_line warn "No file integrity monitor found (consider aide or tripwire)"
    fi
    kv "Kernel module signing" \
        "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 'N/A')"

    echo
    echo -e "  ${BOLD}AVAILABILITY${NC}"
    local uptime_sec
    uptime_sec=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null)
    local days=$(( uptime_sec / 86400 ))
    local hours=$(( (uptime_sec % 86400) / 3600 ))
    kv "System uptime"  "${days}d ${hours}h"
    kv "Load average"   "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"

    if systemctl is-active --quiet ufw 2>/dev/null || \
       sudo iptables -L 2>/dev/null | grep -qE "DROP|REJECT"; then
        status_line ok  "Firewall active"
    else
        status_line warn "No active firewall detected"
    fi
}

# AUTHENTICATION & AUTHORISATION
auth_demo() {
    header "Authentication & Authorisation"

    section "Authentication Factors"
    cat << 'INFO'
  Factor 1 — Something you KNOW   : password, PIN, security question
  Factor 2 — Something you HAVE   : TOTP app, hardware key (FIDO2/YubiKey),
                                     SMS OTP, smart card
  Factor 3 — Something you ARE    : fingerprint, face, iris, voice
  Factor 4 — Somewhere you ARE    : GPS, IP geofencing, network segment

  MFA = combining two or more factors.
  2FA ≠ 2SV: two-step verification may use same factor twice (e.g. password + SMS).

  Phishing-resistant MFA:
    FIDO2/WebAuthn — hardware key bound to origin; immune to phishing.
    Passkeys — same protocol, device-stored credential.
INFO

    section "Password Hashing Algorithms"
    cat << 'INFO'
  Modern (use these):
    bcrypt        — adaptive, salted, work factor (cost): 2^cost iterations
    scrypt        — memory-hard (resists GPU/ASIC), N/r/p parameters
    Argon2id      — winner PHC 2015, combines time + memory hardness
    PBKDF2-SHA256 — NIST approved, widely supported (but weaker than above)

  Legacy (do NOT use):
    MD5-crypt ($1$) — fast, crackable in seconds on GPU
    SHA-256-crypt ($5$) — better but still too fast
    SHA-512-crypt ($6$) — widely used, but too fast for offline attack
    LM hash         — broken, 1980s Windows, trivially cracked
    NTLM            — weak, used in Windows domains, pass-the-hash attacks
INFO

    section "Local Account Security Audit"
    echo -e "${INFO}Password hash algorithms in /etc/shadow:${NC}"
    if [[ -r /etc/shadow ]]; then
        awk -F: '$2 ~ /^\$/ {
            split($2, a, "$");
            if (a[2] == "y")  algo="yescrypt"
            else if (a[2] == "6") algo="SHA-512-crypt"
            else if (a[2] == "5") algo="SHA-256-crypt"
            else if (a[2] == "2b" || a[2] == "2a") algo="bcrypt"
            else if (a[2] == "1") algo="MD5-crypt (WEAK)"
            else algo="unknown ($" a[2] "$)"
            printf "  %-20s %s\n", $1, algo
        }' /etc/shadow
    else
        echo -e "  ${MUTED}/etc/shadow not readable (run with sudo for full audit)${NC}"
        echo -e "  ${MUTED}Readable from /etc/passwd:${NC}"
        awk -F: '$3 >= 1000 && $1 != "nobody" {print "  " $1}' /etc/passwd 2>/dev/null
    fi

    echo
    echo -e "${INFO}Users with empty passwords:${NC}"
    if [[ -r /etc/shadow ]]; then
        local empty
        empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
        [[ -n "$empty" ]] && echo -e "  ${FAILURE}${empty}${NC}" \
                          || status_line ok "No accounts with empty passwords"
    fi

    echo
    echo -e "${INFO}Users with UID 0 (root-equivalent):${NC}"
    awk -F: '$3 == 0 {print "  " $1}' /etc/passwd

    section "Authorisation Models"
    cat << 'INFO'
  DAC (Discretionary Access Control)
    Owner sets permissions. Unix file permissions (rwx) and ACLs.

  MAC (Mandatory Access Control)
    Policy enforced by OS regardless of owner.
    Linux: SELinux (type enforcement), AppArmor (path-based profiles).

  RBAC (Role-Based Access Control)
    Permissions assigned to roles, roles assigned to users.
    Principle of least privilege — minimal necessary rights.

  ABAC (Attribute-Based Access Control)
    Decisions based on user/resource/environment attributes.
    Most flexible (and complex). Used in cloud IAM policies.
INFO

    section "Linux File Permissions Audit"
    echo -e "${INFO}World-writable files in /etc:${NC}"
    find /etc -maxdepth 2 -perm -002 -type f 2>/dev/null | head -10 | while read -r f; do
        echo -e "  ${FAILURE}${f}${NC}"
    done || status_line ok "None found"

    echo
    echo -e "${INFO}SUID binaries (run as owner, typically root):${NC}"
    find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null | while read -r f; do
        local owner
        owner=$(stat -c '%U' "$f" 2>/dev/null)
        printf "  ${YELLOW}%-40s${NC} owner: ${CYAN}%s${NC}\n" "$f" "$owner"
    done | head -15

    echo
    echo -e "${INFO}sudo privileges:${NC}"
    if [[ -r /etc/sudoers ]]; then
        grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' | \
            grep -v "^Defaults" | head -10 | sed 's/^/  /'
    else
        echo -e "  ${MUTED}/etc/sudoers not readable — run: sudo -l${NC}"
        sudo -l 2>/dev/null | grep "may run" | sed 's/^/  /'
    fi
}

# ENCRYPTION BASICS
encryption_basics() {
    header "Encryption — Fundamentals & Live Demo"

    section "Encryption vs Encoding vs Hashing"
    cat << 'INFO'
  Encoding   — transforms data format; NOT secret. Reversible without key.
               Examples: Base64, URL-encoding, ASCII, UTF-8.

  Encryption — transforms data using a key; confidential. Reversible WITH key.
               Examples: AES-256-GCM, ChaCha20-Poly1305, RSA.

  Hashing    — one-way digest; NOT reversible. Deterministic.
               Examples: SHA-256, SHA-3, BLAKE3.
INFO

    section "AES-256-GCM — Symmetric Encryption Demo"
    if cmd_exists openssl; then
        local plaintext="This is a SECRET message — CIA Triad in action."
        local pass="s3cret_demo_passphrase"

        echo -e "  ${INFO}Plaintext:${NC}  ${plaintext}"
        echo

        local ciphertext
        ciphertext=$(echo "$plaintext" | \
            openssl enc -aes-256-gcm -pbkdf2 -iter 100000 -base64 -pass "pass:${pass}" 2>/dev/null)
        echo -e "  ${LABEL}Ciphertext (Base64):${NC}"
        echo -e "  ${MUTED}${ciphertext}${NC}"
        echo

        local decrypted
        decrypted=$(echo "$ciphertext" | \
            openssl enc -aes-256-gcm -pbkdf2 -iter 100000 -d -base64 -pass "pass:${pass}" 2>/dev/null)

        if [[ "$decrypted" == "$plaintext" ]]; then
            status_line ok "Decryption successful: ${decrypted}"
        else
            echo -e "  ${MUTED}AES-GCM demo not supported on this OpenSSL version — trying CBC:${NC}"
            ciphertext=$(echo "$plaintext" | \
                openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -base64 -pass "pass:${pass}" 2>/dev/null)
            echo -e "  ${MUTED}${ciphertext}${NC}"
            decrypted=$(echo "$ciphertext" | \
                openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -d -base64 -pass "pass:${pass}" 2>/dev/null)
            [[ "$decrypted" == "$plaintext" ]] \
                && status_line ok "AES-256-CBC decrypt: ${decrypted}" \
                || status_line fail "Decryption failed"
        fi
    else
        status_line neutral "openssl not available"
    fi

    section "OpenSSL Version & Supported Ciphers"
    if cmd_exists openssl; then
        kv "OpenSSL version" "$(openssl version 2>/dev/null)"
        echo
        echo -e "  ${MUTED}AES cipher variants available:${NC}"
        openssl enc -ciphers 2>/dev/null | tr ' ' '\n' | grep -i "aes" | sort | \
            column 2>/dev/null | head -10 | sed 's/^/  /'
    fi
}

# HASHING vs ENCRYPTING
hash_vs_encrypt() {
    header "Hashing — One-Way Digests"

    section "Hash Function Properties"
    cat << 'INFO'
  1. Deterministic    : same input → always same output
  2. Fixed output     : any input → fixed-length digest
  3. One-way          : computationally infeasible to reverse
  4. Avalanche effect : 1-bit change → ~50% of output bits flip
  5. Collision resist.: hard to find two inputs with same hash

  Common algorithms:
    MD5    — 128-bit. BROKEN for security (collision attacks). Use only for checksums.
    SHA-1  — 160-bit. DEPRECATED. Collision demonstrated (SHAttered, 2017).
    SHA-256— 256-bit. Secure. Part of SHA-2 family. Widely used.
    SHA-512— 512-bit. Stronger SHA-2. Good for high-security applications.
    SHA-3  — Keccak construction. Different design from SHA-2. NIST FIPS 202.
    BLAKE2 — Faster than MD5, more secure than SHA-3. Used in WireGuard.
    BLAKE3 — Even faster, parallelisable. Modern replacement.
INFO

    section "Live Hash Demo"
    if cmd_exists openssl; then
        local input="Hello, Security World!"
        echo -e "  ${INFO}Input: \"${input}\"${NC}"
        echo
        for algo in md5 sha1 sha256 sha512; do
            local digest
            digest=$(echo -n "$input" | openssl dgst "-${algo}" 2>/dev/null | awk '{print $2}')
            printf "  ${LABEL}%-10s${NC} ${WHITE}%s${NC}\n" "${algo^^}" "$digest"
        done

        echo
        echo -e "  ${INFO}Avalanche effect — 1 char difference:${NC}"
        local h1 h2
        h1=$(echo -n "Hello, Security World!"  | openssl dgst -sha256 | awk '{print $2}')
        h2=$(echo -n "hello, Security World!"  | openssl dgst -sha256 | awk '{print $2}')
        echo -e "  ${MUTED}Input A:${NC} ${h1}"
        echo -e "  ${MUTED}Input B:${NC} ${h2}"
        local diff=0
        for (( i=0; i<${#h1}; i++ )); do
            [[ "${h1:$i:1}" != "${h2:$i:1}" ]] && (( diff++ ))
        done
        echo -e "  ${GOLD}Differing hex chars: ${diff} / ${#h1}  ($(( diff * 100 / ${#h1} ))%)${NC}"
    fi

    section "File Integrity Verification"
    echo -e "${INFO}SHA-256 checksums of key system files:${NC}"
    for f in /etc/passwd /etc/hosts /etc/resolv.conf; do
        [[ -f "$f" ]] && sha256sum "$f" 2>/dev/null | awk '{printf "  %-12s  %s\n", $1, $2}'
    done

    echo
    echo -e "  ${MUTED}Compare against known-good checksum to detect tampering.${NC}"
    echo -e "  ${MUTED}Tools: AIDE, Tripwire, or a simple sha256sum manifest.${NC}"
}

# SYMMETRIC vs ASYMMETRIC
symmetric_asymmetric() {
    header "Symmetric vs Asymmetric Cryptography"

    section "Comparison"
    printf "\n  ${BOLD}%-35s %-35s${NC}\n" "Symmetric" "Asymmetric"
    printf "  ${DARK_GRAY}%-35s %-35s${NC}\n" "$(printf '─%.0s' {1..33})" "$(printf '─%.0s' {1..33})"
    while IFS='|' read -r sym asym; do
        printf "  ${GREEN}%-35s${NC} ${CYAN}%-35s${NC}\n" "$sym" "$asym"
    done << 'TABLE'
Single shared key|Key pair: public + private
Fast (hardware AES in CPU)|Slow (large math operations)
AES-256, ChaCha20, 3DES|RSA, ECC (ECDSA, ECDH), ElGamal
Key distribution problem|No pre-shared secret needed
Best for bulk data encryption|Best for key exchange + signatures
Used: VPNs, disk, database|Used: TLS, SSH, PGP, code signing
TABLE

    section "Hybrid Encryption (How TLS Uses Both)"
    cat << 'INFO'
  Real-world systems use BOTH:
    1. Asymmetric crypto (ECDH/RSA) → securely exchange a session key
    2. Symmetric crypto (AES-GCM)   → encrypt bulk data with session key

  This solves the key distribution problem while keeping bulk encryption fast.
INFO

    section "RSA Key Generation Demo"
    if cmd_exists openssl; then
        local tmpkey="/tmp/demo_rsa_$$"
        echo -e "  ${MUTED}Generating 2048-bit RSA key pair...${NC}"
        openssl genrsa -out "${tmpkey}.pem" 2048 2>/dev/null
        echo -e "  ${MUTED}Extracting public key...${NC}"
        openssl rsa -in "${tmpkey}.pem" -pubout -out "${tmpkey}.pub" 2>/dev/null

        echo
        echo -e "  ${INFO}Public key (first 4 lines):${NC}"
        head -4 "${tmpkey}.pub" 2>/dev/null | sed 's/^/  /'

        echo
        echo -e "  ${INFO}Key parameters:${NC}"
        openssl rsa -in "${tmpkey}.pem" -text -noout 2>/dev/null | \
            grep -E "Private-Key|modulus:|publicExponent:" | head -3 | sed 's/^/  /'

        echo
        local plaintext="RSA encryption test message"
        openssl rsautl -encrypt -pubin -inkey "${tmpkey}.pub" \
            -in <(echo "$plaintext") -out "${tmpkey}.enc" 2>/dev/null \
            || openssl pkeyutl -encrypt -pubin -inkey "${tmpkey}.pub" \
                -in <(echo "$plaintext") -out "${tmpkey}.enc" 2>/dev/null

        local decrypted
        decrypted=$(openssl rsautl -decrypt -inkey "${tmpkey}.pem" \
            -in "${tmpkey}.enc" 2>/dev/null \
            || openssl pkeyutl -decrypt -inkey "${tmpkey}.pem" \
                -in "${tmpkey}.enc" 2>/dev/null)
        [[ "$decrypted" == "$plaintext" ]] \
            && status_line ok "RSA encrypt → decrypt round-trip successful" \
            || echo -e "  ${MUTED}RSA demo unavailable on this platform${NC}"

        rm -f "${tmpkey}.pem" "${tmpkey}.pub" "${tmpkey}.enc"
    fi

    section "Elliptic Curve Cryptography"
    if cmd_exists openssl; then
        echo -e "  ${INFO}Generating P-256 (prime256v1) EC key:${NC}"
        local tmpec="/tmp/demo_ec_$$"
        openssl ecparam -genkey -name prime256v1 -out "${tmpec}.pem" 2>/dev/null
        openssl ec -in "${tmpec}.pem" -text -noout 2>/dev/null | \
            grep -E "Private-Key|ASN1|curve:" | head -5 | sed 's/^/  /'
        echo
        status_line ok "EC key size: $(wc -c < "${tmpec}.pem" 2>/dev/null) bytes vs ~1700 bytes for RSA-2048"
        rm -f "${tmpec}.pem"
    fi
}

# TLS HANDSHAKE
tls_handshake() {
    header "TLS Handshake — Securing the Connection"

    section "TLS 1.3 Handshake Flow (RFC 8446)"
    cat << 'INFO'
  Client                              Server
  ─────────────────────────────────────────────────────────
    ClientHello                ──►
      (supported ciphers,
       key_share, extensions)
                               ◄──  ServerHello
                                      (chosen cipher,
                                       key_share)
                               ◄──  {EncryptedExtensions}
                               ◄──  {Certificate}
                               ◄──  {CertificateVerify}
                               ◄──  {Finished}
    {Finished}                 ──►
    {Application Data}         ──►  {Application Data}
  ─────────────────────────────────────────────────────────
  Key: {} = encrypted with derived keys

  TLS 1.3 improvements over TLS 1.2:
    ✓ 1-RTT handshake (vs 2-RTT)
    ✓ 0-RTT resumption (session tickets)
    ✓ Forward secrecy mandatory (ECDHE only)
    ✓ Removed: RSA key exchange, RC4, 3DES, MD5, SHA-1
    ✓ Encrypted earlier (server cert is encrypted)
    ✓ Simplified cipher suite list (5 only)
INFO

    section "Live TLS Probe"
    read -rp "$(echo -e "  ${PROMPT}Enter domain to probe [default: cloudflare.com]:${NC} ")" tls_domain
    tls_domain="${tls_domain:-cloudflare.com}"
    is_valid_host "$tls_domain" || { log_warning "Invalid domain"; tls_domain="cloudflare.com"; }

    if cmd_exists openssl; then
        echo
        echo -e "  ${INFO}TLS connection details for ${tls_domain}:${NC}"
        echo | timeout 8 openssl s_client -connect "${tls_domain}:443" \
            -servername "$tls_domain" 2>/dev/null | \
            grep -E "Protocol|Cipher|Session-ID|TLSv|bits|Verify" | \
            sed 's/^/  /'

        echo
        echo -e "  ${INFO}Certificate:${NC}"
        echo | timeout 8 openssl s_client -connect "${tls_domain}:443" \
            -servername "$tls_domain" 2>/dev/null | \
            openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null | \
            sed 's/^/  /'

        echo
        echo -e "  ${INFO}Supported TLS versions:${NC}"
        for ver in tls1_2 tls1_3; do
            if echo | timeout 4 openssl s_client -connect "${tls_domain}:443" \
                    -servername "$tls_domain" -"${ver}" 2>/dev/null | \
                    grep -q "Cipher is"; then
                status_line ok  "TLS ${ver/tls1_/1.} supported"
            else
                status_line neutral "TLS ${ver/tls1_/1.} not negotiated"
            fi
        done

        echo
        echo -e "  ${INFO}Cipher suite negotiated:${NC}"
        echo | timeout 8 openssl s_client -connect "${tls_domain}:443" \
            -servername "$tls_domain" 2>/dev/null | \
            grep "Cipher    " | sed 's/^/  /'
    else
        status_line neutral "openssl not available"
    fi

    section "Certificate Transparency"
    echo -e "  ${MUTED}Check https://crt.sh/?q=${tls_domain} for all certs issued for this domain.${NC}"
    echo -e "  ${MUTED}CT logs expose mis-issued certs within seconds of issuance.${NC}"
}

# CERTIFICATES & CA
certificates_ca() {
    header "PKI — Certificates & Certificate Authorities"

    section "X.509 Certificate Structure"
    cat << 'INFO'
  An X.509 certificate contains:
    Version        (v1/v2/v3)
    Serial Number  (unique per CA)
    Signature Alg  (what the CA used to sign this cert)
    Issuer         (the CA's Distinguished Name)
    Validity       (Not Before / Not After)
    Subject        (owner's Distinguished Name)
    Public Key     (the public key being certified)
    Extensions     (v3 only):
      SAN (Subject Alt Names)   — hostnames / IPs this cert is valid for
      Basic Constraints         — isCA flag; path length constraint
      Key Usage                 — digitalSignature, keyEncipherment, etc.
      Extended Key Usage        — TLS server, TLS client, code signing
      AKI / SKI                 — authority/subject key identifiers
      CRL Distribution Point    — where to get revocation list
      OCSP                      — Online Certificate Status Protocol URL

  Chain of Trust:
    Root CA (self-signed, offline)
      → Intermediate CA (online, issues leaf certs)
        → Leaf/End-Entity Cert (your server cert)
INFO

    section "Self-Signed Certificate Demo"
    if cmd_exists openssl; then
        local tmpdir="/tmp/pki_demo_$$"
        mkdir -p "$tmpdir"

        echo -e "  ${MUTED}Generating self-signed certificate...${NC}"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout "${tmpdir}/key.pem" -out "${tmpdir}/cert.pem" \
            -days 365 -nodes \
            -subj "/C=US/ST=Demo/L=Lab/O=SecurityLab/CN=demo.lab" 2>/dev/null

        if [[ -f "${tmpdir}/cert.pem" ]]; then
            echo -e "  ${INFO}Certificate fields:${NC}"
            openssl x509 -in "${tmpdir}/cert.pem" -noout \
                -subject -issuer -dates -fingerprint -pubkey 2>/dev/null | \
                head -8 | sed 's/^/  /'

            echo
            echo -e "  ${INFO}Extensions:${NC}"
            openssl x509 -in "${tmpdir}/cert.pem" -noout -text 2>/dev/null | \
                grep -A2 "X509v3" | head -20 | sed 's/^/  /'
        fi

        rm -rf "$tmpdir"
    fi

    section "System Trust Store"
    echo -e "${INFO}Trusted CA certificates on this system:${NC}"
    local ca_store=""
    for d in /etc/ssl/certs /etc/pki/tls/certs /usr/share/ca-certificates; do
        [[ -d "$d" ]] && ca_store="$d" && break
    done
    if [[ -n "$ca_store" ]]; then
        local count
        count=$(find "$ca_store" -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l)
        kv "Trust store" "$ca_store"
        kv "CA certificates" "$count"
    fi

    echo
    echo -e "${INFO}Certificate revocation (OCSP/CRL):${NC}"
    echo -e "  ${MUTED}OCSP: real-time check against CA (privacy concern — CA sees your queries)${NC}"
    echo -e "  ${MUTED}OCSP Stapling: server embeds CA response in TLS handshake (preferred)${NC}"
    echo -e "  ${MUTED}CRL: full revocation list download (large, delayed)${NC}"
}

# HASHING DEMO
hashing_demo() {
    header "Cryptographic Hashing — Deep Dive"

    section "Hash Function Comparison"
    if cmd_exists openssl; then
        local test_input="The quick brown fox jumps over the lazy dog"
        echo -e "  ${INFO}Input: \"${test_input}\"${NC}"
        echo
        printf "  ${BOLD}%-12s %-10s %s${NC}\n" "Algorithm" "Bits" "Digest"
        printf "  ${DARK_GRAY}%-12s %-10s %s${NC}\n" \
            "───────────" "─────────" "──────────────────────────────────────────────────"
        for algo in md5 sha1 sha224 sha256 sha384 sha512; do
            local d
            d=$(echo -n "$test_input" | openssl dgst "-${algo}" 2>/dev/null | awk '{print $2}')
            local bits=$(( ${#d} * 4 ))
            printf "  ${CYAN}%-12s${NC} ${MUTED}%-10s${NC} %s\n" "${algo^^}" "${bits}-bit" "$d"
        done
    fi

    section "Password Hashing with bcrypt"
    if cmd_exists htpasswd; then
        echo -e "  ${MUTED}Generating bcrypt hash for 'mypassword':${NC}"
        htpasswd -bnBC 12 "" "mypassword" 2>/dev/null | tr -d ':\n' | sed 's/^/  /'
        echo
        echo -e "  ${MUTED}Format: \$2y\$<cost>\$<22-char salt><31-char hash>${NC}"
    elif cmd_exists python3; then
        echo -e "  ${MUTED}Python bcrypt demo:${NC}"
        python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'mypassword', salt, 100000)
print('  PBKDF2-SHA256:', dk.hex()[:32]+'...')
" 2>/dev/null
    fi

    section "Salted vs Unsalted Hashing"
    cat << 'INFO'
  Unsalted hash: sha256("password") → same hash for every user with same password.
    → Rainbow table attacks trivially crack common passwords.

  Salted hash:   sha256(salt + "password") → unique hash per user.
    → Pre-computed rainbow tables useless; must brute-force each separately.
    → Salt is stored in plaintext alongside the hash (it's not secret).

  /etc/shadow format example:
    $6$rounds=5000$saltstring$hashedpassword
    $6$ = SHA-512-crypt, rounds = iteration count
INFO

    if cmd_exists openssl; then
        echo -e "  ${INFO}Salted hash demo:${NC}"
        local pw="password123"
        local s1 s2
        s1=$(openssl rand -hex 8 2>/dev/null)
        s2=$(openssl rand -hex 8 2>/dev/null)
        local h1 h2
        h1=$(echo -n "${s1}${pw}" | openssl dgst -sha256 | awk '{print $2}')
        h2=$(echo -n "${s2}${pw}" | openssl dgst -sha256 | awk '{print $2}')
        printf "  ${LABEL}Salt 1:${NC} %-18s → %s\n" "$s1" "$h1"
        printf "  ${LABEL}Salt 2:${NC} %-18s → %s\n" "$s2" "$h2"
        echo -e "  ${MUTED}Same password → completely different hashes${NC}"
    fi
}

# JWT DEMO
jwt_demo() {
    header "JWT — JSON Web Tokens"

    section "JWT Structure"
    cat << 'INFO'
  A JWT is a compact, URL-safe token in 3 Base64url-encoded parts:

    Header.Payload.Signature

  Header:   { "alg": "HS256", "typ": "JWT" }
  Payload:  { "sub": "user123", "role": "admin", "exp": 1700000000, "iat": ... }
  Signature: HMAC-SHA256(base64(header) + "." + base64(payload), secret)

  Common algorithms:
    HS256/HS384/HS512 — HMAC-SHA (symmetric: same key signs + verifies)
    RS256/RS384/RS512 — RSA signatures (asymmetric: private signs, public verifies)
    ES256/ES384/ES512 — ECDSA (smaller signatures than RSA)
    PS256             — RSA-PSS (preferred over PKCS#1 v1.5 for RSA)

  Security issues to watch:
    "alg":"none" attack — attacker removes signature; server accepts if not validated
    Secret brute-force  — weak HS256 secrets crackable offline (jwt_tool, hashcat)
    Algorithm confusion — RS256 key used as HS256 secret
    Missing expiry      — no "exp" claim means token never expires
    Sensitive payload   — payload is only Base64, NOT encrypted; don't put secrets
INFO

    section "JWT Demo (bash + openssl)"
    if cmd_exists openssl && cmd_exists base64; then
        local secret="super_secret_signing_key_do_not_share"
        local exp=$(( $(date +%s) + 3600 ))

        local header_json='{"alg":"HS256","typ":"JWT"}'
        local payload_json="{\"sub\":\"demo_user\",\"role\":\"viewer\",\"iat\":$(date +%s),\"exp\":${exp}}"

        local header_b64
        header_b64=$(echo -n "$header_json" | base64 -w0 | tr '+/' '-_' | tr -d '=')
        local payload_b64
        payload_b64=$(echo -n "$payload_json" | base64 -w0 | tr '+/' '-_' | tr -d '=')

        local sig
        sig=$(echo -n "${header_b64}.${payload_b64}" | \
            openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | \
            base64 -w0 | tr '+/' '-_' | tr -d '=')

        local token="${header_b64}.${payload_b64}.${sig}"

        echo -e "  ${INFO}Generated JWT:${NC}"
        echo -e "  ${MUTED}${token}${NC}"
        echo
        echo -e "  ${INFO}Decoded header:${NC}  ${header_json}"
        echo -e "  ${INFO}Decoded payload:${NC} ${payload_json}"
        echo -e "  ${INFO}Signature:${NC}       ${sig}"
        echo
        echo -e "  ${MUTED}Paste at: https://jwt.io/#debugger to inspect${NC}"
    else
        echo -e "  ${MUTED}openssl / base64 not available for JWT demo${NC}"
    fi
}

# HMAC
hmac_and_signatures() {
    header "HMAC — Hash-based Message Authentication Code"

    section "What is HMAC?"
    cat << 'INFO'
  HMAC = Hash + Secret Key
  Purpose: message authentication (proves both integrity AND sender identity)

  HMAC(K, M) = H( (K XOR opad) || H( (K XOR ipad) || M ) )

  Where:
    H     = underlying hash function (e.g., SHA-256)
    K     = secret key (padded to block size)
    M     = message
    opad  = 0x5c repeated
    ipad  = 0x36 repeated

  Properties:
    ✓ Without the key, cannot forge a valid MAC
    ✓ Detects both accidental corruption AND deliberate tampering
    ✓ Not the same as a digital signature (no non-repudiation)

  Used in: JWT (HS256), API request signing (AWS Sig v4), TLS MAC, TOTP/HOTP
INFO

    section "Live HMAC Demo"
    if cmd_exists openssl; then
        local key="secret_signing_key_123"
        local msg="Transfer \$1000 from Account A to Account B"

        local mac
        mac=$(echo -n "$msg" | openssl dgst -sha256 -hmac "$key" | awk '{print $2}')

        echo -e "  ${LABEL}Message:${NC} ${msg}"
        echo -e "  ${LABEL}Key:${NC}     ${key}"
        echo -e "  ${LABEL}HMAC:${NC}    ${mac}"

        echo
        echo -e "  ${INFO}Tampered message MAC:${NC}"
        local tampered="Transfer \$9000 from Account A to Account B"
        local mac2
        mac2=$(echo -n "$tampered" | openssl dgst -sha256 -hmac "$key" | awk '{print $2}')
        echo -e "  ${LABEL}Message:${NC} ${tampered}"
        echo -e "  ${LABEL}HMAC:${NC}    ${mac2}"
        [[ "$mac" != "$mac2" ]] \
            && status_line ok "MACs differ — tampering detected" \
            || status_line fail "MACs match (should never happen)"
    fi
}

# PERMISSION AUDIT
permission_audit() {
    header "File Permission Security Audit"

    section "Critical File Permissions"
    echo
    printf "  ${BOLD}%-32s %-8s %-8s %s${NC}\n" "File" "Perms" "Owner" "Status"
    printf "  ${DARK_GRAY}%-32s %-8s %-8s %s${NC}\n" \
        "$(printf '─%.0s' {1..31})" "───────" "───────" "──────"

    local -A expected_perms=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/sudoers"]="440"
        ["/etc/ssh/sshd_config"]="600"
        ["/root/.ssh/authorized_keys"]="600"
        ["/etc/crontab"]="644"
    )

    for f in "${!expected_perms[@]}"; do
        [[ ! -e "$f" ]] && continue
        local perms owner expected="${expected_perms[$f]}"
        perms=$(stat -c '%a' "$f" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$f" 2>/dev/null)
        local color sym
        if [[ "$perms" == "$expected" ]] || \
           (( 8#$perms <= 8#$expected )); then
            color="$SUCCESS" sym="✔"
        else
            color="$FAILURE" sym="✘"
        fi
        printf "  ${LABEL}%-32s${NC} ${MUTED}%-8s${NC} ${MUTED}%-8s${NC} ${color}%s${NC}\n" \
            "$f" "$perms" "$owner" "$sym"
    done

    section "Dangerous Conditions"
    echo
    echo -e "${INFO}World-writable files in /etc:${NC}"
    local ww
    ww=$(find /etc -maxdepth 3 -perm -002 -type f 2>/dev/null | head -5)
    [[ -n "$ww" ]] && echo -e "${FAILURE}${ww}${NC}" || status_line ok "None found"

    echo
    echo -e "${INFO}Unowned files (no valid user/group):${NC}"
    local unowned
    unowned=$(find /etc /var /home -maxdepth 3 -nouser -o -nogroup 2>/dev/null | head -5)
    [[ -n "$unowned" ]] && echo -e "${WARNING}${unowned}${NC}" || status_line ok "None found"

    echo
    echo -e "${INFO}SUID/SGID binaries:${NC}"
    find /usr /bin /sbin -maxdepth 3 \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
        while read -r f; do
            local perms owner
            perms=$(stat -c '%a' "$f" 2>/dev/null)
            owner=$(stat -c '%U' "$f" 2>/dev/null)
            printf "  ${YELLOW}%-40s${NC} perms: ${perms}  owner: ${CYAN}%s${NC}\n" "$f" "$owner"
        done | head -15
}

# MAN-IN-THE-MIDDLE SIMULATION
mitm_simulation() {
    header "Man-in-the-Middle — Concepts & Detection"

    section "MitM Attack Categories"
    cat << 'INFO'
  MitM attacks intercept communication between two parties.

  Attack techniques:
    ARP Spoofing     — send fake ARP replies to redirect LAN traffic
    DNS Spoofing     — forge DNS responses to redirect to attacker server
    BGP Hijacking    — announce more-specific routes to intercept internet traffic
    SSL Stripping    — downgrade HTTPS → HTTP (defeated by HSTS preloading)
    HTTPS Spoofing   — use visually similar domain (homograph attack)
    WiFi Evil Twin   — rogue AP with same SSID; intercepts all traffic
    ICMP Redirect    — send ICMP type 5 to change victim's default route

  Defences:
    ✓ HTTPS everywhere (TLS 1.3)
    ✓ HSTS + HSTS Preloading (browser enforces HTTPS before first request)
    ✓ Certificate Pinning (reject unexpected certs — apps, not browsers)
    ✓ DNSSEC (signed DNS records)
    ✓ 802.1X (port authentication — no unauthenticated LAN access)
    ✓ Dynamic ARP Inspection (DAI) on managed switches
    ✓ VPNs for untrusted networks
INFO

    section "Local MitM Indicators"
    echo
    echo -e "${INFO}Duplicate MAC addresses in ARP table (ARP spoofing indicator):${NC}"
    local dup_macs
    dup_macs=$(ip neigh show 2>/dev/null | awk '{print $5}' | sort | uniq -d)
    if [[ -n "$dup_macs" ]]; then
        echo -e "  ${FAILURE}Duplicate MACs found:${NC}"
        echo "$dup_macs" | sed 's/^/  /'
    else
        status_line ok "No duplicate MACs in ARP table"
    fi

    echo
    echo -e "${INFO}ARP entries (check for unexpected MAC→IP mappings):${NC}"
    ip neigh show 2>/dev/null | grep REACHABLE | head -10 | sed 's/^/  /'

    echo
    echo -e "${INFO}ICMP redirect handling:${NC}"
    local redir
    redir=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null)
    if [[ "$redir" == "0" ]]; then
        status_line ok  "ICMP redirects DISABLED — not vulnerable to ICMP redirect attacks"
    else
        status_line warn "ICMP redirects ENABLED — disable with: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    fi

    echo
    echo -e "${INFO}SSL/TLS certificate validation:${NC}"
    if cmd_exists openssl; then
        local result
        result=$(echo | timeout 5 openssl s_client -connect google.com:443 \
            -verify_return_error 2>&1 | grep -E "Verify return|verify error")
        if echo "$result" | grep -q "Verify return code: 0"; then
            status_line ok "TLS cert chain validates correctly"
        else
            status_line warn "TLS validation issue: ${result}"
        fi
    fi
}

main() {
    cia_triad
    auth_demo
    encryption_basics
    hash_vs_encrypt
    symmetric_asymmetric
    tls_handshake
    certificates_ca
    hashing_demo
    jwt_demo
    hmac_and_signatures
    permission_audit
    mitm_simulation
}

main