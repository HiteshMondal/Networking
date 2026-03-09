#!/usr/bin/env bash
# /modules/analysis/cloud_exposure_audit.sh
# Cloud security and exposure audit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

source "$PROJECT_ROOT/lib/init.sh"

set -eo pipefail

OUTPUT_DIR="$PROJECT_ROOT/output/cloud_audit"
mkdir -p "$OUTPUT_DIR"

ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$ERR_DIR"
ERRORS_FILE="$OUTPUT_DIR/errors_summary.txt"
: > "$ERRORS_FILE"

_note_err() {
    local label="$1" ec="${2:-?}"
    echo "[ERROR] '$label' failed (exit $ec)" >> "$ERRORS_FILE"
}

_section_err() {
    local sec="$1" errfile="$2"
    [ -s "$errfile" ] \
        && echo "[WARN] $sec: see errors/$(basename "$errfile")" >> "$ERRORS_FILE" \
        || rm -f "$errfile"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a  >> "$OUTPUT_DIR/run_timestamp.txt"
whoami    >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — CLOUD PLATFORM DETECTION

echo "[*] Detecting cloud platform..."

detect_cloud_platform() {
    local platform="unknown"

    if curl -sf -m 2 "http://169.254.169.254/latest/meta-data/" >/dev/null 2>&1; then
        platform="aws"
    elif curl -sf -m 2 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/" >/dev/null 2>&1; then
        platform="gcp"
    elif curl -sf -m 2 -H "Metadata: true" \
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1; then
        platform="azure"
    elif curl -sf -m 2 "http://169.254.169.254/metadata/v1/" >/dev/null 2>&1; then
        platform="digitalocean"
    elif curl -sf -m 2 "http://100.100.100.200/latest/meta-data/" >/dev/null 2>&1; then
        platform="alibaba"
    else
        platform="bare_metal_or_private"
    fi

    echo "$platform"
}

CLOUD_PLATFORM=$(detect_cloud_platform)
echo "  Platform detected: $CLOUD_PLATFORM"
echo "PLATFORM=$CLOUD_PLATFORM" > "$OUTPUT_DIR/platform_detected.txt"

# SECTION 2 — IMDS AUDIT

echo "[*] Auditing Instance Metadata Service (IMDS)..."

{
    echo "========================================================"
    echo "  IMDS Security Audit"
    echo "  Platform: $CLOUD_PLATFORM"
    echo "========================================================"
    echo

    if [ "$CLOUD_PLATFORM" = "aws" ]; then
        echo "=== AWS IMDSv1 probe (unauthenticated — should be blocked) ==="
        imdsv1_resp=$(curl -sf -m 3 "http://169.254.169.254/latest/meta-data/" 2>/dev/null || true)
        if [ -n "$imdsv1_resp" ]; then
            echo "[CRITICAL] IMDSv1 is accessible without authentication!"
            echo "  Response: $imdsv1_resp"

            echo
            echo "=== AWS IAM credentials via IMDSv1 (CRITICAL exposure) ==="
            iam_role=$(curl -sf -m 3 \
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)
            if [ -n "$iam_role" ]; then
                echo "[CRITICAL] IAM role found: $iam_role"
                iam_creds=$(curl -sf -m 3 \
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/$iam_role" \
                    2>/dev/null || true)
                echo "$iam_creds" | grep -v "SecretAccessKey" || true
                echo "  [SecretAccessKey REDACTED for safety]"
            else
                echo "  No IAM role attached"
            fi

            echo
            echo "=== AWS instance identity document ==="
            curl -sf -m 3 \
                "http://169.254.169.254/latest/dynamic/instance-identity/document" 2>/dev/null \
                || echo "(unavailable)"

            echo
            echo "=== AWS user-data (may contain secrets/bootstrap scripts) ==="
            curl -sf -m 3 \
                "http://169.254.169.254/latest/user-data" 2>/dev/null | head -50 \
                || echo "(user-data unavailable or empty)"

            echo
            echo "=== AWS security groups ==="
            curl -sf -m 3 \
                "http://169.254.169.254/latest/meta-data/security-groups" 2>/dev/null \
                || echo "(unavailable)"
        else
            echo "[OK] IMDSv1 appears blocked (no unauthenticated response)"
        fi

        echo
        echo "=== AWS IMDSv2 probe (token-based — secure design) ==="
        TOKEN=$(curl -sf -m 3 -X PUT \
            "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
        if [ -n "$TOKEN" ]; then
            echo "[INFO] IMDSv2 token acquired — IMDSv2 is available"
            hop_resp=$(curl -sf -m 3 \
                -H "X-aws-ec2-metadata-token: $TOKEN" \
                "http://169.254.169.254/latest/meta-data/network/interfaces/macs/" 2>/dev/null || true)
            echo "  IMDSv2 response: $hop_resp"
        else
            echo "  IMDSv2 not available"
        fi

    elif [ "$CLOUD_PLATFORM" = "gcp" ]; then
        echo "=== GCP Metadata Service probe ==="
        echo "[INFO] GCP requires 'Metadata-Flavor: Google' header"

        echo
        echo "=== GCP instance info ==="
        curl -sf -m 3 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/instance/" 2>/dev/null \
            || echo "(unavailable)"

        echo
        echo "=== GCP service account token ==="
        gcp_token=$(curl -sf -m 3 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
            2>/dev/null || true)
        if [ -n "$gcp_token" ]; then
            echo "[HIGH] GCP service account access token available via metadata!"
            echo "$gcp_token" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'  Token type: {d.get(\"token_type\")}')
    print(f'  Expires in: {d.get(\"expires_in\")} seconds')
    print('  [access_token value REDACTED]')
except Exception as e:
    print(f'  (parse error: {e})')" 2>/dev/null || true
        fi

        echo
        echo "=== GCP project info ==="
        curl -sf -m 3 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null \
            || echo "(unavailable)"

    elif [ "$CLOUD_PLATFORM" = "azure" ]; then
        echo "=== Azure IMDS probe ==="
        curl -sf -m 3 -H "Metadata: true" \
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null \
            | python3 -m json.tool 2>/dev/null | head -40 \
            || echo "(unavailable)"

        echo
        echo "=== Azure managed identity token ==="
        az_token=$(curl -sf -m 3 -H "Metadata: true" \
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/" \
            2>/dev/null || true)
        if [ -n "$az_token" ]; then
            echo "[HIGH] Azure managed identity token available!"
            echo "$az_token" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'  Token type: {d.get(\"token_type\")}')
    print(f'  Expires on: {d.get(\"expires_on\")}')
    print('  [access_token value REDACTED]')
except Exception as e:
    print(f'  (parse error: {e})')" 2>/dev/null || true
        fi
    else
        echo "[INFO] Platform '$CLOUD_PLATFORM' — no IMDS audit applicable"
    fi

} > "$OUTPUT_DIR/imds_audit.txt" 2>"$ERR_DIR/s2_imds.err" || true
_section_err "Section 2 IMDS" "$ERR_DIR/s2_imds.err"

# SECTION 3 — CLOUD CREDENTIAL EXPOSURE AUDIT

echo "[*] Auditing cloud credential files and environment variables..."

{
    echo "=== AWS credential files ==="
    for f in ~/.aws/credentials ~/.aws/config \
              /root/.aws/credentials /root/.aws/config; do
        [ -f "$f" ] || continue
        echo "FOUND: $f"
        grep -v "^#" "$f" \
            | sed 's/aws_secret_access_key.*/aws_secret_access_key = [REDACTED]/g' || true
    done
    find /home -name "credentials" -path "*/.aws/*" 2>/dev/null | while IFS= read -r f; do
        echo "FOUND: $f"
        grep -v "^#" "$f" 2>/dev/null \
            | sed 's/aws_secret_access_key.*/aws_secret_access_key = [REDACTED]/g' || true
    done

    echo
    echo "=== GCP service account key files (JSON) ==="
    find /home /root /etc /opt /var -name "*.json" -type f 2>/dev/null \
        | xargs grep -l '"type": "service_account"' 2>/dev/null \
        | while IFS= read -r f; do
        echo "[HIGH] GCP service account key found: $f"
        python3 -c "
import json, sys
try:
    with open('$f') as fp: d = json.load(fp)
    print(f'  Project:      {d.get(\"project_id\")}')
    print(f'  Client email: {d.get(\"client_email\")}')
    print('  [private_key REDACTED]')
except Exception as e:
    print(f'  (parse error: {e})')" 2>/dev/null || true
    done

    echo
    echo "=== Azure credential / auth files ==="
    find /home /root ~/.azure /etc -name "*.json" -type f 2>/dev/null \
        | xargs grep -l '"tenantId"\|"clientSecret"\|"subscriptionId"' 2>/dev/null \
        | head -5

    echo
    echo "=== Kubernetes kubeconfig files ==="
    for f in ~/.kube/config /root/.kube/config; do
        [ -f "$f" ] || continue
        echo "FOUND: $f"
        grep -E '(server|user|cluster|namespace)' "$f" 2>/dev/null | head -20
    done
    find /home /etc /opt \( -name "kubeconfig" -o -name "*.kubeconfig" \) 2>/dev/null \
        | head -5 | while IFS= read -r f; do
        echo "FOUND: $f"
        grep -E '(server|user|cluster)' "$f" 2>/dev/null | head -10
    done

    echo
    echo "=== Cloud credentials in environment variables ==="
    env 2>/dev/null \
        | grep -iE '(AWS_ACCESS|AWS_SECRET|AWS_SESSION|GOOGLE_APPLICATION|AZURE_CLIENT|AZURE_TENANT|KUBECONFIG|GH_TOKEN|GITHUB_TOKEN|DOCKER_PASSWORD|REGISTRY_PASS)' \
        | sed 's/=.*/= [PRESENT — value hidden]/g' \
        || echo "(none found in current env)"

    echo
    echo "=== Cloud credentials in process environments ==="
    grep -rl \
        'AWS_ACCESS_KEY_ID\|AWS_SECRET_ACCESS_KEY\|GOOGLE_APPLICATION_CREDENTIALS\|AZURE_CLIENT_SECRET' \
        /proc/*/environ 2>/dev/null | while IFS= read -r env_file; do
        pid=$(echo "$env_file" | grep -oE '[0-9]+')
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        echo "PID $pid ($exe): cloud credentials in environment"
    done || echo "(none found)"

} > "$OUTPUT_DIR/cloud_credential_exposure.txt" 2>"$ERR_DIR/s3_creds.err" || true
_section_err "Section 3 credentials" "$ERR_DIR/s3_creds.err"

# SECTION 4 — CONTAINER SECURITY & ESCAPE INDICATORS

echo "[*] Checking container security posture and escape indicators..."

{
    echo "=== Container runtime detection ==="
    if [ -f /.dockerenv ]; then
        echo "[DETECTED] Running inside a Docker container"
    fi
    if grep -q "lxc\|docker\|containerd\|kubepods" /proc/1/cgroup 2>/dev/null; then
        echo "[DETECTED] Cgroup evidence of container runtime"
        grep "lxc\|docker\|containerd\|kubepods" /proc/1/cgroup 2>/dev/null | head -5
    fi
    if [ -f /run/.containerenv ]; then
        echo "[DETECTED] Podman container environment"
    fi

    echo
    echo "=== Docker socket exposure (critical escape vector) ==="
    if [ -S /var/run/docker.sock ]; then
        echo "[CRITICAL] /var/run/docker.sock is accessible!"
        ls -la /var/run/docker.sock
        echo "  This allows full host compromise from within the container"
        if command -v curl >/dev/null 2>&1; then
            echo "  Docker version via socket:"
            curl -sf --unix-socket /var/run/docker.sock \
                http://localhost/version 2>/dev/null \
                | python3 -m json.tool 2>/dev/null | head -10 || true
            echo "  Running containers:"
            curl -sf --unix-socket /var/run/docker.sock \
                "http://localhost/containers/json" 2>/dev/null \
                | python3 -c "
import sys, json
try:
    cs = json.load(sys.stdin)
    for c in cs[:5]:
        print(f'  {c.get(\"Names\",[\"?\"])[0]} — {c.get(\"Status\")}')
except Exception: pass" 2>/dev/null || true
        fi
    else
        echo "[OK] Docker socket not accessible at /var/run/docker.sock"
    fi

    echo
    echo "=== Privileged container check ==="
    cap_bnd=$(grep "^CapBnd:" /proc/1/status 2>/dev/null | awk '{print $2}' || echo "")
    if [ "$cap_bnd" = "0000003fffffffff" ]; then
        echo "[CRITICAL] Full capability bounding set — likely a privileged container!"
    else
        echo "  CapBnd: ${cap_bnd:-(unavailable)} (non-full)"
    fi

    echo
    echo "=== Dangerous mount points (host filesystem exposure) ==="
    mount 2>/dev/null \
        | grep -vE 'overlay|tmpfs|proc|sys|devpts|cgroup|mqueue|hugetlbfs|nsfs' \
        | grep -vE '^\s*$' \
        || echo "(none)"

    echo
    echo "=== Writable host filesystem mounts ==="
    mount 2>/dev/null \
        | grep -vE 'ro,|tmpfs|proc|sys|devpts|cgroup' \
        | awk '{print $3}' | while IFS= read -r mp; do
        [ -w "$mp" ] && echo "WRITABLE: $mp"
    done || true

    echo
    echo "=== /proc/1/root (PID 1 namespace escape check) ==="
    if ls /proc/1/root/etc/passwd >/dev/null 2>&1; then
        echo "[HIGH] /proc/1/root is accessible — can read host root filesystem!"
    else
        echo "[OK] /proc/1/root not accessible from this context"
    fi

    echo
    echo "=== Kernel namespace isolation ==="
    for ns_type in mnt uts ipc pid net user; do
        ns_self=$(readlink "/proc/self/ns/$ns_type" 2>/dev/null || echo "?")
        ns_host=$(readlink "/proc/1/ns/$ns_type"   2>/dev/null || echo "?")
        if [ "$ns_self" = "$ns_host" ] && [ "$ns_self" != "?" ]; then
            echo "[WARN] $ns_type namespace: SHARED with host ($ns_self)"
        else
            echo "  $ns_type namespace: isolated (self=$ns_self)"
        fi
    done

    echo
    echo "=== Container escape tools present ==="
    for tool in nsenter unshare ctr crictl runc docker; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool at $(command -v "$tool")" || true
    done

} > "$OUTPUT_DIR/container_security.txt" 2>"$ERR_DIR/s4_container.err" || true
_section_err "Section 4 container" "$ERR_DIR/s4_container.err"

# SECTION 5 — KUBERNETES SECURITY AUDIT

echo "[*] Auditing Kubernetes security posture..."

{
    SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"

    echo "=== Kubernetes service account token ==="
    if [ -f "$SA_TOKEN" ]; then
        echo "[INFO] Running inside Kubernetes pod (service account token found)"
        echo "  Token file: $SA_TOKEN"

        token_content=$(cat "$SA_TOKEN")

        echo
        echo "  JWT Header:"
        echo "$token_content" | cut -d'.' -f1 \
            | base64 -d 2>/dev/null \
            | python3 -m json.tool 2>/dev/null || echo "  (decode failed)"

        echo
        echo "  JWT Payload (claims):"
        echo "$token_content" | cut -d'.' -f2 \
            | base64 -d 2>/dev/null \
            | python3 -m json.tool 2>/dev/null || echo "  (decode failed)"

        KUBE_NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo "default")
        KUBE_API="https://kubernetes.default.svc"

        echo
        echo "=== Kubernetes API server access check ==="
        echo "  Namespace: $KUBE_NS"
        echo "  API server: $KUBE_API"

        kubectl get pods --all-namespaces 2>/dev/null | head -20 \
        || curl -sfk -m 5 \
            -H "Authorization: Bearer $token_content" \
            "$KUBE_API/api/v1/namespaces/$KUBE_NS/pods" 2>/dev/null \
            | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d.get('items', [])
    print(f'  Pod listing: {len(items)} pods accessible')
    for p in items[:5]: print(f'    - {p[\"metadata\"][\"name\"]}')
except Exception as e:
    print(f'  (parse error: {e})')" 2>/dev/null \
        || echo "  (kubectl unavailable and API probe failed)"

        echo
        echo "=== RBAC permissions check ==="
        kubectl auth can-i --list 2>/dev/null | head -20 \
        || curl -sfk -m 5 \
            -H "Authorization: Bearer $token_content" \
            -H "Content-Type: application/json" \
            "$KUBE_API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
            -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
            2>/dev/null | python3 -m json.tool 2>/dev/null | head -30 \
        || echo "  (RBAC check unavailable)"

    else
        echo "[OK] No Kubernetes service account token found"
    fi

    echo
    echo "=== Kubernetes config files ==="
    find /home /root /etc \
        \( -name "kubeconfig" -o -name "*.kubeconfig" -o \( -name "config" -path "*/.kube/*" \) \) \
        2>/dev/null | while IFS= read -r f; do
        echo "Found: $f"
        grep -E 'server:|name:|namespace:' "$f" 2>/dev/null | head -10
    done

    echo
    echo "=== Kubernetes secret mounts in this pod ==="
    found=0
    find /var/run/secrets /etc/secrets /run/secrets \
        -type f 2>/dev/null | while IFS= read -r s; do
        echo "Secret: $s ($(wc -c < "$s" 2>/dev/null) bytes)"
        found=1
    done
    [ "$found" -eq 0 ] && echo "(none found)" || true

} > "$OUTPUT_DIR/kubernetes_security.txt" 2>"$ERR_DIR/s5_k8s.err" || true
_section_err "Section 5 Kubernetes" "$ERR_DIR/s5_k8s.err"

# SECTION 6 — CLOUD PERSISTENCE MECHANISMS

echo "[*] Checking cloud-specific persistence mechanisms..."

{
    echo "=== Cloud-init scripts (execute at boot) ==="
    for dir in /etc/cloud/cloud.cfg.d /var/lib/cloud/instance/scripts; do
        if [ -d "$dir" ]; then
            ls -la "$dir" 2>/dev/null
            echo
        fi
    done
    [ -f /var/log/cloud-init.log ] && tail -30 /var/log/cloud-init.log || true

    echo
    echo "=== User-data persistence (AWS EC2 user-data) ==="
    [ -f /var/lib/cloud/instance/user-data.txt ] \
        && head -30 /var/lib/cloud/instance/user-data.txt \
        || echo "(no user-data file)"

    echo
    echo "=== Cloud function / Lambda environment indicators ==="
    if [ -n "${AWS_LAMBDA_FUNCTION_NAME:-}" ]; then
        echo "[INFO] Running in AWS Lambda: $AWS_LAMBDA_FUNCTION_NAME"
        echo "  Handler: ${_HANDLER:-unknown}"
        echo "  Runtime: ${AWS_EXECUTION_ENV:-unknown}"
    fi
    if [ -n "${FUNCTION_NAME:-}" ] && [ -n "${K_SERVICE:-}" ]; then
        echo "[INFO] Running in Google Cloud Run/Functions: $FUNCTION_NAME"
    fi

    echo
    echo "=== Cron jobs added by cloud management tools ==="
    find /var/spool/cron /etc/cron.d -type f -ls 2>/dev/null || echo "(none)"

    echo
    echo "=== SSM / AWS Systems Manager agent ==="
    pgrep -la amazon-ssm-agent 2>/dev/null || echo "(not running)"
    systemctl is-active amazon-ssm-agent 2>/dev/null || true

    echo
    echo "=== CloudWatch / cloud monitoring agents ==="
    pgrep -la "cloudwatch\|stackdriver\|datadog\|newrelic\|dynatrace" 2>/dev/null \
        || echo "(none detected)"

} > "$OUTPUT_DIR/cloud_persistence.txt" 2>"$ERR_DIR/s6_persist.err" || true
_section_err "Section 6 cloud persistence" "$ERR_DIR/s6_persist.err"

# SECTION 7 — OBJECT STORAGE MISCONFIGURATION PROBE

echo "[*] Probing object storage accessibility..."

{
    echo "=== Public cloud storage bucket/blob indicators ==="

    echo "--- S3 bucket references found on disk ---"
    grep -rE 's3://[a-z0-9][a-z0-9\-]{2,62}|S3_BUCKET|AWS_BUCKET' \
        /etc /home /opt /var/www 2>/dev/null \
        | head -20 \
        | grep -v "Binary\|\.pyc\|\.so" \
        || echo "(none found)"

    echo
    echo "--- GCS bucket references ---"
    grep -rE 'gs://[a-z0-9][a-z0-9\-_]{2,62}|GCS_BUCKET|GCP_BUCKET' \
        /etc /home /opt /var/www 2>/dev/null \
        | head -20 \
        | grep -v "Binary\|\.pyc\|\.so" \
        || echo "(none found)"

    echo
    echo "--- Azure Storage references ---"
    grep -rE '[a-z0-9]{3,24}\.blob\.core\.windows\.net|AZURE_STORAGE_ACCOUNT' \
        /etc /home /opt /var/www 2>/dev/null \
        | head -20 \
        | grep -v "Binary\|\.pyc\|\.so" \
        || echo "(none found)"

    echo
    echo "=== Current AWS S3 accessible buckets (if AWS CLI configured) ==="
    if command -v aws >/dev/null 2>&1; then
        timeout 10 aws s3 ls 2>/dev/null | head -20 \
            || echo "(AWS CLI not authenticated or no buckets)"
    else
        echo "(AWS CLI not installed)"
    fi

} > "$OUTPUT_DIR/object_storage_audit.txt" 2>"$ERR_DIR/s7_storage.err" || true
_section_err "Section 7 object storage" "$ERR_DIR/s7_storage.err"

# SECTION 8 — SUMMARY REPORT
echo "[*] Generating cloud exposure summary..."

{
    echo "========================================================"
    echo "  Cloud Exposure Audit — Summary Report"
    echo "  Generated: $(date)"
    echo "  Platform:  $CLOUD_PLATFORM"
    echo "  Host:      $(hostname)"
    echo "========================================================"
    echo

    echo "--- Critical Findings ---"

    grep -q "CRITICAL.*IMDSv1" "$OUTPUT_DIR/imds_audit.txt" 2>/dev/null \
        && echo "[CRITICAL] IMDSv1 accessible without authentication (IAM credentials at risk)"

    grep -q "CRITICAL.*docker.sock" "$OUTPUT_DIR/container_security.txt" 2>/dev/null \
        && echo "[CRITICAL] Docker socket exposed inside container (host escape possible)"

    grep -q "CRITICAL.*privileged container" "$OUTPUT_DIR/container_security.txt" 2>/dev/null \
        && echo "[CRITICAL] Container running with full capabilities (privileged mode)"

    grep -q "SHARED with host" "$OUTPUT_DIR/container_security.txt" 2>/dev/null \
        && echo "[HIGH] Container shares one or more namespaces with the host"

    grep -q "Running inside Kubernetes" "$OUTPUT_DIR/kubernetes_security.txt" 2>/dev/null \
        && echo "[HIGH] Kubernetes service account token present — check RBAC permissions"

    grep -q "GCP service account access token available" "$OUTPUT_DIR/imds_audit.txt" 2>/dev/null \
        && echo "[HIGH] GCP service account token accessible via metadata service"

    grep -q "Azure managed identity token available" "$OUTPUT_DIR/imds_audit.txt" 2>/dev/null \
        && echo "[HIGH] Azure managed identity token accessible"

    grep -q "GCP service account key found" "$OUTPUT_DIR/cloud_credential_exposure.txt" 2>/dev/null \
        && echo "[HIGH] GCP service account JSON key file found on disk"

    echo
    echo "--- Script Errors ---"
    if [ -s "$ERRORS_FILE" ]; then
        cat "$ERRORS_FILE"
    else
        echo "[OK] No section errors recorded."
    fi

    echo
    echo "--- Platform: $CLOUD_PLATFORM ---"
    echo "--- Output Files ---"
    ls -lh "$OUTPUT_DIR/"*.txt 2>/dev/null

} > "$OUTPUT_DIR/cloud_audit_summary.txt"

cat "$OUTPUT_DIR/cloud_audit_summary.txt"

# ARCHIVE (contents only, no embedded absolute path)
ARCHIVE="$OUTPUT_DIR/cloud_audit_archive.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true

echo
echo "[+] Cloud audit complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: $ARCHIVE"
[ -s "$ERRORS_FILE" ] && echo "[!] Errors recorded — see $ERRORS_FILE and $ERR_DIR/"