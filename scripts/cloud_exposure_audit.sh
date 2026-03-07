#!/bin/bash
# Cloud Exposure Audit Script
# Purpose : Audit cloud-specific attack surfaces and misconfigurations:
#           IMDSv1/v2 metadata abuse, cloud credential exposure, container
#           and Kubernetes escape indicators, serverless/lambda security,
#           object storage misconfiguration, and cloud-native persistence.
# Output  : cloud_audit/ directory + archive

set -eo pipefail

OUTPUT_DIR="cloud_audit"
mkdir -p "$OUTPUT_DIR"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUTPUT_DIR/run_timestamp.txt" 2>/dev/null \
    || date > "$OUTPUT_DIR/run_timestamp.txt"
uname -a  >> "$OUTPUT_DIR/run_timestamp.txt"
whoami    >> "$OUTPUT_DIR/run_timestamp.txt"

# SECTION 1 — CLOUD PLATFORM DETECTION

echo "[*] Detecting cloud platform..."

detect_cloud_platform() {
    PLATFORM="unknown"

    # AWS
    if curl -sf -m 2 "http://169.254.169.254/latest/meta-data/" >/dev/null 2>&1; then
        PLATFORM="aws"
    # GCP
    elif curl -sf -m 2 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/" >/dev/null 2>&1; then
        PLATFORM="gcp"
    # Azure
    elif curl -sf -m 2 -H "Metadata: true" \
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1; then
        PLATFORM="azure"
    # DigitalOcean
    elif curl -sf -m 2 "http://169.254.169.254/metadata/v1/" >/dev/null 2>&1; then
        PLATFORM="digitalocean"
    # Alibaba
    elif curl -sf -m 2 "http://100.100.100.200/latest/meta-data/" >/dev/null 2>&1; then
        PLATFORM="alibaba"
    # Bare metal / on-prem
    else
        PLATFORM="bare_metal_or_private"
    fi

    echo "$PLATFORM"
}

CLOUD_PLATFORM=$(detect_cloud_platform)
echo "  Platform detected: $CLOUD_PLATFORM"
echo "PLATFORM=$CLOUD_PLATFORM" > "$OUTPUT_DIR/platform_detected.txt"

# SECTION 2 — IMDS (INSTANCE METADATA SERVICE) AUDIT

echo "[*] Auditing Instance Metadata Service (IMDS)..."

IMDS_OUT="$OUTPUT_DIR/imds_audit.txt"

{
    echo "========================================================"
    echo "  IMDS Security Audit"
    echo "  Platform: $CLOUD_PLATFORM"
    echo "========================================================"
    echo

    # ── AWS IMDSv1 (no token required — critical misconfiguration) ─────────
    if [ "$CLOUD_PLATFORM" = "aws" ]; then
        echo "=== AWS IMDSv1 probe (unauthenticated — should be blocked) ==="
        imdsv1_resp=$(curl -sf -m 3 "http://169.254.169.254/latest/meta-data/" 2>/dev/null)
        if [ -n "$imdsv1_resp" ]; then
            echo "[CRITICAL] IMDSv1 is accessible without authentication!"
            echo "  Response: $imdsv1_resp"

            echo
            echo "=== AWS IAM credentials via IMDSv1 (CRITICAL exposure) ==="
            iam_role=$(curl -sf -m 3 \
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null)
            if [ -n "$iam_role" ]; then
                echo "[CRITICAL] IAM role found: $iam_role"
                # Retrieve creds (redact secret key in output)
                iam_creds=$(curl -sf -m 3 \
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/$iam_role" \
                    2>/dev/null)
                echo "$iam_creds" | grep -v "SecretAccessKey" || true
                echo "  [SecretAccessKey REDACTED for safety]"
            else
                echo "  No IAM role attached (or instance has no instance profile)"
            fi

            echo
            echo "=== AWS instance identity document ==="
            curl -sf -m 3 \
                "http://169.254.169.254/latest/dynamic/instance-identity/document" 2>/dev/null

            echo
            echo "=== AWS user-data (may contain secrets/bootstrap scripts) ==="
            curl -sf -m 3 \
                "http://169.254.169.254/latest/user-data" 2>/dev/null | head -50 \
                || echo "(user-data unavailable or empty)"

            echo
            echo "=== AWS security groups ==="
            curl -sf -m 3 \
                "http://169.254.169.254/latest/meta-data/security-groups" 2>/dev/null

        else
            echo "[OK] IMDSv1 appears blocked (no unauthenticated response)"
        fi

        echo
        echo "=== AWS IMDSv2 probe (token-based — secure design) ==="
        TOKEN=$(curl -sf -m 3 -X PUT \
            "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
        if [ -n "$TOKEN" ]; then
            echo "[INFO] IMDSv2 token acquired — IMDSv2 is available"
            # Check hop limit (1 = protected from SSRF chains)
            hop_limit=$(curl -sf -m 3 \
                -H "X-aws-ec2-metadata-token: $TOKEN" \
                "http://169.254.169.254/latest/meta-data/network/interfaces/macs/" 2>/dev/null)
            echo "  IMDSv2 response: $hop_limit"
        else
            echo "  IMDSv2 not available"
        fi

    # ── GCP Metadata Service ────────────────────────────────────────────────
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
            2>/dev/null)
        if [ -n "$gcp_token" ]; then
            echo "[HIGH] GCP service account access token available via metadata!"
            echo "$gcp_token" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'  Token type: {d.get(\"token_type\")}')
    print(f'  Expires in: {d.get(\"expires_in\")} seconds')
    print('  [access_token value REDACTED]')
except: print('  (parse error)')" 2>/dev/null || true
        fi

        echo
        echo "=== GCP project info ==="
        curl -sf -m 3 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null

    # ── Azure IMDS ──────────────────────────────────────────────────────────
    elif [ "$CLOUD_PLATFORM" = "azure" ]; then
        echo "=== Azure IMDS probe ==="
        curl -sf -m 3 -H "Metadata: true" \
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null \
            | python3 -m json.tool 2>/dev/null | head -40

        echo
        echo "=== Azure managed identity token ==="
        az_token=$(curl -sf -m 3 -H "Metadata: true" \
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/" \
            2>/dev/null)
        if [ -n "$az_token" ]; then
            echo "[HIGH] Azure managed identity token available!"
            echo "$az_token" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'  Token type: {d.get(\"token_type\")}')
    print(f'  Expires on: {d.get(\"expires_on\")}')
    print('  [access_token value REDACTED]')
except: print('  (parse error)')" 2>/dev/null || true
        fi
    fi

} > "$IMDS_OUT" 2>/dev/null || true

# SECTION 3 — CLOUD CREDENTIAL EXPOSURE AUDIT

echo "[*] Auditing cloud credential files and environment variables..."

{
    echo "=== AWS credential files ==="
    for f in ~/.aws/credentials ~/.aws/config \
              /root/.aws/credentials /root/.aws/config; do
        [ -f "$f" ] && echo "FOUND: $f" && cat "$f" | grep -v "^#" | \
            sed 's/aws_secret_access_key.*/aws_secret_access_key = [REDACTED]/g'
    done
    find /home -name "credentials" -path "*/.aws/*" 2>/dev/null | while read -r f; do
        echo "FOUND: $f"
        cat "$f" 2>/dev/null | grep -v "^#" | \
            sed 's/aws_secret_access_key.*/aws_secret_access_key = [REDACTED]/g'
    done

    echo
    echo "=== GCP service account key files (JSON) ==="
    find /home /root /etc /opt /var -name "*.json" -type f 2>/dev/null | \
        xargs grep -l '"type": "service_account"' 2>/dev/null | while read -r f; do
        echo "[HIGH] GCP service account key found: $f"
        python3 -c "
import json,sys
with open('$f') as f: d=json.load(f)
print(f'  Project: {d.get(\"project_id\")}')
print(f'  Client email: {d.get(\"client_email\")}')
print('  [private_key REDACTED]')" 2>/dev/null || true
    done

    echo
    echo "=== Azure credential / auth files ==="
    find /home /root ~/.azure /etc -name "*.json" -type f 2>/dev/null | \
        xargs grep -l '"tenantId"\|"clientSecret"\|"subscriptionId"' 2>/dev/null | \
        head -5

    echo
    echo "=== Kubernetes kubeconfig files ==="
    for f in ~/.kube/config /root/.kube/config; do
        [ -f "$f" ] && echo "FOUND: $f" && \
            cat "$f" | grep -E '(server|user|cluster|namespace)' | head -20
    done
    find /home /etc /opt -name "kubeconfig" -o -name "*.kubeconfig" 2>/dev/null | \
        head -5 | while read -r f; do
        echo "FOUND: $f"
        cat "$f" 2>/dev/null | grep -E '(server|user|cluster)' | head -10
    done

    echo
    echo "=== Cloud credentials in environment variables ==="
    env 2>/dev/null | grep -iE \
        '(AWS_ACCESS|AWS_SECRET|AWS_SESSION|GOOGLE_APPLICATION|AZURE_CLIENT|AZURE_TENANT|KUBECONFIG|GH_TOKEN|GITHUB_TOKEN|DOCKER_PASSWORD|REGISTRY_PASS)' \
        | sed 's/=.*/= [PRESENT — value hidden]/g' || echo "(none found in current env)"

    echo
    echo "=== Cloud credentials in process environments ==="
    grep -rl \
        'AWS_ACCESS_KEY_ID\|AWS_SECRET_ACCESS_KEY\|GOOGLE_APPLICATION_CREDENTIALS\|AZURE_CLIENT_SECRET' \
        /proc/*/environ 2>/dev/null | while read -r env_file; do
        pid=$(echo "$env_file" | grep -oE '[0-9]+')
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        echo "PID $pid ($exe): cloud credentials in environment"
    done || echo "(none found)"

} > "$OUTPUT_DIR/cloud_credential_exposure.txt" 2>/dev/null || true

# SECTION 4 — CONTAINER SECURITY & ESCAPE INDICATORS

echo "[*] Checking container security posture and escape indicators..."

{
    echo "=== Container runtime detection ==="
    # Are we inside a container?
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
        # Check if curl can query it
        if command -v curl >/dev/null 2>&1; then
            echo "  Docker version via socket:"
            curl -sf --unix-socket /var/run/docker.sock \
                http://localhost/version 2>/dev/null | \
                python3 -m json.tool 2>/dev/null | head -10 || true
            echo "  Running containers:"
            curl -sf --unix-socket /var/run/docker.sock \
                "http://localhost/containers/json" 2>/dev/null | \
                python3 -c "
import sys,json
try:
    cs = json.load(sys.stdin)
    for c in cs[:5]: print(f'  {c.get(\"Names\",[\"?\"])[0]} — {c.get(\"Status\")}')
except: pass" 2>/dev/null || true
        fi
    else
        echo "[OK] Docker socket not accessible at /var/run/docker.sock"
    fi

    echo
    echo "=== Privileged container check ==="
    # Check capabilities (privileged container has all caps)
    cap_bnd=$(cat /proc/1/status 2>/dev/null | grep "^CapBnd:" | awk '{print $2}')
    if [ "$cap_bnd" = "0000003fffffffff" ]; then
        echo "[CRITICAL] Full capability bounding set — likely a privileged container!"
    else
        echo "  CapBnd: $cap_bnd (non-full)"
    fi

    echo
    echo "=== Dangerous mount points (host filesystem exposure) ==="
    mount 2>/dev/null | grep -vE 'overlay|tmpfs|proc|sys|devpts|cgroup|mqueue|hugetlbfs|nsfs' | \
        grep -vE '^\s*$'

    echo
    echo "=== Writable host filesystem mounts ==="
    mount 2>/dev/null | grep -vE 'ro,|tmpfs|proc|sys|devpts|cgroup' | \
        awk '{print $3}' | while read -r mp; do
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
    # Compare namespaces with PID 1 (host init)
    for ns_type in mnt uts ipc pid net user; do
        ns_self=$(readlink /proc/self/ns/$ns_type 2>/dev/null)
        ns_host=$(readlink /proc/1/ns/$ns_type 2>/dev/null)
        if [ "$ns_self" = "$ns_host" ]; then
            echo "[WARN] $ns_type namespace: SHARED with host ($ns_self)"
        else
            echo "  $ns_type namespace: isolated (self=$ns_self)"
        fi
    done

    echo
    echo "=== Container escape tools present ==="
    for tool in nsenter unshare ctr crictl runc docker; do
        command -v "$tool" >/dev/null 2>&1 \
            && echo "FOUND: $tool at $(which "$tool")" || true
    done

} > "$OUTPUT_DIR/container_security.txt" 2>/dev/null || true

# SECTION 5 — KUBERNETES SECURITY AUDIT

echo "[*] Auditing Kubernetes security posture..."

{
    echo "=== Kubernetes service account token ==="
    SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
    if [ -f "$SA_TOKEN" ]; then
        echo "[INFO] Running inside Kubernetes pod (service account token found)"
        echo "  Token file: $SA_TOKEN"

        # Decode JWT header and payload (no signature check)
        token_content=$(cat "$SA_TOKEN")
        echo
        echo "  JWT Header:"
        echo "$token_content" | cut -d'.' -f1 | base64 -d 2>/dev/null | \
            python3 -m json.tool 2>/dev/null || true
        echo
        echo "  JWT Payload (claims):"
        echo "$token_content" | cut -d'.' -f2 | base64 -d 2>/dev/null | \
            python3 -m json.tool 2>/dev/null || true

        KUBE_NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
        KUBE_API="https://kubernetes.default.svc"

        echo
        echo "=== Kubernetes API server access check ==="
        echo "  Namespace: $KUBE_NS"
        echo "  API server: $KUBE_API"

        # Can this pod list other pods?
        kubectl get pods --all-namespaces 2>/dev/null | head -20 || \
        curl -sfk -m 5 \
            -H "Authorization: Bearer $token_content" \
            "$KUBE_API/api/v1/namespaces/$KUBE_NS/pods" 2>/dev/null | \
            python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    items=d.get('items',[])
    print(f'  Pod listing: {len(items)} pods accessible')
    for p in items[:5]: print(f'    - {p[\"metadata\"][\"name\"]}')
except Exception as e: print(f'  (parse error: {e})')" 2>/dev/null || \
            echo "  (kubectl unavailable and API probe failed)"

        # Check for over-privileged service accounts
        echo
        echo "=== RBAC permissions check ==="
        kubectl auth can-i --list 2>/dev/null | head -20 || \
        curl -sfk -m 5 \
            -H "Authorization: Bearer $token_content" \
            "$KUBE_API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
            -H "Content-Type: application/json" \
            -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
            2>/dev/null | python3 -m json.tool 2>/dev/null | head -30 || \
            echo "  (RBAC check unavailable)"

    else
        echo "[OK] No Kubernetes service account token found"
    fi

    echo
    echo "=== Kubernetes config files ==="
    find /home /root /etc -name "kubeconfig" -o -name "*.kubeconfig" -o \
        -name "config" -path "*/.kube/*" 2>/dev/null | while read -r f; do
        echo "Found: $f"
        grep -E 'server:|name:|namespace:' "$f" 2>/dev/null | head -10
    done

    echo
    echo "=== Kubernetes secret mounts in this pod ==="
    find /var/run/secrets /etc/secrets /run/secrets -type f 2>/dev/null | while read -r s; do
        echo "Secret: $s ($(wc -c < "$s" 2>/dev/null) bytes)"
    done || echo "(none found)"

} > "$OUTPUT_DIR/kubernetes_security.txt" 2>/dev/null || true

# SECTION 6 — CLOUD PERSISTENCE MECHANISMS

echo "[*] Checking cloud-specific persistence mechanisms..."

{
    echo "=== Cloud-init scripts (execute at boot) ==="
    for dir in /etc/cloud/cloud.cfg.d /var/lib/cloud/instance/scripts; do
        [ -d "$dir" ] && ls -la "$dir" && echo
    done
    [ -f /var/log/cloud-init.log ] && tail -30 /var/log/cloud-init.log

    echo
    echo "=== User-data persistence (AWS EC2 user-data) ==="
    [ -f /var/lib/cloud/instance/user-data.txt ] && \
        cat /var/lib/cloud/instance/user-data.txt | head -30

    echo
    echo "=== Cloud function / Lambda environment indicators ==="
    if [ -n "$AWS_LAMBDA_FUNCTION_NAME" ]; then
        echo "[INFO] Running in AWS Lambda: $AWS_LAMBDA_FUNCTION_NAME"
        echo "  Handler: $_HANDLER"
        echo "  Runtime: $AWS_EXECUTION_ENV"
    fi
    if [ -n "$FUNCTION_NAME" ] && [ -n "$K_SERVICE" ]; then
        echo "[INFO] Running in Google Cloud Run/Functions: $FUNCTION_NAME"
    fi

    echo
    echo "=== Cron jobs added by cloud management tools ==="
    find /var/spool/cron /etc/cron.d -type f -ls 2>/dev/null | while read -r line; do
        echo "$line"
    done

    echo
    echo "=== SSM / AWS Systems Manager agent ==="
    pgrep -la amazon-ssm-agent 2>/dev/null || true
    systemctl is-active amazon-ssm-agent 2>/dev/null || true

    echo
    echo "=== CloudWatch / cloud monitoring agents (may enable RCE via run commands) ==="
    pgrep -la "cloudwatch\|stackdriver\|datadog\|newrelic\|dynatrace" 2>/dev/null || true

} > "$OUTPUT_DIR/cloud_persistence.txt" 2>/dev/null || true

# SECTION 7 — OBJECT STORAGE MISCONFIGURATION PROBE

echo "[*] Probing object storage accessibility..."

{
    echo "=== Public cloud storage bucket/blob indicators ==="

    # Look for S3 bucket names in configs/code
    echo "--- S3 bucket references found on disk ---"
    grep -rE 's3://[a-z0-9][a-z0-9\-]{2,62}|S3_BUCKET|AWS_BUCKET' \
        /etc /home /opt /var/www 2>/dev/null | head -20 | \
        grep -v "Binary\|\.pyc\|\.so" || echo "(none found)"

    echo
    echo "--- GCS bucket references ---"
    grep -rE 'gs://[a-z0-9][a-z0-9\-_]{2,62}|GCS_BUCKET|GCP_BUCKET' \
        /etc /home /opt /var/www 2>/dev/null | head -20 | \
        grep -v "Binary\|\.pyc\|\.so" || echo "(none found)"

    echo
    echo "--- Azure Storage references ---"
    grep -rE '[a-z0-9]{3,24}\.blob\.core\.windows\.net|AZURE_STORAGE_ACCOUNT' \
        /etc /home /opt /var/www 2>/dev/null | head -20 | \
        grep -v "Binary\|\.pyc\|\.so" || echo "(none found)"

    echo
    echo "=== Current AWS S3 accessible buckets (if AWS CLI configured) ==="
    if command -v aws >/dev/null 2>&1; then
        timeout 10 aws s3 ls 2>/dev/null | head -20 || \
            echo "(AWS CLI not authenticated or no buckets)"
    else
        echo "(AWS CLI not installed)"
    fi

} > "$OUTPUT_DIR/object_storage_audit.txt" 2>/dev/null || true

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

    # IMDSv1
    grep -q "CRITICAL.*IMDSv1" "$OUTPUT_DIR/imds_audit.txt" 2>/dev/null && \
        echo "[CRITICAL] IMDSv1 accessible without authentication (IAM credentials at risk)"

    # Docker socket
    grep -q "CRITICAL.*docker.sock" "$OUTPUT_DIR/container_security.txt" 2>/dev/null && \
        echo "[CRITICAL] Docker socket exposed inside container (host escape possible)"

    # Privileged container
    grep -q "CRITICAL.*privileged container" "$OUTPUT_DIR/container_security.txt" 2>/dev/null && \
        echo "[CRITICAL] Container running with full capabilities (privileged mode)"

    # Host namespace sharing
    grep -q "SHARED with host" "$OUTPUT_DIR/container_security.txt" 2>/dev/null && \
        echo "[HIGH] Container shares one or more namespaces with the host"

    # Service account token exposure
    grep -q "Running inside Kubernetes" "$OUTPUT_DIR/kubernetes_security.txt" 2>/dev/null && \
        echo "[HIGH] Kubernetes service account token present — check RBAC permissions"

    # GCP token
    grep -q "GCP service account access token available" "$OUTPUT_DIR/imds_audit.txt" 2>/dev/null && \
        echo "[HIGH] GCP service account token accessible via metadata service"

    # Azure managed identity
    grep -q "Azure managed identity token available" "$OUTPUT_DIR/imds_audit.txt" 2>/dev/null && \
        echo "[HIGH] Azure managed identity token accessible"

    # GCP JSON keys
    grep -q "GCP service account key found" "$OUTPUT_DIR/cloud_credential_exposure.txt" 2>/dev/null && \
        echo "[HIGH] GCP service account JSON key file found on disk"

    echo
    echo "--- Platform: $CLOUD_PLATFORM ---"
    echo "--- Output files ---"
    ls -lh "$OUTPUT_DIR/"*.txt 2>/dev/null

} > "$OUTPUT_DIR/cloud_audit_summary.txt"

cat "$OUTPUT_DIR/cloud_audit_summary.txt"

# ARCHIVE

tar -czf cloud_audit_archive.tar.gz "$OUTPUT_DIR" 2>/dev/null || true
echo
echo "[+] Cloud audit complete. Results in: $OUTPUT_DIR/"
echo "[+] Archive: cloud_audit_archive.tar.gz"