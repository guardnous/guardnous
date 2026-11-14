#!/usr/bin/env bash
# ============================================================
# GuardNous — Interactive Kubernetes Setup Wizard
# Generates .env.k8s and Helm values from user input.
# Works on macOS, Linux, and Git Bash (Windows).
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.k8s"
VALUES_FILE="${ROOT_DIR}/helm/guardnous/values-generated.yaml"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}🛡️  GuardNous — Kubernetes Setup Wizard${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo -e "This wizard generates configuration files for deploying"
  echo -e "GuardNous to Kubernetes via Helm."
  echo ""
  echo -e "Generated files:"
  echo -e "  ${GREEN}${ENV_FILE}${NC}      — environment variables"
  echo -e "  ${GREEN}${VALUES_FILE}${NC}   — Helm values override"
  echo ""
}

# These helpers are called as VAR=$(ask ...): only the answer may go to
# stdout, so prompts are written to stderr.
ask() {
  local prompt="$1" default="${2:-}" answer=""
  if [[ -n "$default" ]]; then
    echo -en "${BOLD}${prompt}${NC} [${default}]: " >&2
  else
    echo -en "${BOLD}${prompt}${NC}: " >&2
  fi
  read -r answer || answer=""
  printf '%s\n' "${answer:-$default}"
}

ask_yn() {
  local prompt="$1" default="${2:-y}" answer=""
  local hint="Y/n"
  [[ "$default" == "n" ]] && hint="y/N"
  echo -en "${BOLD}${prompt}${NC} (${hint}): " >&2
  read -r answer || answer=""
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy] ]]
}

ask_secret() {
  local prompt="$1" default="${2:-}" answer=""
  if [[ -n "$default" ]]; then
    echo -en "${BOLD}${prompt}${NC} [****]: " >&2
  else
    echo -en "${BOLD}${prompt}${NC}: " >&2
  fi
  read -rs answer || answer=""
  echo "" >&2
  printf '%s\n' "${answer:-$default}"
}

# Percent-encode a value for the user:password part of a URL.
urlencode() {
  local s="$1" out="" c i
  local LC_ALL=C
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) out+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  printf '%s' "$out"
}

# Escape a value for a double-quoted YAML string.
yaml_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

section() {
  echo ""
  echo -e "${BLUE}── $1 ──────────────────────────────────────────${NC}"
  echo ""
}

# Track missing items for final reminder
MISSING=()

add_missing() {
  MISSING+=("$1")
}

# ── Generate crypto keys ────────────────────────────────────
generate_secret_key() {
  if command -v openssl &>/dev/null; then
    openssl rand -hex 32
  elif command -v python3 &>/dev/null; then
    python3 -c "import secrets; print(secrets.token_hex(32))"
  fi
}

# A Fernet key is 32 random bytes, URL-safe base64: 44 characters ending in "=".
generate_fernet_key() {
  local key=""
  key=$(openssl rand -base64 32 2>/dev/null | tr -d '\r\n' | tr '+/' '-_' || true)
  if [[ ${#key} -ne 44 ]]; then
    key=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" 2>/dev/null || true)
  fi
  printf '%s\n' "$key"
}

# 24 characters with upper, lower, digit and two symbols; see scripts/setup.sh.
generate_password() {
  local raw="" attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    raw=$(openssl rand -base64 48 2>/dev/null | LC_ALL=C tr -dc 'A-Za-z0-9' || true)
    if [[ ${#raw} -lt 22 ]]; then
      raw=$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(22)))" 2>/dev/null || true)
    fi
    raw="${raw:0:22}"
    if [[ ${#raw} -eq 22 && "$raw" =~ [A-Z] && "$raw" =~ [a-z] && "$raw" =~ [0-9] ]]; then
      printf '%s@%s^%s\n' "${raw:0:7}" "${raw:7:8}" "${raw:15:7}"
      return 0
    fi
  done
  return 1
}

if ! command -v openssl &>/dev/null && ! command -v python3 &>/dev/null; then
  echo -e "${RED}Neither openssl nor python3 is installed; one of them is needed to generate keys.${NC}" >&2
  exit 1
fi

# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════
banner

# ── 1. Deployment Mode ──────────────────────────────────────
section "1/7 — Deployment Mode"
echo -e "  ${CYAN}1)${NC} Production  — external managed DB & Redis (recommended)"
echo -e "  ${CYAN}2)${NC} Development — bundled PostgreSQL & Redis in-cluster"
echo ""
DEPLOY_MODE=$(ask "Select mode" "1")

if [[ "$DEPLOY_MODE" == "2" ]]; then
  MODE="dev"
  echo -e "\n${GREEN}✓${NC} Development mode — bundled PostgreSQL & Redis will be deployed."
else
  MODE="prod"
  echo -e "\n${GREEN}✓${NC} Production mode — you'll provide external DB & Redis endpoints."
fi

# ── 2. PostgreSQL ───────────────────────────────────────────
section "2/7 — PostgreSQL Database"

DB_EXTERNAL_URL=""
DB_BUNDLED="false"
DB_PASSWORD="guardnous"

if [[ "$MODE" == "prod" ]]; then
  if ask_yn "Do you have a PostgreSQL instance already deployed?"; then
    DB_HOST=$(ask "  PostgreSQL host" "")
    DB_PORT=$(ask "  PostgreSQL port" "5432")
    DB_NAME=$(ask "  Database name" "guardnous")
    DB_USER=$(ask "  Username" "guardnous")
    DB_PASS=$(ask_secret "  Password" "")
    DB_SSL=$(ask "  SSL mode (disable/require/verify-full)" "require")

    if [[ -z "$DB_HOST" ]]; then
      add_missing "DATABASE: Host is empty — set database.externalUrl in values-generated.yaml"
      DB_EXTERNAL_URL=""
    elif [[ -z "$DB_PASS" ]]; then
      add_missing "DATABASE: Password is empty — set database.externalUrl in values-generated.yaml"
      DB_EXTERNAL_URL="postgresql://$(urlencode "$DB_USER"):CHANGE_ME@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL}"
    else
      DB_EXTERNAL_URL="postgresql://$(urlencode "$DB_USER"):$(urlencode "$DB_PASS")@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL}"
    fi
  else
    echo ""
    echo -e "${YELLOW}⚠ No PostgreSQL provided.${NC}"
    echo -e "  You MUST set ${BOLD}database.externalUrl${NC} before deploying."
    add_missing "DATABASE: No external URL provided — set database.externalUrl in values-generated.yaml"
  fi
else
  DB_BUNDLED="true"
  DB_PASSWORD=$(ask "Bundled PostgreSQL password (letters and digits only)" "guardnous")
  if [[ ! "$DB_PASSWORD" =~ ^[A-Za-z0-9]+$ ]]; then
    echo -e "${YELLOW}⚠ Only letters and digits are allowed (the password is placed in a URL); using 'guardnous'.${NC}"
    DB_PASSWORD="guardnous"
  fi
  echo -e "${GREEN}✓${NC} Bundled PostgreSQL will be deployed in-cluster."
fi

# ── 3. Redis ────────────────────────────────────────────────
section "3/7 — Redis Cache"

REDIS_EXTERNAL_URL=""
REDIS_BUNDLED="false"

if [[ "$MODE" == "prod" ]]; then
  if ask_yn "Do you have a Redis instance already deployed?"; then
    REDIS_HOST=$(ask "  Redis host" "")
    REDIS_PORT=$(ask "  Redis port" "6379")
    REDIS_PASS=$(ask_secret "  Password (blank if none)" "")
    REDIS_SCHEME="redis"
    REDIS_QUERY=""
    if ask_yn "  Does it require TLS?" "n"; then
      REDIS_SCHEME="rediss"
      REDIS_QUERY="?ssl_cert_reqs=required"
    fi

    # No database number: the chart appends /0 (cache), /1 and /2 (Celery).
    if [[ -z "$REDIS_HOST" ]]; then
      add_missing "REDIS: Host is empty — set redis.externalUrl in values-generated.yaml"
      REDIS_EXTERNAL_URL=""
    elif [[ -n "$REDIS_PASS" ]]; then
      REDIS_EXTERNAL_URL="${REDIS_SCHEME}://:$(urlencode "$REDIS_PASS")@${REDIS_HOST}:${REDIS_PORT}${REDIS_QUERY}"
    else
      REDIS_EXTERNAL_URL="${REDIS_SCHEME}://${REDIS_HOST}:${REDIS_PORT}${REDIS_QUERY}"
    fi
  else
    echo ""
    echo -e "${YELLOW}⚠ No Redis provided.${NC}"
    echo -e "  You MUST set ${BOLD}redis.externalUrl${NC} before deploying."
    add_missing "REDIS: No external URL provided — set redis.externalUrl in values-generated.yaml"
  fi
else
  REDIS_BUNDLED="true"
  echo -e "${GREEN}✓${NC} Bundled Redis will be deployed in-cluster."
fi

# ── 4. Container Registry ──────────────────────────────────
section "4/7 — Container Images"

IMAGE_REGISTRY=$(ask "Container registry (e.g. ghcr.io/your-org, 123456.dkr.ecr.us-east-1.amazonaws.com)" "")
IMAGE_TAG=$(ask "Image tag" "latest")

IMAGE_REGISTRY="${IMAGE_REGISTRY%/}"

if [[ -z "$IMAGE_REGISTRY" && "$MODE" == "prod" ]]; then
  add_missing "IMAGES: No registry set — set global.imageRegistry in values-generated.yaml"
fi

# ── 5. Ingress ──────────────────────────────────────────────
section "5/7 — Ingress & Domain"

INGRESS_ENABLED="true"
INGRESS_HOST=""
INGRESS_CLASS="nginx"
TLS_ENABLED="false"

if ask_yn "Enable Ingress (external access)?"; then
  INGRESS_HOST=$(ask "  Domain name" "guardnous.example.com")
  INGRESS_CLASS=$(ask "  Ingress class (nginx/traefik/alb/gce)" "nginx")
  if ask_yn "  Enable TLS (HTTPS)?"; then
    TLS_ENABLED="true"
  fi
else
  INGRESS_ENABLED="false"
fi

# ── 6. Security Keys ───────────────────────────────────────
section "6/7 — Security Keys"

echo -e "These keys sign JWTs and encrypt VCS tokens."
echo -e "We can auto-generate them for you.\n"

if ask_yn "Auto-generate secret keys?"; then
  SECRET_KEY=$(generate_secret_key)
  ENCRYPTION_KEY=$(generate_fernet_key)
  echo -e "${GREEN}✓${NC} Keys generated."
else
  SECRET_KEY=$(ask_secret "JWT secret key (hex, 64 chars)")
  ENCRYPTION_KEY=$(ask_secret "Fernet encryption key (44 characters, URL-safe base64)")
fi
if [[ ${#SECRET_KEY} -lt 32 ]]; then
  SECRET_KEY=""
  add_missing "SECURITY: secretKey is missing or shorter than 32 characters — set secrets.secretKey in values-generated.yaml (openssl rand -hex 32)"
fi
if [[ ${#ENCRYPTION_KEY} -ne 44 || ! "$ENCRYPTION_KEY" =~ ^[A-Za-z0-9_-]{43}=$ ]]; then
  ENCRYPTION_KEY=""
  add_missing "SECURITY: encryptionKey is not a valid 44-character key — set secrets.encryptionKey in values-generated.yaml (openssl rand -base64 32 | tr '+/' '-_')"
fi

echo ""
echo -e "The administrator account admin@guardnous.com is created on first start."
ADMIN_PASSWORD=""
ADMIN_PASSWORD_GENERATED=false
if ask_yn "Generate its initial password?"; then
  if ADMIN_PASSWORD=$(generate_password); then
    ADMIN_PASSWORD_GENERATED=true
    echo -e "${GREEN}✓${NC} Password generated (shown once in the summary)."
  else
    ADMIN_PASSWORD=""
    echo -e "${YELLOW}⚠ Could not generate a password; the application will generate one and print it in its log.${NC}"
  fi
else
  ADMIN_PASSWORD=$(ask_secret "Initial administrator password (8+ chars: upper, lower, digit, symbol; blank = generated by the application)")
fi

# ── 7. Optional: VCS / AI ──────────────────────────────────
section "7/7 — Optional Integrations"

GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
NVD_API_KEY=""
LLM_PROVIDER="mock"
LLM_API_KEY=""

if ask_yn "Configure GitHub OAuth (for repo scanning)?" "n"; then
  GITHUB_CLIENT_ID=$(ask "  GitHub Client ID")
  GITHUB_CLIENT_SECRET=$(ask_secret "  GitHub Client Secret")
fi

if ask_yn "Set NVD API key (faster CVE sync)?" "n"; then
  NVD_API_KEY=$(ask_secret "  NVD API Key")
fi

if ask_yn "Configure AI Copilot (OpenAI/Azure/Anthropic)?" "n"; then
  echo -e "  ${CYAN}1)${NC} openai   ${CYAN}2)${NC} azure   ${CYAN}3)${NC} anthropic   ${CYAN}4)${NC} ollama"
  LLM_CHOICE=$(ask "  Provider" "1")
  case "$LLM_CHOICE" in
    1) LLM_PROVIDER="openai" ;;
    2) LLM_PROVIDER="azure" ;;
    3) LLM_PROVIDER="anthropic" ;;
    4) LLM_PROVIDER="ollama" ;;
    *) LLM_PROVIDER="$LLM_CHOICE" ;;
  esac
  LLM_API_KEY=$(ask_secret "  API Key")
fi

# ════════════════════════════════════════════════════════════
# GENERATE .env.k8s
# ════════════════════════════════════════════════════════════
section "Generating Files"

cat > "$ENV_FILE" <<ENVEOF
# ─────────────────────────────────────────────────────────────
# GuardNous Kubernetes Environment
# Generated by setup-k8s.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Source this into your Helm deploy or CI pipeline.
# ─────────────────────────────────────────────────────────────

# ── Deploy Mode ──────────────────────────────────────────────
GUARDNOUS_MODE=${MODE}

# ── Database ─────────────────────────────────────────────────
DATABASE_EXTERNAL_URL='${DB_EXTERNAL_URL}'
DATABASE_BUNDLED=${DB_BUNDLED}

# ── Redis ────────────────────────────────────────────────────
REDIS_EXTERNAL_URL='${REDIS_EXTERNAL_URL}'
REDIS_BUNDLED=${REDIS_BUNDLED}

# ── Images ───────────────────────────────────────────────────
IMAGE_REGISTRY=${IMAGE_REGISTRY}
IMAGE_TAG=${IMAGE_TAG}

# ── Ingress ──────────────────────────────────────────────────
INGRESS_ENABLED=${INGRESS_ENABLED}
INGRESS_HOST=${INGRESS_HOST}
INGRESS_CLASS=${INGRESS_CLASS}
TLS_ENABLED=${TLS_ENABLED}

# ── Secrets ──────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# ── Optional ─────────────────────────────────────────────────
GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
NVD_API_KEY=${NVD_API_KEY}
LLM_PROVIDER=${LLM_PROVIDER}
LLM_API_KEY=${LLM_API_KEY}
ENVEOF

chmod 600 "$ENV_FILE"
echo -e "${GREEN}✓${NC} Created ${ENV_FILE}"

# ════════════════════════════════════════════════════════════
# GENERATE values-generated.yaml
# ════════════════════════════════════════════════════════════

# Public address: used for the web image build and shown in the summary.
if [[ "$INGRESS_ENABLED" == "true" ]]; then
  if [[ "$TLS_ENABLED" == "true" ]]; then
    PUBLIC_URL="https://${INGRESS_HOST}"
  else
    PUBLIC_URL="http://${INGRESS_HOST}"
  fi
  PROXY_COUNT=1
else
  PUBLIC_URL="http://localhost:7002"
  PROXY_COUNT=0
fi

# The file holds secrets: create it readable by the owner only.
: > "$VALUES_FILE"
chmod 600 "$VALUES_FILE"

cat > "$VALUES_FILE" <<VALEOF
# ============================================================
# GuardNous — Generated Helm Values
# Created by setup-k8s.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Usage: helm install guardnous ./helm/guardnous -f helm/guardnous/values-generated.yaml
# ============================================================

global:
  imageRegistry: "${IMAGE_REGISTRY}"

# ── Database ─────────────────────────────────────────────────
# Plain postgresql:// form; the chart derives the driver-specific URLs.
database:
  externalUrl: "$(yaml_escape "$DB_EXTERNAL_URL")"
  bundled:
    enabled: ${DB_BUNDLED}

# ── Redis ────────────────────────────────────────────────────
# No database number; the chart appends /0, /1 and /2.
redis:
  externalUrl: "$(yaml_escape "$REDIS_EXTERNAL_URL")"
  bundled:
    enabled: ${REDIS_BUNDLED}

# ── Images ───────────────────────────────────────────────────
api:
  image:
    tag: "${IMAGE_TAG}"
VALEOF

if [[ "$MODE" != "prod" ]]; then
  # Local cluster: images are loaded into the cluster, never pulled
  echo "    pullPolicy: Never" >> "$VALUES_FILE"
fi

if [[ "$MODE" == "prod" ]]; then
  cat >> "$VALUES_FILE" <<VALEOF
  replicaCount: 3
  hpa:
    enabled: true

web:
  image:
    tag: "${IMAGE_TAG}"
  replicaCount: 2
  hpa:
    enabled: true

worker:
  image:
    tag: "${IMAGE_TAG}"
  replicaCount: 3
  hpa:
    enabled: true

beat:
  image:
    tag: "${IMAGE_TAG}"
VALEOF
else
  cat >> "$VALUES_FILE" <<VALEOF
  replicaCount: 1

web:
  image:
    tag: "${IMAGE_TAG}"
    pullPolicy: Never
  replicaCount: 1

worker:
  image:
    tag: "${IMAGE_TAG}"
    pullPolicy: Never
  replicaCount: 1

beat:
  image:
    tag: "${IMAGE_TAG}"
    pullPolicy: Never
VALEOF
fi

cat >> "$VALUES_FILE" <<VALEOF

# ── Config ───────────────────────────────────────────────────
# frontendUrl, backendUrl and corsOrigins are derived from the Ingress host
# (or default to the port-forward addresses when Ingress is off).
config:
  environment: $( [[ "$MODE" == "prod" ]] && echo production || echo development )
  trustedProxyCount: ${PROXY_COUNT}
  llm:
    provider: "${LLM_PROVIDER}"

# ── Secrets ──────────────────────────────────────────────────
secrets:
  secretKey: "$(yaml_escape "$SECRET_KEY")"
  encryptionKey: "$(yaml_escape "$ENCRYPTION_KEY")"
VALEOF

# Add optional secrets only if provided
add_secret() {  # add_secret <values key> <value>
  if [[ -n "$2" ]]; then
    echo "  $1: \"$(yaml_escape "$2")\"" >> "$VALUES_FILE"
  fi
}
if [[ "$DB_BUNDLED" == "true" ]]; then
  add_secret databasePassword "$DB_PASSWORD"
fi
add_secret initialAdminPassword "$ADMIN_PASSWORD"
add_secret githubClientId "$GITHUB_CLIENT_ID"
add_secret githubClientSecret "$GITHUB_CLIENT_SECRET"
add_secret nvdApiKey "$NVD_API_KEY"
add_secret llmApiKey "$LLM_API_KEY"

# Ingress
cat >> "$VALUES_FILE" <<VALEOF

# ── Ingress ──────────────────────────────────────────────────
ingress:
  enabled: ${INGRESS_ENABLED}
  className: "${INGRESS_CLASS}"
  host: "${INGRESS_HOST:-guardnous.example.com}"
  tls:
    enabled: ${TLS_ENABLED}
VALEOF

echo -e "${GREEN}✓${NC} Created ${VALUES_FILE}"

# ════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}📋 Setup Summary${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Mode:       ${BOLD}${MODE}${NC}"
describe_backend() {  # describe_backend <bundled true|false> <external url>
  if [[ "$1" == "true" ]]; then
    echo "bundled"
  elif [[ -n "$2" ]]; then
    echo "external"
  else
    echo -e "${RED}NOT CONFIGURED${NC}"
  fi
}
echo -e "  Database:   $(describe_backend "$DB_BUNDLED" "$DB_EXTERNAL_URL")"
echo -e "  Redis:      $(describe_backend "$REDIS_BUNDLED" "$REDIS_EXTERNAL_URL")"
echo -e "  Registry:   ${IMAGE_REGISTRY:-not set}"
echo -e "  Image Tag:  ${IMAGE_TAG}"
echo -e "  Ingress:    ${INGRESS_ENABLED} (${INGRESS_HOST:-none})"
echo -e "  TLS:        ${TLS_ENABLED}"
echo ""
echo -e "  First login: admin@guardnous.com"
if $ADMIN_PASSWORD_GENERATED; then
  echo -e "  Password:    ${ADMIN_PASSWORD}"
  echo -e "  ${YELLOW}This password is shown only now (it is also in the generated values file as${NC}"
  echo -e "  ${YELLOW}secrets.initialAdminPassword). Change it after your first login.${NC}"
elif [[ -n "$ADMIN_PASSWORD" ]]; then
  echo -e "  Password:    the one you entered"
else
  echo -e "  Password:    generated by the application on first start and printed once in the"
  echo -e "               api pod log (container prepare-database)"
fi
echo ""
echo -e "  ${YELLOW}Both generated files contain secrets. They are excluded from git; keep them private.${NC}"
echo -e "  ${YELLOW}The Helm chart has been reviewed but not yet tested on a cluster.${NC}"
echo ""

# ── Missing items reminder ──────────────────────────────────
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}⚠️  Action Required — Missing Configuration${NC}"
  echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  for i in "${!MISSING[@]}"; do
    echo -e "  ${RED}$((i+1)).${NC} ${MISSING[$i]}"
  done
  echo ""
  echo -e "  Please edit ${BOLD}${VALUES_FILE}${NC}"
  echo -e "  and fill in the missing values before deploying."
  echo ""
fi

# ── Next steps ──────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}🚀 Next Steps${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}1.${NC} Build container images (the web image is built for ${PUBLIC_URL}):"
if [[ -n "$IMAGE_REGISTRY" ]]; then
  echo -e "     ${GREEN}./scripts/build-images.sh -r ${IMAGE_REGISTRY} -t ${IMAGE_TAG} --api-url ${PUBLIC_URL} -p${NC}"
elif [[ "$MODE" == "prod" ]]; then
  echo -e "     ${GREEN}./scripts/build-images.sh -r <your-registry> -t ${IMAGE_TAG} --api-url ${PUBLIC_URL} -p${NC}"
else
  echo -e "     ${GREEN}./scripts/build-images.sh -t ${IMAGE_TAG} --api-url ${PUBLIC_URL}${NC}"
  echo -e "     then load both images into the cluster, e.g."
  echo -e "     ${GREEN}minikube image load guardnous/api:${IMAGE_TAG} && minikube image load guardnous/web:${IMAGE_TAG}${NC}"
fi
echo ""
echo -e "  ${BOLD}2.${NC} Deploy to Kubernetes:"
echo -e "     ${GREEN}./scripts/deploy.sh -f helm/guardnous/values-generated.yaml${NC}"
echo ""
echo -e "  ${BOLD}3.${NC} Verify pods are running:"
echo -e "     ${GREEN}kubectl get pods -n guardnous${NC}"
echo ""

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo -e "  ${YELLOW}⚠ Deployment will fail until missing values above are filled in.${NC}"
  echo ""
fi
