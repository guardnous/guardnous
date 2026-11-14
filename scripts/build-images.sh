#!/usr/bin/env bash
# ============================================================
# GuardNous — Build Container Images
# CI-agnostic: works with Docker, Podman, or any OCI builder
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
REGISTRY=""
TAG="latest"
PUSH=false
BUILDER="docker"
# The address browsers use to reach the API. Next.js compiles it into the web
# image, so it cannot be changed when the container starts.
API_URL="http://localhost:7002"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build GuardNous container images.

Options:
  -r, --registry REGISTRY   Container registry prefix (e.g. ghcr.io/myorg, 123456.dkr.ecr.us-east-1.amazonaws.com)
  -t, --tag TAG              Image tag (default: latest)
  -u, --api-url URL          Public address of the API as seen from the browser, compiled
                             into the web image (default: http://localhost:7002).
                             Behind the chart's Ingress use https://<your-host>
  -p, --push                 Push images after building
  -b, --builder BUILDER      Container builder: docker or podman (default: docker)
  -h, --help                 Show this help

Image names (they match the Helm chart defaults):
  without --registry:  guardnous/api:TAG              guardnous/web:TAG
  with --registry:     REGISTRY/guardnous/api:TAG     REGISTRY/guardnous/web:TAG

Examples:
  # Build locally for dev (web UI reached with port-forward, API on localhost:7002)
  $(basename "$0") -t dev

  # Build and push for a cluster served at https://guardnous.example.com
  $(basename "$0") -r ghcr.io/myorg -t v1.0.0 -u https://guardnous.example.com -p

  # Build with Podman
  $(basename "$0") -b podman -t latest
EOF
  exit "${1:-0}"
}

need_value() {
  if [[ $# -lt 2 || -z "$2" ]]; then
    echo "Option $1 needs a value." >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--registry) need_value "$@"; REGISTRY="$2"; shift 2 ;;
    -t|--tag)      need_value "$@"; TAG="$2"; shift 2 ;;
    -u|--api-url)  need_value "$@"; API_URL="${2%/}"; shift 2 ;;
    -p|--push)     PUSH=true; shift ;;
    -b|--builder)  need_value "$@"; BUILDER="$2"; shift 2 ;;
    -h|--help)     usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

if ! command -v "$BUILDER" &>/dev/null; then
  echo "❌ ${BUILDER} not found." >&2
  exit 1
fi

# Resolve image names (the chart renders <global.imageRegistry>/<repository>:<tag>
# with repository guardnous/api and guardnous/web)
API_IMAGE="guardnous/api:${TAG}"
WEB_IMAGE="guardnous/web:${TAG}"

if [[ -n "$REGISTRY" ]]; then
  # Strip trailing slash
  REGISTRY="${REGISTRY%/}"
  API_IMAGE="${REGISTRY}/guardnous/api:${TAG}"
  WEB_IMAGE="${REGISTRY}/guardnous/web:${TAG}"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🛡️  GuardNous — Building Container Images"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Builder:  ${BUILDER}"
echo "API:      ${API_IMAGE}"
echo "Web:      ${WEB_IMAGE}"
echo "API URL:  ${API_URL}  (compiled into the web image)"
echo "Push:     ${PUSH}"
echo ""

# Build API image
echo "📦 Building API image..."
${BUILDER} build \
  -t "${API_IMAGE}" \
  -f "${ROOT_DIR}/backend/Dockerfile" \
  "${ROOT_DIR}/backend"

# Build Web image
echo "📦 Building Web image..."
${BUILDER} build \
  -t "${WEB_IMAGE}" \
  --build-arg NEXT_PUBLIC_API_URL="${API_URL}" \
  -f "${ROOT_DIR}/frontend/Dockerfile" \
  "${ROOT_DIR}/frontend"

echo ""
echo "✅ Images built successfully!"

# Push if requested
if [[ "$PUSH" == "true" ]]; then
  echo ""
  echo "🚀 Pushing images..."
  ${BUILDER} push "${API_IMAGE}"
  ${BUILDER} push "${WEB_IMAGE}"
  echo "✅ Images pushed!"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next steps:"
if [[ -n "$REGISTRY" ]]; then
  echo "  Deploy:  ./scripts/deploy.sh -f <your-values.yaml> \\"
  echo "             --set global.imageRegistry=${REGISTRY} --image-tag ${TAG}"
  echo "  Registry images:"
  echo "    ${API_IMAGE}"
  echo "    ${WEB_IMAGE}"
else
  echo "  Deploy (local cluster): ./scripts/deploy.sh --dev --image-tag ${TAG}"
  echo "  (minikube/kind do not see the host's images: load them first, e.g."
  echo "   'minikube image load ${API_IMAGE}' or 'kind load docker-image ${API_IMAGE}')"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
