#!/usr/bin/env bash
# ============================================================
# GuardNous — Deploy to Kubernetes via Helm
# CI-agnostic: works with any K8s cluster
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CHART_DIR="${ROOT_DIR}/helm/guardnous"

# Defaults
RELEASE_NAME="guardnous"
NAMESPACE="guardnous"
DRY_RUN=false
DEV=false
IMAGE_TAG=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy GuardNous to Kubernetes using Helm.

Options:
  -n, --namespace NS         Kubernetes namespace (default: guardnous)
  -r, --release NAME         Helm release name (default: guardnous)
  -f, --values FILE          Additional values file (can be repeated)
  -d, --dev                  Deploy with dev values (bundled DB/Redis, 1 replica, images tagged "dev")
  -t, --image-tag TAG        Image tag for the api, web, worker and beat images
      --dry-run              Helm dry-run only (template + validate, no deploy)
  -s, --set KEY=VALUE        Set individual Helm values (can be repeated)
  -h, --help                 Show this help

The chart has been reviewed but not yet tested on a cluster.

Examples:
  # Deploy for local dev (minikube/kind); build and load the images first:
  #   ./scripts/build-images.sh -t dev
  $(basename "$0") --dev

  # Deploy to production (edit the example addresses in the values file first)
  $(basename "$0") -f helm/guardnous/values-production.yaml \\
    --set secrets.existingSecret=my-secrets --image-tag v1.0.0

  # Deploy the values written by ./scripts/setup-k8s.sh
  $(basename "$0") -f helm/guardnous/values-generated.yaml

  # Dry-run to preview rendered manifests
  $(basename "$0") --dev --dry-run

  # Deploy with custom namespace
  $(basename "$0") -n my-namespace -f my-values.yaml
EOF
  exit "${1:-0}"
}

need_value() {
  if [[ $# -lt 2 || -z "$2" ]]; then
    echo "Option $1 needs a value." >&2
    exit 1
  fi
}

VALUES_FILES=()
SET_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)  need_value "$@"; NAMESPACE="$2"; shift 2 ;;
    -r|--release)    need_value "$@"; RELEASE_NAME="$2"; shift 2 ;;
    -f|--values)     need_value "$@"; VALUES_FILES+=("$2"); shift 2 ;;
    -d|--dev)        DEV=true; shift ;;
    -t|--image-tag)  need_value "$@"; IMAGE_TAG="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=true; shift ;;
    -s|--set)        need_value "$@"; SET_ARGS+=("--set" "$2"); shift 2 ;;
    -h|--help)       usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

for vf in "${VALUES_FILES[@]+"${VALUES_FILES[@]}"}"; do
  if [[ ! -f "$vf" ]]; then
    echo "❌ Values file not found: $vf" >&2
    exit 1
  fi
done

# Check prerequisites
if ! command -v helm &>/dev/null; then
  echo "❌ helm not found. Install: https://helm.sh/docs/intro/install/"
  exit 1
fi

if ! command -v kubectl &>/dev/null; then
  echo "❌ kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/"
  exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🛡️  GuardNous — Kubernetes Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Release:   ${RELEASE_NAME}"
echo "Namespace: ${NAMESPACE}"
echo "Dev mode:  ${DEV}"
echo "Dry-run:   ${DRY_RUN}"
echo ""

# Values arguments, shared by the validation render and the deployment
VALUE_ARGS=()

# Add dev values if requested
if [[ "$DEV" == "true" ]]; then
  VALUE_ARGS+=(-f "${CHART_DIR}/values-dev.yaml")
fi

# Add user-specified values files
for vf in "${VALUES_FILES[@]+"${VALUES_FILES[@]}"}"; do
  VALUE_ARGS+=(-f "$vf")
done

# One tag for all four images
if [[ -n "$IMAGE_TAG" ]]; then
  VALUE_ARGS+=(--set-string "api.image.tag=${IMAGE_TAG}" --set-string "web.image.tag=${IMAGE_TAG}"
    --set-string "worker.image.tag=${IMAGE_TAG}" --set-string "beat.image.tag=${IMAGE_TAG}")
fi

# Add --set args (last, so they win)
for sa in "${SET_ARGS[@]+"${SET_ARGS[@]}"}"; do
  VALUE_ARGS+=("$sa")
done

# ── Pre-deploy validation ────────────────────────────────────
# The chart itself refuses to render when the database, Redis or the two keys
# are not configured (templates/_helpers.tpl, "guardnous.validate"), so a
# render with exactly the values of this deployment is the validation.
echo "🔍 Validating configuration..."
echo ""

if ! RENDER_ERROR=$(helm template "${RELEASE_NAME}" "${CHART_DIR}" \
  --namespace "${NAMESPACE}" \
  ${VALUE_ARGS[@]+"${VALUE_ARGS[@]}"} 2>&1 >/dev/null); then
  echo "❌ Deployment blocked — the chart could not be rendered with these values:"
  echo ""
  echo "$RENDER_ERROR" | sed 's/^/   /'
  echo ""
  echo "💡 Run ./scripts/setup-k8s.sh to generate a values file, or edit yours and retry."
  exit 1
fi

echo "✅ Configuration validated."
echo ""

# Build helm command
HELM_CMD=(helm upgrade --install "${RELEASE_NAME}" "${CHART_DIR}"
  --namespace "${NAMESPACE}" --create-namespace
  ${VALUE_ARGS[@]+"${VALUE_ARGS[@]}"})

# Add dry-run flag
if [[ "$DRY_RUN" == "true" ]]; then
  HELM_CMD+=(--dry-run --debug)
fi

# Values given with --set may contain secrets, so the command is not echoed.
"${HELM_CMD[@]}"

if [[ "$DRY_RUN" == "false" ]]; then
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "✅ Deployment complete!"
  echo ""
  echo "Check status:"
  echo "  kubectl get pods -n ${NAMESPACE}"
  echo "  kubectl get svc -n ${NAMESPACE}"
  echo ""
  echo "Without Ingress, forward the services (service names: kubectl get svc -n ${NAMESPACE}):"
  echo "  kubectl port-forward svc/<release>-web 7003:3000 -n ${NAMESPACE}"
  echo "  kubectl port-forward svc/<release>-api 7002:8000 -n ${NAMESPACE}"
  echo "then open http://localhost:7003. First login: see the notes printed by Helm above."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
