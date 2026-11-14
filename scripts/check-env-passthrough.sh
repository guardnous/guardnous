#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# GuardNous — check that every backend setting reaches the containers
#
# Reads backend/app/core/config.py and docker-compose.yml (nothing is started
# or changed; .env is not read) and reports, for the api, celery-worker and
# celery-beat services:
#   - settings that are neither listed under `environment:` nor covered by an
#     `env_file` entry for .env                                  -> failure
#   - container addresses (database, Redis, Celery) that are not pinned under
#     `environment:` and could therefore be overridden by .env   -> failure
#   - settings missing from .env.example                          -> note only
#
# Usage:  ./scripts/check-env-passthrough.sh
# Exit:   0 = every setting is passed through, 1 = something is missing
# ─────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$REPO_ROOT/backend/app/core/config.py"
COMPOSE="$REPO_ROOT/docker-compose.yml"
EXAMPLE="$REPO_ROOT/.env.example"

SERVICES="api celery-worker celery-beat"
# Inside the containers these must point at the compose services, not at
# whatever .env says, so they have to be explicit `environment:` entries.
PINNED="DATABASE_URL DATABASE_URL_SYNC REDIS_URL CELERY_BROKER_URL CELERY_RESULT_BACKEND"

for f in "$CONFIG" "$COMPOSE"; do
    if [[ ! -f "$f" ]]; then
        echo "✖ Not found: $f" >&2
        exit 1
    fi
done

# Setting names: class attributes of Settings, e.g. "    SMTP_HOST: str = ..."
SETTINGS=$(awk '
    /^class Settings\(/ { in_class = 1; next }
    in_class && /^[^[:space:]#]/ { in_class = 0 }
    in_class && /^    [A-Z][A-Z0-9_]*[[:space:]]*:/ {
        name = $1; sub(/:.*/, "", name); print name
    }' "$CONFIG" | sort -u)

if [[ -z "$SETTINGS" ]]; then
    echo "✖ No settings found in $CONFIG" >&2
    exit 1
fi

# Keys of a top-level YAML block that carries the given anchor (&name).
anchor_keys() {
    awk -v anchor="&$1" '
        /^[^[:space:]#]/ { in_block = (index($0, anchor) > 0); next }
        in_block && /^  [A-Za-z_][A-Za-z0-9_]*:/ {
            key = $1; sub(/:.*/, "", key); print key
        }' "$COMPOSE"
}

# Whether an anchored top-level block names .env (used for env_file aliases).
anchor_has_dotenv() {
    awk -v anchor="&$1" '
        /^[^[:space:]#]/ { in_block = (index($0, anchor) > 0); next }
        in_block && /(^|[[:space:]\/"\047])\.env["\047]?[[:space:]]*$/ { found = 1 }
        END { exit found ? 0 : 1 }' "$COMPOSE"
}

# Prints "ENVFILE" when the service has an env_file entry for .env, and one
# "KEY name" line per explicit environment entry ("MERGE alias" for <<: *alias).
service_facts() {
    awk -v svc="$1" '
        /^services:/ { in_services = 1; next }
        in_services && /^[^[:space:]#]/ { in_services = 0 }
        !in_services { next }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            name = $1; sub(/:$/, "", name); in_svc = (name == svc); section = ""; next
        }
        !in_svc { next }
        /^    [A-Za-z_]+:/ {
            section = $1; sub(/:.*/, "", section)
            if (section == "env_file") {
                rest = $0; sub(/^    env_file:[[:space:]]*/, "", rest)
                if (rest ~ /^\*/) { sub(/^\*/, "", rest); print "ENVALIAS " rest }
                else if (rest ~ /\.env/) print "ENVFILE"
            }
            next
        }
        section == "env_file" && /\.env["\047]?[[:space:]]*$/ { print "ENVFILE" }
        section == "environment" && /^      <<:[[:space:]]*\*/ {
            alias = $2; sub(/^\*/, "", alias); print "MERGE " alias; next
        }
        section == "environment" && /^      [A-Za-z_][A-Za-z0-9_]*:/ {
            key = $1; sub(/:.*/, "", key); print "KEY " key
        }' "$COMPOSE"
}

contains() {  # contains "<newline-separated list>" "<item>"
    printf '%s\n' "$1" | grep -qx -- "$2"
}

TOTAL=$(printf '%s\n' "$SETTINGS" | grep -c .)
echo "Settings defined in backend/app/core/config.py: $TOTAL"
echo ""

FAILED=0
for svc in $SERVICES; do
    facts=$(service_facts "$svc")
    if [[ -z "$facts" ]]; then
        echo "✖ $svc: service not found in docker-compose.yml"
        FAILED=1
        continue
    fi

    has_env_file=false
    if printf '%s\n' "$facts" | grep -qx "ENVFILE"; then
        has_env_file=true
    fi
    while read -r kind alias; do
        if [[ "$kind" == "ENVALIAS" ]] && anchor_has_dotenv "$alias"; then
            has_env_file=true
        fi
    done <<< "$facts"

    explicit=$(printf '%s\n' "$facts" | awk '$1 == "KEY" { print $2 }')
    while read -r kind alias; do
        if [[ "$kind" == "MERGE" ]]; then
            explicit=$(printf '%s\n%s\n' "$explicit" "$(anchor_keys "$alias")")
        fi
    done <<< "$facts"
    explicit=$(printf '%s\n' "$explicit" | grep . | sort -u || true)

    n_explicit=0
    missing=""
    while read -r name; do
        if contains "$explicit" "$name"; then
            n_explicit=$((n_explicit + 1))
        elif ! $has_env_file; then
            missing="$missing $name"
        fi
    done <<< "$SETTINGS"

    unpinned=""
    for name in $PINNED; do
        contains "$explicit" "$name" || unpinned="$unpinned $name"
    done

    if $has_env_file; then
        echo "✔ $svc: env_file .env present; $n_explicit settings set explicitly, $((TOTAL - n_explicit)) taken from .env"
    else
        echo "– $svc: no env_file for .env; $n_explicit settings set explicitly"
    fi
    if [[ -n "$missing" ]]; then
        echo "  ✖ never reach the container:"
        for name in $missing; do echo "      $name"; done
        FAILED=1
    fi
    if [[ -n "$unpinned" ]]; then
        echo "  ✖ not pinned under environment: (a localhost value in .env would be used):$unpinned"
        FAILED=1
    fi
done

if [[ -f "$EXAMPLE" ]]; then
    documented=$(grep -E '^#?[[:space:]]*[A-Z][A-Z0-9_]*=' "$EXAMPLE" | sed -e 's/^#[[:space:]]*//' -e 's/=.*//' | sort -u)
    undocumented=""
    while read -r name; do
        contains "$documented" "$name" || undocumented="$undocumented $name"
    done <<< "$SETTINGS"
    echo ""
    if [[ -n "$undocumented" ]]; then
        echo "Note: settings not listed in .env.example (they still work when added to .env):"
        for name in $undocumented; do echo "    $name"; done
    else
        echo "Every setting is listed in .env.example."
    fi
fi

echo ""
if [[ $FAILED -eq 0 ]]; then
    echo "✔ Every setting in config.py reaches the api, celery-worker and celery-beat containers."
    exit 0
fi
echo "✖ Some settings do not reach the containers (see above)."
exit 1
