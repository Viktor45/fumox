#!/usr/bin/env bash
# Tear the smoke stand down (the counterpart of scripts/smoke-up.sh).
# The stand is disposable, so its volumes (the SQLite DB and the meow config
# exchange) are deleted by default; pass --keep-data to preserve them.
# Images are never removed: the fumox:local tag is shared with the main stack.
#
# Usage:
#   scripts/smoke-down.sh [--keep-data]
set -euo pipefail

cd "$(dirname "$0")/.."

SMOKE_PROJECT="${SMOKE_PROJECT:-fumox-smoke}"

case "${1:-}" in
    "") VOLUME_FLAGS=(-v) ;;
    --keep-data) VOLUME_FLAGS=() ;;
    *) echo "usage: scripts/smoke-down.sh [--keep-data]" >&2; exit 64 ;;
esac

if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif podman compose version >/dev/null 2>&1; then
    COMPOSE=(podman compose)
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose)
else
    echo "error: neither 'docker compose', 'podman compose' nor 'podman-compose' found" >&2
    exit 1
fi

echo ">> tearing down the smoke stand: project=$SMOKE_PROJECT"
"${COMPOSE[@]}" -p "$SMOKE_PROJECT" down --remove-orphans "${VOLUME_FLAGS[@]}"
echo ">> done (images kept: fumox:local, fumox-meow:local)"
