#!/usr/bin/env bash
# Tear the smoke stand down (the counterpart of scripts/smoke-up.sh).
# The stand is disposable, so its volumes (the SQLite DB and the meow config
# exchange) can be deleted -- but only when the operator asks for it with
# --purge-volumes. The project name comes from the environment, and a
# mistyped one must not take a volume with it.
# Images are never removed: their tags are shared with the main stack.
#
# Usage:
#   scripts/smoke-down.sh [--purge-volumes]
#
# Environment:
#   SMOKE_PROJECT  compose project name (default: fumox-smoke). Only
#                  'fumox-smoke' and 'fumox-smoke-<suffix>' are accepted.
set -euo pipefail

cd "$(dirname "$0")/.."

SMOKE_PROJECT="${SMOKE_PROJECT:-fumox-smoke}"
# Allow-list: this script can delete volumes, so it may only ever touch a
# project of the smoke stand's own naming scheme.
case "$SMOKE_PROJECT" in
    fumox-smoke | fumox-smoke-*) ;;
    *)
        echo "error: refusing to tear down project '$SMOKE_PROJECT':" >&2
        echo "       the name must be 'fumox-smoke' or 'fumox-smoke-<suffix>'" >&2
        exit 64
        ;;
esac

case "${1:-}" in
    "") VOLUME_FLAGS=() ;;
    --purge-volumes) VOLUME_FLAGS=(-v) ;;
    *) echo "usage: scripts/smoke-down.sh [--purge-volumes]" >&2; exit 64 ;;
esac

# `timeout` is not on macOS (there it is `gtimeout`, and coreutils may not
# be installed at all), so the deadline is enforced with a background job.
run_with_timeout() { # <seconds> <command...>
    local secs="$1" pid waited
    shift
    "$@" &
    pid=$!
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$secs" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        waited=$((waited + 1))
    done
    wait "$pid"
}

# --- container engine --------------------------------------------------------
# `compose version` only proves the plugin is installed; the daemon behind
# it may be down. `info` is the check that actually matters, and it is what
# decides which engine this run talks to. The candidates are tried in turn,
# so a stopped docker does not hide a working podman.
COMPOSE=()
ENGINES=()
if command -v docker >/dev/null 2>&1; then ENGINES+=(docker); fi
if command -v podman >/dev/null 2>&1; then ENGINES+=(podman); fi
if [ "${#ENGINES[@]}" -eq 0 ]; then
    echo "error: neither 'docker' nor 'podman' found" >&2
    exit 1
fi

echo ">> tearing down the smoke stand: project=$SMOKE_PROJECT"

torn_down=false
for engine in "${ENGINES[@]}"; do
    if ! run_with_timeout 20 "$engine" info >/dev/null 2>&1; then
        echo ">> $engine: the daemon is not reachable, trying the next engine" >&2
        continue
    fi

    case "$engine" in
        docker)
            if ! docker compose version >/dev/null 2>&1; then
                echo ">> docker: no compose plugin, trying the next engine" >&2
                continue
            fi
            COMPOSE=(docker compose)
            ;;
        podman)
            if podman compose version >/dev/null 2>&1; then
                COMPOSE=(podman compose)
            elif command -v podman-compose >/dev/null 2>&1; then
                COMPOSE=(podman-compose)
            else
                echo ">> podman: no compose front-end, trying the next engine" >&2
                continue
            fi
            ;;
    esac

    # An empty "${arr[@]}" is fatal under `set -u` on the stock macOS bash 3.2,
    # which is what the default (no volume deletion) puts VOLUME_FLAGS in; the
    # + guard expands to nothing there. COMPOSE is never empty here, but is
    # guarded the same way.
    if ${COMPOSE[@]+"${COMPOSE[@]}"} -p "$SMOKE_PROJECT" down --remove-orphans \
        ${VOLUME_FLAGS[@]+"${VOLUME_FLAGS[@]}"}; then
        torn_down=true
        break
    fi
    echo ">> $engine: the teardown failed, trying the next engine" >&2
done

if [ "$torn_down" != "true" ]; then
    echo "error: no engine could tear down project '$SMOKE_PROJECT'" >&2
    exit 1
fi

echo ">> done (images kept: ghcr.io/viktor45/fumox:latest, ghcr.io/viktor45/fumox-meow:latest)"
