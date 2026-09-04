#!/usr/bin/env bash
# Bring up the disposable smoke stand: the full docker-compose stack (server +
# probe + meow) under an isolated compose project, on shifted host ports, with
# its own generated admin token and fresh volumes. The main stack (ports
# 8080/8081, project "fumox") is never touched; both stands share the
# fumox:local image tag, so the smoke build doubles as the main-stack rebuild.
#
# Usage:
#   scripts/smoke-up.sh [--no-build]
#
# Environment:
#   SMOKE_PROJECT      compose project name          (default: fumox-smoke)
#   SMOKE_PUBLIC_PORT  host port for /sub, /src      (default: 18080)
#   SMOKE_ADMIN_PORT   host port for the admin panel (default: 18081)
#   FUMOX_ADMIN__TOKEN reuse this token instead of generating one
#
# Tear the stand down with scripts/smoke-down.sh.
set -euo pipefail

cd "$(dirname "$0")/.."

SMOKE_PROJECT="${SMOKE_PROJECT:-fumox-smoke}"
SMOKE_PUBLIC_PORT="${SMOKE_PUBLIC_PORT:-18080}"
SMOKE_BIND="${SMOKE_BIND:-127.0.0.1}"
SMOKE_ADMIN_PORT="${SMOKE_ADMIN_PORT:-18081}"

# --- compose command ----------------------------------------------------------
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

# --- pre-flight ----------------------------------------------------------------
port_busy() { lsof -ti ":$1" >/dev/null 2>&1; }
for port in "$SMOKE_PUBLIC_PORT" "$SMOKE_ADMIN_PORT"; do
    if port_busy "$port"; then
        echo "error: host port $port is already in use; free it or pick another via" >&2
        echo "       SMOKE_PUBLIC_PORT / SMOKE_ADMIN_PORT" >&2
        exit 1
    fi
done

if [ -z "${FUMOX_ADMIN__TOKEN:-}" ]; then
    if command -v openssl >/dev/null 2>&1; then
        FUMOX_ADMIN__TOKEN="$(openssl rand -hex 16)"
    else
        FUMOX_ADMIN__TOKEN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    GENERATED_TOKEN=1
fi
export FUMOX_ADMIN__TOKEN FUMOX_PUBLIC_PORT="$SMOKE_PUBLIC_PORT" FUMOX_ADMIN_BIND="$SMOKE_BIND" FUMOX_ADMIN_PORT="$SMOKE_ADMIN_PORT"

BUILD_FLAGS=(--build)
if [ "${1:-}" = "--no-build" ]; then
    BUILD_FLAGS=()
elif [ -n "${1:-}" ]; then
    echo "usage: scripts/smoke-up.sh [--no-build]" >&2
    exit 64
fi

echo ">> smoke stand: project=$SMOKE_PROJECT public=$SMOKE_BIND:$SMOKE_PUBLIC_PORT admin=$SMOKE_BIND:$SMOKE_ADMIN_PORT"
# `${arr[@]+...}` (not a bare `${arr[@]}`): under `set -u` an empty array is
# "unset" for bash 3.2 (macOS), which would abort the script.
"${COMPOSE[@]}" -p "$SMOKE_PROJECT" up -d ${BUILD_FLAGS[@]+"${BUILD_FLAGS[@]}"}

# --- wait for startup and run the checks ----------------------------------------
wait_for() { # wait_for <what> <url> <expected_code> <timeout_s>
    local what="$1" url="$2" expected="$3" deadline=$((SECONDS + $4)) code
    while [ "$SECONDS" -lt "$deadline" ]; do
        code="$(curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
        [ "$code" = "$expected" ] && return 0
        sleep 2
    done
    echo "error: $what did not answer $expected within the deadline (last: ${code:-none})" >&2
    return 1
}

# Container-level liveness, independent of the configured log level: the
# probe's own startup line is INFO and invisible when [log] levels are
# error/warn, so state + restart count are the reliable signal. docker and
# podman CLIs share the inspect template.
CONTAINER=("${COMPOSE[0]}")
container_ok() { # container_ok <service>
    local id state
    id="$("${COMPOSE[@]}" -p "$SMOKE_PROJECT" ps -q "$1" 2>/dev/null)" || return 1
    [ -n "$id" ] || return 1
    state="$("${CONTAINER[@]}" inspect -f '{{.State.Status}} {{.RestartCount}}' "$id" 2>/dev/null)" || return 1
    [ "$state" = "running 0" ]
}

echo ">> waiting for the public listener (/healthz)"
if ! wait_for "public /healthz" "http://$SMOKE_BIND:$SMOKE_PUBLIC_PORT/healthz" 200 120; then
    "${COMPOSE[@]}" -p "$SMOKE_PROJECT" logs --tail 20 server >&2 || true
    exit 1
fi

echo ">> checking the admin panel (login page)"
if ! wait_for "admin login page" "http://$SMOKE_BIND:$SMOKE_ADMIN_PORT/admin/login" 200 60; then
    "${COMPOSE[@]}" -p "$SMOKE_PROJECT" logs --tail 20 server >&2 || true
    exit 1
fi

echo ">> checking that a wrong alive-export token answers 404"
if ! wait_for "alive-export 404" "http://$SMOKE_BIND:$SMOKE_PUBLIC_PORT/export/alive/wrong-token" 404 30; then
    exit 1
fi

echo ">> waiting for all three containers to settle (running, no restarts)"
container_deadline=$((SECONDS + 60))
until container_ok server && container_ok probe && container_ok meow; do
    if [ "$SECONDS" -ge "$container_deadline" ]; then
        echo "error: containers did not settle into 'running' without restarts:" >&2
        "${COMPOSE[@]}" -p "$SMOKE_PROJECT" ps -a >&2 || true
        "${COMPOSE[@]}" -p "$SMOKE_PROJECT" logs --tail 20 probe >&2 || true
        exit 1
    fi
    sleep 3
done
echo ">> server, probe and meow are up"

# Soft check: meow-rs backoff in the fresh probe logs means the T2 kernel is
# unreachable over the compose network. Not fatal for the smoke verdict, but
# worth flagging.
if "${COMPOSE[@]}" -p "$SMOKE_PROJECT" logs probe 2>/dev/null | grep -qi "backoff"; then
    echo "WARNING: the probe logged a meow-rs backoff — T2 tunnel checks may be down"
fi

echo
echo "Smoke stand is up:"
echo "  public       http://$SMOKE_BIND:$SMOKE_PUBLIC_PORT   (/healthz, /sub/{id}, /src/{id})"
echo "  admin        http://$SMOKE_BIND:$SMOKE_ADMIN_PORT/admin"
if [ "${GENERATED_TOKEN:-0}" = 1 ]; then
    echo "  admin token  $FUMOX_ADMIN__TOKEN   (generated, shown once)"
fi
echo "  project      $SMOKE_PROJECT  (isolated volumes: ${SMOKE_PROJECT}_fumox-data, ${SMOKE_PROJECT}_meow-shared)"
echo "  teardown     scripts/smoke-down.sh"
