#!/usr/bin/env bash
# Bring up the disposable smoke stand: the full stack (server + probe + meow)
# under an isolated compose project, on shifted host ports, with its own
# generated admin token and fresh volumes. The main stack (ports 8080/8081,
# project "fumox") is never touched. The stand runs the local build: the
# compose file pins the published images by digest and the overlay
# (docker-compose.build.yml) swaps them for the locally built ones. The
# shared host ./config mount is the one thing a compose project cannot scope,
# so the server gets it read-only (FUMOX_CONFIG_ACCESS=ro) and its admin
# panel can read app.toml but never writes it.
#
# Usage:
#   scripts/smoke-up.sh [--no-build] [--show-token]
#
# Environment:
#   SMOKE_PROJECT      compose project name          (default: fumox-smoke)
#   SMOKE_BIND         bind address for the stand    (default: 127.0.0.1)
#   SMOKE_PUBLIC_PORT  host port for /sub, /src      (default: 18080)
#   SMOKE_ADMIN_PORT   host port for the admin panel (default: 18081)
#   FUMOX_ADMIN__TOKEN reuse this token instead of generating one
#   FUMOX_MEOW__API_TOKEN reuse this controller secret instead of generating one
#
# The generated tokens are written to private files (0600) whose paths are
# printed; --show-token prints the tokens themselves instead.
#
# Tear the stand down with scripts/smoke-down.sh.
set -euo pipefail

cd "$(dirname "$0")/.."

# Parsed before any environment probing, so --help and a bad flag answer
# without docker, curl or a free port
BUILD_FLAGS=(--build)
SHOW_TOKEN=0
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD_FLAGS=() ;;
        --show-token) SHOW_TOKEN=1 ;;
        -h | --help)
            # Prints the header, comment markers stripped. awk rather than
            # sed: BSD sed lacks the nested delete-and-print address range
            awk 'NR == 1 { next } /^set -euo/ { exit }
                 { sub(/^# ?/, ""); print }' "$0"
            exit 0
            ;;
        *)
            echo "usage: scripts/smoke-up.sh [--no-build] [--show-token]" >&2
            exit 64
            ;;
    esac
done

SMOKE_PROJECT="${SMOKE_PROJECT:-fumox-smoke}"
SMOKE_PUBLIC_PORT="${SMOKE_PUBLIC_PORT:-18080}"
SMOKE_BIND="${SMOKE_BIND:-127.0.0.1}"
SMOKE_ADMIN_PORT="${SMOKE_ADMIN_PORT:-18081}"

# The project name decides which real volumes the stand owns, so only the
# smoke stand's own naming scheme is accepted
case "$SMOKE_PROJECT" in
    fumox-smoke | fumox-smoke-*) ;;
    *)
        echo "error: refusing to use project '$SMOKE_PROJECT':" >&2
        echo "       the name must be 'fumox-smoke' or 'fumox-smoke-<suffix>'" >&2
        exit 64
        ;;
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

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.build.yml)

# The binary that owns the containers is not ${COMPOSE[0]}: for podman-compose
# that is a compose front-end with no `inspect` at all, so the engine is the
# binary that has one
case "${COMPOSE[0]}" in
    docker) CONTAINER_CLI=(docker) ;;
    podman) CONTAINER_CLI=(podman) ;;
    podman-compose)
        if command -v podman >/dev/null 2>&1; then
            CONTAINER_CLI=(podman)
        else
            CONTAINER_CLI=()
        fi
        ;;
    *) CONTAINER_CLI=() ;;
esac

# Checked up front: a missing curl would otherwise surface as a failed
# wait_for a minute into the bring-up, which reads like a stand that did not
# come up rather than like a missing tool
command -v curl >/dev/null 2>&1 || { echo "error: curl is required by the smoke checks" >&2; exit 1; }

# Whether a host TCP port already has a listener: lsof on macOS and most
# Linux, /proc/net/tcp{,6} where lsof is missing. Returns 0 if busy, 1 if free
port_busy() {
    local port="$1" hex found=0
    hex=$(printf '%04X' "$port")
    if command -v lsof >/dev/null 2>&1; then
        if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    # local_address is "<hex_ip>:<hex_port>", state 0A == LISTEN. Both files
    # are walked: a v6-only listener is in tcp6 alone
    for f in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$f" ] || continue
        if awk -v hex=":$hex" '$4 == "0A" && $2 ~ hex"$" { found=1 } END { exit found ? 0 : 1 }' "$f"; then
            found=1
        fi
    done
    # No /proc/net/tcp and no lsof: assume free rather than falsely abort
    [ "$found" -eq 1 ]
}
for port in "$SMOKE_PUBLIC_PORT" "$SMOKE_ADMIN_PORT"; do
    if port_busy "$port"; then
        echo "error: host port $port is already in use, so the compose project" >&2
        echo "       '$SMOKE_PROJECT' cannot come up. Free the port or pick another" >&2
        echo "       via SMOKE_PUBLIC_PORT / SMOKE_ADMIN_PORT (bind address:" >&2
        echo "       SMOKE_BIND, default 127.0.0.1)" >&2
        exit 1
    fi
done

TOKEN_FILE=""
MEOW_TOKEN_FILE=""
GENERATED_TOKEN=0
GENERATED_MEOW_TOKEN=0

random_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# Two credentials: the admin panel token and the proxy kernel's controller
# secret (the kernel refuses to start without one)
if [ -z "${FUMOX_ADMIN__TOKEN:-}" ]; then
    FUMOX_ADMIN__TOKEN="$(random_secret)"
    GENERATED_TOKEN=1
fi
if [ -z "${FUMOX_MEOW__API_TOKEN:-}" ]; then
    FUMOX_MEOW__API_TOKEN="$(random_secret)"
    GENERATED_MEOW_TOKEN=1
fi

# Generated credentials go to private files (0600 in a 0700 dir), never to
# the terminal scrollback by default
if [ "$GENERATED_TOKEN" = 1 ] || [ "$GENERATED_MEOW_TOKEN" = 1 ]; then
    if TOKEN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fumox-smoke.XXXXXX" 2>/dev/null)" \
       && chmod 700 "$TOKEN_DIR" 2>/dev/null; then
        if [ "$GENERATED_TOKEN" = 1 ]; then
            TOKEN_FILE="$TOKEN_DIR/admin-token"
            if ! printf '%s\n' "$FUMOX_ADMIN__TOKEN" >"$TOKEN_FILE" 2>/dev/null \
               || ! chmod 600 "$TOKEN_FILE" 2>/dev/null; then
                TOKEN_FILE=""
            fi
        fi
        if [ "$GENERATED_MEOW_TOKEN" = 1 ]; then
            MEOW_TOKEN_FILE="$TOKEN_DIR/meow-token"
            if ! printf '%s\n' "$FUMOX_MEOW__API_TOKEN" >"$MEOW_TOKEN_FILE" 2>/dev/null \
               || ! chmod 600 "$MEOW_TOKEN_FILE" 2>/dev/null; then
                MEOW_TOKEN_FILE=""
            fi
        fi
    fi
fi
export FUMOX_ADMIN__TOKEN FUMOX_MEOW__API_TOKEN FUMOX_PUBLIC_PORT="$SMOKE_PUBLIC_PORT" FUMOX_ADMIN_BIND="$SMOKE_BIND" FUMOX_ADMIN_PORT="$SMOKE_ADMIN_PORT"
# The ./config bind mount is not project-scoped, both stands mount the same
# host directory: read-only keeps the smoke admin page from rewriting the
# main stack's app.toml
export FUMOX_CONFIG_ACCESS=ro

echo ">> smoke stand: project=$SMOKE_PROJECT public=$SMOKE_BIND:$SMOKE_PUBLIC_PORT admin=$SMOKE_BIND:$SMOKE_ADMIN_PORT"

# Baseline before `up`: a recreated container starts its restart counter at
# zero, so the counter is only meaningful together with the container id
container_facts() { # container_facts <service> -> "<id> <state> <restarts>"
    local id state count
    [ "${#CONTAINER_CLI[@]}" -gt 0 ] || return 1
    id="$("${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" ps -q "$1" 2>/dev/null | head -1 | tr -d '[:space:]')" || return 1
    [ -n "$id" ] || return 1
    state="$("${CONTAINER_CLI[@]}" inspect -f '{{.State.Status}}' "$id" 2>/dev/null | tr -d '[:space:]')" || return 1
    count="$("${CONTAINER_CLI[@]}" inspect -f '{{.RestartCount}}' "$id" 2>/dev/null | tr -d '[:space:]')" || return 1
    printf '%s %s %s\n' "$id" "$state" "$count"
}
base_id_server=""
base_count_server=0
base_id_probe=""
base_count_probe=0
base_id_meow=""
base_count_meow=0
facts="$(container_facts server || true)"
if [ -n "$facts" ]; then
    base_id_server="$(printf '%s' "$facts" | cut -d' ' -f1)"
    base_count_server="$(printf '%s' "$facts" | cut -d' ' -f3)"
fi
facts="$(container_facts probe || true)"
if [ -n "$facts" ]; then
    base_id_probe="$(printf '%s' "$facts" | cut -d' ' -f1)"
    base_count_probe="$(printf '%s' "$facts" | cut -d' ' -f3)"
fi
facts="$(container_facts meow || true)"
if [ -n "$facts" ]; then
    base_id_meow="$(printf '%s' "$facts" | cut -d' ' -f1)"
    base_count_meow="$(printf '%s' "$facts" | cut -d' ' -f3)"
fi

# `${arr[@]+...}` (not a bare `${arr[@]}`): under `set -u` an empty array is
# "unset" for bash 3.2 (macOS), which would abort the script.
"${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" up -d ${BUILD_FLAGS[@]+"${BUILD_FLAGS[@]}"}

# From here the stand exists, so a failed exit must tear it down again (no
# -v: the volumes survive a failed run, like smoke-down.sh by default). The
# trap is disarmed once the checks pass
smoke_teardown_on_fail() {
    echo ">> the smoke checks failed, tearing the stand down (volumes kept, project $SMOKE_PROJECT)" >&2
    "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" down --remove-orphans >&2 2>&1 || true
}
trap smoke_teardown_on_fail EXIT

wait_for() { # wait_for <what> <url> <expected_code> <timeout_s>
    local what="$1" url="$2" expected="$3" deadline=$((SECONDS + $4)) code
    while [ "$SECONDS" -lt "$deadline" ]; do
        # Bounded connect and transfer so a hang cannot eat the deadline, a
        # timeout counts as a failed attempt (code 000)
        code="$(curl -s -o /dev/null -w '%{http_code}' \
            --connect-timeout 2 --max-time 5 "$url" 2>/dev/null || true)"
        [ "$code" = "$expected" ] && return 0
        sleep 2
    done
    # An empty code is not 000: curl itself produced no answer, a different
    # failure from the stand answering something else
    if [ -n "$code" ]; then
        echo "error: $what did not answer $expected within the deadline (last HTTP code: $code)" >&2
    else
        echo "error: $what did not answer $expected within the deadline (curl produced no answer at all — is the tool there and the URL reachable?)" >&2
    fi
    return 1
}

# Container liveness independent of the log level: the probe's startup line
# is INFO and invisible under error/warn [log] levels, so the state is the
# reliable signal. The restart counter is compared against the `up` baseline
container_settled() { # container_settled <service> <base_id> <base_count>
    local facts id state count
    facts="$(container_facts "$1")" || return 1
    id="$(printf '%s' "$facts" | cut -d' ' -f1)"
    state="$(printf '%s' "$facts" | cut -d' ' -f2)"
    count="$(printf '%s' "$facts" | cut -d' ' -f3)"
    [ "$state" = "running" ] || return 1
    # A container `up` recreated starts its counter at zero
    if [ "$id" != "$2" ]; then
        [ "$count" -eq 0 ] 2>/dev/null || return 1
        return 0
    fi
    [ "$count" -eq "$3" ] 2>/dev/null || return 1
    return 0
}

echo ">> waiting for the public listener (/healthz)"
if ! wait_for "public /healthz" "http://$SMOKE_BIND:$SMOKE_PUBLIC_PORT/healthz" 200 120; then
    "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" logs --tail 20 server >&2 || true
    exit 1
fi

echo ">> checking the admin panel (login page)"
if ! wait_for "admin login page" "http://$SMOKE_BIND:$SMOKE_ADMIN_PORT/admin/login" 200 60; then
    "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" logs --tail 20 server >&2 || true
    exit 1
fi

echo ">> checking that a wrong alive-export token answers 404"
if ! wait_for "alive-export 404" "http://$SMOKE_BIND:$SMOKE_PUBLIC_PORT/export/alive/wrong-token" 404 30; then
    exit 1
fi

echo ">> waiting for all three containers to settle (running, no restarts)"
container_deadline=$((SECONDS + 60))
until container_settled server "$base_id_server" "$base_count_server" \
   && container_settled probe "$base_id_probe" "$base_count_probe" \
   && container_settled meow "$base_id_meow" "$base_count_meow"; do
    if [ "$SECONDS" -ge "$container_deadline" ]; then
        echo "error: containers did not settle into 'running' without restarts:" >&2
        "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" ps -a >&2 || true
        "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" logs --tail 20 probe >&2 || true
        exit 1
    fi
    sleep 3
done
echo ">> server, probe and meow are up"

# Soft check: a meow-rs backoff in the fresh probe logs means the T2 kernel
# is unreachable over the compose network, not fatal for the verdict
if "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" -p "$SMOKE_PROJECT" logs probe 2>/dev/null | grep -qi "backoff"; then
    echo "WARNING: the probe logged a meow-rs backoff: T2 tunnel checks may be down"
fi

# Stand verified, so the exit trap is disarmed and the stand stays up
trap - EXIT

echo
echo "Smoke stand is up:"
echo "  public       http://$SMOKE_BIND:$SMOKE_PUBLIC_PORT   (/healthz, /sub/{id}, /src/{id})"
echo "  admin        http://$SMOKE_BIND:$SMOKE_ADMIN_PORT/admin"
if [ "${GENERATED_TOKEN:-0}" = 1 ]; then
    if [ "$SHOW_TOKEN" = 1 ]; then
        echo "  admin token  $FUMOX_ADMIN__TOKEN   (generated, shown once)"
    elif [ -n "$TOKEN_FILE" ]; then
        echo "  admin token  $TOKEN_FILE   (generated, mode 0600)"
    else
        echo "  admin token  (generated, but no private file could be written:"
        echo "               re-run with --show-token to print it)"
    fi
fi
if [ "${GENERATED_MEOW_TOKEN:-0}" = 1 ]; then
    if [ "$SHOW_TOKEN" = 1 ]; then
        echo "  meow token   $FUMOX_MEOW__API_TOKEN   (generated, shown once)"
    elif [ -n "$MEOW_TOKEN_FILE" ]; then
        echo "  meow token   $MEOW_TOKEN_FILE   (generated, mode 0600)"
    else
        echo "  meow token   (generated, but no private file could be written:"
        echo "               re-run with --show-token to print it)"
    fi
fi
echo "  project      $SMOKE_PROJECT  (isolated volumes: ${SMOKE_PROJECT}_fumox-data, ${SMOKE_PROJECT}_fumox-geo, ${SMOKE_PROJECT}_fumox-meow)"
echo "  teardown     scripts/smoke-down.sh"
