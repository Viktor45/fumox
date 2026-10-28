#!/usr/bin/env bash
# Cold-start e2e test for the kube layout (podman kube play).
#
# What it proves on an EMPTY volume:
#   1. `podman kube play` brings both pods up;
#   2. the server reaches the running state and /healthz answers 200;
#   3. the probe reaches the running state as well;
#   4. neither container restarted: the probe does not depend on the server,
#      both apply the schema on startup and the loser of the SQLite lock
#      retries instead of dying, so a restart count above zero means the
#      cold start is NOT race-free.
#
# The point of the test is the empty volume: a second run starts against a
# populated database and would hide a broken cold start.
#
# Usage:
#   scripts/kube-coldstart-smoke.sh
#
# Environment:
#   FUMOX_IMAGE       the fumox image (default: localhost/fumox:local)
#   FUMOX_MEOW_IMAGE  the meow image  (default: localhost/fumox-meow:local)
#   FUMOX_TIMEOUT     the seconds the whole cold start may take (default: 300)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/docker/kube/fumox-pod.yaml"
FUMOX_IMAGE="${FUMOX_IMAGE:-localhost/fumox:local}"
FUMOX_MEOW_IMAGE="${FUMOX_MEOW_IMAGE:-localhost/fumox-meow:local}"
TIMEOUT="${FUMOX_TIMEOUT:-300}"

if ! command -v podman >/dev/null 2>&1; then
    echo "error: 'podman' not found (the kube layout needs podman >= 4.4)" >&2
    exit 1
fi
if [ ! -f "$MANIFEST" ]; then
    echo "error: ${MANIFEST} not found" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-kube-coldstart.XXXXXX")"
# The volumes behind the PVCs get their own names, so the test never
# touches the volumes of a real deployment on the same machine.
DATA_VOLUME="fumox-coldstart-data-$$"
GEO_VOLUME="fumox-coldstart-geo-$$"
MEOW_VOLUME="fumox-coldstart-meow-$$"

cleanup() {
    podman kube down "$WORK/fumox-pod.yaml" >/dev/null 2>&1 || true
    podman secret rm -f fumox-env fumox-admin >/dev/null 2>&1 || true
    podman volume rm -f "$DATA_VOLUME" "$GEO_VOLUME" "$MEOW_VOLUME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "error: $*" >&2
    echo "--- podman ps ---" >&2
    podman ps -a >&2 || true
    echo "--- server logs ---" >&2
    podman logs fumox 2>&1 | tail -40 >&2 || true
    echo "--- probe logs ---" >&2
    podman logs fumox-worker-probe 2>&1 | tail -40 >&2 || true
    exit 1
}

# --- the manifest, with the hostPath and the images pointed at the test ------
# The shipped manifest names /opt/fumox/config as the hostPath of the config
# directory; the test uses its own directory instead, so it never touches the
# configuration of a real deployment. The PVC names are suffixed too: the
# volumes are named volumes on the host, and a test must not create, let
# alone delete, the ones a real deployment uses.
mkdir -p "$WORK/config"
cp "$ROOT/config/app.toml" "$WORK/config/app.toml"
sed -e "s|path: /opt/fumox/config|path: ${WORK}/config|" \
    -e "s|image: localhost/fumox:local|image: ${FUMOX_IMAGE}|" \
    -e "s|image: localhost/fumox-meow:local|image: ${FUMOX_MEOW_IMAGE}|" \
    -e "s|claimName: fumox-data|claimName: ${DATA_VOLUME}|" \
    -e "s|claimName: fumox-geo|claimName: ${GEO_VOLUME}|" \
    -e "s|claimName: fumox-meow|claimName: ${MEOW_VOLUME}|" \
    "$MANIFEST" >"$WORK/fumox-pod.yaml"

# The two secrets: the admin token belongs to the server alone, the controller
# secret to everybody. Both are random, never a placeholder.
printf 'FUMOX_ADMIN__TOKEN=%s\n' "$(openssl rand -hex 32)" \
    | podman secret create fumox-admin - >/dev/null
printf 'FUMOX_MEOW__API_TOKEN=%s\n' "$(openssl rand -hex 32)" \
    | podman secret create fumox-env - >/dev/null

# The named volumes behind the PVCs. They are created and chowned here
# instead of being left to `podman kube play`: the containers run as uid
# 999 (the kernel as uid 998, gid 999) and the SQLite database directory
# must be writable by them. `kube play` does not apply the pod's
# runAsUser to the volume root, so an unprepared volume would fail the
# startup with a permission error instead of a real result.
for volume in "$DATA_VOLUME" "$GEO_VOLUME" "$MEOW_VOLUME"; do
    podman volume rm -f "$volume" >/dev/null 2>&1 || true
    podman volume create "$volume" >/dev/null
done
# The data and the geo volume belong to the server/probe (uid 999); the
# exchange volume is group-writable for gid 999, so the probe (uid 999)
# writes the config and the kernel (uid 998, gid 999) reads it.
podman run --rm -v "${DATA_VOLUME}:/v" alpine chown 999:999 /v
podman run --rm -v "${GEO_VOLUME}:/v" alpine chown 999:999 /v
podman run --rm -v "${MEOW_VOLUME}:/v" alpine sh -c 'chown 999:999 /v && chmod 0770 /v'

# The config directory is a hostPath: the container runs as uid 999 and
# must be able to read app.toml. The test only reads it (the admin editor
# is not exercised), so world-readable is enough.
chmod 755 "$WORK" "$WORK/config"
chmod 644 "$WORK/config/app.toml"

echo ">> image:  $FUMOX_IMAGE"
echo ">> image:  $FUMOX_MEOW_IMAGE"

echo ">> podman kube play"
podman kube play "$WORK/fumox-pod.yaml" >/dev/null

# --- the server comes up and answers -----------------------------------------
echo ">> waiting for /healthz on 127.0.0.1:8080"
deadline=$((SECONDS + TIMEOUT))
until curl -fsS --max-time 3 "http://127.0.0.1:8080/healthz" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        fail "/healthz did not answer within ${TIMEOUT}s"
    fi
    sleep 2
done
echo ">> /healthz answers 200"

# --- the probe comes up too, and neither container restarted -----------------
deadline=$((SECONDS + TIMEOUT))
probe=""
while [ "$SECONDS" -lt "$deadline" ]; do
    probe="$(podman ps --filter name=fumox-worker --format '{{.Names}}' 2>/dev/null \
        | grep -E 'probe' | head -1)"
    [ -n "$probe" ] && break
    sleep 2
done
[ -n "$probe" ] || fail "the probe container never reached the running state"
echo ">> the probe is running ($probe)"

for container in fumox "$probe"; do
    restarts="$(podman inspect -f '{{.RestartCount}}' "$container" 2>/dev/null | tr -d '[:space:]')"
    [ "$restarts" = "0" ] || fail "$container restarted $restarts time(s) during the cold start"
done
echo ">> no container restarted during the cold start"

echo
echo "kube cold-start smoke test: all checks passed"
