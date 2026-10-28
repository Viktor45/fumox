#!/usr/bin/env bash
# Container smoke test for the fumox runtime image.
#
# What it proves on every architecture the CI builds:
#   1. the image starts with the bind mounts a deployment uses: /app/data
#      owned by the fumox uid (999), /app/config read-only;
#   2. the server comes up and /healthz answers 200;
#   3. the SQLite database is created inside the data mount;
#   4. a read-only data mount fails PREDICTABLY: the container exits with
#      a non-zero code, it does not hang and it does not serve anyway.
#
# The last case is the one that matters for a deployment: a misconfigured
# mount must surface as a failed start, not as a container that looks alive
# and silently keeps nothing.
#
# Usage:
#   scripts/container-smoke.sh [image]
#
# Environment:
#   FUMOX_IMAGE   the image under test (default: localhost/fumox:local)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${1:-${FUMOX_IMAGE:-localhost/fumox:local}}"

if docker version >/dev/null 2>&1; then
    CLI=(docker)
elif podman version >/dev/null 2>&1; then
    CLI=(podman)
else
    echo "error: neither 'docker' nor 'podman' found" >&2
    exit 1
fi

# The work dir lives inside the repository: Docker Desktop only shares
# some host paths with the VM, and the repository is one of them.
WORK="$ROOT/target/container-smoke"
rm -rf "$WORK"
mkdir -p "$WORK/data" "$WORK/config" "$WORK/ro-data"
cp "$ROOT/config/app.toml" "$WORK/config/app.toml"

# The container runs as uid 999: the data mount must be writable by it.
# On a rootless engine or on macOS the ownership is virtualized and the
# chown is neither possible nor needed.
if ! chown -R 999:999 "$WORK/data" 2>/dev/null; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo -n chown -R 999:999 "$WORK/data"
    else
        echo "note: could not chown the data mount to 999:999, continuing"
    fi
fi

NAME="fumox-smoke-$$"
RO_NAME="fumox-smoke-ro-$$"
cleanup() {
    "${CLI[@]}" rm -f "$NAME" "$RO_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "error: $*" >&2
    "${CLI[@]}" logs "$NAME" >&2 2>/dev/null || true
    exit 1
}

echo ">> image: $IMAGE"

# --- 1. the server starts and answers -----------------------------------------
echo ">> starting the server with the deployment mounts"
"${CLI[@]}" run -d --name "$NAME" \
    -p 127.0.0.1::8080 \
    -v "$WORK/data:/app/data" \
    -v "$WORK/config:/app/config:ro" \
    "$IMAGE" >/dev/null

port="$("${CLI[@]}" port "$NAME" 8080/tcp 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
if [ -z "$port" ]; then
    fail "the published port of the container could not be read"
fi

echo ">> waiting for /healthz on 127.0.0.1:$port"
deadline=$((SECONDS + 120))
until curl -fsS --max-time 3 "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; do
    if [ "$("${CLI[@]}" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
        fail "the container exited before /healthz answered"
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        fail "/healthz did not answer within the deadline"
    fi
    sleep 2
done
echo ">> /healthz answers 200"

# --- 2. the database is created in the data mount -----------------------------
if [ ! -f "$WORK/data/fumox.db" ]; then
    fail "the SQLite database was not created in the data mount"
fi
echo ">> the database was created in the data mount"

"${CLI[@]}" rm -f "$NAME" >/dev/null 2>&1 || true

# --- 3. a read-only data mount must fail, not hang ---------------------------
echo ">> starting the server with a read-only data mount (must fail fast)"
"${CLI[@]}" run -d --name "$RO_NAME" \
    -v "$WORK/ro-data:/app/data:ro" \
    -v "$WORK/config:/app/config:ro" \
    "$IMAGE" >/dev/null

deadline=$((SECONDS + 60))
state="running"
code="0"
while [ "$SECONDS" -lt "$deadline" ]; do
    state="$("${CLI[@]}" inspect -f '{{.State.Status}}' "$RO_NAME" 2>/dev/null | tr -d '[:space:]')"
    code="$("${CLI[@]}" inspect -f '{{.State.ExitCode}}' "$RO_NAME" 2>/dev/null | tr -d '[:space:]')"
    [ "$state" = "exited" ] && break
    sleep 1
done

if [ "$state" != "exited" ]; then
    echo "error: the container did not fail with a read-only data mount, it is still '$state'" >&2
    "${CLI[@]}" logs "$RO_NAME" >&2 2>/dev/null || true
    exit 1
fi
if [ "$code" = "0" ]; then
    echo "error: the container exited 0 with a read-only data mount" >&2
    "${CLI[@]}" logs "$RO_NAME" >&2 2>/dev/null || true
    exit 1
fi
echo ">> the read-only case failed predictably (exit code $code)"

echo
echo "container smoke test: all checks passed"
