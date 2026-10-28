#!/usr/bin/env bash
# Controller smoke test for the fumox-meow image.
#
# What it proves:
#   1. the kernel refuses to start without a controller secret: an
#      external-controller without authentication can rewrite the proxy
#      configuration, so a missing secret must be a failed start, not a
#      running controller that answers everyone;
#   2. the controller rejects a request that carries no Authorization
#      header (or a wrong one);
#   3. the controller answers a request that presents the secret.
#
# Usage:
#   scripts/meow-controller-smoke.sh [image]
#
# Environment:
#   FUMOX_MEOW_IMAGE   the image under test (default: localhost/fumox-meow:local)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${1:-${FUMOX_MEOW_IMAGE:-localhost/fumox-meow:local}}"

if docker version >/dev/null 2>&1; then
    CLI=(docker)
elif podman version >/dev/null 2>&1; then
    CLI=(podman)
else
    echo "error: neither 'docker' nor 'podman' found" >&2
    exit 1
fi

NAME="fumox-meow-smoke-$$"
NOAUTH_NAME="fumox-meow-noauth-$$"
NOAUTH_TOKEN_NAME="fumox-meow-notoken-$$"

cleanup() {
    "${CLI[@]}" rm -f "$NAME" "$NOAUTH_NAME" "$NOAUTH_TOKEN_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "error: $*" >&2
    exit 1
}

SECRET="$(openssl rand -hex 32)"

echo ">> image: $IMAGE"

# --- 1. no secret: the kernel must not start ---------------------------------
echo ">> starting the kernel without a controller secret (must fail)"
"${CLI[@]}" run -d --name "$NOAUTH_TOKEN_NAME" \
    --tmpfs /run/meow:rw,noexec,nosuid,nodev,mode=1777,size=16m \
    "$IMAGE" >/dev/null

deadline=$((SECONDS + 30))
state="running"
code="0"
while [ "$SECONDS" -lt "$deadline" ]; do
    state="$("${CLI[@]}" inspect -f '{{.State.Status}}' "$NOAUTH_TOKEN_NAME" 2>/dev/null | tr -d '[:space:]')"
    code="$("${CLI[@]}" inspect -f '{{.State.ExitCode}}' "$NOAUTH_TOKEN_NAME" 2>/dev/null | tr -d '[:space:]')"
    [ "$state" = "exited" ] && break
    sleep 1
done
if [ "$state" != "exited" ]; then
    fail "the kernel started without a controller secret, it is still '$state'"
fi
if [ "$code" = "0" ]; then
    fail "the kernel exited 0 without a controller secret"
fi
echo ">> the kernel refused to start without a secret (exit code $code)"

# --- 2. the controller answers only with the secret --------------------------
echo ">> starting the kernel with a controller secret"
"${CLI[@]}" run -d --name "$NAME" \
    -p 127.0.0.1::9090 \
    --tmpfs /run/meow:rw,noexec,nosuid,nodev,mode=1777,size=16m \
    -e "FUMOX_MEOW__API_TOKEN=$SECRET" \
    -e "FUMOX_MEOW_API_BIND=0.0.0.0:9090" \
    "$IMAGE" >/dev/null

port="$("${CLI[@]}" port "$NAME" 9090/tcp 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
if [ -z "$port" ]; then
    fail "the published port of the controller could not be read"
fi
echo ">> controller on 127.0.0.1:$port"

# The controller comes up asynchronously; wait for the socket to answer at
# all (the answer may be a rejection, that is fine).
deadline=$((SECONDS + 60))
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$("${CLI[@]}" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
        fail "the kernel exited before the controller answered"
    fi
    if curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$port/version"; then
        break
    fi
    sleep 1
done

# --- 3. no Authorization: the request must be rejected ------------------------
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/version")"
case "$code" in
    2*) fail "the controller answered $code to a request without Authorization" ;;
    000) fail "the controller did not answer at all" ;;
esac
echo ">> the controller rejected an unauthenticated request (HTTP $code)"

wrong="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H 'Authorization: Bearer wrong-secret' "http://127.0.0.1:$port/version")"
case "$wrong" in
    2*) fail "the controller answered $wrong to a request with a wrong secret" ;;
    000) fail "the controller did not answer at all" ;;
esac
echo ">> the controller rejected a request with a wrong secret (HTTP $wrong)"

# --- 4. with the secret: the controller answers ------------------------------
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$port/version")"
case "$code" in
    2*) echo ">> the controller answered an authenticated request (HTTP $code)" ;;
    *) fail "the controller rejected the valid secret (HTTP $code)" ;;
esac

echo
echo "meow controller smoke test: all checks passed"
