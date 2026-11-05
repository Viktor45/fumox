#!/usr/bin/env bash
# Smoke test for the nginx TLS-front image (docker/nginx/).
#
# What it proves, against a running container with a real (self-signed)
# certificate pair mounted at /certs:
#   1. the configuration is valid (`nginx -t`);
#   2. /.well-known/acme-challenge/ is served on :80 WITHOUT the HTTPS
#      redirect (ACME webroot mode) while every other HTTP request is
#      redirected 301 to HTTPS;
#   3. a TLS handshake against :443 succeeds (the upstream is deliberately
#      not running, so the answer is a 502 — the handshake is what counts);
#   4. the access log never carries the raw /export token: the log format
#      masks the token segment (see nginx.conf, $fumox_safe_uri);
#   5. a replaced certificate + SIGHUP reload serves the NEW certificate:
#      the config reloads without restart, the way a certbot renewal does.
#
# The image is built with the default compose flavour (resolver +
# variable proxy_pass); the podman flavour differs only in resolver.conf,
# which the checks below do not exercise.
#
# Usage:
#   scripts/nginx-smoke.sh [image]
#
# Environment:
#   FUMOX_NGINX_IMAGE   the image under test (default: localhost/fumox-nginx:local)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${1:-${FUMOX_NGINX_IMAGE:-localhost/fumox-nginx:local}}"

if docker version >/dev/null 2>&1; then
    CLI=(docker)
elif podman version >/dev/null 2>&1; then
    CLI=(podman)
else
    echo "error: neither 'docker' nor 'podman' found" >&2
    exit 1
fi

# The work dir lives inside the repository (see container-smoke.sh): the
# bind mount must be a path the engine shares with its VM.
WORK="$ROOT/target/nginx-smoke"
NAME="fumox-nginx-smoke-$$"

rm -rf "$WORK"
mkdir -p "$WORK"

cleanup() {
    "${CLI[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "error: $*" >&2
    "${CLI[@]}" logs "$NAME" >&2 2>/dev/null || true
    exit 1
}

gen_cert() {
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
        -keyout "$WORK/privkey.pem" -out "$WORK/fullchain.pem" \
        -subj "/CN=fumox-smoke.invalid" >/dev/null 2>&1
}

# Served-certificate fingerprint as the reload test sees it.
served_fingerprint() {
    echo | openssl s_client -connect "127.0.0.1:$1" -servername fumox-smoke.invalid 2>/dev/null \
        | openssl x509 -fingerprint -sha256 -noout
}

echo ">> image: $IMAGE"

gen_cert

echo ">> starting the front with self-signed certs mounted at /certs"
"${CLI[@]}" run -d --name "$NAME" \
    -p 127.0.0.1::80 -p 127.0.0.1::443 \
    -v "$WORK:/certs:ro" \
    -e FUMOX_UPSTREAM_PUBLIC=127.0.0.1:8080 \
    -e FUMOX_UPSTREAM_ADMIN=127.0.0.1:8081 \
    -e FUMOX_SERVER_NAME=fumox-smoke.invalid \
    "$IMAGE" >/dev/null

port80="$("${CLI[@]}" port "$NAME" 80/tcp 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
port443="$("${CLI[@]}" port "$NAME" 443/tcp 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
[ -n "$port80" ] && [ -n "$port443" ] || fail "the published ports could not be read"

deadline=$((SECONDS + 30))
until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port80/" 2>/dev/null; do
    if [ "$("${CLI[@]}" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
        fail "the container exited before answering on :80"
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail ":80 did not answer within the deadline"
    sleep 1
done

# --- 1. the configuration is valid ---------------------------------------------
echo ">> nginx -t"
"${CLI[@]}" exec "$NAME" nginx -t || fail "nginx -t rejected the configuration"

# --- 2. ACME challenges are not redirected --------------------------------------
echo ">> /.well-known/acme-challenge/ on :80 (must NOT redirect)"
code="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port80/.well-known/acme-challenge/smoke-token")"
if [ "$code" != "404" ]; then
    fail "the ACME challenge location answered $code, not a plain 404 (a 301 would break HTTP-01)"
fi
echo ">> no redirect for the ACME location (404)"

# --- 3. every other HTTP request redirects to HTTPS -----------------------------
echo ">> /sub on :80 (must redirect 301 to HTTPS)"
out="$(curl -s --max-time 10 -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:$port80/sub?x=1")"
case "$out" in
    "301 https://"*) echo ">> redirect: $out" ;;
    *) fail "expected '301 https://…', got: $out" ;;
esac

# --- 4. the TLS handshake succeeds ----------------------------------------------
echo ">> TLS handshake on :443"
fp_before="$(served_fingerprint "$port443")"
case "$fp_before" in
    *sha256\ Fingerprint*=*) ;;
    *) fail "no TLS handshake against :443 (fingerprint: ${fp_before:-empty})" ;;
esac
echo ">> handshake ok ($fp_before)"

# --- 5. the access log masks the /export tokens ---------------------------------
echo ">> requesting /export/alive and /export/ready with a known token"
TOKEN="smoke-token-0123456789abcdef"
# The upstream is deliberately absent (nothing listens on the front's own
# loopback :8080), so the TLS request answers 502 — exactly the upstream
# failure that used to put the raw request line into the error log.
curl -s --max-time 30 -o /dev/null "http://127.0.0.1:$port80/export/alive/$TOKEN"
curl -sk --max-time 30 -o /dev/null "https://127.0.0.1:$port443/export/ready/$TOKEN"
sleep 1
if "${CLI[@]}" logs "$NAME" 2>&1 | grep -F "$TOKEN" >/dev/null; then
    fail "the raw export token leaked into the access log"
fi
"${CLI[@]}" logs "$NAME" 2>&1 | grep -F "/export/alive/<masked>" >/dev/null \
    || fail "the masked URI is not in the access log"
echo ">> the token is masked in the access log"

# --- 6. a replaced certificate + SIGHUP reload serves the new one ---------------
echo ">> replacing the certificate and reloading with SIGHUP"
gen_cert
"${CLI[@]}" kill -s HUP "$NAME" >/dev/null 2>&1 || fail "SIGHUP delivery failed"
sleep 2
fp_after="$(served_fingerprint "$port443")"
case "$fp_after" in
    *sha256\ Fingerprint*=*) ;;
    *) fail "no TLS handshake after the reload (fingerprint: ${fp_after:-empty})" ;;
esac
if [ "$fp_before" = "$fp_after" ]; then
    fail "the served certificate did not change after the reload"
fi
echo ">> the reload serves the new certificate ($fp_after)"

echo
echo "nginx smoke test: all checks passed"
