#!/usr/bin/env bash
# Integration test for scripts/smoke-up.sh, the bring-up counterpart of
# scripts/smoke-down.sh.
#
# Needs nothing but bash: docker, curl and lsof are stubbed, so the test
# exercises the script's own logic -- the environment it hands to compose,
# the pre-flight port check, the token handling and the argument parsing --
# without a container engine, a network or a listening socket.
#
# Run directly:  bash scripts/tests/smoke-up.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/smoke-up.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-smoke-up-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

STUB="$WORK/bin"
mkdir -p "$STUB"

# docker stub: a compose front-end that records every call and the two
# environment variables the stand is expected to set, and answers the
# container queries the script makes.
cat >"$STUB/docker" <<STUB
#!/bin/sh
if [ "\$1" = "compose" ]; then
    if [ "\$2" = "version" ]; then exit 0; fi
    printf '%s\n' "\$*" >> "$WORK/compose.args"
    printf 'FUMOX_CONFIG_ACCESS=%s\n' "\${FUMOX_CONFIG_ACCESS:-}" >> "$WORK/compose.env"
    printf 'FUMOX_ADMIN__TOKEN=%s\n' "\${FUMOX_ADMIN__TOKEN:-}" >> "$WORK/compose.env"
    printf 'FUMOX_MEOW__API_TOKEN=%s\n' "\${FUMOX_MEOW__API_TOKEN:-}" >> "$WORK/compose.env"
    case "\$*" in
        *" ps -q "*) echo "stubcontainerid"; exit 0 ;;
    esac
    exit 0
fi
if [ "\$1" = "inspect" ]; then
    case "\$3" in
        *State.Status*) echo "running"; exit 0 ;;
        *RestartCount*) echo "0"; exit 0 ;;
    esac
    exit 0
fi
exit 0
STUB
chmod +x "$STUB/docker"

# curl stub: the URL is the last argument; the script only looks at the
# status code.
cat >"$STUB/curl" <<'STUB'
#!/bin/sh
url=""
for a in "$@"; do url="$a"; done
case "$url" in
    */healthz) echo 200 ;;
    */admin/login) echo 200 ;;
    */export/alive/*) echo 404 ;;
    *) echo 000 ;;
esac
exit 0
STUB
chmod +x "$STUB/curl"

# lsof stub: reports the ports in STUB_BUSY_PORTS as taken.
cat >"$STUB/lsof" <<'STUB'
#!/bin/sh
port=""
for a in "$@"; do
    case "$a" in
        -tiTCP:*) port="${a#-tiTCP:}" ;;
    esac
done
case ",${STUB_BUSY_PORTS:-}," in
    *",$port,"*) exit 0 ;;
esac
exit 1
STUB
chmod +x "$STUB/lsof"

run_up() { # run_up [env assignments...] -- <script args...>
    local envs=() args=()
    while [ "${1:-}" != "--" ]; do
        envs+=("$1")
        shift
    done
    shift
    args=("$@")
    : >"$WORK/compose.args"
    : >"$WORK/compose.env"
    set +e
    OUT="$(env "${envs[@]+"${envs[@]}"}" PATH="$STUB:$PATH" "$SCRIPT" "${args[@]+"${args[@]}"}" 2>&1)"
    CODE=$?
    set -e
}

# ── a successful bring-up ────────────────────────────────────────────
run_up -- --no-build
[ "$CODE" -eq 0 ] || fail "smoke-up.sh exited $CODE, expected 0:
$OUT"
note "smoke-up.sh exits 0 on a successful bring-up"

grep -q -- "up -d" "$WORK/compose.args" || fail "compose was never asked to come up:
$(cat "$WORK/compose.args")"
grep -q -- "-p fumox-smoke" "$WORK/compose.args" || fail "compose was not scoped to the smoke project:
$(cat "$WORK/compose.args")"
note "compose up runs under -p fumox-smoke"

grep -q -- "-f docker-compose.build.yml" "$WORK/compose.args" \
    || fail "the stand must run the local build overlay:
$(cat "$WORK/compose.args")"
note "compose up runs with the build overlay"

grep -qx "FUMOX_CONFIG_ACCESS=ro" "$WORK/compose.env" \
    || fail "the stand must hand compose FUMOX_CONFIG_ACCESS=ro:
$(cat "$WORK/compose.env")"
note "the stand mounts the shared config read-only"

# The kernel controller refuses to start without a secret, so the stand
# must always hand one to compose.
MEOW_TOKEN="$(grep -m1 '^FUMOX_MEOW__API_TOKEN=' "$WORK/compose.env" | cut -d= -f2-)"
[ -n "$MEOW_TOKEN" ] || fail "the stand must hand compose a controller secret:
$(cat "$WORK/compose.env")"
case "$MEOW_TOKEN" in
    *[!A-Za-z0-9._-]*) fail "the generated controller secret must survive the kernel's entrypoint check: $MEOW_TOKEN" ;;
esac
note "the stand generates a controller secret for the kernel"

# ── the port is taken: the stand must not come up ───────────────────
run_up "STUB_BUSY_PORTS=18080" -- --no-build
[ "$CODE" -eq 1 ] || fail "a taken port must abort with exit 1, got $CODE:
$OUT"
grep -q -- "up -d" "$WORK/compose.args" && fail "compose was started although the port was taken"
note "a taken host port aborts before compose up"

# ── a token the operator supplied is used as it is ──────────────────
run_up "FUMOX_ADMIN__TOKEN=operator-supplied-token" -- --no-build
[ "$CODE" -eq 0 ] || fail "smoke-up.sh exited $CODE, expected 0:
$OUT"
grep -qx "FUMOX_ADMIN__TOKEN=operator-supplied-token" "$WORK/compose.env" \
    || fail "the supplied token was replaced:
$(cat "$WORK/compose.env")"
case "$OUT" in
    *"admin token"*) fail "a supplied token must not be printed as a generated one" ;;
esac
note "a supplied token is passed through unchanged"

# ── a generated token lands in a private file, not on the terminal ───
run_up -- --no-build
[ "$CODE" -eq 0 ] || fail "smoke-up.sh exited $CODE, expected 0:
$OUT"
TOKEN_PATH="$(printf '%s\n' "$OUT" | sed -n 's/^  admin token  \(.*\)   (generated, mode 0600)$/\1/p')"
[ -n "$TOKEN_PATH" ] || fail "the generated token is not reported through a file:
$OUT"
[ -f "$TOKEN_PATH" ] || fail "the reported token file does not exist: $TOKEN_PATH"
MODE="$(stat -c '%a' "$TOKEN_PATH" 2>/dev/null || stat -f '%Lp' "$TOKEN_PATH" 2>/dev/null || echo '')"
[ "$MODE" = "600" ] || fail "the token file must be mode 0600, got '${MODE:-unknown}'"
note "the generated token is written to a 0600 file"

# ── an unknown argument is refused ──────────────────────────────────
run_up -- --bogus
[ "$CODE" -eq 64 ] || fail "an unknown argument must exit 64, got $CODE"
note "an unknown argument exits 64"

echo
echo "smoke-up.sh: all checks passed"
