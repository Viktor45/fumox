#!/usr/bin/env bash
# Integration test for scripts/smoke-down.sh, the counterpart of
# scripts/smoke-up.sh.
#
# The script must keep running on the stock macOS bash 3.2, where an
# unquoted empty-array expansion is fatal under `set -u`, exactly the
# state --keep-data puts VOLUME_FLAGS in. This test drives it through a
# stubbed `docker` and asserts on the compose command it builds, under the
# oldest bash on the machine so the guard stays load-bearing where it
# matters. Needs nothing but bash.
#
# Run directly:  bash scripts/tests/smoke-down.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/smoke-down.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-smoke-down-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The oldest bash available: /bin/bash on macOS is 3.2, the version the
# empty-array guard exists for. BASH_BIN overrides, to point the test at a
# specific one.
BASH_BIN="${BASH_BIN:-}"
for candidate in $BASH_BIN /bin/bash bash; do
    if [[ -n "$candidate" ]] && command -v "$candidate" >/dev/null 2>&1; then
        BASH_BIN="$candidate"
        break
    fi
done
[[ -n "$BASH_BIN" ]] || { echo "SKIP: no bash found"; exit 0; }
BASH_MAJOR="$("$BASH_BIN" -c 'echo "${BASH_VERSINFO[0]}"' 2>/dev/null || echo '?')"

# Whether this bash is the kind the guard is for: 3.2 fails the expansion
# outright, later ones do not. Either way the script must produce the same
# compose command.
if "$BASH_BIN" -uc 'arr=(); printf "%s\n" "${arr[@]}"' >/dev/null 2>&1; then
    note "bash ${BASH_MAJOR} tolerates empty arrays; the guard is checked for args only"
else
    note "bash ${BASH_MAJOR} trips set -u on empty arrays; the guard is load-bearing here"
fi

# docker stub: claims compose capability, records every other command line.
STUB="$WORK/bin"
mkdir -p "$STUB"
cat >"$STUB/docker" <<STUB
#!/bin/sh
if [ "\$1" = compose ] && [ "\$2" = version ]; then
    exit 0
fi
printf '%s\n' "\$*" >> "$WORK/compose.args"
exit 0
STUB
chmod +x "$STUB/docker"

run_down() { # expected compose command line, then script args
    local expected="$1"
    shift
    : >"$WORK/compose.args"
    PATH="$STUB:$PATH" "$BASH_BIN" "$SCRIPT" "$@" || fail "smoke-down.sh $* failed"
    local got
    got="$(cat "$WORK/compose.args")"
    [[ "$got" == "$expected" ]] || fail "compose got '$got', expected '$expected'"
    note "compose ran: $got"
}

# Default: the stand's volumes go with it.
run_down "compose -p fumox-smoke down --remove-orphans -v"
# --keep-data: volumes preserved, and nothing else about the command moves.
run_down "compose -p fumox-smoke down --remove-orphans" --keep-data

set +e
OUT="$(PATH="$STUB:$PATH" "$BASH_BIN" "$SCRIPT" --bogus 2>&1)"
CODE=$?
set -e
[[ "$CODE" -eq 64 ]] || fail "unknown flag: expected exit 64, got $CODE"
note "unknown flag exits 64"

echo
echo "smoke-down.sh: all checks passed"
