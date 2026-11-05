#!/usr/bin/env bash
# Fixture test for scripts/validate-meow-version.sh.
#
# The meow_version input of docker-meow.yml reaches the release download
# URL, the published tag list and the image itself, and the build and
# merge jobs must accept exactly the same values: the rule lives in one
# script and this table pins it. Accepted tag spellings (with and
# without the `v`, surrounded by whitespace) on one side; `latest`,
# partial versions, prereleases and shell metacharacters on the other.
#
# Run directly:  bash scripts/tests/validate-meow-version.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate-meow-version.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-validate-meow-version-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

run_case() { # run_case <input> -> OUT (stdout) and CODE
    set +e
    OUT="$("$SCRIPT" "$1" 2>"$WORK/err")"
    CODE=$?
    set -e
}

assert_says() { # assert_says <needle> <haystack> <label>
    if ! printf '%s' "$2" | grep -qF -- "$1"; then
        fail "$3: expected '$1' in the output"
    fi
}

# --- the table: input|exit|stdout ("-" = no stdout expected) ------------------
CASES=(
    "v0.27.0|0|v0.27.0"
    "0.27.0|0|0.27.0"
    "  v0.27.0  |0|v0.27.0"
    $'\tv0.1.2\t|0|v0.1.2'
    "v10.20.30|0|v10.20.30"
    "|1|-"
    "latest|1|-"
    "v0.27|1|-"
    "0.27.0.1|1|-"
    "v0.27.0-rc1|1|-"
    "v0.27.0+build|1|-"
    "v0.27.0;rm -rf /|1|-"
    "main|1|-"
)

for spec in "${CASES[@]}"; do
    IFS='|' read -r input want_code want_out <<<"$spec"
    run_case "$input"
    if [ "$CODE" -ne "$want_code" ]; then
        fail "input ${input@Q}: expected exit $want_code, got $CODE"
    fi
    if [ "$want_out" = "-" ]; then
        [ -z "$OUT" ] || fail "input ${input@Q}: expected no stdout, got ${OUT@Q}"
        assert_says "must be a tag like v0.27.0" "$(cat "$WORK/err")" "the rejection of ${input@Q}"
    else
        [ "$OUT" = "$want_out" ] || fail "input ${input@Q}: expected ${want_out@Q}, got ${OUT@Q}"
    fi
done
note "the table accepts versioned tags and rejects everything else"

# The rejected value stays out of the `::error::` workflow command: a
# workflow command runs to the end of the line, and an unvalidated value
# must not carry one.
run_case "evil"
if grep -qF "evil" <(sed -n 's/^::error:://p' "$WORK/err"); then
    fail "the unvalidated value must not be echoed inside the ::error:: line"
fi
note "the rejected value is not embedded in the ::error:: command"

# --- the argument count is validated ------------------------------------------
set +e
"$SCRIPT" >/dev/null 2>&1
CODE=$?
set -e
[ "$CODE" -eq 64 ] || fail "a missing argument must exit 64, got $CODE"

set +e
"$SCRIPT" a b >/dev/null 2>&1
CODE=$?
set -e
[ "$CODE" -eq 64 ] || fail "two arguments must exit 64, got $CODE"
note "the argument count is validated"

echo
echo "validate-meow-version.sh: all checks passed"
