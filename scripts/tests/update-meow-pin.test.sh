#!/usr/bin/env bash
# Fixture test for scripts/update-meow-pin.sh.
#
# The script rewrites the meow-rs pin in five files at once and refuses to
# build a bump it cannot prove. Both halves need pinning: a bump must
# reach every copy of the value (and only the copies that are pins, not
# the prose examples), and a release whose archive does not hash to the
# published sum must leave the tree untouched.
#
# `gh` and `curl` are stubs answering from a fixture directory, so no
# network is involved. The script is COPIED into a fixture checkout along
# with the five real files, because it resolves the repository root from
# its own location: the real working tree is never written to.
#
# Run directly:  bash scripts/tests/update-meow-pin.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/update-meow-pin.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-update-meow-pin-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{print $1}'; }
else
    sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

PIN_FILES=(docker/meow/Dockerfile docker-compose.build.yml .env.example USERGUIDE.md USERGUIDE.ru.md)

# The pin the repository currently carries, read from the real Dockerfile
# so this test keeps working after a future bump.
CUR_VERSION="$(sed -n 's/^ARG MEOW_VERSION=//p' "$ROOT/docker/meow/Dockerfile")"
CUR_AMD64="$(sed -n 's/^ARG MEOW_SHA256_AMD64=//p' "$ROOT/docker/meow/Dockerfile")"
CUR_ARM64="$(sed -n 's/^ARG MEOW_SHA256_ARM64=//p' "$ROOT/docker/meow/Dockerfile")"
if [ -z "$CUR_VERSION" ] || [ -z "$CUR_AMD64" ] || [ -z "$CUR_ARM64" ]; then
    fail "could not read the current pin from docker/meow/Dockerfile"
fi

# Snapshot the real files: nothing below may write to them.
REAL_SNAPSHOT="$WORK/real-before"
for f in "${PIN_FILES[@]}"; do
    printf '%s  %s\n' "$(sha256_of "$ROOT/$f")" "$f"
done >"$REAL_SNAPSHOT"

# --- the fixture releases -----------------------------------------------------
# A version that is not the current pin, with archives whose real sums the
# published .sha256 assets carry.
NEW_VERSION="v0.99.0"
AMD64_ASSET="meow-${NEW_VERSION}-x86_64-unknown-linux-musl.tar.gz"
ARM64_ASSET="meow-${NEW_VERSION}-aarch64-unknown-linux-musl.tar.gz"

NEW_ASSETS="$WORK/assets-new"
mkdir -p "$NEW_ASSETS"
printf 'fake amd64 kernel for %s\n' "$NEW_VERSION" >"$NEW_ASSETS/$AMD64_ASSET"
printf 'fake arm64 kernel for %s\n' "$NEW_VERSION" >"$NEW_ASSETS/$ARM64_ASSET"
AMD64_SUM="$(sha256_of "$NEW_ASSETS/$AMD64_ASSET")"
ARM64_SUM="$(sha256_of "$NEW_ASSETS/$ARM64_ASSET")"
printf '%s  %s\n' "$AMD64_SUM" "$AMD64_ASSET" >"$NEW_ASSETS/$AMD64_ASSET.sha256"
printf '%s  %s\n' "$ARM64_SUM" "$ARM64_ASSET" >"$NEW_ASSETS/$ARM64_ASSET.sha256"

# The same release, but the amd64 checksum file claims a sum the archive
# does not have: a corrupted or substituted upload.
BAD_ASSETS="$WORK/assets-bad"
mkdir -p "$BAD_ASSETS"
cp "$NEW_ASSETS/$ARM64_ASSET" "$NEW_ASSETS/$ARM64_ASSET.sha256" "$BAD_ASSETS/"
cp "$NEW_ASSETS/$AMD64_ASSET" "$BAD_ASSETS/"
printf '%064d  %s\n' 0 "$AMD64_ASSET" >"$BAD_ASSETS/$AMD64_ASSET.sha256"

# Only the checksum files for the version already pinned: a no-op run
# must not need the archives, and this fixture would 404 if it asked.
CUR_ASSETS="$WORK/assets-current"
mkdir -p "$CUR_ASSETS"
for pair in "x86_64-unknown-linux-musl:$CUR_AMD64" "aarch64-unknown-linux-musl:$CUR_ARM64"; do
    asset="meow-${CUR_VERSION}-${pair%%:*}.tar.gz"
    printf '%s  %s\n' "${pair#*:}" "$asset" >"$CUR_ASSETS/$asset.sha256"
done

# --- the stubs ----------------------------------------------------------------
STUB="$WORK/bin"
mkdir -p "$STUB"

# gh: answers the release lookup with $STUB_TAG.
cat >"$STUB/gh" <<STUB
#!/bin/sh
if [ "\$1" = "api" ] && [ "\$2" = "repos/meow-rs/meow-rs/releases/latest" ]; then
    printf '%s\n' "\${STUB_TAG:-$NEW_VERSION}"
    exit 0
fi
echo "gh stub: unexpected call: \$*" >&2
exit 1
STUB

# curl: serves \$STUB_ASSETS/<url basename>, records every fetch so the
# test can tell a checksum-only run from one that pulled the archives.
cat >"$STUB/curl" <<'STUB'
#!/bin/sh
dest=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) dest="$2"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
name="${url##*/}"
printf '%s\n' "$name" >>"$STUB_FETCHED"
if [ -f "$STUB_ASSETS/$name" ]; then
    cp "$STUB_ASSETS/$name" "$dest"
    exit 0
fi
echo "curl stub: 404 $url" >&2
exit 22
STUB
chmod +x "$STUB/gh" "$STUB/curl"

export PATH="$STUB:$PATH"
export STUB_FETCHED="$WORK/fetched"

# A fresh fixture checkout: the five real files plus the two scripts the
# updater needs, so `dirname $0/..` resolves inside the fixture.
new_repo() { # new_repo <label> -> REPO
    REPO="$WORK/repo-$1"
    mkdir -p "$REPO/scripts" "$REPO/docker/meow"
    local f
    for f in "${PIN_FILES[@]}"; do
        cp "$ROOT/$f" "$REPO/$f"
    done
    cp "$SCRIPT" "$REPO/scripts/update-meow-pin.sh"
    cp "$ROOT/scripts/validate-meow-version.sh" "$REPO/scripts/validate-meow-version.sh"
    chmod +x "$REPO/scripts/update-meow-pin.sh" "$REPO/scripts/validate-meow-version.sh"
}

run_script() { # run_script [args...] -> CODE, OUT (uses $REPO)
    set +e
    OUT="$("$REPO/scripts/update-meow-pin.sh" "$@" 2>"$WORK/err")"
    CODE=$?
    set -e
}

assert_absent() { # assert_absent <needle> <file> <label>
    if grep -qF -- "$1" "$2"; then
        fail "$3: '$1' is still present in $2"
    fi
}

assert_present() { # assert_present <needle> <file> <label>
    if ! grep -qF -- "$1" "$2"; then
        fail "$3: '$1' is missing from $2"
    fi
}

count_of() { # count_of <needle> <file>
    grep -oF -- "$1" "$2" | wc -l | tr -d '[:space:]'
}

# --- a bump reaches every pin, and only the pins ------------------------------
new_repo bump
export STUB_ASSETS="$NEW_ASSETS"
: >"$STUB_FETCHED"
GITHUB_OUTPUT="$WORK/output" run_script
[ "$CODE" -eq 0 ] || fail "the bump exited $CODE: $(cat "$WORK/err")"

grep -q '^updated=true$' "$WORK/output" || fail "expected updated=true in \$GITHUB_OUTPUT"
grep -q "^version=$NEW_VERSION$" "$WORK/output" || fail "expected version=$NEW_VERSION"
grep -q "^previous_version=$CUR_VERSION$" "$WORK/output" || fail "expected previous_version=$CUR_VERSION"
grep -q "^sha256_amd64=$AMD64_SUM$" "$WORK/output" || fail "expected the amd64 sum in \$GITHUB_OUTPUT"
grep -q "^sha256_arm64=$ARM64_SUM$" "$WORK/output" || fail "expected the arm64 sum in \$GITHUB_OUTPUT"

# Both archives were downloaded and verified, not just the checksum files.
grep -qx "$AMD64_ASSET" "$STUB_FETCHED" || fail "the amd64 archive was not verified"
grep -qx "$ARM64_ASSET" "$STUB_FETCHED" || fail "the arm64 archive was not verified"

for f in docker/meow/Dockerfile docker-compose.build.yml .env.example; do
    assert_absent "$CUR_VERSION" "$REPO/$f" "the version bump"
    assert_absent "$CUR_AMD64" "$REPO/$f" "the amd64 bump"
    assert_absent "$CUR_ARM64" "$REPO/$f" "the arm64 bump"
    assert_present "$NEW_VERSION" "$REPO/$f" "the version bump"
    assert_present "$AMD64_SUM" "$REPO/$f" "the amd64 bump"
    assert_present "$ARM64_SUM" "$REPO/$f" "the arm64 bump"
done

# The Dockerfile header's `docker build` example claims to show the current
# pin, so it moves with the ARG block: two occurrences, not one.
[ "$(count_of "$NEW_VERSION" "$REPO/docker/meow/Dockerfile")" -eq 2 ] \
    || fail "the Dockerfile must carry the new version in both the ARG and the header example"
[ "$(count_of "$AMD64_SUM" "$REPO/docker/meow/Dockerfile")" -eq 2 ] \
    || fail "the Dockerfile must carry the new amd64 sum in both places"
[ "$(count_of "$ARM64_SUM" "$REPO/docker/meow/Dockerfile")" -eq 2 ] \
    || fail "the Dockerfile must carry the new arm64 sum in both places"

# The guides: the table cell is the documented default and moves; the
# prose example of the dispatch input is illustrative and stays.
for g in USERGUIDE.md USERGUIDE.ru.md; do
    row="$(grep "^| \`MEOW_VERSION\`" "$REPO/$g")"
    if ! printf '%s' "$row" | grep -qF "\`$NEW_VERSION\`"; then
        fail "$g: the MEOW_VERSION table row was not bumped"
    fi
    if printf '%s' "$row" | grep -qF "$CUR_VERSION"; then
        fail "$g: the table row still documents the old version"
    fi
    [ "$(count_of "$CUR_VERSION" "$REPO/$g")" -eq 1 ] \
        || fail "$g: only the prose example should still name the old version"
done
note "a bump rewrites all five files, the header example, and only the table cell in the guides"

# The rewrite must not leave sed's backup files behind.
if [ -n "$(find "$REPO" -name '*.bak' -print -quit)" ]; then
    fail "sed backup files were left in the tree"
fi
note "no .bak files are left behind"

# --- an already-current pin is a no-op, without the archive downloads ---------
new_repo noop
export STUB_ASSETS="$CUR_ASSETS"
: >"$STUB_FETCHED"
before="$(cat "$REPO/docker/meow/Dockerfile" "$REPO/docker-compose.build.yml" "$REPO/.env.example")"
STUB_TAG="$CUR_VERSION" GITHUB_OUTPUT="$WORK/output-noop" run_script
[ "$CODE" -eq 0 ] || fail "a current pin must exit 0, got $CODE: $(cat "$WORK/err")"
grep -q '^updated=false$' "$WORK/output-noop" || fail "expected updated=false for a current pin"
after="$(cat "$REPO/docker/meow/Dockerfile" "$REPO/docker-compose.build.yml" "$REPO/.env.example")"
[ "$before" = "$after" ] || fail "a no-op run must not rewrite anything"
if grep -q '\.tar\.gz$' "$STUB_FETCHED"; then
    fail "a no-op run must not download the archives"
fi
note "an already-current pin changes nothing and skips the archive downloads"

# --- an archive that does not match the published sum fails closed ------------
new_repo mismatch
export STUB_ASSETS="$BAD_ASSETS"
before="$(cat "$REPO/docker/meow/Dockerfile")"
run_script --version "$NEW_VERSION"
[ "$CODE" -ne 0 ] || fail "a sum mismatch must fail the bump"
grep -q 'does not match the sum the release publishes' "$WORK/err" \
    || fail "expected a sum-mismatch diagnostic, got: $(cat "$WORK/err")"
[ "$before" = "$(cat "$REPO/docker/meow/Dockerfile")" ] \
    || fail "a failed verification must leave the tree untouched"
note "a sum mismatch fails before anything is written"

# --- a missing published sum fails closed ------------------------------------
new_repo nosum
export STUB_ASSETS="$CUR_ASSETS"
run_script --version "$NEW_VERSION"
[ "$CODE" -ne 0 ] || fail "a release without the .sha256 assets must fail"
note "a release without usable checksum assets fails"

# --- the version rule is the one docker-meow.yml applies ----------------------
new_repo badversion
before="$(cat "$REPO/docker/meow/Dockerfile")"
run_script --version latest
[ "$CODE" -ne 0 ] || fail "'latest' must be refused"
[ "$before" = "$(cat "$REPO/docker/meow/Dockerfile")" ] || fail "a refused version must not write"
note "a non-versioned tag is refused by the shared validator"

# --- a missing anchor fails instead of half-applying -------------------------
new_repo anchor
grep -v '^ARG MEOW_SHA256_ARM64=' "$REPO/docker/meow/Dockerfile" >"$REPO/docker/meow/Dockerfile.tmp"
mv "$REPO/docker/meow/Dockerfile.tmp" "$REPO/docker/meow/Dockerfile"
run_script --version "$NEW_VERSION"
[ "$CODE" -ne 0 ] || fail "a missing ARG anchor must fail the bump"
grep -q 'expected exactly one ARG MEOW_SHA256_ARM64=' "$WORK/err" \
    || fail "expected a missing-anchor diagnostic, got: $(cat "$WORK/err")"
note "a missing ARG anchor fails loudly"

# --- argument parsing --------------------------------------------------------
new_repo args
run_script --nonsense
[ "$CODE" -eq 64 ] || fail "an unknown flag must exit 64, got $CODE"
run_script --version
[ "$CODE" -eq 64 ] || fail "--version without a value must exit 64, got $CODE"
note "the argument parsing is validated"

# --- the real working tree was never touched ---------------------------------
for f in "${PIN_FILES[@]}"; do
    printf '%s  %s\n' "$(sha256_of "$ROOT/$f")" "$f"
done >"$WORK/real-after"
cmp -s "$REAL_SNAPSHOT" "$WORK/real-after" \
    || fail "the real working tree was modified by the test"
note "the real working tree was not written to"

echo
echo "update-meow-pin.sh: all checks passed"