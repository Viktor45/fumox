#!/usr/bin/env bash
# Fixture test for scripts/cleanup-ghcr.sh.
#
# The script decides which GHCR versions may be deleted. The rules are
# subtle enough (a per-arch child of a live index must survive, an
# attestation must survive together with its subject, a response that
# does not match the API schema must not be read as "everything is
# untagged") that they need a test of their own: `gh` and `docker` are
# replaced by stubs that answer from a fixture directory, so no network
# and no registry are involved.
#
# Run directly:  bash scripts/tests/cleanup-ghcr.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/cleanup-ghcr.sh"

if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-cleanup-ghcr-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

STUB="$WORK/bin"
FIX="$WORK/fixtures"
mkdir -p "$STUB" "$FIX/tags" "$FIX/manifests"

# --- the digests the fixture describes ---------------------------------------
# The merged index behind the `latest` tag and its two per-arch children.
D_LATEST="sha256:1111111111111111111111111111111111111111111111111111111111111111"
D_CHILD1="sha256:2222222222222222222222222222222222222222222222222222222222222222"
D_CHILD2="sha256:3333333333333333333333333333333333333333333333333333333333333333"
# The merged index of an old build, tagged only with a transient sha-*.
D_SHA="sha256:4444444444444444444444444444444444444444444444444444444444444444"
# An untagged version nobody references any more.
D_ORPHAN="sha256:5555555555555555555555555555555555555555555555555555555555555555"
# The attestation manifest and the image manifest it vouches for.
D_ATTEST="sha256:6666666666666666666666666666666666666666666666666666666666666666"
D_SUBJECT="sha256:7777777777777777777777777777777777777777777777777777777777777777"
# A fresh build: sha-only, but younger than the retention window.
D_RECENT="sha256:8888888888888888888888888888888888888888888888888888888888888888"

OLD="2020-01-01T00:00:00Z"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '%s\n' "$D_LATEST" >"$FIX/tags/latest.digest"
printf '%s\n' "$D_SHA" >"$FIX/tags/sha-1111111.digest"
printf '%s\n' "$D_RECENT" >"$FIX/tags/sha-2222222.digest"

cat >"$FIX/manifests/$D_LATEST.json" <<JSON
{"schemaVersion":2,"manifests":[{"digest":"$D_CHILD1"},{"digest":"$D_CHILD2"}]}
JSON

cat >"$FIX/manifests/$D_ATTEST.json" <<JSON
{"schemaVersion":2,"subject":{"digest":"$D_SUBJECT"},"predicateType":"https://slsa.dev/provenance/v1"}
JSON

# The version list the API returns. Seven versions, one page.
cat >"$FIX/page-1.json" <<JSON
[
  {"id": 1, "name": "$D_SHA",     "created_at": "$OLD",
   "metadata": {"container": {"tags": ["sha-1111111"]}}},
  {"id": 2, "name": "$D_LATEST",  "created_at": "$OLD",
   "metadata": {"container": {"tags": ["latest", "0.2.0"]}}},
  {"id": 3, "name": "$D_CHILD1",  "created_at": "$OLD",
   "metadata": {"container": {"tags": []}}},
  {"id": 4, "name": "$D_ORPHAN",  "created_at": "$OLD",
   "metadata": {"container": {"tags": []}}},
  {"id": 5, "name": "$D_ATTEST",  "created_at": "$OLD",
   "metadata": {"container": {"tags": []}}},
  {"id": 6, "name": "$D_SUBJECT", "created_at": "$OLD",
   "metadata": {"container": {"tags": []}}},
  {"id": 7, "name": "$D_RECENT",  "created_at": "$NOW",
   "metadata": {"container": {"tags": ["sha-2222222"]}}}
]
JSON
printf '[]\n' >"$FIX/page-2.json"

# --- the stubs ----------------------------------------------------------------
cat >"$STUB/gh" <<'STUB'
#!/bin/sh
# gh stub. Answers from the fixture directory, records every DELETE.
method=GET
path=""
for arg in "$@"; do
    case "$arg" in
        -X) method=DELETE ;;
        -*) ;;
        /*) path="$arg" ;;
    esac
done

case "$path" in
    */packages/container/*/versions/*)
        if [ "$method" = "DELETE" ]; then
            printf '%s\n' "$path" >>"$FIX/deleted"
            exit 0
        fi
        ;;
    */packages/container/*/versions*)
        page="${path##*page=}"
        if [ -f "$FIX/page-$page.json" ]; then
            cat "$FIX/page-$page.json"
            exit 0
        fi
        echo "gh: HTTP 404: Not Found" >&2
        exit 1
        ;;
    /orgs/*)
        if [ "${STUB_ORG_LOOKUP:-ok}" = "fail" ]; then
            echo "gh: HTTP 404: Not Found" >&2
            exit 1
        fi
        echo "Organization"
        exit 0
        ;;
    /users/*)
        case "${STUB_OWNER_TYPE:-User}" in
            fail)
                echo "gh: HTTP 404: Not Found" >&2
                exit 1
                ;;
            *)
                echo "${STUB_OWNER_TYPE:-User}"
                exit 0
                ;;
        esac
        ;;
esac

echo "gh: unhandled path: $path" >&2
exit 1
STUB
chmod +x "$STUB/gh"

cat >"$STUB/docker" <<'STUB'
#!/bin/sh
# docker stub. Only `buildx imagetools inspect` is used by the script.
if [ "$1" = "login" ]; then
    cat >/dev/null
    exit 0
fi
if [ "$1" != "buildx" ] || [ "$2" != "imagetools" ] || [ "$3" != "inspect" ]; then
    exit 0
fi

ref="$4"
mode="$5"
digest=""
case "$ref" in
    *@*) digest="${ref##*@}" ;;
    *:*) digest="$(cat "$FIX/tags/${ref##*:}.digest" 2>/dev/null || true)" ;;
esac
[ -n "$digest" ] || exit 1

case "$mode" in
    --raw)
        if [ -f "$FIX/manifests/$digest.json" ]; then
            cat "$FIX/manifests/$digest.json"
            exit 0
        fi
        exit 1
        ;;
    --format)
        printf '%s\n' "$digest"
        exit 0
        ;;
esac
exit 1
STUB
chmod +x "$STUB/docker"

OUT=""
CODE=0
run() { # run <args...> -> OUT (the combined output) and CODE
    set +e
    OUT="$(PATH="$STUB:$PATH" FIX="$FIX" GH_TOKEN=test-token \
        "$SCRIPT" "$@" 2>&1)"
    CODE=$?
    set -e
}

assert_says() { # assert_says <needle> <haystack> <label>
    if ! printf '%s' "$2" | grep -qF -- "$1"; then
        fail "$3: expected '$1' in the output"
    fi
}

assert_not_says() { # assert_not_says <needle> <haystack> <label>
    if printf '%s' "$2" | grep -qF -- "$1"; then
        fail "$3: unexpected '$1' in the output"
    fi
}

assert_deleted() { # assert_deleted <id> <deleted paths> <label>
    if ! printf '%s' "$2" | grep -qE "/versions/$1\$"; then
        fail "$3: version $1 was not deleted: $2"
    fi
}

assert_not_deleted() { # assert_not_deleted <id> <deleted paths> <label>
    if printf '%s' "$2" | grep -qE "/versions/$1\$"; then
        fail "$3: version $1 was deleted but must survive: $2"
    fi
}

# --- 1. the default pass keeps every untagged version ------------------------
run --owner viktor45 --packages fumox --dry-run
[ "$CODE" -eq 0 ] || fail "the default dry run exited $CODE"
assert_says "would delete id=1" "$OUT" "the sha-*-only version"
assert_not_says "would delete id=3" "$OUT" "the child of the live index"
assert_not_says "would delete id=4" "$OUT" "the untagged orphan"
assert_not_says "would delete id=5" "$OUT" "the attestation"
assert_not_says "would delete id=6" "$OUT" "the attestation subject"
assert_not_says "would delete id=7" "$OUT" "the recent build"
assert_says "packages processed: 1, skipped: 0" "$OUT" "the package counters"
note "without --prune-untagged only the sha-*-only version is a candidate"

# --- 2. with --prune-untagged the orphan goes, the referenced ones stay ------
run --owner viktor45 --packages fumox --dry-run --prune-untagged
[ "$CODE" -eq 0 ] || fail "the pruning dry run exited $CODE"
assert_says "would delete id=1" "$OUT" "the sha-*-only version"
assert_says "would delete id=4" "$OUT" "the untagged orphan"
assert_not_says "would delete id=3" "$OUT" "the child of the live index"
assert_not_says "would delete id=5" "$OUT" "the attestation"
assert_not_says "would delete id=6" "$OUT" "the attestation subject"
assert_not_says "would delete id=7" "$OUT" "the recent build"
note "with --prune-untagged the unreferenced orphan is a candidate too"

# --- 3. the deletion itself only touches the candidates ----------------------
: >"$FIX/deleted"
run --owner viktor45 --packages fumox --no-dry-run --prune-untagged
[ "$CODE" -eq 0 ] || fail "the real run exited $CODE"
DELETED="$(cat "$FIX/deleted")"
assert_deleted 1 "$DELETED" "the sha-*-only version"
assert_deleted 4 "$DELETED" "the untagged orphan"
for id in 2 3 5 6 7; do
    assert_not_deleted "$id" "$DELETED" "a version that must survive"
done
note "only the two candidates are deleted"

# --- 4. a response that is not the documented shape is not read as a list ----
cp "$FIX/page-1.json" "$FIX/page-1.json.bak"
printf '{"message":"Not Found"}\n' >"$FIX/page-1.json"
run --owner viktor45 --packages fumox --dry-run
[ "$CODE" -eq 1 ] || fail "a malformed response must fail the run, got $CODE"
assert_says "packages processed: 0, skipped: 1" "$OUT" "the package counters"
assert_says "does not match the expected schema" "$OUT" "the schema complaint"
mv "$FIX/page-1.json.bak" "$FIX/page-1.json"
note "a response that does not match the schema aborts the package"

# --- 5. the owner type decides the API root ---------------------------------
run --owner viktor45 --packages fumox --dry-run
assert_says "Owner viktor45 → /users/viktor45" "$OUT" "a user-owned account"

: >"$FIX/deleted"
STUB_OWNER_TYPE=Organization run --owner viktor45 --packages fumox --no-dry-run
assert_says "Owner viktor45 → /orgs/viktor45" "$OUT" "an organisation-owned account"
DELETED="$(cat "$FIX/deleted")"
if ! printf '%s' "$DELETED" | grep -q '/orgs/viktor45/packages/container/'; then
    fail "the org-scoped API path was not used: $DELETED"
fi
note "an organisation-owned account is read through /orgs"

# The /users lookup fails and /orgs answers: the fallback must kick in.
: >"$FIX/deleted"
STUB_OWNER_TYPE=fail run --owner viktor45 --packages fumox --no-dry-run
assert_says "Owner viktor45 → /orgs/viktor45" "$OUT" "the /orgs fallback"
DELETED="$(cat "$FIX/deleted")"
if ! printf '%s' "$DELETED" | grep -q '/orgs/viktor45/packages/container/'; then
    fail "the /orgs fallback did not reach the versions API: $DELETED"
fi
note "a failing /users lookup falls back to /orgs"

# Neither lookup answers: /users is the default, and the run still works.
STUB_OWNER_TYPE=fail STUB_ORG_LOOKUP=fail \
    run --owner viktor45 --packages fumox --dry-run
assert_says "Owner viktor45 → /users/viktor45" "$OUT" "the default API root"
note "when no lookup answers /users is used"

# --- 6. the arguments are validated -----------------------------------------
set +e
PATH="$STUB:$PATH" "$SCRIPT" --bogus >/dev/null 2>&1
CODE=$?
set -e
[ "$CODE" -eq 64 ] || fail "an unknown flag must exit 64, got $CODE"

set +e
PATH="$STUB:$PATH" "$SCRIPT" --owner viktor45 >/dev/null 2>&1
CODE=$?
set -e
[ "$CODE" -eq 64 ] || fail "a missing --packages must exit 64, got $CODE"

set +e
PATH="$STUB:$PATH" "$SCRIPT" --owner viktor45 --packages fumox --retention-days 0 >/dev/null 2>&1
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "a retention of 0 days must be rejected, got $CODE"
note "the arguments are validated"

echo
echo "cleanup-ghcr.sh: all checks passed"
