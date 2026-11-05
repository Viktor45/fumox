#!/usr/bin/env bash
# Fixture test for cliff.toml.
#
# The changelog pipeline is two stages: git-cliff turns commits into the
# flat `date|sha|category|message` draft, scripts/make-changelog.py then
# sections it. The draft's category is decided by the commit_parsers of
# cliff.toml, and a wrong rule there silently mislabels (or leaks) commits
# into CHANGELOG.md: dependency bumps must never reach the draft as
# `Changed` and chore/merge noise must never reach it at all. This fixture
# pins the table: one commit per parser rule, the draft asserted against
# the group each subject is supposed to land in.
#
# Run directly:  bash scripts/tests/cliff-config.test.sh
# Needs git and git-cliff on PATH (the CI step installs git-cliff).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG="$ROOT/cliff.toml"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

command -v git >/dev/null 2>&1 || fail "git is not on PATH"
command -v git-cliff >/dev/null 2>&1 || fail "git-cliff is not on PATH"
[ -f "$CONFIG" ] || fail "${CONFIG} not found"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-cliff-config-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# A throwaway repo with one commit per rule the config must classify.
git init -q "$WORK/repo"
git -C "$WORK/repo" config user.email "cliff-config-test@example.com"
git -C "$WORK/repo" config user.name "cliff-config-test"
(
    cd "$WORK/repo"
    for subject in \
        "feat: add the thing" \
        "fix: repair the other thing" \
        "docs: update the guide" \
        "manual: regenerate the manual" \
        "perf: speed the export up" \
        "refactor: split the parser" \
        "chore: tidy the tree" \
        "chore(deps): bump a crate" \
        "build(deps): bump serde from 1.0.1 to 1.0.2" \
        "Bump tokio from 1.0 to 2.0" \
        "Merge pull request #12 from fumox/branch"; do
        printf '%s\n' "$subject" >file.txt
        git add file.txt
        git commit -qm "$subject"
    done
)

DRAFT="$(cd "$WORK/repo" && git-cliff --config "$CONFIG" --unreleased 2>"$WORK/err")" \
    || fail "git-cliff failed against cliff.toml: $(cat "$WORK/err")"

assert_draft_has() { # assert_draft_has <category> <message-tail>
    if ! printf '%s\n' "$DRAFT" | grep -qF "|$1|$2"; then
        fail "expected '$2' under $1 in the draft"
    fi
}

assert_draft_lacks() { # assert_draft_lacks <needle>
    if printf '%s\n' "$DRAFT" | grep -qF -- "$1"; then
        fail "the draft must not contain '$1'"
    fi
}

# --- the kept subjects land in their Keep a Changelog groups ------------------
assert_draft_has "Added" "Add the thing"
assert_draft_has "Fixed" "Repair the other thing"
assert_draft_has "Docs" "Update the guide"
assert_draft_has "Docs" "Regenerate the manual"
assert_draft_has "Changed" "Speed the export up"
assert_draft_has "Changed" "Split the parser"
note "feat/fix/docs/manual/perf/refactor keep their groups"

# --- the noise never reaches the draft at all ---------------------------------
assert_draft_lacks "|Internal|"
assert_draft_lacks "Tidy the tree"
assert_draft_lacks "Bump a crate"
assert_draft_lacks "Bump serde from 1.0.1 to 1.0.2"
assert_draft_lacks "Bump tokio from 1.0 to 2.0"
assert_draft_lacks "Merge pull request"
note "chore, chore(deps), build(deps), Bump and merge subjects are skipped"

echo
echo "cliff.toml: all checks passed"
