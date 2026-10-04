#!/usr/bin/env bash
# Integration test for scripts/revive-xhttp-proxies.sh, the one-shot
# revival of vless/xhttp rows meow 0.22 can tunnel again.
#
# The script is operational tooling with real write paths (revive,
# adoption, restore), and the restore's integrity/liveness guards are
# exactly what commit 78ad528 hardened. This test drives the script
# against a scratch SQLite database carrying the column subset the script
# touches, and asserts on both the data and the exit codes. It needs only
# bash and the sqlite3 CLI, so CI runs it right after `cargo test`.
#
# Run directly:  bash scripts/tests/revive-xhttp-proxies.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/revive-xhttp-proxies.sh"

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "SKIP: sqlite3 CLI not installed"
    exit 0
fi
if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-revive-test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

DB="$WORK/fumox.db"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

expect_eq() { # label actual expected
    [[ "$2" == "$3" ]] || fail "$1: expected '$3', got '$2'"
    note "$1 = $3"
}

q() { sqlite3 -cmd ".timeout 5000" "$DB" "$1"; }

count_backups() {
    ls "$WORK"/fumox.db.pre-xhttp-revival-* 2>/dev/null | wc -l | tr -d ' '
}

assert_output() { # output pattern
    grep -Eq "$2" <<<"$1" || fail "expected output matching /$2/, got:
$1"
    note "output matches /$2/"
}

# ── Scratch database ─────────────────────────────────────────────
# Mirrors the production column names/types the script reads and writes
# (proxies, sources, proxy_source_links, probe_requests), not the whole
# schema: the tool must keep working against exactly what it queries.
sqlite3 -cmd ".timeout 5000" "$DB" <<'SQL'
CREATE TABLE proxies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scheme           TEXT NOT NULL,
    params           TEXT,
    status           TEXT NOT NULL DEFAULT 'unknown',
    fail_count       INTEGER NOT NULL DEFAULT 0,
    quarantined_at   INTEGER,
    ladder_at        INTEGER,
    ladder_step      INTEGER NOT NULL DEFAULT 0,
    removed_at       INTEGER,
    last_t2_failed_at INTEGER,
    updated_at       INTEGER NOT NULL
);
CREATE TABLE sources (
    id         TEXT PRIMARY KEY,
    slug       TEXT UNIQUE,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    pipeline   TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE proxy_source_links (
    proxy_id  INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    seen_at   INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, source_id)
);
CREATE TABLE probe_requests (
    proxy_id     INTEGER PRIMARY KEY,
    requested_at INTEGER NOT NULL
);

INSERT INTO sources (id, slug, name, enabled, pipeline, created_at)
VALUES ('srcA0000000', 'alpha', 'Alpha', 1, NULL, 1000);

INSERT INTO proxies (id, scheme, params, status, fail_count, removed_at, updated_at) VALUES
  (1, 'vless', '{"type":"xhttp"}', 'removed', 7, 500, 500),
  (2, 'vless', '{"type":"xhttp"}', 'removed', 3, 500, 500),
  (3, 'vless', '{"type":"ws"}',    'removed', 2, 500, 500),
  (4, 'vless', '{"type":"xhttp"}', 'alive',   0, NULL, 500);

INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
VALUES (1, 'srcA0000000', 500);
SQL

# ── --help ───────────────────────────────────────────────────────
OUT="$("$SCRIPT" --help)"
assert_output "$OUT" "revive-xhttp-proxies.sh"

# ── Dry run: counts only, nothing written ────────────────────────
OUT="$("$SCRIPT" --dry-run "$DB" 2>&1)" || fail "dry run failed:
$OUT"
assert_output "$OUT" "xhttp transport: 3"
assert_output "$OUT" "live lane: +1"
assert_output "$OUT" "with a source link: +1"
assert_output "$OUT" "would revive 1 row\(s\)"
expect_eq "dry run leaves status" "$(q "SELECT status FROM proxies WHERE id = 1")" "removed"
expect_eq "dry run writes no backup" "$(count_backups)" "0"

# ── Real run, default scope: linked rows only ────────────────────
OUT="$("$SCRIPT" "$DB" 2>&1)" || fail "revive run failed:
$OUT"
assert_output "$OUT" "revived: +1"
assert_output "$OUT" "enqueued for priority checking: 1"
assert_output "$OUT" "To undo, restore"
expect_eq "backup written" "$(count_backups)" "1"
expect_eq "linked row revived" "$(q "SELECT status FROM proxies WHERE id = 1")" "unknown"
expect_eq "fail_count reset" "$(q "SELECT fail_count FROM proxies WHERE id = 1")" "0"
expect_eq "ladder fields cleared" \
    "$(q "SELECT COUNT(*) FROM proxies WHERE id = 1
           AND ladder_at IS NULL AND ladder_step = 0 AND removed_at IS NULL
           AND quarantined_at IS NULL AND last_t2_failed_at IS NULL")" "1"
expect_eq "unlinked xhttp row skipped" "$(q "SELECT status FROM proxies WHERE id = 2")" "removed"
expect_eq "non-xhttp row untouched" "$(q "SELECT status FROM proxies WHERE id = 3")" "removed"
expect_eq "live row untouched" "$(q "SELECT status FROM proxies WHERE id = 4")" "alive"
expect_eq "revived row enqueued for priority check" \
    "$(q "SELECT group_concat(proxy_id) FROM probe_requests")" "1"

BACKUP="$(ls "$WORK"/fumox.db.pre-xhttp-revival-*)"

# ── --restore: the undo, with its integrity guards ───────────────
OUT="$("$SCRIPT" --restore "$BACKUP" "$DB" 2>&1)" || fail "restore failed:
$OUT"
assert_output "$OUT" "restored database passes integrity_check"
expect_eq "restore brings the row back" "$(q "SELECT status FROM proxies WHERE id = 1")" "removed"
expect_eq "restore reverts fail_count" "$(q "SELECT fail_count FROM proxies WHERE id = 1")" "7"
expect_eq "restore drops the enqueue" "$(q "SELECT COUNT(*) FROM probe_requests")" "0"

# A damaged backup is refused before anything is touched.
printf 'not a sqlite database' >"$WORK/garbage.db"
set +e
OUT="$("$SCRIPT" --restore "$WORK/garbage.db" "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "damaged backup exit code" "$CODE" "67"
assert_output "$OUT" "does not pass PRAGMA integrity_check"
expect_eq "refusal leaves the database alone" "$(q "SELECT status FROM proxies WHERE id = 1")" "removed"

# Revival options and --restore are mutually exclusive.
set +e
OUT="$("$SCRIPT" --restore "$BACKUP" --include-unlinked "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "conflicting options exit code" "$CODE" "64"
assert_output "$OUT" "takes none of the revival options"

# ── --include-unlinked with an explicit adoption target ──────────
OUT="$("$SCRIPT" --include-unlinked --adopt-source srcA0000000 "$DB" 2>&1)" || fail "adoption run failed:
$OUT"
assert_output "$OUT" "revived: +2"
assert_output "$OUT" "adopted: +1 into Alpha \(srcA0000000\)"
expect_eq "linked row revived" "$(q "SELECT status FROM proxies WHERE id = 1")" "unknown"
expect_eq "unlinked row revived" "$(q "SELECT status FROM proxies WHERE id = 2")" "unknown"
expect_eq "unlinked row adopted into the source" \
    "$(q "SELECT COUNT(*) FROM proxy_source_links WHERE proxy_id = 2 AND source_id = 'srcA0000000'")" "1"
expect_eq "both rows enqueued" "$(q "SELECT COUNT(*) FROM probe_requests")" "2"
expect_eq "non-xhttp row still untouched" "$(q "SELECT status FROM proxies WHERE id = 3")" "removed"

echo
echo "revive-xhttp-proxies.sh: all checks passed"
