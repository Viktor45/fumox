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

q_on() { sqlite3 -cmd ".timeout 5000" "$1" "$2"; }

count_backups() {
    ls "$WORK"/fumox.db.pre-xhttp-revival-* 2>/dev/null | wc -l | tr -d ' '
}

assert_output() { # output pattern
    grep -Eq "$2" <<<"$1" || fail "expected output matching /$2/, got:
$1"
    note "output matches /$2/"
}

assert_no_output() { # output pattern
    if grep -Eq "$2" <<<"$1"; then
        fail "expected no output matching /$2/, got:
$1"
    fi
    note "no output matches /$2/"
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

# ── the adoption flags need --include-unlinked ──────────────────
# They only have a subject together with it: the linked half keeps the
# link it already has. A flag that is silently ignored is worse than a
# refusal, because the operator believes a target was chosen.
set +e
OUT="$("$SCRIPT" --adopt-source srcA0000000 "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "adopt-source without include-unlinked exit code" "$CODE" "64"
assert_output "$OUT" "only apply together with"

set +e
OUT="$("$SCRIPT" --no-adopt "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "no-adopt without include-unlinked exit code" "$CODE" "64"
assert_output "$OUT" "only apply together with"

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

# ── --adopt-source never reaches SQL raw ─────────────────────────
# A fresh unlinked removed row so the adoption block runs below; every run
# in this block is dry, so it survives all of them.
q "INSERT INTO proxies (id, scheme, params, status, fail_count, removed_at, updated_at)
   VALUES (5, 'vless', '{\"type\":\"xhttp\"}', 'removed', 1, 500, 500)"

# The injection payload: interpolated raw this dropped the proxies table
# before any backup was taken, even in a dry run.
set +e
OUT="$("$SCRIPT" --dry-run --include-unlinked --adopt-source "x'; DROP TABLE proxies;--" "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "injection attempt exit code" "$CODE" "67"
assert_output "$OUT" "no source matches"
expect_eq "injection left the proxies table in place" "$(q 'SELECT COUNT(*) FROM proxies')" "5"

# Escaping rather than refusing: a legitimate name that carries quotes must
# still match, or every source with an apostrophe would become unadoptable.
q "INSERT INTO sources (id, slug, name, enabled, pipeline, created_at)
   VALUES ('srcC0000000', 'quoted', 'O''Brien''s list', 1, NULL, 1200)"
OUT="$("$SCRIPT" --dry-run --include-unlinked --adopt-source "O'Brien's list" "$DB" 2>&1)" || fail "quoted-name run failed:
$OUT"
assert_output "$OUT" "adopt into: O'Brien's list \(srcC0000000\)"
assert_output "$OUT" "enabled, no drop rules"
assert_output "$OUT" "would revive 1 row\(s\)"
expect_eq "dry run still writes no backup" "$(count_backups)" "2"

# ── a pipe in a source name cannot shift the report's split ──────
# The name rides last in the sqlite3 rows so the fields the classification
# reads (enabled, drops) cannot be pushed out of place by a 'foo|bar' name.
q "INSERT INTO sources (id, slug, name, enabled, pipeline, created_at)
   VALUES ('srcB0000000', 'beta', 'Beta|Gamma', 1, NULL, 900)"

# ── a source id that carries a quote is never interpolated ───────
# The id reaches a SQL string literal, so only a plain nanoid may be used.
# The ranked path has to skip such a source rather than paste its id
# into the statement; created_at 800 puts it first in the ranking, so a
# ranked run that ignored the rule would adopt it.
q "INSERT INTO sources (id, slug, name, enabled, pipeline, created_at)
   VALUES ('src''D000000', 'quoted-id', 'Quoted Id', 1, NULL, 800)"

# Ranked path: the quoted id is skipped, the pipe-named source is next.
OUT="$("$SCRIPT" --dry-run --include-unlinked "$DB" 2>&1)" || fail "ranked adoption run failed:
$OUT"
assert_output "$OUT" "adopt into: Beta|Gamma \(srcB0000000\)"
assert_output "$OUT" "enabled, no drop rules"
assert_no_output "$OUT" "has 1 drop rule"
assert_no_output "$OUT" "Quoted Id"

# Explicit path: named directly, the id is refused rather than used.
set +e
OUT="$("$SCRIPT" --dry-run --include-unlinked --adopt-source "src'D000000" "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "quoted source id exit code" "$CODE" "67"
assert_output "$OUT" "is not a plain nanoid"
expect_eq "the quoted id was not adopted into" \
    "$(q "SELECT COUNT(*) FROM proxy_source_links WHERE source_id = 'src''D000000'")" "0"

# Explicit path: matched by the pipe-bearing name itself.
OUT="$("$SCRIPT" --dry-run --include-unlinked --adopt-source 'Beta|Gamma' "$DB" 2>&1)" || fail "pipe-name run failed:
$OUT"
assert_output "$OUT" "adopt into: Beta|Gamma \(srcB0000000\)"
assert_output "$OUT" "enabled, no drop rules"
assert_no_output "$OUT" "has 1 drop rule"

# ── a database the script cannot read is a hard error ────────────
# An exclusive lock used to leave the census empty and the run saying
# "Nothing to revive." with exit 0, with no hint anything had gone wrong.
LOCK_FIFO="$WORK/census-lock.fifo"
mkfifo "$LOCK_FIFO"
sqlite3 "$DB" <"$LOCK_FIFO" >/dev/null 2>&1 &
LOCK_PID=$!
exec 9>"$LOCK_FIFO"
# The BEGIN is re-issued until the lock actually bites: the locker's own
# busy timeout is 0, so one that races a lock the previous scenario was
# still releasing fails once and would otherwise idle for good.
LOCKED=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    kill -0 "$LOCK_PID" 2>/dev/null || break
    printf 'BEGIN EXCLUSIVE;\n' >&9 2>/dev/null || break
    if ! sqlite3 -cmd ".timeout 0" "$DB" 'SELECT count(*) FROM sqlite_master;' >/dev/null 2>&1; then
        LOCKED=1
        break
    fi
    sleep 0.1
done
[[ "$LOCKED" -eq 1 ]] || fail "could not take the exclusive lock this test needs"
set +e
OUT="$(FUMOX_SQLITE_BUSY_TIMEOUT_MS=50 "$SCRIPT" --dry-run "$DB" 2>&1)"
CODE=$?
set -e
printf '.quit\n' >&9
exec 9>&-
wait "$LOCK_PID" 2>/dev/null || true
expect_eq "locked census exit code" "$CODE" "75"
assert_output "$OUT" "could not read the census"
# The success verdict as its own line must be gone (the error text itself
# mentions the phrase, so the pattern is anchored to the whole line).
assert_no_output "$OUT" '^Nothing to revive\.$'
expect_eq "locked run left the row removed" "$(q 'SELECT status FROM proxies WHERE id = 5')" "removed"

# ── the error path cannot offer the bare cp the header forbids ───
# A stub sqlite3 that corrupts exactly the revival batch drives the run
# down the count-parse-failure exit, whose undo advice must not be a bare cp.
REAL_SQLITE3="$(command -v sqlite3)"
mkdir -p "$WORK/stub"
cat >"$WORK/stub/sqlite3" <<STUB
#!/bin/sh
input=\$(cat)
case "\$input" in
  *xhttp_revive*) printf 'stub noise, no pipe-separated counts here\n'; exit 0 ;;
esac
printf '%s' "\$input" | "$REAL_SQLITE3" "\$@"
STUB
chmod +x "$WORK/stub/sqlite3"
set +e
OUT="$(PATH="$WORK/stub:$PATH" "$SCRIPT" --include-unlinked "$DB" 2>&1 </dev/null)"
CODE=$?
set -e
expect_eq "count parse failure exit code" "$CODE" "70"
assert_output "$OUT" "could not read the revived count back from sqlite3"
assert_output "$OUT" "the backup .* is intact. To undo, stop the daemon"
assert_no_output "$OUT" "restore with: cp"
BACKUP_PATH="$(grep -oE "$DB\.pre-xhttp-revival-[0-9]+-[0-9]+" <<<"$OUT" | head -1)"
[[ -n "$BACKUP_PATH" && -f "$BACKUP_PATH" ]] || fail "the undo advice names a backup that does not exist: ${BACKUP_PATH:-<none>}"
note "the undo advice names a backup that exists"
expect_eq "parse failure left row 5 removed" "$(q 'SELECT status FROM proxies WHERE id = 5')" "removed"

# ── the backup is not readable by anyone else ────────────────────
# It holds the whole database, credentials included.
BACKUP_MODE="$(stat -f '%Lp' "$BACKUP" 2>/dev/null || stat -c '%a' "$BACKUP" 2>/dev/null || echo '')"
expect_eq "backup permissions" "$BACKUP_MODE" "600"

# ── the restore refuses the paths it must not follow ─────────────
# A symlink at the database path is a link to something else, and a
# symlink at the backup path would restore whatever it points at.
ln -s "$DB" "$WORK/link.db"
set +e
OUT="$("$SCRIPT" --restore "$BACKUP" "$WORK/link.db" 2>&1)"
CODE=$?
set -e
expect_eq "symlinked database exit code" "$CODE" "66"
assert_output "$OUT" "is a symlink"

ln -s "$BACKUP" "$WORK/link-backup.db"
set +e
OUT="$("$SCRIPT" --restore "$WORK/link-backup.db" "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "symlinked backup exit code" "$CODE" "66"
assert_output "$OUT" "is a symlink"

# An empty file is not a database.
: >"$WORK/empty.db"
set +e
OUT="$("$SCRIPT" --restore "$WORK/empty.db" "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "empty backup exit code" "$CODE" "67"
assert_output "$OUT" "is empty"

# A valid database that is not Fumox's: restoring it would leave the
# daemon with a schema it cannot query.
sqlite3 "$WORK/foreign.db" "CREATE TABLE something_else (id TEXT);"
set +e
OUT="$("$SCRIPT" --restore "$WORK/foreign.db" "$DB" 2>&1)"
CODE=$?
set -e
expect_eq "foreign schema exit code" "$CODE" "67"
assert_output "$OUT" "does not carry the Fumox schema"
expect_eq "the refusals left the row alone" "$(q 'SELECT status FROM proxies WHERE id = 1')" "unknown"

# ── a database that carries a write-ahead log ────────────────────
# The log belongs to the file the restore replaces, so it goes with it.
# The restore reports the branch it took, because a database that was
# not closed cleanly is worth knowing about.
WAL_DB="$WORK/wal.db"
cp "$DB" "$WAL_DB"
sqlite3 -cmd ".timeout 5000" "$WAL_DB" 'PRAGMA journal_mode=WAL;' >/dev/null
cp "$WAL_DB" "$WORK/wal-backup.db"
WAL_EXPECTED="$(q_on "$WORK/wal-backup.db" 'SELECT status FROM proxies WHERE id = 1;')"
sqlite3 -cmd ".timeout 5000" "$WAL_DB" "UPDATE proxies SET status = 'quarantine' WHERE id = 1;"
expect_eq "the row changed before the restore" \
    "$(q_on "$WAL_DB" 'SELECT status FROM proxies WHERE id = 1;')" "quarantine"

# A writer that dies mid-transaction leaves the log behind: the frames
# are uncommitted and the connection is gone.
WAL_FIFO="$WORK/wal-writer.fifo"
mkfifo "$WAL_FIFO"
sqlite3 -cmd ".timeout 5000" "$WAL_DB" <"$WAL_FIFO" >/dev/null 2>&1 &
WAL_PID=$!
exec 9>"$WAL_FIFO"
printf 'BEGIN IMMEDIATE;\nINSERT INTO proxies (id, scheme, params, status, updated_at) VALUES (99, "vless", "{}", "unknown", 1);\n' >&9
sleep 0.5
kill -9 "$WAL_PID" 2>/dev/null || true
exec 9>&-
wait "$WAL_PID" 2>/dev/null || true
[[ -e "${WAL_DB}-wal" ]] || fail "the killed writer left no write-ahead log behind"
[[ -e "${WAL_DB}-shm" ]] || fail "the killed writer left no shared memory file behind"

OUT="$("$SCRIPT" --restore "$WORK/wal-backup.db" "$WAL_DB" 2>&1)" || fail "restore over a WAL database failed:
$OUT"
assert_output "$OUT" "had a write-ahead log"
assert_output "$OUT" "restored database passes integrity_check"
expect_eq "the row status matches the backup" \
    "$(q_on "$WAL_DB" 'SELECT status FROM proxies WHERE id = 1;')" "$WAL_EXPECTED"
expect_eq "the write-ahead log is gone" \
    "$([[ -e "${WAL_DB}-wal" ]] && echo yes || echo no)" "no"
expect_eq "the shared memory file is gone" \
    "$([[ -e "${WAL_DB}-shm" ]] && echo yes || echo no)" "no"

# ── a database that is still open is not restored over ──────────
# A restore under a live writer is what produces "database disk image
# is malformed", or a restore that quietly changes nothing.
HOLD_DB="$WORK/hold.db"
cp "$DB" "$HOLD_DB"
sqlite3 -cmd ".timeout 5000" "$HOLD_DB" 'PRAGMA journal_mode=WAL;' >/dev/null
HOLD_FIFO="$WORK/hold.fifo"
mkfifo "$HOLD_FIFO"
sqlite3 -cmd ".timeout 5000" "$HOLD_DB" <"$HOLD_FIFO" >/dev/null 2>&1 &
HOLD_PID=$!
exec 9>"$HOLD_FIFO"
# The statement is what makes the connection touch the file: without it
# the CLI waits for input with the database still unopened.
printf 'SELECT count(*) FROM proxies;\n' >&9
sleep 0.5
HOLD_BEFORE="$(q_on "$HOLD_DB" 'SELECT status FROM proxies WHERE id = 1;')"
set +e
OUT="$("$SCRIPT" --restore "$BACKUP" "$HOLD_DB" 2>&1)"
CODE=$?
set -e
exec 9>&-
kill "$HOLD_PID" 2>/dev/null || true
wait "$HOLD_PID" 2>/dev/null || true
expect_eq "held database exit code" "$CODE" "75"
assert_output "$OUT" "still has"
expect_eq "the held database was not touched" \
    "$(q_on "$HOLD_DB" 'SELECT status FROM proxies WHERE id = 1;')" "$HOLD_BEFORE"

echo
echo "revive-xhttp-proxies.sh: all checks passed"
