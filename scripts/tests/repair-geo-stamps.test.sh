#!/usr/bin/env bash
# Integration test for scripts/repair-geo-stamps.sh, the one-shot
# clearing of the proxies.geo_* columns.
#
# The script has real write paths (a backup, a table-wide UPDATE), and it
# is the tool an operator reaches for when the geo stamps are wrong. This
# test drives it against a scratch SQLite database and asserts on both the
# data and the exit codes. It needs only bash and the sqlite3 CLI, so CI
# runs it right after `cargo test`.
#
# Run directly:  bash scripts/tests/repair-geo-stamps.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/repair-geo-stamps.sh"

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "SKIP: sqlite3 CLI not installed"
    exit 0
fi
if [[ ! -f "$SCRIPT" ]]; then
    echo "FAIL: ${SCRIPT} not found" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-geo-repair-test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# The script refuses to run in a directory others may write to, so the
# scratch directory is private from the start.
chmod 700 "$WORK"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

expect_eq() { # label actual expected
    [[ "$2" == "$3" ]] || fail "$1: expected '$3', got '$2'"
    note "$1 = $3"
}

q() { sqlite3 -cmd ".timeout 5000" "$1" "$2"; }

make_db() { # path
    sqlite3 -cmd ".timeout 5000" "$1" <<'SQL'
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    geo_country TEXT,
    geo_city    TEXT,
    geo_asn     INTEGER
);
INSERT INTO proxies (geo_country, geo_city, geo_asn) VALUES
  ('DE', 'Berlin', 3320),
  ('US', NULL,    15169),
  (NULL, NULL,    NULL);
SQL
}

# ── a missing database is refused ────────────────────────────────
set +e
OUT="$("$SCRIPT" "$WORK/absent.db" 2>&1)"
CODE=$?
set -e
expect_eq "missing database exit code" "$CODE" "66"
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
assert_output "$OUT" "no database at"

# ── a symlinked database is refused ──────────────────────────────
make_db "$WORK/real.db"
ln -s "$WORK/real.db" "$WORK/link.db"
set +e
OUT="$("$SCRIPT" "$WORK/link.db" 2>&1)"
CODE=$?
set -e
expect_eq "symlinked database exit code" "$CODE" "66"
assert_output "$OUT" "is a symlink"

# ── a directory others may write to is refused ──────────────────
SHARED="$WORK/shared"
mkdir -p "$SHARED"
chmod 777 "$SHARED"
make_db "$SHARED/fumox.db"
set +e
OUT="$("$SCRIPT" "$SHARED/fumox.db" 2>&1)"
CODE=$?
set -e
expect_eq "shared directory exit code" "$CODE" "73"
assert_output "$OUT" "writable by group or others"
expect_eq "no backup was written" "$(ls "$SHARED" | grep -c 'pre-geo-repair' || true)" "0"

# ── a running server stops the run ──────────────────────────────
# The repair and the running backfill write the same rows, so the script
# refuses while a server process is visible.
STUB="$WORK/stub"
mkdir -p "$STUB"
cat >"$STUB/pgrep" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$STUB/pgrep"
make_db "$WORK/running.db"
set +e
OUT="$(PATH="$STUB:$PATH" "$SCRIPT" "$WORK/running.db" 2>&1)"
CODE=$?
set -e
expect_eq "running server exit code" "$CODE" "75"
assert_output "$OUT" "STOP it first"
assert_output "$OUT" "docker compose stop server probe"
expect_eq "no backup was written" \
    "$(ls "$WORK" | grep -c 'running.db.pre-geo-repair' || true)" "0"

# The operator who knows better can override the check.
set +e
OUT="$(FUMOX_ALLOW_RUNNING_SERVER=1 PATH="$STUB:$PATH" "$SCRIPT" "$WORK/running.db" 2>&1)"
CODE=$?
set -e
expect_eq "override exit code" "$CODE" "0"

# ── the happy path ──────────────────────────────────────────────
DB="$WORK/fumox.db"
make_db "$DB"
OUT="$("$SCRIPT" "$DB" 2>&1)" || fail "the repair failed:
$OUT"
assert_output "$OUT" "rows with a geo stamp before repair: 2"
assert_output "$OUT" "rows cleared: 2"
assert_output "$OUT" "rows with a geo stamp after repair:  0"
expect_eq "the stamps are gone" \
    "$(q "$DB" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL OR geo_country IS NOT NULL OR geo_city IS NOT NULL")" \
    "0"

BACKUP="$(ls "$WORK"/fumox.db.pre-geo-repair-* | head -1)"
[[ -n "$BACKUP" ]] || fail "the run must leave a backup behind"
note "the run left a backup behind"

# The backup holds the rows as they were, and it is not readable by
# anyone else: it is a copy of a file that holds the credentials.
expect_eq "the backup keeps the old stamps" \
    "$(q "$BACKUP" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL")" "2"
MODE="$(stat -f '%Lp' "$BACKUP" 2>/dev/null || stat -c '%a' "$BACKUP")"
expect_eq "the backup mode" "$MODE" "600"

# ── an existing backup is never overwritten ──────────────────────
DB2="$WORK/second.db"
make_db "$DB2"
"$SCRIPT" "$DB2" >/dev/null 2>&1
PLANTED="$WORK/planted.db.pre-geo-repair-pinned"
make_db "$WORK/planted.db"
: >"$PLANTED"
set +e
OUT="$(FUMOX_GEO_REPAIR_BACKUP="$PLANTED" "$SCRIPT" "$WORK/planted.db" 2>&1)"
CODE=$?
set -e
expect_eq "existing backup exit code" "$CODE" "73"
assert_output "$OUT" "already exists"
expect_eq "the planted file is untouched" "$(wc -c <"$PLANTED" | tr -d ' ')" "0"

# ── a symlink at the backup path is refused ─────────────────────
SYMLINKED="$WORK/symlinked.db"
make_db "$SYMLINKED"
TARGET="$WORK/target.db"
make_db "$TARGET"
ln -s "$TARGET" "$WORK/symlinked.db.pre-geo-repair-pinned"
set +e
OUT="$(FUMOX_GEO_REPAIR_BACKUP="$WORK/symlinked.db.pre-geo-repair-pinned" "$SCRIPT" "$SYMLINKED" 2>&1)"
CODE=$?
set -e
expect_eq "symlinked backup exit code" "$CODE" "73"
assert_output "$OUT" "already exists"
expect_eq "the symlink target is untouched" \
    "$(q "$TARGET" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL")" "2"

# ── the clearing runs in batches ────────────────────────────────
# One transaction over the whole table holds the write lock for as long
# as it takes; a batch of rows at a time releases it between the batches.
BATCHED="$WORK/batched.db"
sqlite3 -cmd ".timeout 5000" "$BATCHED" <<'SQL'
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    geo_country TEXT,
    geo_city    TEXT,
    geo_asn     INTEGER
);
WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < 25)
INSERT INTO proxies (geo_country, geo_city, geo_asn)
SELECT 'DE', 'Berlin', 3320 FROM seq;
SQL
OUT="$(FUMOX_GEO_REPAIR_BATCH=1 "$SCRIPT" "$BATCHED" 2>&1)" || fail "the batched repair failed:
$OUT"
expect_eq "every row is cleared" \
    "$(q "$BATCHED" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL")" "0"
assert_output "$OUT" "rows cleared: 25"

# A batch size that is not a number is refused rather than interpolated.
set +e
OUT="$(FUMOX_GEO_REPAIR_BATCH='x; DROP TABLE proxies' "$SCRIPT" "$WORK/second.db" 2>&1)"
CODE=$?
set -e
expect_eq "bad batch size exit code" "$CODE" "64"
expect_eq "the table is still there" "$(q "$WORK/second.db" "SELECT COUNT(*) FROM proxies")" "3"

# ── a row stamped with only a city is counted and cleared ────────
# The counters and the clearing must agree on all three geo columns: a
# row carrying only geo_city used to fall out of the count.
CITY_DB="$WORK/city-only.db"
sqlite3 -cmd ".timeout 5000" "$CITY_DB" <<'SQL'
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    geo_country TEXT,
    geo_city    TEXT,
    geo_asn     INTEGER
);
INSERT INTO proxies (geo_city) VALUES ('Hamburg');
SQL
OUT="$("$SCRIPT" "$CITY_DB" 2>&1)" || fail "the city-only repair failed:
$OUT"
assert_output "$OUT" "rows with a geo stamp before repair: 1"
assert_output "$OUT" "rows cleared: 1"
assert_output "$OUT" "rows with a geo stamp after repair:  0"

# ── a relative path resolves against the invocation directory ────
# The script cd's to the repository root, but the path the operator types
# is where they are standing: a run from another directory must touch that
# directory's database, not the repository's own fumox.db.
REL="$WORK/rel"
mkdir -p "$REL"
# The backup goes next to the relative database, and the script refuses a
# backup directory others may write to.
chmod 700 "$REL"
make_db "$REL/test.db"
# The cwd the script sees is cd's own, normalized (a doubled TMPDIR slash
# collapses), so the expectation is built from the same view of the path.
REL_ABS="$(cd "$REL" && pwd)"
OUT="$(cd "$REL" && "$SCRIPT" ./test.db 2>&1)" || fail "the relative-path repair failed:
$OUT"
assert_output "$OUT" "database: $REL_ABS/test\.db"
assert_output "$OUT" "rows cleared: 2"
[[ -n "$(ls "$REL"/test.db.pre-geo-repair-* 2>/dev/null)" ]] \
    || fail "the backup did not go next to the relative database"
note "the relative backup went next to the relative database"

# The same for a pinned relative backup path.
make_db "$REL/second.db"
OUT="$(cd "$REL" && FUMOX_GEO_REPAIR_BACKUP=./pinned-backup.db "$SCRIPT" ./second.db 2>&1)" \
    || fail "the relative-backup repair failed:
$OUT"
[[ -f "$REL/pinned-backup.db" ]] \
    || fail "the relative backup path did not resolve against the invocation directory"
note "the pinned relative backup resolved against the invocation directory"

# ── a control character in a path is refused before any output ───
CTRL_DB="$WORK/$(printf 'bad\nname.db')"
make_db "$CTRL_DB"
set +e
OUT="$("$SCRIPT" "$CTRL_DB" 2>&1)"
CODE=$?
set -e
expect_eq "control character in database path exit code" "$CODE" "64"
assert_output "$OUT" "control character"
assert_no_output "$OUT" "^database:"

echo
echo "repair-geo-stamps.sh: all checks passed"
