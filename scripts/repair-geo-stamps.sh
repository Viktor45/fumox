#!/usr/bin/env bash
# One-shot repair of the proxies.geo_* columns.
#
# Until 2026-10-02 the ingest path handed `reconcile_source` the entry list
# AFTER a source's pipeline drop rules had shortened it, together with the geo
# stamps resolved for the list BEFORE the drop. The two are paired by index,
# so every proxy past the first dropped entry was stored carrying a
# neighbouring host's country and ASN, and the admin ASN cleanup buttons then
# acted on that noise (an "AS13335" row whose host was really AS20473).
#
# The resolver itself was never wrong, so the repair is a rewrite, not a
# migration: clear the three columns and let the startup geo backfill
# (crates/fumox-server/src/geo_backfill.rs) resolve every row again from its
# own host. The backfill picks up exactly the rows with all three columns
# NULL, which is what this script produces.
#
# Usage:
#   scripts/repair-geo-stamps.sh [path/to/fumox.db]
#
# Environment:
#   FUMOX_GEO_REPAIR_BACKUP       path of the backup file (default:
#                                 <database>.pre-geo-repair-<timestamp>)
#   FUMOX_GEO_REPAIR_BATCH        rows per transaction (default: 500)
#   FUMOX_SQLITE_BUSY_TIMEOUT_MS  busy timeout of the sqlite3 calls (30000)
#   FUMOX_ALLOW_RUNNING_SERVER=1  run even when a server process is visible
#
# STOP the server (and the probe) before running this script: the repair and
# a running server's backfill would write the same rows, and the result
# depends on who wins the race. After the repair RESTART the server (a
# restart, not a plain start: the backfill runs at the start of the process,
# so a server that was never stopped keeps its old stamps). Takes a backup
# first and refuses to touch a database that is not there.
set -euo pipefail

# Captured before the cd below moves to the repository root: a relative
# database or backup path resolves against the invocation directory
INVOCATION_PWD="$PWD"

cd "$(dirname "$0")/.."

# The backup holds credentials, so nothing this script writes may be world-readable
umask 077

DB="${1:-fumox.db}"
# An explicitly given relative path belongs to the invocation directory
# (captured above); the default stays relative to the repository root
if [[ $# -ge 1 ]]; then
    [[ "$DB" == /* ]] || DB="$INVOCATION_PWD/${DB#./}"
fi

fail() {
    echo "error: $*" >&2
    exit 70
}

if [[ ! -f "$DB" ]]; then
    echo "error: no database at $DB" >&2
    exit 66
fi

# A symlink would repair whatever it points at, not the file that was named
if [[ -L "$DB" ]]; then
    echo "error: ${DB} is a symlink, refusing to follow it" >&2
    exit 66
fi

# A containerised server cannot be seen from here, so the refusal message
# names the compose services as well
server_is_running() {
    command -v pgrep >/dev/null 2>&1 || return 1
    pgrep -x fumox-server >/dev/null 2>&1 && return 0
    pgrep -x fumox-probe >/dev/null 2>&1 && return 0
    # A cargo-started server runs under cargo, whose command line carries the
    # binary path
    pgrep -f 'fumox-server' >/dev/null 2>&1 && return 0
    pgrep -f 'fumox-probe' >/dev/null 2>&1 && return 0
    return 1
}

if [[ "${FUMOX_ALLOW_RUNNING_SERVER:-0}" != "1" ]] && server_is_running; then
    echo >&2
    echo "error: a fumox server or probe looks like it is running." >&2
    echo "STOP it first — the repair and the running backfill would write the" >&2
    echo "same rows. For the container deployment:" >&2
    echo >&2
    echo "  docker compose stop server probe" >&2
    echo >&2
    echo "and RESTART the server after the repair (a restart, not a start: the" >&2
    echo "geo backfill runs at the start of the process)." >&2
    exit 75
fi

# The path reaches a SQL string literal: a quote is doubled, a control
# character would split the statement and is refused instead
sql_literal() {
    if [[ "$1" == *[[:cntrl:]]* ]]; then
        echo "error: the path contains a control character: ${1}" >&2
        exit 64
    fi
    local quoted="'"
    printf "%s%s%s" "$quoted" "${1//\'/$quoted$quoted}" "$quoted"
}

STAMP="$(date +%Y%m%d-%H%M%S)"
# The operator may pin the backup: a name that says what it is for, or a
# directory of its own
BACKUP="${FUMOX_GEO_REPAIR_BACKUP:-${DB}.pre-geo-repair-${STAMP}}"
# A pinned relative backup path belongs to the invocation directory too (the
# default sits next to the database)
if [[ -n "${FUMOX_GEO_REPAIR_BACKUP:-}" ]]; then
    [[ "$BACKUP" == /* ]] || BACKUP="$INVOCATION_PWD/${BACKUP#./}"
fi

# The paths are printed and reach a SQL literal, so a control character in
# either is refused before anything is written or shown
if [[ "$DB" == *[[:cntrl:]]* ]]; then
    echo "error: the database path contains a control character" >&2
    exit 64
fi
if [[ "$BACKUP" == *[[:cntrl:]]* ]]; then
    echo "error: the backup path contains a control character" >&2
    exit 64
fi

# A directory others can write to is no place for a copy of the credentials:
# the backup could be swapped between the check and the write
BACKUP_DIR="$(dirname "$BACKUP")"
if [[ -d "$BACKUP_DIR" ]]; then
    DIR_MODE="$(stat -f '%Lp' "$BACKUP_DIR" 2>/dev/null || stat -c '%a' "$BACKUP_DIR" 2>/dev/null || echo "")"
    if [[ -n "$DIR_MODE" ]] && (( 0$DIR_MODE & 0022 )); then
        echo "error: ${BACKUP_DIR} is writable by group or others (mode ${DIR_MODE})." >&2
        echo "The backup holds the whole database; put it in a directory only" >&2
        echo "the owner can write to (chmod 0700), and run the script again." >&2
        exit 73
    fi
fi

# `VACUUM INTO` writes the backup itself and refuses to overwrite, so a stale
# backup or a planted symlink stops the run instead of being written through
# (a `.backup` dot command would have taken the path unescaped)
if [[ -e "$BACKUP" || -L "$BACKUP" ]]; then
    echo "error: ${BACKUP} already exists, refusing to overwrite it" >&2
    exit 73
fi

# A server that slipped past the pgrep probe holds the database between the
# calls below. The sqlite3 CLI defaults to a zero busy timeout, which turns
# that into an immediate "database is locked", so wait for the writer instead
BUSY_MS="${FUMOX_SQLITE_BUSY_TIMEOUT_MS:-30000}"

# %q: what the operator typed is echoed back, and a path is data, not format
# or code
printf 'database: %q\n' "$DB"
printf 'backup:   %q\n' "$BACKUP"

if ! sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "VACUUM INTO $(sql_literal "$BACKUP")"; then
    fail "the backup of ${DB} could not be written to ${BACKUP}; nothing was changed."
fi
# The backup carries the same rows, so it gets the same mode: 0600, never wider
chmod 600 "$BACKUP"

for sidecar in "${DB}-wal" "${DB}-shm"; do
    [[ -e "$sidecar" ]] && echo "note: ${sidecar} exists, the backup above is a consistent snapshot of it"
done

STAMPED="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL OR geo_city IS NOT NULL OR geo_country IS NOT NULL")"
echo "rows with a geo stamp before repair: ${STAMPED}"

# One transaction over the whole table would hold the write lock for the
# whole sweep and grow the write-ahead log to the size of the table, a batch
# at a time releases the lock between batches
BATCH_SIZE="${FUMOX_GEO_REPAIR_BATCH:-500}"
if ! [[ "$BATCH_SIZE" =~ ^[0-9]+$ ]] || [[ "$BATCH_SIZE" -lt 1 ]]; then
    echo "error: FUMOX_GEO_REPAIR_BATCH must be a positive number, got '${BATCH_SIZE}'" >&2
    exit 64
fi

MAX_ID="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "SELECT COALESCE(MAX(id), 0) FROM proxies")"
CLEARED=0
START=0
while [[ "$START" -lt "$MAX_ID" ]]; do
    END=$((START + BATCH_SIZE))
    BATCH_CLEARED="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "UPDATE proxies
   SET geo_country = NULL, geo_city = NULL, geo_asn = NULL
 WHERE id > ${START} AND id <= ${END}
   AND (geo_asn IS NOT NULL OR geo_city IS NOT NULL OR geo_country IS NOT NULL);
SELECT changes();")"
    CLEARED=$((CLEARED + BATCH_CLEARED))
    START="$END"
done
echo "rows cleared: ${CLEARED}"

LEFT="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL OR geo_city IS NOT NULL OR geo_country IS NOT NULL")"
echo "rows with a geo stamp after repair:  ${LEFT}"

cat <<EOF

Done. RESTART the server — a restart, not a plain start: the startup geo
backfill re-resolves every row from its own host and writes the corrected
country, city and ASN. It runs in the background in batches of 500, so the
first seconds after the restart show rows without a stamp while the sweep
works through them.

To follow it, or to confirm it finished, watch for the backfill's own log
line ("geo backfill complete", with the row count and elapsed time).

To undo, put the backup back (stop the server first, copy it over the
database and remove the -wal and -shm files next to it).
EOF
