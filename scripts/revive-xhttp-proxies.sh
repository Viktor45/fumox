#!/usr/bin/env bash
# One-shot revival of vless proxies that meow-rs stranded in `removed`.
#
# meow-rs 0.21.x had no XHTTP outbound (0.22.0 added it), so every vless entry
# with `type=xhttp` failed its T2 checks and walked the fail ladder to the
# terminal `removed` status. Fumox renders the transport verbatim, so these
# rows are testable again under an XHTTP-capable engine and only their status
# is wrong.
#
# Two populations. Linked rows (source link present) already sit in a probe
# lane and rejoin the normal ladder once revived. Unlinked rows sit in no lane
# at all and nothing recovers them: the upsert's `ON CONFLICT DO UPDATE` never
# touches `status` and `[ingest].removed_as_unknown` is false as shipped, so a
# revived unlinked row stays dead to every lane, feed and export.
#
# `--include-unlinked` also adopts the unlinked rows: it links them to a
# source they never came from, which is what puts them back in rotation (a
# deliberate fiction until a feed carries the proxy). Reconciliation can undo
# the link: a fetch of the chosen source stamps the links of what it carried
# and deletes the rest, so an adopted link survives only on a disabled source
# (never fetched) or one with no drop rules (the alive-linger policy exempts
# live tiers). Under `[ingest].drop_gate = true` a source with drop rules
# loses the adoption at its next refresh; the script picks around that or
# says so when it cannot.
#
# Scope: vless rows only. Snell v6 and the SIP003 plugins are other 0.22.0
# gains with no older stranded population to revive.
#
# Usage:
#   scripts/revive-xhttp-proxies.sh [--dry-run] [--include-unlinked]
#                                   [--adopt-source ID|SLUG|NAME] [--no-adopt] [db]
#   scripts/revive-xhttp-proxies.sh --restore BACKUP [--dry-run] [db]
#
# --adopt-source and --no-adopt apply only together with --include-unlinked;
# using either alone is refused (exit 64) rather than silently ignored.
#
# Environment:
#   FUMOX_REFRESH_CHECK_LIMIT      cap on the priority enqueue (default 100)
#   FUMOX_SQLITE_BUSY_TIMEOUT_MS   busy timeout of the sqlite3 calls (5000)
#   FUMOX_REVIVE_CONFIRM_STOPPED=1 restore over a database that still looks busy
#
# Takes a backup first and refuses to touch a database that is not there.
# Linked and adopted rows are enqueued for priority checking.
#
# --restore is the undo: it checks the backup (integrity, Fumox schema) before
# touching anything, refuses while anything still holds the database,
# snapshots the current contents, holds the exclusive lock for the whole copy,
# stages the copy beside the database and verifies the result. A bare `cp`
# fails two ways: SQLite replays a -wal belonging to another file (`database
# disk image is malformed`), or the log fits and the "restored" database is
# the pre-restore one, passing integrity_check silently.
set -euo pipefail

# Captured before the cd below moves to the repository root: a relative db or
# backup path on the command line resolves against the invocation directory
INVOCATION_PWD="$PWD"

cd "$(dirname "$0")/.."

# The backup holds credentials, so nothing this script writes may be world-readable
umask 077

DRY_RUN=0
INCLUDE_UNLINKED=0
ADOPT=1
ADOPT_SOURCE=""
RESTORE=""
DB=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --include-unlinked) INCLUDE_UNLINKED=1; shift ;;
        --no-adopt) ADOPT=0; shift ;;
        --adopt-source)
            [[ $# -ge 2 ]] || {
                echo "error: --adopt-source needs a value" >&2
                exit 64
            }
            ADOPT_SOURCE="$2"
            shift 2
            ;;
        --restore)
            [[ $# -ge 2 ]] || {
                echo "error: --restore needs a backup file" >&2
                exit 64
            }
            RESTORE="$2"
            shift 2
            ;;
        -h | --help)
            # Prints the header, comment markers stripped. awk rather than
            # sed: BSD sed lacks the nested delete-and-print address range
            awk 'NR == 1 { next } /^set -euo/ { exit }
                 { sub(/^# ?/, ""); print }' "$0"
            exit 0
            ;;
        -*)
            echo "error: unknown option $1" >&2
            exit 64
            ;;
        *)
            DB="$1"
            shift
            ;;
    esac
done
# A relative db or backup path resolves against INVOCATION_PWD (captured
# above the cd); the default db is the repository root's own fumox.db. Both
# are made absolute so the printed restore command means the same file from
# any directory, and a leading ./ is folded away
if [[ -n "$DB" ]]; then
    [[ "$DB" == /* ]] || DB="$INVOCATION_PWD/${DB#./}"
fi
DB="${DB:-fumox.db}"
if [[ "$DB" != /* ]]; then
    DB="$PWD/$DB"
fi
if [[ -n "$RESTORE" ]]; then
    [[ "$RESTORE" == /* ]] || RESTORE="$INVOCATION_PWD/${RESTORE#./}"
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "error: the sqlite3 CLI is not installed" >&2
    exit 69
fi

# Matches `[ingest].refresh_check_limit` as shipped in config/app.toml: the
# admin revival path caps its enqueue the same way and reports when the cap bit
ENQUEUE_LIMIT="${FUMOX_REFRESH_CHECK_LIMIT:-100}"
# Interpolated into the LIMIT clause, so the environment value must be a plain number
if ! [[ "$ENQUEUE_LIMIT" =~ ^[0-9]+$ ]]; then
    echo "error: FUMOX_REFRESH_CHECK_LIMIT must be a number, got '${ENQUEUE_LIMIT}'" >&2
    exit 64
fi

# The sqlite3 CLI defaults to a zero busy timeout, which turns a momentary
# lock into a mid-update "database is locked", so wait for the writer instead
BUSY_MS="${FUMOX_SQLITE_BUSY_TIMEOUT_MS:-5000}"

# Field separator of the multi-column queries below: it has to be a character
# that cannot appear in the data, and the sqlite3 CLI escapes the control
# characters it prints (0x1f comes out as "^_"), so the separator is set on
# the CLI itself rather than built into the query: the shell writes it out
# raw, while a character inside a value would be escaped and could not collide
FIELD_SEP=$'\x1f'

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

# Anything but exactly "ok" means the file is damaged, and restoring on top
# of a damaged file is not worth attempting
integrity_is_ok() {
    [[ "$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$1" 'PRAGMA integrity_check;' 2>/dev/null)" == "ok" ]]
}

# A file that passes integrity_check is still only a file: restoring one
# whose schema is not Fumox's would give the daemon a database it cannot use
schema_is_fumox() {
    local counts
    counts="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$1" "
SELECT
  (SELECT COUNT(*) FROM sqlite_master
    WHERE type = 'table'
      AND name IN ('proxies','sources','proxy_source_links','probe_requests')),
  (SELECT COUNT(*) FROM pragma_table_info('proxies')
    WHERE name IN ('id','scheme','params','status','fail_count','quarantined_at',
                   'ladder_at','ladder_step','removed_at','last_t2_failed_at',
                   'updated_at')),
  (SELECT COUNT(*) FROM pragma_table_info('sources')
    WHERE name IN ('id','slug','name','enabled','pipeline')),
  (SELECT COUNT(*) FROM pragma_table_info('proxy_source_links')
    WHERE name IN ('proxy_id','source_id')),
  (SELECT COUNT(*) FROM pragma_table_info('probe_requests')
    WHERE name IN ('proxy_id'));" 2>/dev/null)" || return 1
    [[ "$counts" == "4|11|5|2|1" ]]
}

# File permissions as a chmod argument, empty when the platform does not answer
file_mode() {
    stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null || echo ""
}

# File owner as a numeric uid, empty when the platform does not answer
file_uid() {
    stat -f '%u' "$1" 2>/dev/null || stat -c '%u' "$1" 2>/dev/null || echo ""
}

# Whether anything still holds the database open. Two probes, because one is
# not enough in either journal mode: BEGIN EXCLUSIVE fails on any live
# connection in rollback-journal mode but succeeds while WAL readers are
# open, and the -wal/-shm sidecars (kept while any connection holds a WAL
# database, deleted at the last close) cover that case. What neither probe
# sees is an idle lock-free connection in rollback-journal mode, so the
# printed procedure still tells the operator to stop the daemon
db_is_closed() {
    local journal
    journal="$(sqlite3 -cmd ".timeout 0" "$DB" 'PRAGMA journal_mode;' 2>/dev/null)" || return 1
    if ! sqlite3 -cmd ".timeout 0" "$DB" \
        'BEGIN EXCLUSIVE; SELECT count(*) FROM sqlite_master; COMMIT;' >/dev/null 2>&1; then
        return 1
    fi
    if [[ "$journal" == "wal" ]]; then
        [[ -e "${DB}-wal" || -e "${DB}-shm" ]] && return 1
    fi
    return 0
}

# The restore replaces the database file, so a concurrent write during the
# copy would land in the file being replaced, leaving a database that is
# neither old nor new: the lock is taken before the copy and held until it
# is done. The holder is a separate process, since this script's own sqlite3
# calls must still be able to read the database. It reads commands from a
# FIFO, so the transaction stays open until the input ends: closing the
# write end releases the lock even if the script is killed
HOLD_PID=""
HOLD_DIR=""
HOLD_FD=0

hold_exclusive_lock() {
    local fifo out err waited=0
    HOLD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fumox-restore-lock.XXXXXX")"
    fifo="${HOLD_DIR}/hold.fifo"
    out="${HOLD_DIR}/held"
    err="${HOLD_DIR}/err"
    mkfifo "$fifo" || return 1
    # -cmd rather than a SQL argument: the CLI runs a SQL argument and exits,
    # taking the transaction with it. Reading from the FIFO keeps it waiting
    # with the transaction still open
    sqlite3 -cmd ".timeout ${BUSY_MS}" -cmd "BEGIN EXCLUSIVE;" -cmd "SELECT 'held';" \
        "$DB" <"$fifo" >"$out" 2>"$err" &
    HOLD_PID=$!
    # FIFO handshake: neither open completes until the other side is ready
    exec 8>"$fifo" || return 1
    HOLD_FD=1
    # The marker means the lock was taken, a busy database errors on stderr
    while [[ "$waited" -lt 100 ]]; do
        if grep -q held "$out" 2>/dev/null && ! grep -qi error "$err" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$HOLD_PID" 2>/dev/null; then
            break
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}

release_exclusive_lock() {
    if [[ "$HOLD_FD" -eq 1 ]]; then
        exec 8>&-
        HOLD_FD=0
    fi
    if [[ -n "$HOLD_PID" ]]; then
        local waited=0
        while kill -0 "$HOLD_PID" 2>/dev/null && [[ "$waited" -lt 50 ]]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        kill "$HOLD_PID" 2>/dev/null || true
        wait "$HOLD_PID" 2>/dev/null || true
        HOLD_PID=""
    fi
    if [[ -n "$HOLD_DIR" ]]; then
        rm -rf "$HOLD_DIR" 2>/dev/null || true
        HOLD_DIR=""
    fi
}

# Staged next to the database so the rename into place is atomic and stays
# on one filesystem, and the replacement file is complete and verified
# before it takes the name
stage_copy() {
    local src="$1"
    STAGED="$(mktemp "$(dirname "$DB")/.fumox-restore.XXXXXX")"
    cp -P "$src" "$STAGED"
}

# Owner and mode are applied to the staged file before the rename: the name
# is all the daemon sees afterwards
install_over_db() {
    local staged="$1"
    local mode uid staged_uid
    mode="$(file_mode "$DB")"
    if [[ -n "$mode" ]]; then
        chmod "$mode" "$staged"
    fi
    uid="$(file_uid "$DB")"
    staged_uid="$(file_uid "$staged")"
    if [[ -n "$uid" && -n "$staged_uid" && "$uid" != "$staged_uid" ]]; then
        if ! chown "$uid" "$staged" 2>/dev/null; then
            echo >&2
            echo "error: the restored database would be owned by uid ${staged_uid} instead" >&2
            echo "of ${uid}, and the ownership could not be changed. Run the restore as" >&2
            echo "the owner of ${DB}, or as root." >&2
            return 1
        fi
    fi
    mv -f "$staged" "$DB"
}

run_restore() {
    if [[ -n "$ADOPT_SOURCE" || "$INCLUDE_UNLINKED" -eq 1 || "$ADOPT" -eq 0 ]]; then
        echo "error: --restore does the undo, it does not revive anything, so it" >&2
        echo "takes none of the revival options." >&2
        exit 64
    fi
    if [[ ! -f "$DB" ]]; then
        echo "error: no database at ${DB}" >&2
        echo "nothing to restore over. Restoring is an undo, not an install:" >&2
        echo "it replaces a database that is already there." >&2
        exit 66
    fi
    # A symlink would restore whatever it points at, not the file that was named
    if [[ -L "$DB" ]]; then
        echo "error: ${DB} is a symlink, refusing to follow it" >&2
        exit 66
    fi
    if [[ ! -f "$RESTORE" ]]; then
        echo "error: no such backup: ${RESTORE}" >&2
        exit 66
    fi
    # Same for the backup: copying through a symlink restores the target
    if [[ -L "$RESTORE" ]]; then
        echo "error: ${RESTORE} is a symlink, refusing to copy through it" >&2
        exit 66
    fi

    echo "database: ${DB}"
    echo "backup:   ${RESTORE}"

    # Noted before anything opens the file: the probes below are connections
    # too, and SQLite deletes the sidecars at the last close, so by the time
    # the cleanup runs the log is already gone
    HAD_WAL=0
    for sidecar in "${DB}-wal" "${DB}-shm"; do
        [[ -e "$sidecar" ]] && HAD_WAL=1
    done

    # An empty file is not a database and SQLite says so only after trying.
    # The size is read here so the copy can be compared against it later
    BACKUP_SIZE="$(wc -c <"$RESTORE" | tr -d ' ')"
    echo "size:     ${BACKUP_SIZE} bytes"
    if [[ "$BACKUP_SIZE" -eq 0 ]]; then
        echo >&2
        echo "error: ${RESTORE} is empty." >&2
        echo "An empty file is not a database. Nothing was touched." >&2
        exit 67
    fi

    # Checked before anything is touched, so a damaged backup costs an error
    # message and not the database it was about to replace
    if ! integrity_is_ok "$RESTORE"; then
        echo >&2
        echo "error: ${RESTORE} does not pass PRAGMA integrity_check." >&2
        echo "Restoring it would replace a working database with a damaged one," >&2
        echo "so nothing was touched. Find another backup, or dump what is" >&2
        echo "recoverable with '.recover' from the damaged file." >&2
        exit 67
    fi
    echo "check:    backup passes integrity_check"

    # A valid database is not yet a Fumox database, and the daemon cannot
    # query another schema
    if ! schema_is_fumox "$RESTORE"; then
        echo >&2
        echo "error: ${RESTORE} does not carry the Fumox schema." >&2
        echo "It is a valid database, but not this one: the tables and columns" >&2
        echo "Fumox works with (proxies, sources, proxy_source_links," >&2
        echo "probe_requests) are missing or have another shape. Restoring it" >&2
        echo "would replace the database with a schema the daemon cannot use." >&2
        echo "Nothing was touched." >&2
        exit 67
    fi
    echo "check:    backup carries the Fumox schema"

    if ! db_is_closed; then
        if [[ "${FUMOX_REVIVE_CONFIRM_STOPPED:-0}" == "1" ]]; then
            echo >&2
            echo "note: something still has ${DB} open, but FUMOX_REVIVE_CONFIRM_STOPPED=1" >&2
            echo "was set, so the restore continues. Stop the daemon first if you" >&2
            echo "have not: a write that lands during the copy is lost." >&2
        else
            echo >&2
            echo "error: something still has ${DB} open." >&2
            echo "A restore under a live writer is what produces 'database disk image" >&2
            echo "is malformed', or a restore that quietly changes nothing. Stop the" >&2
            echo "daemon first:" >&2
            echo >&2
            echo "  docker compose stop server probe" >&2
            echo >&2
            echo "and re-run this command. If the daemon really is stopped and the" >&2
            echo "database is in WAL mode, the leftovers are stale: remove the" >&2
            echo "-wal/-shm next to it, or set FUMOX_REVIVE_CONFIRM_STOPPED=1 to" >&2
            echo "say so explicitly." >&2
            exit 75
        fi
    fi
    echo "check:    nothing else has the database open"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo
        echo "dry run: ${RESTORE} would be restored over ${DB}, with its -wal and"
        echo "-shm removed afterwards and the current contents snapshotted to"
        echo "${DB}.pre-restore-$(date +%Y%m%d-%H%M%S). Re-run without --dry-run."
        exit 0
    fi

    # The restore must itself be undoable: this snapshot is the state the
    # operator was about to throw away, and there may be no other way back
    STAMP="$(date +%Y%m%d-%H%M%S)"
    PREV="${DB}.pre-restore-${STAMP}"

    # Installed before the first mutating action: every abort from here must
    # say how to put the old state back, and the snapshot path is known
    # before the file exists
    trap on_restore_err ERR

    if [[ -e "$PREV" || -L "$PREV" ]]; then
        echo >&2
        echo "error: ${PREV} already exists, refusing to overwrite it" >&2
        exit 73
    fi
    # Written beside the database so the rename stays on one filesystem.
    # VACUUM INTO refuses to overwrite, so an existing path stops the run
    if ! sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" \
        "VACUUM INTO $(sql_literal "$PREV");" 2>/dev/null; then
        echo >&2
        echo "error: could not snapshot ${DB} to ${PREV}." >&2
        echo "The restore was not started, so nothing was changed." >&2
        exit 70
    fi
    chmod 600 "$PREV"
    if ! integrity_is_ok "$PREV"; then
        echo >&2
        echo "error: the snapshot ${PREV} does not pass integrity_check, so the" >&2
        echo "restore was not started. The database was not touched." >&2
        exit 67
    fi
    echo "snapshot: ${PREV}  (what was there before, restorable the same way)"

    # The lock is held for the whole copy: a second writer would write into
    # the file being replaced
    if ! hold_exclusive_lock; then
        release_exclusive_lock
        echo >&2
        echo "error: could not take the exclusive lock on ${DB}." >&2
        echo "Something else is writing to it, or it is busy. The restore was" >&2
        echo "not started; the database was not touched. Stop the daemon and" >&2
        echo "re-run." >&2
        exit 75
    fi

    # Re-checked right before the copy: the hold must still be ours when the
    # file is replaced
    if ! kill -0 "$HOLD_PID" 2>/dev/null; then
        release_exclusive_lock
        echo >&2
        echo "error: the lock holder died before the copy; ${DB} was not touched." >&2
        exit 75
    fi

    STAGED=""
    if ! stage_copy "$RESTORE"; then
        release_exclusive_lock
        echo >&2
        echo "error: could not stage the copy of ${RESTORE} next to ${DB}." >&2
        echo "The database was not touched." >&2
        exit 70
    fi
    STAGED_SIZE="$(wc -c <"$STAGED" | tr -d ' ')"
    if [[ "$STAGED_SIZE" -ne "$BACKUP_SIZE" ]]; then
        rm -f "$STAGED"
        release_exclusive_lock
        echo >&2
        echo "error: the staged copy is ${STAGED_SIZE} bytes, the backup is" >&2
        echo "${BACKUP_SIZE}. The copy is short, so it was not installed and the" >&2
        echo "database was not touched." >&2
        exit 70
    fi
    if ! integrity_is_ok "$STAGED"; then
        rm -f "$STAGED"
        release_exclusive_lock
        echo >&2
        echo "error: the staged copy does not pass integrity_check, so it was not" >&2
        echo "installed and the database was not touched." >&2
        exit 70
    fi

    if ! install_over_db "$STAGED"; then
        rm -f "$STAGED"
        release_exclusive_lock
        exit 70
    fi
    STAGED=""

    # Size re-checked on the installed file: a short copy is rolled back, not
    # left in place
    NEW_SIZE="$(wc -c <"$DB" | tr -d ' ')"
    if [[ "$NEW_SIZE" -ne "$BACKUP_SIZE" ]]; then
        release_exclusive_lock
        echo >&2
        echo "error: ${DB} is ${NEW_SIZE} bytes after the restore, the backup is" >&2
        echo "${BACKUP_SIZE}. The copy is short, so the previous state is put" >&2
        echo "back now." >&2
        rollback_to_prev
        exit 70
    fi

    release_exclusive_lock

    # The sidecars belong to the file that was just replaced and a stale log
    # would be replayed on top of the restored file, so they go only after
    # the copy is confirmed
    REMOVED=()
    for sidecar in "${DB}-wal" "${DB}-shm"; do
        if [[ -e "$sidecar" ]]; then
            rm -f "$sidecar"
            REMOVED+=("$(basename "$sidecar")")
        fi
    done
    if [[ "$HAD_WAL" -eq 1 ]]; then
        echo "log:      the database had a write-ahead log, so it was not closed" >&2
        echo "          cleanly. It was checkpointed into ${DB} by the check above" >&2
        echo "          and the -wal/-shm are gone; a log left in place would have"
        echo "          been replayed on top of the restored file."
    else
        echo "log:      none, the database was closed cleanly"
    fi
    if [[ "${#REMOVED[@]}" -gt 0 ]]; then
        echo "          also removed: ${REMOVED[*]}"
    fi

    if ! integrity_is_ok "$DB"; then
        echo >&2
        echo "error: ${DB} does not pass integrity_check after the restore." >&2
        echo "The backup passed the same check a moment ago, so the copy itself" >&2
        echo "is suspect rather than its contents. The previous state is put back" >&2
        echo "now." >&2
        rollback_to_prev
        exit 70
    fi
    echo "check:    restored database passes integrity_check"

    trap - ERR

    PROXIES="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" 'SELECT COUNT(*) FROM proxies;' 2>/dev/null || echo '?')"
    cat <<EOF

Restored. ${DB} now holds the contents of ${RESTORE}
($(wc -c <"$DB" | tr -d ' ') bytes, ${PROXIES} rows in proxies).

Start the daemon again. Check it with 'PRAGMA integrity_check;' any time: it
must print exactly 'ok', and unlike the bare cp this replaced, a failure
here means the copy is damaged rather than that a stale log got in.

To put the previous contents back, restore the snapshot the same way:
  scripts/revive-xhttp-proxies.sh --restore ${PREV} ${DB}
EOF
}

# Used when the restore fails its checks: the operator's database is worth
# more than the restore
rollback_to_prev() {
    if [[ -z "${PREV:-}" || ! -f "$PREV" ]]; then
        echo >&2
        echo "there is no snapshot to roll back to." >&2
        return 1
    fi
    local staged
    staged="$(mktemp "$(dirname "$DB")/.fumox-rollback.XXXXXX")" || return 1
    cp -P "$PREV" "$staged" || { rm -f "$staged"; return 1; }
    mv -f "$staged" "$DB" || { rm -f "$staged"; return 1; }
    rm -f "${DB}-wal" "${DB}-shm"
    echo >&2
    echo "the state from before the restore was put back from ${PREV}." >&2
}

# Runs from the first mutating action on, so it always knows the snapshot's
# path and can hand the operator a ready-made rollback
on_restore_err() {
    local code=$?
    trap - ERR
    release_exclusive_lock
    echo >&2
    echo "error: aborted with code ${code}; ${DB} may be half-restored." >&2
    if [[ -n "${PREV:-}" && -f "$PREV" ]]; then
        echo >&2
        echo "the state from before the restore is at ${PREV}. Put it back with:" >&2
        echo >&2
        echo "  rm -f ${DB}-wal ${DB}-shm && cp ${PREV} ${DB}" >&2
        echo >&2
        echo "and check it with 'PRAGMA integrity_check;'." >&2
    else
        echo >&2
        echo "nothing was changed yet, so the database is still the one that was" >&2
        echo "there before the restore." >&2
    fi
    exit "$code"
}

if [[ -n "$RESTORE" ]]; then
    run_restore
    exit 0
fi

# Silently ignoring the adoption flags would leave the operator believing a
# target was chosen when none was
if [[ "$INCLUDE_UNLINKED" -eq 0 && ( -n "$ADOPT_SOURCE" || "$ADOPT" -eq 0 ) ]]; then
    echo "error: --adopt-source and --no-adopt only apply together with" >&2
    echo "--include-unlinked: the adoption target is needed for the unlinked" >&2
    echo "half only, and the linked half keeps the link it already has." >&2
    exit 64
fi

if [[ ! -f "$DB" ]]; then
    echo "error: no database at $DB" >&2
    exit 66
fi

# One link predicate for every query: two spellings of it once shipped a
# broken default run (the report's copy resolved, the target set's did not)
LINKED="EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)"
if [[ "$INCLUDE_UNLINKED" -eq 1 ]]; then
    SELECT_LINKED="1"
    SELECT_SCOPE="every removed xhttp vless row, linked or not"
else
    SELECT_LINKED="$LINKED"
    SELECT_SCOPE="removed xhttp vless rows that still have a source link"
fi

# json_extract raises on malformed JSON rather than returning NULL, so
# json_valid guards it, and CASE evaluating its branches in order keeps the
# malformed rows out of the extraction
XHTTP="scheme = 'vless' AND CASE WHEN json_valid(params) THEN lower(json_extract(params, '\$.type')) END = 'xhttp'"

# The selection, shared by every report and the update. json_extract keeps it
# exact: a LIKE over `params` would also match an xhttp string in a path or
# host, which is not an xhttp transport.
#
# The census decides whether the run says "Nothing to revive." and exits 0, so
# an unreadable database must not be mistaken for an empty one
CENSUS_ERR="$(mktemp "${TMPDIR:-/tmp}/fumox-census.XXXXXX")"
if ! CENSUS="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" 2>"${CENSUS_ERR}" <<SQL
SELECT
  (SELECT COUNT(*) FROM proxies p WHERE ${XHTTP}),
  (SELECT COUNT(*) FROM proxies p WHERE ${XHTTP} AND status != 'removed'),
  (SELECT COUNT(*) FROM proxies p
    WHERE ${XHTTP} AND status = 'removed' AND NOT ${LINKED}),
  (SELECT COUNT(*) FROM proxies p
    WHERE ${XHTTP} AND status = 'removed' AND ${LINKED});
SQL
)"; then
    CENSUS_MSG="$(cat "$CENSUS_ERR")"
    rm -f "$CENSUS_ERR"
    echo >&2
    echo "error: could not read the census from ${DB}." >&2
    if [[ "$CENSUS_MSG" == *locked* ]]; then
        echo "The database is locked by another writer, which reads the same as an" >&2
        echo "empty one, and an empty one becomes a quiet 'Nothing to revive.'" >&2
        echo "Stop whatever writes to ${DB} and re-run." >&2
        exit 75
    fi
    echo "sqlite3 failed: ${CENSUS_MSG:-<no message>}" >&2
    echo "The database could not be read, which is not the same as an empty" >&2
    echo "database, so the run stops here instead of saying 'Nothing to revive.'" >&2
    exit 70
fi
rm -f "$CENSUS_ERR"
IFS='|' read -r TOTAL LIVE UNLINKED_REMOVED LINKED_REMOVED <<<"$CENSUS"
if ! [[ "$TOTAL" =~ ^[0-9]+$ && "$LIVE" =~ ^[0-9]+$ && \
        "$UNLINKED_REMOVED" =~ ^[0-9]+$ && "$LINKED_REMOVED" =~ ^[0-9]+$ ]]; then
    echo >&2
    echo "error: the census from ${DB} is not four counts: ${CENSUS:-<empty>}" >&2
    exit 70
fi

if [[ "$INCLUDE_UNLINKED" -eq 1 ]]; then
    REVIVABLE=$((LINKED_REMOVED + UNLINKED_REMOVED))
else
    REVIVABLE="$LINKED_REMOVED"
fi

echo "database: $DB"
echo "scope:    ${SELECT_SCOPE}"
echo "vless entries with an xhttp transport: ${TOTAL}"
echo "  already in a live lane:              ${LIVE}"
echo "  removed, with a source link:         ${LINKED_REMOVED}"
if [[ "$INCLUDE_UNLINKED" -eq 1 ]]; then
    echo "  removed, no source link:             ${UNLINKED_REMOVED}  (included)"
else
    echo "  removed, no source link:             ${UNLINKED_REMOVED}  (skipped: pass --include-unlinked to take them)"
fi

if [[ "$REVIVABLE" -eq 0 ]]; then
    echo
    echo "Nothing to revive."
    exit 0
fi

# Only the unlinked half is adopted: a second link would make reconciliation
# of either source responsible for the other's proxies
ADOPT_ID=""
ADOPT_NAME=""
ADOPT_RISK=""
ADOPT_ENABLED=""
ADOPT_DROPS=""
if [[ "$INCLUDE_UNLINKED" -eq 1 && "$UNLINKED_REMOVED" -gt 0 ]]; then
    if [[ "$ADOPT" -eq 0 ]]; then
        echo
        echo "adoption: off (--no-adopt). The ${UNLINKED_REMOVED} unlinked row(s) come"
        echo "back as 'unknown' with no link, so no probe lane, no export and no"
        echo "future fetch can reach them. They wait for a feed that carries them."
    elif [[ -n "$ADOPT_SOURCE" ]]; then
        # An explicit target is matched on id, then slug, then name, and an
        # ambiguous name is refused: a wrong source here is a link nothing
        # will ever reconcile. The value reaches SQL literals below, so its
        # quotes are doubled through a variable because bash 3.2 keeps the
        # backslashes of an escaped replacement in ${var//pat/repl}
        QUOTED_QUOTE="''"
        ADOPT_SOURCE_SQL="${ADOPT_SOURCE//\'/$QUOTED_QUOTE}"
        # Name read last: everything after the third separator lands there,
        # so a '|' in a name cannot shift the fields
        IFS="$FIELD_SEP" read -r MATCHES ADOPT_ID ADOPT_ENABLED ADOPT_DROPS ADOPT_NAME <<<"$(sqlite3 -cmd ".timeout ${BUSY_MS}" -cmd ".separator ${FIELD_SEP}" "$DB" <<SQL
SELECT COUNT(*), id, enabled,
       COALESCE(json_array_length(json_extract(pipeline, '\$.drop')), 0),
       name
  FROM sources
 WHERE id = '${ADOPT_SOURCE_SQL}' OR slug = '${ADOPT_SOURCE_SQL}' OR name = '${ADOPT_SOURCE_SQL}'
 ORDER BY CASE WHEN id = '${ADOPT_SOURCE_SQL}' THEN 0
               WHEN slug = '${ADOPT_SOURCE_SQL}' THEN 1
               ELSE 2 END,
          id
 LIMIT 1;
SQL
)"
        if [[ "${MATCHES:-0}" -eq 0 ]]; then
            echo >&2
            echo "error: no source matches '${ADOPT_SOURCE}' (looked at id, slug and name)" >&2
            exit 67
        fi
        # The id reaches a SQL literal just below, so it is checked against
        # the shape nanoid(12) produces before its first use
        if ! [[ "$ADOPT_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
            echo >&2
            echo "error: source id '${ADOPT_ID}' is not a plain nanoid, refusing to interpolate it" >&2
            exit 67
        fi
        AMBIGUOUS="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "SELECT COUNT(*) FROM sources WHERE name = '${ADOPT_SOURCE_SQL}' AND id != '${ADOPT_ID}'")"
        if [[ "$AMBIGUOUS" -gt 0 ]]; then
            echo >&2
            echo "error: '${ADOPT_SOURCE}' matches ${AMBIGUOUS} other sources by name" >&2
            echo "pass the id or the slug instead" >&2
            exit 67
        fi
    else
        # Cheapest safety first: enabled with no drop rules serves /sub and
        # keeps the link (alive-linger holds under any drop_gate), disabled
        # keeps the link but serves nothing, and drop rules are only safe
        # while [ingest].drop_gate is off, a config fact this script does
        # not read, so such a source goes last with a warning.
        #
        # A unit separator rather than a pipe: a '|' in a source name must
        # not shift the drop-rule count into the wrong safety branch
        CANDIDATES="$(sqlite3 -cmd ".timeout ${BUSY_MS}" -cmd ".separator ${FIELD_SEP}" "$DB" <<SQL
WITH ranked AS (
  SELECT id, name, enabled, created_at,
         COALESCE(json_array_length(json_extract(pipeline, '\$.drop')), 0) AS drops
    FROM sources
)
SELECT id, enabled, drops, name
  FROM ranked
 ORDER BY CASE WHEN enabled = 1 AND drops = 0 THEN 0
               WHEN enabled = 0 THEN 1
               ELSE 2 END,
          created_at, id;
SQL
)"
        SEEN_CANDIDATES=0
        while IFS="$FIELD_SEP" read -r RANK_ID RANK_ENABLED RANK_DROPS RANK_NAME; do
            [[ -n "$RANK_ID" ]] || continue
            SEEN_CANDIDATES=$((SEEN_CANDIDATES + 1))
            # The id reaches a SQL literal below: a source whose id is not a
            # plain nanoid is skipped rather than adopted, since its id could
            # carry a quote into the statement
            if ! [[ "$RANK_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
                continue
            fi
            ADOPT_ID="$RANK_ID"
            ADOPT_ENABLED="$RANK_ENABLED"
            ADOPT_DROPS="$RANK_DROPS"
            ADOPT_NAME="$RANK_NAME"
            break
        done <<<"$CANDIDATES"
        if [[ -z "$ADOPT_ID" && "$SEEN_CANDIDATES" -gt 0 ]]; then
            echo >&2
            echo "error: none of the ${SEEN_CANDIDATES} source(s) has an id that can be" >&2
            echo "used as an adoption target: the id reaches a SQL literal, so only a" >&2
            echo "plain nanoid is accepted. Re-run with --no-adopt to revive the" >&2
            echo "unlinked rows link-less." >&2
            exit 67
        fi
        if [[ -z "$ADOPT_ID" ]]; then
            echo >&2
            echo "error: there are no sources, so there is nothing to adopt the" >&2
            echo "${UNLINKED_REMOVED} unlinked row(s) into. Re-run with --no-adopt to" >&2
            echo "revive them link-less, or add a source first." >&2
            exit 67
        fi
    fi

    if [[ -n "$ADOPT_ID" ]]; then
        if [[ "$ADOPT_ENABLED" == "0" ]]; then
            ADOPT_RISK="disabled, so it is never fetched and never reconciles the link away (but it serves nothing either)"
        elif [[ "$ADOPT_DROPS" -gt 0 ]]; then
            ADOPT_RISK="has ${ADOPT_DROPS} drop rule(s): safe only while [ingest].drop_gate is false, otherwise the next refresh of this source unlinks and retires every adopted row"
        else
            ADOPT_RISK="enabled, no drop rules: the link survives its next refresh and the rows appear in its subscription output"
        fi

        echo
        echo "adopt into: ${ADOPT_NAME} (${ADOPT_ID})"
        echo "            ${ADOPT_RISK}"
        if [[ -n "$ADOPT_SOURCE" && "$ADOPT_ENABLED" == "1" && "$ADOPT_DROPS" -gt 0 ]]; then
            echo "            named explicitly, so this script did not second-guess the choice."
        fi
    fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo
    echo "dry run: would revive ${REVIVABLE} row(s). Re-run without --dry-run to apply."
    exit 0
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${DB}.pre-xhttp-revival-${STAMP}"
echo "backup:   ${BACKUP}"

# The backup path must be free: VACUUM INTO refuses to overwrite, and a
# symlink planted there would be written through
if [[ -e "$BACKUP" || -L "$BACKUP" ]]; then
    echo "error: ${BACKUP} already exists, refusing to overwrite it" >&2
    exit 73
fi
# WAL mode: the .db alone is not a consistent snapshot, so VACUUM INTO makes
# the copy itself and the path never reaches a dot command as text
if ! sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" \
    "VACUUM INTO $(sql_literal "$BACKUP");" 2>/dev/null; then
    echo >&2
    echo "error: could not write the backup ${BACKUP}." >&2
    echo "The database was not touched." >&2
    exit 70
fi
chmod 600 "$BACKUP"
if ! integrity_is_ok "$BACKUP"; then
    echo >&2
    echo "error: the backup ${BACKUP} does not pass integrity_check." >&2
    echo "The database was not touched." >&2
    exit 70
fi
for sidecar in "${DB}-wal" "${DB}-shm"; do
    [[ -e "$sidecar" ]] && echo "note: ${sidecar} exists, the backup above already checkpointed it"
done

# Why a bare cp is never suggested: it swaps the main file while the -wal and
# -shm of the current database stay next to it, and SQLite then replays a log
# that belongs to a different file. That reads as a hard
# `database disk image is malformed`, or worse as no error at all: the log
# replays cleanly and the "restored" database is the pre-restore one, passing
# integrity_check while silently not being the file that was copied
restore_hint() {
    cat <<EOF
To undo, restore ${BACKUP}. Stop whatever writes to ${DB} first: with a
live writer the -wal and -shm of the current database survive the copy and
SQLite replays a log that belongs to a different file, which reads as
'database disk image is malformed' or, worse, restores nothing at all
while reporting ok.

The way to do that is this script's own restore, run after stopping the
daemon:

  scripts/revive-xhttp-proxies.sh --restore ${BACKUP} ${DB}

It checks the backup before touching anything (integrity, schema),
snapshots the database it is about to overwrite, holds the exclusive lock
for the whole copy and verifies the result.

The manual route below is the fallback, not the primary one:

  1. stop the daemon (docker compose stop server probe, or whatever runs it)
  2. rm -f ${DB}-wal ${DB}-shm
  3. cp ${BACKUP} ${DB}
  4. sqlite3 ${DB} 'PRAGMA integrity_check;'      # must print exactly: ok
  5. start the daemon again

Step 4 is the one that matters: a restore that skipped steps 1 and 2 can
pass it while holding the wrong data. The bare cp does no snapshot of the
database it overwrites and no verification of the backup.
EOF
}

# Shorter advice for aborts after the backup, never a bare cp
undo_hint() {
    echo "the backup ${BACKUP} is intact. To undo, stop the daemon and run" >&2
    echo "  scripts/revive-xhttp-proxies.sh --restore ${BACKUP} ${DB}" >&2
    echo "which verifies the backup and snapshots what it overwrites. The" >&2
    echo "manual route is a fallback, not the primary one: a bare cp does no" >&2
    echo "snapshot and no backup verification, and it leaves the current" >&2
    echo "database's write-ahead log next to the restored file." >&2
}

NOW="$(date +%s)"

# The backup now exists, so every abort must say how to undo itself: `set -e`
# would otherwise exit silently with the database already touched
on_err() {
    local code=$?
    echo >&2
    echo "error: aborted with code ${code}; the database may be half-written" >&2
    if [[ -n "${BACKUP:-}" && -f "${BACKUP}" ]]; then
        echo >&2
        undo_hint
    fi
    exit "$code"
}
trap on_err ERR

# Materialised first so the update, the adoption and the enqueue agree on the
# same rows, without a RETURNING clause the reader would have to know the
# SQLite version for. The link predicate rides on the row so the adoption can
# tell the two populations apart without re-deriving it
ADOPT_SQL=""
if [[ -n "$ADOPT_ID" ]]; then
    ADOPT_SQL="
CREATE TEMP TABLE xhttp_adopt AS
SELECT id FROM xhttp_revive WHERE linked = 0;

INSERT OR IGNORE INTO proxy_source_links (proxy_id, source_id, seen_at)
SELECT id, '${ADOPT_ID}', ${NOW} FROM xhttp_adopt;

SELECT 'adopted', changes();"
fi

# `changes()` is read straight after the statement it describes: it reports
# the rows INSERT actually added, not what the table holds for those ids.
# Counting the table instead once reported ten enqueues that were never made
RESULT="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" <<SQL
CREATE TEMP TABLE xhttp_revive AS
SELECT p.id AS id, ${LINKED} AS linked
  FROM proxies p
 WHERE ${XHTTP}
   AND status = 'removed'
   AND ${SELECT_LINKED};

UPDATE proxies
   SET status = 'unknown',
       fail_count = 0,
       quarantined_at = NULL,
       ladder_at = NULL,
       ladder_step = 0,
       removed_at = NULL,
       last_t2_failed_at = NULL,
       updated_at = ${NOW}
 WHERE id IN (SELECT id FROM xhttp_revive);
${ADOPT_SQL}
INSERT OR IGNORE INTO probe_requests (proxy_id, requested_at)
SELECT p.id, ${NOW} FROM proxies p
 WHERE p.id IN (SELECT id FROM xhttp_revive)
   AND p.status = 'unknown'
   AND p.scheme NOT IN ('hysteria2', 'tuic', 'mieru')
   AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
 ORDER BY p.id DESC
 LIMIT ${ENQUEUE_LIMIT};

SELECT 'queued', changes();

-- Counted in this same connection: the temp table is gone once sqlite3 exits,
-- and a later recount could not tell our rows from anything else enqueued
SELECT 'revived', (SELECT COUNT(*) FROM xhttp_revive)
UNION ALL
SELECT 'revived_linked', (SELECT COUNT(*) FROM xhttp_revive WHERE linked = 1);
SQL
)"

read_count() {
    printf '%s\n' "$RESULT" | awk -F'|' -v k="$1" '$1==k {print $2}'
}
REVIVED="$(read_count revived)"
REVIVED_LINKED="$(read_count revived_linked)"
ADOPTED="$(read_count adopted)"
QUEUED="$(read_count queued)"

# The counts come back as text: a silent parse failure would surface later as
# arithmetic on an empty string, far from its cause
for pair in "revived:${REVIVED}" "linked:${REVIVED_LINKED}" "queued:${QUEUED}"; do
    if ! [[ "${pair#*:}" =~ ^[0-9]+$ ]]; then
        echo "error: could not read the ${pair%%:*} count back from sqlite3" >&2
        undo_hint
        exit 70
    fi
done
if [[ -n "$ADOPT_SQL" && ! "${ADOPTED:-}" =~ ^[0-9]+$ ]]; then
    echo "error: could not read the adopted count back from sqlite3" >&2
    undo_hint
    exit 70
fi
ADOPTED="${ADOPTED:-0}"

if [[ "$REVIVED" -ne "$REVIVABLE" ]]; then
    # Expected only if the daemon moved rows while the script ran, which the
    # busy timeout absorbs rather than fails on
    echo "note: ${REVIVABLE} row(s) matched the selection but ${REVIVED} were"
    echo "revived, so something else changed them in between."
fi

echo
echo "revived:  ${REVIVED}  (${REVIVED_LINKED} linked, $((REVIVED - REVIVED_LINKED)) unlinked)"
if [[ "$ADOPTED" -gt 0 ]]; then
    echo "adopted:  ${ADOPTED} into ${ADOPT_NAME} (${ADOPT_ID})"
    echo "          an adopted link is the proxy's only ticket into a probe lane"
    echo "          and into the alive/ready exports; the source it points at does"
    echo "          not carry the proxy until a feed says so."
elif [[ "$INCLUDE_UNLINKED" -eq 1 && "$UNLINKED_REMOVED" -gt 0 ]]; then
    echo "adopted:  0  (${ADOPT_RISK:-adoption was off})"
    echo "          the unlinked rows are 'unknown' with no link, so nothing probes"
    echo "          or serves them until a feed re-links one."
fi
echo "enqueued for priority checking: ${QUEUED}"

# Only rows that ended up with a link are enqueueable, so a run that revived
# nothing enqueueable has not hit the cap, it simply had nothing to enqueue
ENQUEUEABLE=$((REVIVED_LINKED + ADOPTED))
if [[ "${QUEUED}" -lt "${ENQUEUEABLE}" ]]; then
    echo
    echo "note: ${ENQUEUEABLE} row(s) were enqueueable and ${QUEUED} made the queue."
    if [[ "$ADOPTED" -gt 0 ]]; then
        echo "The cap (FUMOX_REFRESH_CHECK_LIMIT=${ENQUEUE_LIMIT}) held the rest back."
    fi
    echo "The ones left out are 'unknown' with a link, so the random T1 sample still"
    echo "reaches them, just not at priority. Re-running this script will not enqueue"
    echo "them — it selects rows that are still 'removed' — so either leave it (the"
    echo "next source refresh enqueues unknowns of its own) or raise the cap before"
    echo "a run that still sees them as 'removed'."
fi

cat <<EOF

Done. The revived rows rejoin the normal ladder: T1 reachability first (they
are 'unknown', which no T2 batch selects), then T2 once T1 puts them in
'alive'. An entry that is genuinely dead fails its checks again and walks
back down to 'removed' on its own, so a row revived here costs one probe
cycle and nothing more.

EOF

restore_hint
