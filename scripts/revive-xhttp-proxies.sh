#!/usr/bin/env bash
# One-shot revival of vless proxies that meow-rs stranded in `removed`.
#
# Background. meow-rs 0.22.0 added the XHTTP transport as a real outbound
# (0.21.x had no XHTTP at all: `grep -c '"xhttp"' crates/meow-config/src/
# proxy_parser.rs` returns 0 on the old tag, non-zero on the new one). Before
# that, a vless entry whose network parameter was `type=xhttp` could not be
# tunnelled by the engine, so every T2 check failed, the fail ladder ran its
# course, and the row ended up `removed`: terminal, with no lane that would
# ever pick it up again. Nothing about the entry changed, only the engine's
# ability to carry it, and Fumox already rendered the transport correctly
# (formats/clash.rs passes an unrecognised network through verbatim), so
# these rows are testable again and only their terminal status is wrong.
#
# Two populations, and they need different treatment.
#
# The linked ones (source link present) are the ordinary case. Every probe
# lane selects on `EXISTS (SELECT 1 FROM proxy_source_links ...)`, so a
# revived row is picked up on the next cycle and walks the normal ladder.
#
# The unlinked ones are why `--include-unlinked` exists. `revive_removed`
# skips them, and so does this script by default, because a row with no
# source link sits in no probe lane at all: not the T1 sample, not the T2
# batch, not the priority queue, and not the alive/ready exports. Reviving
# one on its own changes nothing an operator can see except its badge, and
# leaves it in a state no feed can recover from: the upsert's
# `ON CONFLICT DO UPDATE` never touches `status`, so a re-linked `removed`
# row stays `removed`, and `[ingest].removed_as_unknown` is false as
# shipped, so nothing revives it either. The row is dead permanently,
# whatever its feed does later.
#
# So `--include-unlinked` also adopts them: the revived rows are linked to
# a source they never came from, which is what actually puts them back in
# rotation. The link is a deliberate fiction, `the source carries the
# proxy` is untrue for the adopted half until a feed starts saying so, and
# it is the only way to give a link-less row a probe lane. Reconciliation
# is what makes it survive: a fetch of the chosen source stamps the links
# of what it carried and deletes the rest, so an adopted link is a
# candidate for deletion on that source's next refresh. A disabled source
# is never fetched, and a source with no drop rules runs the alive-linger
# policy that exempts every live tier (`unknown` is one) from the unlink,
# so the link outlives the refresh. A source with drop rules under
# `[ingest].drop_gate = true` is neither, and an adoption there is undone
# by the very next refresh; the script picks around that and says so when
# it cannot.
#
# `--adopt-source` names the target explicitly (id, slug or name),
# `--no-adopt` revives the unlinked rows without linking them, which is
# the old behaviour: a pristine `unknown` waiting for a feed, reachable
# by nothing.
#
# Scope: vless rows whose network parameter is xhttp. Snell v6 and the
# in-process SIP003 Shadowsocks plugins are the other two 0.22.0 gains, but
# Fumox only learned to parse Snell and AnyTLS recently, so there is no older
# population of stranded rows for them to revive.
#
# Usage:
#   scripts/revive-xhttp-proxies.sh [--dry-run] [--include-unlinked]
#                                   [--adopt-source ID|SLUG|NAME] [--no-adopt] [db]
#   scripts/revive-xhttp-proxies.sh --restore BACKUP [--dry-run] [db]
#
# Takes a backup first and refuses to touch a database that is not there.
# Linked rows are enqueued for priority checking, so the probe picks them up
# on its next cycle instead of waiting for the random sample. Adopted rows
# are enqueued on the same terms: they have a link by then.
#
# `--restore` is the undo, done the only way that is safe. It checks the
# backup before touching anything, refuses while anything has the database
# open, snapshots what it is about to overwrite, deletes the write-ahead log
# that would otherwise be replayed on top of the restored file, and verifies
# the result. The bare `cp` this script used to suggest fails in two ways,
# and the quiet one is worse: either SQLite replays a log belonging to a
# different file and reports `database disk image is malformed`, or the log
# fits, the copy "succeeds", `PRAGMA integrity_check` prints `ok`, and the
# database holds the pre-restore data after all.
set -euo pipefail

cd "$(dirname "$0")/.."

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
            # The header block: from the second line to the line before the
            # first executable one, comment markers stripped. awk rather
            # than sed because BSD sed has no address range with a nested
            # delete-and-print, and macOS is where this runs.
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
DB="${DB:-fumox.db}"

# Matches `[ingest].refresh_check_limit` as shipped in config/app.toml. The
# probe's own throttle would apply either way, but the admin revival path
# caps its enqueue the same way, and the script reports if the cap bit.
ENQUEUE_LIMIT="${FUMOX_REFRESH_CHECK_LIMIT:-100}"

# The daemon may be running against the same file. The sqlite3 CLI defaults to
# a zero busy timeout, which would turn a momentary lock into an immediate
# "database is locked" halfway through the update; wait for the writer instead.
BUSY_MS="${FUMOX_SQLITE_BUSY_TIMEOUT_MS:-5000}"

# ── --restore ────────────────────────────────────────────────────
# Whether anything has the database open. `locking_mode=EXCLUSIVE` needs
# exclusive access to the shared-memory index, so it fails the moment another
# connection has actually touched the file, reader or writer alike, and
# succeeds when the file is closed by everyone. A connection that opened the
# path and read nothing still passes, but such a connection holds no lock and
# no index mark, so it cannot be what a restore trips over. This is the only
# honest test available from outside the daemon: it cannot see a process that
# has the file open but idle, so the printed procedure still tells the
# operator to stop the daemon, and this catches the daemon that is running.
db_is_closed() {
    sqlite3 -cmd ".timeout 0" "$DB" \
        'PRAGMA locking_mode=EXCLUSIVE; SELECT count(*) FROM sqlite_master;' \
        >/dev/null 2>&1
}

# The one output that must be exactly "ok". Anything else means the file is
# damaged, and a restore on top of a damaged file is not worth attempting.
integrity_is_ok() {
    [[ "$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$1" 'PRAGMA integrity_check;' 2>/dev/null)" == "ok" ]]
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
    if [[ ! -f "$RESTORE" ]]; then
        echo "error: no such backup: ${RESTORE}" >&2
        exit 66
    fi

    echo "database: ${DB}"
    echo "backup:   ${RESTORE}"
    echo "size:     $(wc -c <"$RESTORE" | tr -d ' ') bytes"

    # Noted before anything opens the file. The liveness probe below is
    # itself a connection, and SQLite deletes the sidecars when the last one
    # closes, so by the time the restore reaches its own cleanup the log is
    # already gone and the report would claim there was nothing to remove.
    HAD_WAL=0
    for sidecar in "${DB}-wal" "${DB}-shm"; do
        [[ -e "$sidecar" ]] && HAD_WAL=1
    done

    # The backup is checked before anything is touched, so a damaged backup
    # costs an error message and not the database it was about to replace.
    if ! integrity_is_ok "$RESTORE"; then
        echo >&2
        echo "error: ${RESTORE} does not pass PRAGMA integrity_check." >&2
        echo "Restoring it would replace a working database with a damaged one," >&2
        echo "so nothing was touched. Find another backup, or dump what is" >&2
        echo "recoverable with '.recover' from the damaged file." >&2
        exit 67
    fi
    echo "check:    backup passes integrity_check"

    if ! db_is_closed; then
        echo >&2
        echo "error: something still has ${DB} open." >&2
        echo "A restore under a live writer is what produces 'database disk image" >&2
        echo "is malformed', or a restore that quietly changes nothing. Stop the" >&2
        echo "daemon first:" >&2
        echo >&2
        echo "  docker compose stop server probe" >&2
        echo >&2
        echo "and re-run this command." >&2
        exit 75
    fi
    echo "check:    nothing else has the database open"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo
        echo "dry run: ${RESTORE} would be restored over ${DB}, with its -wal and"
        echo "-shm removed first and the current contents snapshotted to"
        echo "${DB}.pre-restore-$(date +%Y%m%d-%H%M%S). Re-run without --dry-run."
        exit 0
    fi

    # The restore is itself undoable. Without this the only way back from a
    # restore the operator did not want is another restore, and there may not
    # be one: this snapshot is the state they were about to throw away.
    STAMP="$(date +%Y%m%d-%H%M%S)"
    PREV="${DB}.pre-restore-${STAMP}"
    sqlite3 "$DB" ".timeout ${BUSY_MS}" ".backup '${PREV}'"
    if ! integrity_is_ok "$PREV"; then
        echo >&2
        echo "error: the current ${DB} does not pass integrity_check, so it cannot" >&2
        echo "be snapshotted and the restore was not started. Repair or replace it" >&2
        echo "first; restoring over it would lose whatever is still readable in it." >&2
        exit 67
    fi
    echo "snapshot: ${PREV}  (what was there before, restorable the same way)"

    # The whole point of stopping the daemon: a -wal left next to the restored
    # file is a log of a different database, and SQLite replays it on open.
    # The rm is belt and braces, because the liveness probe opening and
    # closing the file already checkpointed the log away, which is the
    # recovery SQLite would have done on its own had the daemon been left to
    # come back up.
    REMOVED=()
    for sidecar in "${DB}-wal" "${DB}-shm"; do
        if [[ -e "$sidecar" ]]; then
            rm -f "$sidecar"
            REMOVED+=("$(basename "$sidecar")")
        fi
    done
    if [[ "$HAD_WAL" -eq 1 ]]; then
        echo "log:      the database had a write-ahead log, so it was not closed" >&2
        echo "          cleanly. It was checkpointed into ${DB} by the check above"
        echo "          and the -wal/-shm are gone; a log left in place would have"
        echo "          been replayed on top of the restored file."
    else
        echo "log:      none, the database was closed cleanly"
    fi
    if [[ "${#REMOVED[@]}" -gt 0 ]]; then
        echo "          also removed: ${REMOVED[*]}"
    fi

    # cp onto the existing file rather than rm+cp: it keeps the inode, so the
    # owner and mode the daemon expects survive the restore. Running this as
    # root over a file owned by the service user is the common case, and
    # rm+cp would hand the database to root.
    cp "$RESTORE" "$DB"

    if ! integrity_is_ok "$DB"; then
        echo >&2
        echo "error: ${DB} does not pass integrity_check after the restore." >&2
        echo "The backup passed the same check a moment ago, so the copy itself" >&2
        echo "is suspect rather than its contents. Put the previous state back:" >&2
        echo >&2
        echo "  rm -f ${DB}-wal ${DB}-shm && cp ${PREV} ${DB}" >&2
        echo >&2
        echo "and check it with 'PRAGMA integrity_check;'." >&2
        exit 70
    fi
    echo "check:    restored database passes integrity_check"

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

if [[ -n "$RESTORE" ]]; then
    run_restore
    exit 0
fi

if [[ ! -f "$DB" ]]; then
    echo "error: no database at $DB" >&2
    exit 66
fi

# Every query below reads `proxies` through the same alias, so one link
# predicate serves all of them. Two spellings of it is how this script once
# shipped a broken default run: the report's unaliased copy resolved, the
# target set's did not.
LINKED="EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)"
if [[ "$INCLUDE_UNLINKED" -eq 1 ]]; then
    SELECT_LINKED="1"
    SELECT_SCOPE="every removed xhttp vless row, linked or not"
else
    SELECT_LINKED="$LINKED"
    SELECT_SCOPE="removed xhttp vless rows that still have a source link"
fi

XHTTP="scheme = 'vless' AND lower(json_extract(params, '\$.type')) = 'xhttp'"

# The selection, shared by every report and by the update. json_extract keeps
# this exact: a LIKE over `params` would also match an xhttp string living in
# a path or a host, which is not the same thing as an xhttp transport.
IFS='|' read -r TOTAL LIVE UNLINKED_REMOVED LINKED_REMOVED <<<"$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" <<SQL
SELECT
  (SELECT COUNT(*) FROM proxies p WHERE ${XHTTP}),
  (SELECT COUNT(*) FROM proxies p WHERE ${XHTTP} AND status != 'removed'),
  (SELECT COUNT(*) FROM proxies p
    WHERE ${XHTTP} AND status = 'removed' AND NOT ${LINKED}),
  (SELECT COUNT(*) FROM proxies p
    WHERE ${XHTTP} AND status = 'removed' AND ${LINKED});
SQL
)"

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

# ── Adoption target ──────────────────────────────────────────────
# Only the unlinked half is adopted; rows that already have a link keep the
# one they have, since a second link would make reconciliation of either
# source responsible for the other's proxies.
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
        # ambiguous name is refused rather than resolved by row order: a
        # wrong source here is a link nothing will ever reconcile.
        IFS='|' read -r MATCHES ADOPT_ID ADOPT_NAME ADOPT_ENABLED ADOPT_DROPS <<<"$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" <<SQL
SELECT COUNT(*), id, name, enabled,
       COALESCE(json_array_length(json_extract(pipeline, '\$.drop')), 0)
  FROM sources
 WHERE id = '${ADOPT_SOURCE}' OR slug = '${ADOPT_SOURCE}' OR name = '${ADOPT_SOURCE}'
 ORDER BY (id = '${ADOPT_SOURCE}') DESC, id
 LIMIT 1;
SQL
)"
        if [[ "${MATCHES:-0}" -eq 0 ]]; then
            echo >&2
            echo "error: no source matches '${ADOPT_SOURCE}' (looked at id, slug and name)" >&2
            exit 67
        fi
        AMBIGUOUS="$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" "SELECT COUNT(*) FROM sources WHERE name = '${ADOPT_SOURCE}' AND id != '${ADOPT_ID}'")"
        if [[ "$AMBIGUOUS" -gt 0 ]]; then
            echo >&2
            echo "error: '${ADOPT_SOURCE}' matches ${AMBIGUOUS} other sources by name" >&2
            echo "pass the id or the slug instead" >&2
            exit 67
        fi
        # The id reaches a SQL string literal further down, so it is checked
        # against the shape nanoid(12) produces rather than trusted.
        if ! [[ "$ADOPT_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
            echo >&2
            echo "error: source id '${ADOPT_ID}' is not a plain nanoid, refusing to interpolate it" >&2
            exit 67
        fi
    else
        # Preference order, cheapest safety first: a source that is enabled
        # and has no drop rules serves the proxy in its /sub output and
        # still keeps the link (no drop rules means the alive-linger policy
        # holds under any drop_gate), a disabled source keeps the link but
        # serves nothing, and a source with drop rules is only safe while
        # drop_gate is off, which is a config fact this script does not
        # read, so it goes last and gets a warning.
        IFS='|' read -r ADOPT_ID ADOPT_NAME ADOPT_ENABLED ADOPT_DROPS <<<"$(sqlite3 -cmd ".timeout ${BUSY_MS}" "$DB" <<SQL
WITH ranked AS (
  SELECT id, name, enabled, created_at,
         COALESCE(json_array_length(json_extract(pipeline, '\$.drop')), 0) AS drops
    FROM sources
)
SELECT id, name, enabled, drops
  FROM ranked
 ORDER BY CASE WHEN enabled = 1 AND drops = 0 THEN 0
               WHEN enabled = 0 THEN 1
               ELSE 2 END,
          created_at, id
 LIMIT 1;
SQL
)"
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

# WAL mode: the .db alone is not a consistent snapshot, let sqlite make it.
sqlite3 "$DB" ".timeout ${BUSY_MS}" ".backup '${BACKUP}'"
for sidecar in "${DB}-wal" "${DB}-shm"; do
    [[ -e "$sidecar" ]] && echo "note: ${sidecar} exists, the .backup above already checkpointed it"
done

# The undo instructions, in one place because they are wrong in one obvious
# way and that way is what an operator reaches for. `cp backup db` swaps the
# main file while the -wal and -shm of the *current* database stay next to
# it, and SQLite then replays a write-ahead log that belongs to a different
# file. The result is either a hard `database disk image is malformed` (the
# log's frames do not fit the restored file) or, worse, no error at all: the
# log replays cleanly on top of the backup and the "restored" database is
# the pre-restore one, verified `ok` and silently not the file you copied.
# Both come from the same copy, and both mean the sidecars have to go and
# the writers have to be stopped first.
restore_hint() {
    cat <<EOF
To undo, restore ${BACKUP}. Stop whatever writes to ${DB} first: with a
live writer the -wal and -shm of the current database survive the copy and
SQLite replays a log that belongs to a different file, which reads as
'database disk image is malformed' or, worse, restores nothing at all
while reporting ok.

  1. stop the daemon (docker compose stop server probe, or whatever runs it)
  2. rm -f ${DB}-wal ${DB}-shm
  3. cp ${BACKUP} ${DB}
  4. sqlite3 ${DB} 'PRAGMA integrity_check;'      # must print exactly: ok
  5. start the daemon again

Step 4 is the one that matters: a restore that skipped steps 1 and 2 can
pass it while holding the wrong data.
EOF
}

NOW="$(date +%s)"

# From here on the backup exists, so any abort must say how to undo itself:
# `set -e` would otherwise exit silently with the database already touched.
on_err() {
    local code=$?
    echo >&2
    echo "error: aborted with code ${code}; the database may be half-written" >&2
    if [[ -n "${BACKUP:-}" && -f "${BACKUP}" ]]; then
        echo >&2
        echo "the backup ${BACKUP} is intact. To undo, stop the daemon, delete" >&2
        echo "${DB}-wal and ${DB}-shm, copy the backup over ${DB}, and check it" >&2
        echo "with 'PRAGMA integrity_check;'. A bare cp leaves the current" >&2
        echo "database's write-ahead log next to the restored file." >&2
    fi
    exit "$code"
}
trap on_err ERR

# The target set is materialised first so the update, the adoption and the
# enqueue agree on exactly the same rows, without a RETURNING clause the
# reader would have to know the SQLite version for. The link predicate rides
# on the row so the adoption can tell the two populations apart without
# re-deriving it.
ADOPT_SQL=""
if [[ -n "$ADOPT_ID" ]]; then
    ADOPT_SQL="
CREATE TEMP TABLE xhttp_adopt AS
SELECT id FROM xhttp_revive WHERE linked = 0;

INSERT OR IGNORE INTO proxy_source_links (proxy_id, source_id, seen_at)
SELECT id, '${ADOPT_ID}', ${NOW} FROM xhttp_adopt;

SELECT 'adopted', changes();"
fi

# `changes()` is read straight after the statement it describes, so nothing
# may sit between them: it reports the rows that INSERT actually added, not
# the rows the table happens to hold for those ids. Counting the table
# instead is how this script once reported ten enqueues it never made, the
# ten being rows another enqueue had left there earlier.
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

-- Counted in the same connection: the temp table above is gone by the time a
-- second sqlite3 runs, and a durable recount could not tell our rows from
-- anything else enqueued in the same second.
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

# The counts come back as text; a silent parse failure would surface much
# later as an arithmetic error on an empty string, far from its cause.
for pair in "revived:${REVIVED}" "linked:${REVIVED_LINKED}" "queued:${QUEUED}"; do
    if ! [[ "${pair#*:}" =~ ^[0-9]+$ ]]; then
        echo "error: could not read the ${pair%%:*} count back from sqlite3" >&2
        echo "restore with: cp ${BACKUP} ${DB}" >&2
        exit 70
    fi
done
if [[ -n "$ADOPT_SQL" && ! "${ADOPTED:-}" =~ ^[0-9]+$ ]]; then
    echo "error: could not read the adopted count back from sqlite3" >&2
    echo "restore with: cp ${BACKUP} ${DB}" >&2
    exit 70
fi
ADOPTED="${ADOPTED:-0}"

if [[ "$REVIVED" -ne "$REVIVABLE" ]]; then
    # Expected only if the daemon moved rows while the script ran, which the
    # busy timeout is there to absorb rather than to fail on.
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

# Only rows that ended up with a link are enqueueable at all, so the cap is
# worth mentioning only when there were some: a run that revived nothing
# enqueueable has not hit the cap, it simply had nothing to enqueue.
ENQUEUEABLE=$((REVIVED_LINKED + ADOPTED))
if [[ "${QUEUED}" -lt "${ENQUEUEABLE}" ]]; then
    echo
    echo "note: ${ENQUEUEABLE} row(s) were enqueueable and ${QUEUED} made the queue."
    if [[ "$ADOPTED" -gt 0 ]]; then
        echo "The cap (FUMOX_REFRESH_CHECK_LIMIT=${ENQUEUE_LIMIT}) held the rest back."
    fi
    echo "The ones left out are 'unknown' with a link, so the random T1 sample still"
    echo "reaches them, just not at priority. Raise the cap and re-run to enqueue"
    echo "more, or leave it: the next source refresh enqueues unknowns of its own."
fi

cat <<EOF

Done. The revived rows rejoin the normal ladder: T1 reachability first (they
are 'unknown', which no T2 batch selects), then T2 once T1 puts them in
'alive'. An entry that is genuinely dead fails its checks again and walks
back down to 'removed' on its own, so a row revived here costs one probe
cycle and nothing more.

EOF

restore_hint
