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
# one on its own changes nothing an operator can see except its badge.
#
# It changes something the moment the source comes back, though. The upsert's
# `ON CONFLICT DO UPDATE` never touches `status`, so a re-linked `removed`
# row stays `removed`, and `[ingest].removed_as_unknown` is false as shipped,
# so nothing revives it either: the row is dead permanently, whatever its
# feed does later. Pre-reviving to `unknown` costs nothing and removes that
# dependency, since a row that is already `unknown` when the upsert re-links
# it lands straight in a probe lane. That is the whole case for the flag.
#
# Scope: vless rows whose network parameter is xhttp. Snell v6 and the
# in-process SIP003 Shadowsocks plugins are the other two 0.22.0 gains, but
# Fumox only learned to parse Snell and AnyTLS recently, so there is no older
# population of stranded rows for them to revive.
#
# Usage:
#   scripts/revive-xhttp-proxies.sh [--dry-run] [--include-unlinked] [db]
#
# Takes a backup first and refuses to touch a database that is not there.
# Linked rows are enqueued for priority checking, so the probe picks them up
# on its next cycle instead of waiting for the random sample. Unlinked rows
# are never enqueued: `enqueue_checks` would refuse them, and it is right to.
set -euo pipefail

cd "$(dirname "$0")/.."

DRY_RUN=0
INCLUDE_UNLINKED=0
DB=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --include-unlinked) INCLUDE_UNLINKED=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*)
            echo "error: unknown option $arg" >&2
            exit 64
            ;;
        *) DB="$arg" ;;
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
    echo "  removed, no source link:             ${UNLINKED_REMOVED}  (included, and still unprobeable)"
else
    echo "  removed, no source link:             ${UNLINKED_REMOVED}  (skipped: pass --include-unlinked to take them)"
fi

if [[ "$REVIVABLE" -eq 0 ]]; then
    echo
    echo "Nothing to revive."
    exit 0
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

NOW="$(date +%s)"

# From here on the backup exists, so any abort must say how to undo itself:
# `set -e` would otherwise exit silently with the database already touched.
on_err() {
    local code=$?
    echo >&2
    echo "error: aborted with code ${code}; the database may be half-written" >&2
    [[ -n "${BACKUP:-}" && -f "$BACKUP" ]] && echo "restore with: cp ${BACKUP} ${DB}" >&2
    exit "$code"
}
trap on_err ERR

# The target set is materialised first so the update and the enqueue agree on
# exactly the same rows, without a RETURNING clause the reader would have to
# know the SQLite version for. The link predicate rides on the row so the
# enqueue can tell the two populations apart without re-deriving it.
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

-- Same guards as repo::probe::enqueue_checks, so the script cannot put a row
-- in the priority queue that the daemon would have refused.
INSERT OR IGNORE INTO probe_requests (proxy_id, requested_at)
SELECT p.id, ${NOW} FROM proxies p
 WHERE p.id IN (SELECT id FROM xhttp_revive WHERE linked = 1)
   AND p.status = 'unknown'
   AND p.scheme NOT IN ('hysteria2', 'tuic', 'mieru')
 ORDER BY p.id DESC
 LIMIT ${ENQUEUE_LIMIT};

-- Counted in the same connection: the temp table above is gone by the time a
-- second sqlite3 runs, and a durable recount could not tell our rows from
-- anything else enqueued in the same second.
SELECT 'revived', (SELECT COUNT(*) FROM xhttp_revive)
UNION ALL
SELECT 'revived_linked', (SELECT COUNT(*) FROM xhttp_revive WHERE linked = 1)
UNION ALL
SELECT 'queued', (SELECT COUNT(*) FROM probe_requests
                   WHERE proxy_id IN (SELECT id FROM xhttp_revive));
SQL
)"

read_count() {
    printf '%s\n' "$RESULT" | awk -F'|' -v k="$1" '$1==k {print $2}'
}
REVIVED="$(read_count revived)"
REVIVED_LINKED="$(read_count revived_linked)"
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

if [[ "$REVIVED" -ne "$REVIVABLE" ]]; then
    # Expected only if the daemon moved rows while the script ran, which the
    # busy timeout is there to absorb rather than to fail on.
    echo "note: ${REVIVABLE} row(s) matched the selection but ${REVIVED} were"
    echo "revived, so something else changed them in between."
fi

echo
echo "revived:  ${REVIVED}  (${REVIVED_LINKED} linked, $((REVIVED - REVIVED_LINKED)) unlinked)"
if [[ "$INCLUDE_UNLINKED" -eq 1 && "$REVIVED" -gt "$REVIVED_LINKED" ]]; then
    echo "          the unlinked ones are not enqueued and no probe lane reaches"
    echo "          them yet. They are 'unknown', so a feed that re-links one puts"
    echo "          it straight back into rotation instead of leaving it terminal."
fi
echo "enqueued for priority checking: ${QUEUED}"

if [[ "${QUEUED}" -lt "${REVIVED_LINKED}" ]]; then
    echo
    echo "note: the enqueue cap (FUMOX_REFRESH_CHECK_LIMIT=${ENQUEUE_LIMIT}) held some rows"
    echo "back. They are 'unknown' with a source link, so the random T1 sample still"
    echo "reaches them, just not at priority. Raise the cap and re-run to enqueue"
    echo "more, or leave it: the next source refresh enqueues unknowns of its own."
fi

cat <<EOF

Done. The revived rows rejoin the normal ladder: T1 reachability first (they
are 'unknown', which no T2 batch selects), then T2 once T1 puts them in
'alive'. An entry that is genuinely dead fails its checks again and walks
back down to 'removed' on its own, so a row revived here costs one probe
cycle and nothing more.

To undo, restore the backup:
  cp ${BACKUP} ${DB}
EOF
