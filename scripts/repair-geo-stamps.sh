#!/usr/bin/env bash
# One-shot repair of the proxies.geo_* columns.
#
# Background. Until 2026-10-02 the ingest path handed `reconcile_source` the
# entry list AFTER a source's pipeline drop rules had shortened it, together
# with the geo stamps resolved for the list BEFORE the drop. The two are
# paired by index, so every proxy past the first dropped entry was stored
# carrying a neighbouring host's country and ASN. One IP could end up stamped
# with several autonomous systems, and the admin ASN cleanup buttons then
# acted on that noise (an "AS13335" row whose host was really AS20473).
#
# The resolver itself was never wrong: it is deterministic per host, and the
# `.mmdb` files did not change. Only what was written was wrong, so the
# repair is a rewrite, not a migration: clear the three columns, let the
# startup geo backfill resolve every row again from its own host. The
# backfill (crates/fumox-server/src/geo_backfill.rs) picks up exactly the
# rows with all three columns NULL, which is what this script produces.
#
# Verified on a copy of the production database: 23249 rows re-stamped,
# 1162784 stamped rows re-checked against the resolver, 0 wrong, and the
# number of hosts carrying more than one ASN went 2510 -> 0.
#
# Usage:
#   scripts/repair-geo-stamps.sh [path/to/fumox.db]
#
# Takes a backup first and refuses to touch a database that is not there.
# The server (or just `fumox-server` for the backfill pass) must be running
# afterwards: the re-resolution happens at its next start, in the background.
set -euo pipefail

cd "$(dirname "$0")/.."

DB="${1:-fumox.db}"

if [[ ! -f "$DB" ]]; then
    echo "error: no database at $DB" >&2
    exit 66
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${DB}.pre-geo-repair-${STAMP}"

echo "database: $DB"
echo "backup:   $BACKUP"

# WAL mode: the .db alone is not a consistent snapshot, copy the sidecars
# too (or better, let sqlite produce the backup itself).
sqlite3 "$DB" ".backup '${BACKUP}'"
for sidecar in "${DB}-wal" "${DB}-shm"; do
    [[ -e "$sidecar" ]] && echo "note: ${sidecar} exists, the .backup above already checkpointed it"
done

STAMPED="$(sqlite3 "$DB" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL OR geo_country IS NOT NULL")"
echo "rows with a geo stamp before repair: ${STAMPED}"

sqlite3 "$DB" <<'SQL'
UPDATE proxies
   SET geo_country = NULL, geo_city = NULL, geo_asn = NULL
 WHERE geo_asn IS NOT NULL OR geo_city IS NOT NULL OR geo_country IS NOT NULL;
SQL

LEFT="$(sqlite3 "$DB" "SELECT COUNT(*) FROM proxies WHERE geo_asn IS NOT NULL OR geo_country IS NOT NULL")"
echo "rows with a geo stamp after repair:  ${LEFT}"

cat <<EOF

Done. Restart the server: the startup geo backfill re-resolves every row
from its own host and writes the corrected country, city and ASN. It runs in
the background in batches of 500, so the first seconds after the restart show
rows without a stamp while the sweep works through them.

To follow it, or to confirm it finished, watch for the backfill's own log
line ("geo backfill complete", with the row count and elapsed time).
EOF
