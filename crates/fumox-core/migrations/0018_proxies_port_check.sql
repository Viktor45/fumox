-- no-transaction
-- A proxy port must be a dialable endpoint: 1..=65535.
--
-- SQLite cannot add a CHECK to an existing column, so the constraint ships
-- as a table rebuild (the procedure from https://sqlite.org/lang_altertable.html):
-- the `proxies` rows are copied into a fresh table that carries
-- `CHECK (port BETWEEN 1 AND 65535)` on `port`, and every legacy row with
-- port = 0 (or otherwise out of range) stays behind in the dropped table.
-- Rows without a usable port are junk that no client could ever dial, so
-- their probe history, source links and speed rows go with them — the
-- explicit deletes below stand in for the `ON DELETE CASCADE` the schema
-- declares, which cannot fire while foreign keys are off.
--
-- `PRAGMA foreign_keys` is a no-op inside a transaction, and leaving it off
-- would let the `DROP TABLE` of the old table (or the copy) cascade away
-- the child rows of every proxy, so the file starts with the sqlx
-- `-- no-transaction` directive (parsed for SQLite too since the directive
-- moved into the shared migration source; see sqlx-core `source.rs`) and
-- manages the transaction and the pragma itself. sqlx executes each
-- statement in order on one connection, so the pragma state the connection
-- returns to the pool with is the one the last line restores.
--
-- The script is safe to re-run: a crash mid-rebuild rolls the transaction
-- back, and a crash after the commit but before the migration is stamped
-- replays harmlessly (`IF EXISTS` guards, and the copy only carries rows
-- the CHECK accepts).
PRAGMA foreign_keys = OFF;
BEGIN;

DROP TABLE IF EXISTS proxies_new;
CREATE TABLE proxies_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint     TEXT NOT NULL UNIQUE,        -- stable dedup key (per-scheme hash of the connection line)
    scheme          TEXT NOT NULL,               -- vless|vmess|trojan|ss|hysteria2|tuic|mieru|socks5|naive
    name            TEXT NOT NULL DEFAULT '',    -- display name (fragment / ps)
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL CONSTRAINT proxies_port_range CHECK (port BETWEEN 1 AND 65535),
    credential      TEXT NOT NULL DEFAULT '',    -- uuid / password / method:pass / user:pass
    params          TEXT,                        -- JSON: recognized protocol parameters
    unknown_params  TEXT,                        -- JSON: unrecognized parameters (pass-through!)
    raw_line        TEXT,                        -- original line (debugging/recovery)

    -- geo enrichment (filled by the pipeline)
    geo_country     TEXT,                        -- ISO code, e.g. 'DE'
    geo_city        TEXT,                        -- when a City database is configured
    geo_asn         TEXT,                        -- when an ASN database is configured
    resolved_ip     TEXT,                        -- last resolved IP

    -- status and lifecycle (owned by probe)
    status          TEXT NOT NULL DEFAULT 'unknown', -- unknown|alive|quarantine|removed
    fail_count      INTEGER NOT NULL DEFAULT 0,  -- consecutive failed checks
    last_checked_at INTEGER,
    last_alive_at   INTEGER,
    quarantined_at  INTEGER,                     -- when quarantine started
    removed_at      INTEGER,                     -- when finally removed

    -- speed (filled later, see speed_results)
    latency_ms      INTEGER,                     -- last measured latency
    speed_mbps      REAL,                        -- last measured speed (later)

    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,

    -- quarantine ladder (0005)
    ladder_at         INTEGER,                   -- when the next ladder step fires
    ladder_step       INTEGER NOT NULL DEFAULT 0, -- 0 = second chance pending, 1..N = the Nth recheck
    -- T1 suppression after a T2 failure (0007)
    last_t2_failed_at INTEGER,
    -- the path segment of the parsed URI (0010)
    raw_path          TEXT,
    -- geo backfill bookkeeping (0012)
    geo_attempts       INTEGER NOT NULL DEFAULT 0,
    last_geo_attempt_at INTEGER,
    -- denormalised T2 recency stamp (0014)
    last_t2_checked_at INTEGER
);

-- The column list is explicit and mirrors the table above (the physical
-- order of the old table is kept): the rebuild must not depend on a
-- `SELECT *` shape that a later migration could reorder.
INSERT INTO proxies_new (id, fingerprint, scheme, name, host, port, credential,
                         params, unknown_params, raw_line,
                         geo_country, geo_city, geo_asn, resolved_ip,
                         status, fail_count, last_checked_at, last_alive_at,
                         quarantined_at, removed_at, latency_ms, speed_mbps,
                         created_at, updated_at,
                         ladder_at, ladder_step, last_t2_failed_at, raw_path,
                         geo_attempts, last_geo_attempt_at, last_t2_checked_at)
SELECT id, fingerprint, scheme, name, host, port, credential,
       params, unknown_params, raw_line,
       geo_country, geo_city, geo_asn, resolved_ip,
       status, fail_count, last_checked_at, last_alive_at,
       quarantined_at, removed_at, latency_ms, speed_mbps,
       created_at, updated_at,
       ladder_at, ladder_step, last_t2_failed_at, raw_path,
       geo_attempts, last_geo_attempt_at, last_t2_checked_at
  FROM proxies
 WHERE port BETWEEN 1 AND 65535;

-- Children of the rows the CHECK refuses: with foreign keys off the
-- cascade cannot fire, and an orphan would violate the constraint the
-- moment foreign keys come back on. Every table referencing proxies(id)
-- is listed here.
DELETE FROM proxy_source_links WHERE proxy_id NOT IN (SELECT id FROM proxies_new);
DELETE FROM probe_results      WHERE proxy_id NOT IN (SELECT id FROM proxies_new);
DELETE FROM speed_results      WHERE proxy_id NOT IN (SELECT id FROM proxies_new);
DELETE FROM probe_requests     WHERE proxy_id NOT IN (SELECT id FROM proxies_new);

DROP TABLE proxies;
ALTER TABLE proxies_new RENAME TO proxies;

-- Dropping the old table dropped its indexes with it; the rename freed
-- nothing, so every index is rebuilt under the same name and definition
-- it had before the rebuild.
DROP INDEX IF EXISTS idx_proxies_status;
CREATE INDEX idx_proxies_status   ON proxies(status);
DROP INDEX IF EXISTS idx_proxies_hostport;
CREATE INDEX idx_proxies_hostport ON proxies(host, port);
DROP INDEX IF EXISTS idx_proxies_scheme;
CREATE INDEX idx_proxies_scheme   ON proxies(scheme);
DROP INDEX IF EXISTS idx_proxies_country;
CREATE INDEX idx_proxies_country  ON proxies(geo_country);
DROP INDEX IF EXISTS idx_proxies_ladder;
CREATE INDEX idx_proxies_ladder   ON proxies(status, ladder_at);
DROP INDEX IF EXISTS idx_proxies_t2_block;
CREATE INDEX idx_proxies_t2_block ON proxies(last_t2_failed_at);
DROP INDEX IF EXISTS idx_proxies_updated_at;
CREATE INDEX idx_proxies_updated_at ON proxies(updated_at DESC, id DESC);
DROP INDEX IF EXISTS idx_proxies_geo_attempt;
CREATE INDEX idx_proxies_geo_attempt ON proxies(last_geo_attempt_at);
DROP INDEX IF EXISTS idx_proxies_last_t2_checked_at;
CREATE INDEX idx_proxies_last_t2_checked_at ON proxies(last_t2_checked_at, id);

COMMIT;
PRAGMA foreign_keys = ON;
