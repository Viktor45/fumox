-- Fumox initial schema — transcribed from docs/DATABASE.md v0.4.
--
-- Connection-level PRAGMAs (journal_mode=WAL, foreign_keys=ON, busy_timeout)
-- are applied by fumox_core::db::connect_pool on every connection and are
-- deliberately absent here: migrations run inside a transaction, where
-- journal_mode cannot be changed.

-- ─────────────────────────────────────────────
-- Sources
-- ─────────────────────────────────────────────
CREATE TABLE sources (
    id              TEXT PRIMARY KEY,            -- nanoid(12); doubles as the /src/{id} token when slug is unset
    slug            TEXT UNIQUE,                 -- human-readable identifier (for /sub/{slug})
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,  -- 0/1
    encoding        TEXT NOT NULL DEFAULT 'auto',  -- 'plain'|'base64'|'auto'
    input_format    TEXT,                        -- 'uri_list'|'clash_yaml'|'sing_box_json'; NULL = auto-detect
    protocols       TEXT,                        -- JSON array of scheme names, NULL = auto-detect
    cache_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    tags            TEXT,                        -- JSON array of strings
    pipeline        TEXT,                        -- JSON: processing rules (SPEC §5)
    headers         TEXT,                        -- JSON: extra HTTP headers for fetch
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    last_fetched_at INTEGER,                     -- last successful fetch
    last_error      TEXT,                        -- last fetch error message
    error_class     TEXT                         -- 'network'|'http_server'|'http_client'|'parse_error' (NULL = success; SPEC §10.2)
);
CREATE INDEX idx_sources_enabled ON sources(enabled);

-- ─────────────────────────────────────────────
-- Profiles (combinations of sources)
-- ─────────────────────────────────────────────
CREATE TABLE profiles (
    id              TEXT PRIMARY KEY,            -- nanoid(12); doubles as the /sub/{id} token when slug is unset
    slug            TEXT UNIQUE,                 -- human-readable identifier (for /sub/{slug})
    access_token    TEXT,                        -- optional /sub access token (NULL = public; SPEC §10.1)
    name            TEXT NOT NULL,
    output_format   TEXT NOT NULL DEFAULT 'uri_list', -- uri_list|base64|clash|sing_box
    pipeline        TEXT,                        -- JSON: rule overrides
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE profile_sources (
    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    source_id  TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL DEFAULT 0,       -- merge order
    PRIMARY KEY (profile_id, source_id)
);

-- ─────────────────────────────────────────────
-- Proxies (normalized records)
-- ─────────────────────────────────────────────
CREATE TABLE proxies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint     TEXT NOT NULL UNIQUE,        -- stable dedup key (DATABASE.md «Fingerprint»)
    scheme          TEXT NOT NULL,               -- vless|vmess|trojan|ss|hysteria2|tuic|mieru|socks5|naive
    name            TEXT NOT NULL DEFAULT '',    -- display name (fragment / ps)
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
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
    second_chance_at INTEGER,                    -- when the second chance fires
    recheck_15m_at  INTEGER,                     -- recheck after 15 minutes
    recheck_30m_at  INTEGER,                     -- recheck after 30 minutes
    recheck_1h_at   INTEGER,                     -- recheck after 1 hour
    removed_at      INTEGER,                     -- when finally removed

    -- speed (filled later, see speed_results)
    latency_ms      INTEGER,                     -- last measured latency
    speed_mbps      REAL,                        -- last measured speed (later)

    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX idx_proxies_status   ON proxies(status);
CREATE INDEX idx_proxies_hostport ON proxies(host, port);
CREATE INDEX idx_proxies_scheme   ON proxies(scheme);
CREATE INDEX idx_proxies_country  ON proxies(geo_country); -- admin filter

-- ─────────────────────────────────────────────
-- Proxy ↔ source links (M:N)
-- ─────────────────────────────────────────────
CREATE TABLE proxy_source_links (
    proxy_id  INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
    source_id TEXT    NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    seen_at   INTEGER NOT NULL,                  -- last time seen in this source
    PRIMARY KEY (proxy_id, source_id)
);
CREATE INDEX idx_links_source ON proxy_source_links(source_id);

-- ─────────────────────────────────────────────
-- Health-check history (written by probe)
-- ─────────────────────────────────────────────
CREATE TABLE probe_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id    INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
    checked_at  INTEGER NOT NULL,
    ok          INTEGER NOT NULL,                -- 0/1
    latency_ms  INTEGER,                         -- NULL when unreachable
    error       TEXT,                            -- error text on failure
    probe_kind  TEXT NOT NULL DEFAULT 'tcp'      -- 'tcp' | 'tls' | 't2' | (later 'speed'); t2 = real check via meow-rs (SPEC §8.1)
);
CREATE INDEX idx_probe_proxy_time ON probe_results(proxy_id, checked_at);
CREATE INDEX idx_probe_time ON probe_results(checked_at); -- history retention

-- ─────────────────────────────────────────────
-- Speed measurement results (later, mihomo-speedtest-rs)
-- ─────────────────────────────────────────────
CREATE TABLE speed_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id     INTEGER NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
    measured_at  INTEGER NOT NULL,
    latency_ms   INTEGER,
    jitter_ms    INTEGER,
    loss_pct     REAL,
    download_mbps REAL,
    upload_mbps  REAL,
    tool         TEXT NOT NULL DEFAULT 'mihomo-speedtest-rs'
);
CREATE INDEX idx_speed_proxy_time ON speed_results(proxy_id, measured_at);

-- ─────────────────────────────────────────────
-- Source fetch log
-- ─────────────────────────────────────────────
CREATE TABLE fetch_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    fetched_at  INTEGER NOT NULL,
    ok          INTEGER NOT NULL,
    http_status INTEGER,
    bytes       INTEGER,
    proxies_found INTEGER,                       -- how many proxies were recognized
    error       TEXT,
    error_class TEXT                          -- 'network'|'http_server'|'http_client'|'parse_error' (NULL = success; SPEC §10.2)
);
CREATE INDEX idx_fetch_source_time ON fetch_log(source_id, fetched_at);
CREATE INDEX idx_fetch_time ON fetch_log(fetched_at); -- admin journal (time ordering)

-- ─────────────────────────────────────────────
-- Service key-value table
-- ─────────────────────────────────────────────
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
