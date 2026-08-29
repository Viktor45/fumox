-- ─────────────────────────────────────────────
-- Probe priority queue (SPEC §8.3): fumox-server enqueues freshly ingested
-- `unknown` proxies of T1-probeable schemes at source-refresh time (bounded
-- by [probe].refresh_check_limit); fumox-probe drains the queue at the start
-- of every cycle, newest first, then falls back to the random sample.
-- Rows self-clean through the FK cascade when a proxy is deleted.
-- ─────────────────────────────────────────────
CREATE TABLE probe_requests (
    proxy_id     INTEGER PRIMARY KEY REFERENCES proxies(id) ON DELETE CASCADE,
    requested_at INTEGER NOT NULL
);
CREATE INDEX idx_probe_requests_time ON probe_requests(requested_at);
