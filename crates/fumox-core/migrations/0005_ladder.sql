-- Generic quarantine ladder (configurable recheck steps, SPEC §8.3a).
--
-- The fixed `second_chance_at` + `recheck_15m_at`/`recheck_30m_at`/
-- `recheck_1h_at` columns encoded a hard-coded ladder of exactly three
-- rechecks. The delays are now configured (`[probe] recheck_delays_secs`),
-- so the schedule is generalized: `ladder_step` 0 = waiting for the second
-- chance, 1..N = the Nth recheck (N = len(recheck_delays_secs)); failing
-- step k schedules `ladder_at = now + delays[k]` or, past the end, removes
-- the proxy. Exactly one of the old columns was ever non-NULL, so the
-- mapping below is total.
ALTER TABLE proxies ADD COLUMN ladder_at INTEGER;
ALTER TABLE proxies ADD COLUMN ladder_step INTEGER NOT NULL DEFAULT 0;

UPDATE proxies SET ladder_at = second_chance_at, ladder_step = 0
WHERE second_chance_at IS NOT NULL;
UPDATE proxies SET ladder_at = recheck_15m_at, ladder_step = 1
WHERE recheck_15m_at IS NOT NULL;
UPDATE proxies SET ladder_at = recheck_30m_at, ladder_step = 2
WHERE recheck_30m_at IS NOT NULL;
UPDATE proxies SET ladder_at = recheck_1h_at, ladder_step = 3
WHERE recheck_1h_at IS NOT NULL;

ALTER TABLE proxies DROP COLUMN second_chance_at;
ALTER TABLE proxies DROP COLUMN recheck_15m_at;
ALTER TABLE proxies DROP COLUMN recheck_30m_at;
ALTER TABLE proxies DROP COLUMN recheck_1h_at;

-- The quarantine-due selector filters by status first, then the ladder
-- timestamp; quarantine rows are few, but the composite index keeps the
-- scan exact.
CREATE INDEX idx_proxies_ladder ON proxies(status, ladder_at);
