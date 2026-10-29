-- How often the geo backfill tried a row and when it last did.
--
-- A row whose host no database can answer stays missing for good. Without
-- a marker the backfill walked those rows on every pass, and they took the
-- budget away from the rows that were never tried at all: a stale or
-- half-written database kept the fresh rows unfilled pass after pass.
--
-- `geo_attempts` counts the consecutive failed lookups of a row,
-- `last_geo_attempt_at` is the time of the last attempt (unix seconds).
-- A row that was looked up recently is left out of the missing set until
-- the retry window passed, so a hopeless host is retried rarely instead of
-- never.
ALTER TABLE proxies ADD COLUMN geo_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxies ADD COLUMN last_geo_attempt_at INTEGER;
-- The backfill walks the missing rows by id; the retry window filters on
-- the attempt timestamp, so it needs its own index to stay cheap.
CREATE INDEX idx_proxies_geo_attempt ON proxies(last_geo_attempt_at);
