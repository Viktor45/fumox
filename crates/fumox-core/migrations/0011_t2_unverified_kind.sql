-- The unverified T2 label joins the t2 slice of the history.
--
-- An attempt the tunnel engine never verified (the engine was down) is
-- still an attempt: the recency selector has to see it, otherwise the rows
-- the engine failed on stay at the head of the queue forever and are served
-- again in every cycle. SQLite cannot widen a partial index in place, so
-- the old one is dropped and a wider one takes its place.
DROP INDEX idx_probe_t2_last;
CREATE INDEX idx_probe_t2_last ON probe_results(proxy_id, checked_at)
WHERE probe_kind IN ('t2', 't2_unverified');
