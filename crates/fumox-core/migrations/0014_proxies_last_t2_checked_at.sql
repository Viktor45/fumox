-- Denormalise the T2 recency stamp onto the proxy row.
--
-- The T2 batch is ordered by "the oldest last tunnel attempt first", and
-- the attempt moment used to be computed by a correlated
-- MAX(checked_at) over `probe_results`: one index seek into the largest
-- table of the database for every candidate row the batch looks at. The
-- moment is a property of the proxy, not of the journal, so it belongs
-- on the proxy row where the batch can read it from an index.
--
-- The stamp is permanent on purpose. The journal rotates after the
-- retention window, and a proxy whose history was trimmed must not look
-- never-checked again: it would be served as a first-timer in every
-- cycle from then on. The backfill takes the newest T2 attempt of every
-- proxy that has one.
--
-- NULL keeps its meaning "no T2 attempt yet": SQLite sorts NULL first in
-- an ascending order, which is exactly the tier the batch wants (the
-- never-checked rows come before the checked ones).
ALTER TABLE proxies ADD COLUMN last_t2_checked_at INTEGER;

UPDATE proxies
   SET last_t2_checked_at = (
           SELECT MAX(r.checked_at)
             FROM probe_results r
            WHERE r.proxy_id = proxies.id
              AND r.probe_kind IN ('t2', 't2_unverified'))
 WHERE last_t2_checked_at IS NULL
   AND EXISTS (SELECT 1
                 FROM probe_results r
                WHERE r.proxy_id = proxies.id
                  AND r.probe_kind IN ('t2', 't2_unverified'));

-- The batch reads the stamp in recency order and breaks the ties by id,
-- so the index carries both columns and answers the batch's ORDER BY
-- without a sort step.
CREATE INDEX idx_proxies_last_t2_checked_at ON proxies(last_t2_checked_at, id);
