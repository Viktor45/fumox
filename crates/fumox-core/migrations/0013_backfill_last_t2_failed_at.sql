-- Backfill the T2 block from the probe history.
--
-- Migration 0007 added `last_t2_failed_at` and the T1 selector that reads
-- it (`last_t2_failed_at IS NULL`), but it added the column empty. Every
-- row that existed at that moment looked like a proxy that had never
-- failed a tunnel check, so the T1 sample kept serving exactly the
-- proxies the probe had already found untunnellable — the migration was
-- supposed to take them out of the T1 lane and did not.
--
-- The marker was already there, in the probe history: a `t2` row with
-- `ok = 0` is a failed tunnel attempt, and its `checked_at` is when it
-- happened. `t2_unverified` counts as a T2 attempt too (the engine never
-- produced a verdict), so it is part of the same slice.
--
-- Only the *last* T2 attempt decides: the stamp is cleared by a
-- successful T2, so a proxy whose newest attempt succeeded has to stay
-- NULL. The stamp therefore takes the timestamp of the newest T2 attempt
-- when that attempt failed, and nothing otherwise.
--
-- After this migration NULL means one of three things: the proxy never
-- had a T2 attempt, its last T2 attempt succeeded, or its history was
-- trimmed before the backfill could see it — "state unknown / no check
-- since the migration". The first two are the ordinary "no T2 failure";
-- the third is a gap the probe closes with its next T2 attempt.
UPDATE proxies
   SET last_t2_failed_at = (
           SELECT r.checked_at
             FROM probe_results r
            WHERE r.proxy_id = proxies.id
              AND r.probe_kind IN ('t2', 't2_unverified')
            ORDER BY r.checked_at DESC, r.id DESC
            LIMIT 1)
 WHERE last_t2_failed_at IS NULL
   AND (
           SELECT r.ok
             FROM probe_results r
            WHERE r.proxy_id = proxies.id
              AND r.probe_kind IN ('t2', 't2_unverified')
            ORDER BY r.checked_at DESC, r.id DESC
            LIMIT 1) = 0;
