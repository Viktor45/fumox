-- T2 recency-priority sample: never-checked proxies first, then the oldest
-- last-T2 attempt. Replaces the old ORDER BY RANDOM() T2 batch which could
-- leave a proxy tunnel-unverified for months in a large pool.
--
-- The T2 batch used to be ORDER BY RANDOM(): in a large pool a proxy could
-- stay tunnel-unverified for months while its `alive` status rested on T1
-- connectivity alone. The selector now picks proxies with no T2 attempt
-- yet first, then the ones whose last T2 check is the oldest. The ordering
-- expression is the correlated MAX(checked_at) per proxy, computed from
-- the t2 slice of the history; this partial index keeps that slice tiny
-- (t1 rows are the vast majority of probe_results) and lets SQLite seek
-- each proxy's last t2 moment through (proxy_id, checked_at).
CREATE INDEX idx_probe_t2_last ON probe_results(proxy_id, checked_at)
WHERE probe_kind = 't2';
