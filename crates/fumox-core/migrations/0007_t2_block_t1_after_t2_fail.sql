-- T1 suppression after a T2 failure (SPEC §8.3).
--
-- Once a proxy's most recent T2 attempt fails it sits out T1 checks until
-- the next successful T2. NULL means "no recent T2 failure" (no T2 attempt
-- yet, or a successful T2 since). The T1 candidate query filters by
-- `last_t2_failed_at IS NULL`, so the recency-ordered T2 batch is the only
-- path back to T1 for a row in this state.
ALTER TABLE proxies ADD COLUMN last_t2_failed_at INTEGER;
CREATE INDEX idx_proxies_t2_block ON proxies(last_t2_failed_at);