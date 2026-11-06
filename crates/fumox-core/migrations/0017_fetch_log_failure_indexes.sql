-- Indexes for the failure views of the fetch journal.
--
-- The admin journal screen's `ok = 0` filter and the failure-history
-- reads (`scheduler` keeps a per-source failure window) both walk the
-- journal by time; without these indexes each does a full scan over the
-- whole table to find the failures scattered in it.
--
-- `idx_fetch_fail` is partial: successes are the vast majority of the
-- rows and are never looked up through this index, so only the failure
-- rows pay for it. `idx_fetch_error_class` serves the error-class
-- filter, newest first.

CREATE INDEX idx_fetch_fail ON fetch_log(fetched_at) WHERE ok = 0;

CREATE INDEX idx_fetch_error_class ON fetch_log(error_class, fetched_at);
