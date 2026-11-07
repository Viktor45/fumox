-- Keyset index for the fetch journal screens.
--
-- The journal screens page with a keyset cursor on (fetched_at, id): the
-- seek needs both columns of the sort key, and `idx_fetch_time` (the old
-- page-number walk's index) is a strict prefix of the new composite, so
-- it is dropped — the highest-write table does not carry two indexes
-- over the same column.

CREATE INDEX idx_fetch_time_id ON fetch_log(fetched_at, id);

DROP INDEX idx_fetch_time;
