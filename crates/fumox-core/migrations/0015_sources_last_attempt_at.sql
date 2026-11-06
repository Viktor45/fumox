-- Stamp the moment of the last fetch attempt on the source row.
--
-- `last_fetched_at` moves only on a success, and `last_error` carries no
-- moment of its own, so a source that keeps failing had no visible
-- "when did we last try" answer. `repo::sources::record_fetch_outcome`
-- writes the attempt moment of both outcomes (`FetchOutcome::Success`
-- and `FetchOutcome::Failure`) here; a failure never touches
-- `last_fetched_at`, so the freshness stamp keeps meaning "last good
-- payload".
ALTER TABLE sources ADD COLUMN last_attempt_at INTEGER;
