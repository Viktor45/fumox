-- Measured wall-clock duration of a source fetch attempt, in milliseconds.
--
-- From the start of the fetch (retries and their backoff included) to its
-- verdict, so a slow upstream or a long retry-backoff chain is visible and
-- attributable per attempt in the admin fetch journal; NULL for rows
-- written without a measurement (older versions, test fixtures).
ALTER TABLE fetch_log ADD COLUMN duration_ms INTEGER;
