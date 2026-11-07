-- Optional access token of the source's own public endpoint.
--
-- `/src/{id}` is a public URL like `/sub/{id}`, and a profile access
-- token does not extend to it: the profile guards its own merged output
-- only. A source that needs the same protection carries its own token
-- here; NULL keeps the endpoint public. The column stores the token's
-- hash (`sha256$<hex>`), the same self-describing form the profiles
-- table uses, so a legacy plain-text row keeps verifying until it is
-- re-hashed (see `fumox_core::token::verify`).
ALTER TABLE sources ADD COLUMN access_token TEXT;
