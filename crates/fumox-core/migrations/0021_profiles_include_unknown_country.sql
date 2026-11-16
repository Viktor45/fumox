-- The geo-unknown flag (`Profile.include_unknown_country`): whether
-- proxies without a determined country stay in the subscription while
-- the country allowlist is set. 0 (the default) = the historical
-- semantics: the geo filter passes confirmed geo facts only. Before
-- this column the flag existed only in the model and the document
-- formats, so an imported `true` was silently lost at the database.
ALTER TABLE profiles ADD COLUMN include_unknown_country INTEGER NOT NULL DEFAULT 0;
