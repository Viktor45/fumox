-- Profile-level country filter: a JSON array of ISO 3166-1
-- alpha-2 codes (uppercase, e.g. '["DE","US"]'). NULL / empty array = no
-- filtering; while set, /sub serves only proxies whose stored geo_country
-- matches, and proxies without a determined country stay out.
ALTER TABLE profiles ADD COLUMN countries TEXT;
