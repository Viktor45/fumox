-- Speed measurement and Cloudflare trace enrichment on `proxies` (Phase 5).
--
-- The probe writes the measurement outcome straight onto the proxy row:
-- `speed_mbps` (the column reserved in 0001) gets its companion `speed_at`
-- stamp, and the Cloudflare `/cdn-cgi/trace` fields land next to it — the
-- four the pipeline filters and sorts on as first-class columns, everything
-- else the operator asked to keep as one JSON blob. The egress GeoIP facts
-- (`egress_country`/`egress_asn`/`egress_asn_org`) are the server's: the
-- probe has no mmdb access, so a background server task backfills them from
-- `egress_ip` (the same split that keeps `geo_*` server-written and outside
-- the probe's authorizer allow-list).
--
-- All columns are nullable: a proxy that has never been measured carries
-- NULL, and the pipeline treats a stale or absent measurement as "no data".
ALTER TABLE proxies ADD COLUMN speed_at INTEGER; -- when speed_mbps was measured (unix seconds)
ALTER TABLE proxies ADD COLUMN egress_ip TEXT; -- trace ip=: the proxy's egress address, v4 or v6
ALTER TABLE proxies ADD COLUMN cf_colo TEXT; -- trace colo=: the Cloudflare datacenter (IATA code)
ALTER TABLE proxies ADD COLUMN cf_loc TEXT; -- trace loc=: the country the egress appears from
ALTER TABLE proxies ADD COLUMN cf_warp TEXT; -- trace warp=: on | off | plus
ALTER TABLE proxies ADD COLUMN trace_json TEXT; -- the saved trace fields beyond the four columns, as a JSON object
ALTER TABLE proxies ADD COLUMN egress_country TEXT; -- GeoIP country of egress_ip (server backfill)
ALTER TABLE proxies ADD COLUMN egress_asn TEXT; -- GeoIP autonomous system of egress_ip, 'AS<n>' like geo_asn
ALTER TABLE proxies ADD COLUMN egress_asn_org TEXT; -- GeoIP AS organization name of egress_ip
-- The egress backfill's bookkeeping (0012's pattern): a row whose address no
-- loaded database knows is marked, so the next passes leave it alone until
-- the retry window passed instead of taking the budget from fresh rows
ALTER TABLE proxies ADD COLUMN egress_geo_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxies ADD COLUMN last_egress_geo_attempt_at INTEGER;

CREATE INDEX idx_proxies_speed         ON proxies(speed_mbps);      -- pipeline speed filter/sort
CREATE INDEX idx_proxies_egress_country ON proxies(egress_country); -- pipeline egress filter (admin filter too)
CREATE INDEX idx_proxies_colo          ON proxies(cf_colo);         -- pipeline colo filter (admin filter too)
