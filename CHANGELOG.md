# Changelog

Fumox ships as rolling image snapshots (`ghcr.io/viktor45/fumox:sha-<hash>`
plus the moving `latest`); this changelog lists what each published batch
of changes contains, newest first in the published changelog; the git-cliff
draft is oldest-first. Match the `sha-` tag of the image you pulled
(`docker images`) to the hash in a section header, or just diff your pull
date against the section dates.

The categories follow [Keep a Changelog](https://keepachangelog.com/);
`Docs` covers the user guide and READMEs, `Internal` is a drop bucket for
`chore` and merge commits; CI-plumbing and script-only commits that are
part of a published batch are recorded under their Conventional-Commits
category (`Added`/`Fixed`/`Changed`), like any other change in the batch.

## Unreleased

Not yet shipped in a published image; the date and the `sha-<hash>` suffix
are stamped when the batch is published.

### Added

- Speed measurements and Cloudflare trace facts for `ready` proxies. Right after a successful delay verdict, the probe fetches
  `[network].trace_url` through the proxy and stores ip/colo/loc/warp (plus
  the configured `[network].trace_fields` in `trace_json`, migration 0022),
  then streams a payload through the same tunnel from `[network].speed_url`
  without writing to disk: the full `[network].speed_bytes` (25 MiB) or the
  `[network].speed_time_ceiling_secs` (15 s) ceiling, whichever comes first —
  an interrupted download yields an honest number over the bytes actually
  read. The measurement runs through listeners the kernel declares at
  startup, pinned to the proxy under test with a hot-reloadable
  `IN-PORT,<port>,fumox-{id}` rule, so no request bypasses the tunnel (see
  the Fixed entry on meow-rs's startup-snapshot listeners); only the first
  `[network].speed_concurrency` rows of a T2 batch get a lane, and
  re-measuring happens no more often than `[network].speed_interval_secs`
  (24 h). A failed
  measurement journals its reason and never touches the status machine —
  the speed is a metric only (owner decision, 2026-11-21); a failed trace
  skips that cycle's download.
- The pipeline reads the new facts: a `speed` section (`min_mbps` +
  `max_age_secs`, unmeasured and stale-measured proxies are dropped),
  `filter.colo`/`exclude_colo`, `filter.loc`/`exclude_loc`,
  `filter.warp` (`on`/`off`/`plus`), `filter.egress_countries` and
  `filter.egress_asns` over the trace facts (allowlists drop unmeasured
  proxies: confirmed facts only), `sort.by = "speed"` (fastest first by
  default), and seven new name placeholders: `{speed}`, `{colo}`, `{loc}`,
  `{warp}`, `{egress_flag}`, `{egress_country}`, `{egress_asn}`.
  `{egress_flag}` renders the flag of the server-resolved egress country.
- Egress geo backfill: the server derives `egress_country`/`egress_asn`/
  `egress_asn_org` from `egress_ip` through the GeoLite2 databases in a
  background pass (at startup and on the six-hour geo-backfill tick) — the
  probe has no access to the mmdb files. The retry window for
  unresolvable egress IPs mirrors the host-geo one (6 h).
- The proxy card shows the measured speed with its measurement timestamp,
  the egress facts (egress IP, colo, loc, warp, the derived egress country
  and ASN) and the pretty-printed `trace_json`; the probe history decodes
  the new `speed`/`trace` kinds. The proxy browser grew speed/egress
  filters and Egress/Speed columns; the **Probe** screen summarizes the
  measurements (how many proxies carry one, how many went stale, how many
  speed/trace attempts failed over 24 h).
- Speed measurements retry `[network].speed_backup_url` after a primary HTTP
  error (including 429) or connect/TLS/read failure. The backup defaults to
  `https://speed.edgecompute.app/down?bytes={bytes}`; an empty value disables it.
- Nine `[network]` settings for all of the above in `config/app.toml` and on
  the settings edit page: `speed_enabled`, `speed_url`, `speed_backup_url`,
  `speed_bytes`, `speed_time_ceiling_secs`, `speed_concurrency`,
  `speed_interval_secs`, `trace_url`, `trace_fields`.
- `[database].allow_checksum_repair` (default `false`): the opt-in that
  lets the boot re-stamp an applied migration whose file changed since it
  was applied. Off by default, and the refusal is explicit: a mismatch
  stops the start and names the version, the reason and the two ways out
  (ship a new migration file, or start once with the flag set). A repair
  that rewrote nothing re-raises the original mismatch instead of
  claiming a repair that did not happen.
- The migrations run under an inter-process lock now (a `flock` sidecar
  next to the database, mode 0600, symlink-proof), so two processes that
  started at once no longer race: the second one waits, re-reads the
  applied list and continues. A busy database is retried with a backoff
  instead of failing the start.
- `FUMOX_REVIVE_CONFIRM_STOPPED=1`: the explicit confirmation for a
  restore over a database that still looks busy. The restore refuses by
  default; the variable says "the daemon really is stopped, go ahead".
- An integration test for `scripts/repair-geo-stamps.sh`
  (`scripts/tests/repair-geo-stamps.test.sh`).
- The probe cycle summary reports the wall-clock cost of the cycle and
  of every stage, and how many rows the spent budget deferred; a cycle
  that overran its period says so.
- An integration test for `scripts/smoke-down.sh`
  (`scripts/tests/smoke-down.test.sh`), and matching negative coverage
  in the revive-script suite.

- `[geo].startup_download_budget_secs` (default 60, `0` = do not
  wait): the ceiling on how long startup blocks on the GeoLite2
  download before it binds the listeners. The budget is an upper
  bound on a stalled mirror, not a promise that geo is ready; past
  it the download continues detached and that run serves without geo
  enrichment until the next start. Tunable like every other key
  (`FUMOX_GEO__STARTUP_DOWNLOAD_BUDGET_SECS`).
- Snell and AnyTLS proxy protocols: parsed from subscriptions (URI
  and Clash YAML), rendered into the Clash output and the URI list,
  and covered by T2 tunnel checks. sing-box exports leave them out:
  the sing-box outbound set has no type for either.
- meow-rs 0.22.0 gains for T2, with no further Fumox change: the
  `xhttp` transport is a real outbound, and SIP003 Shadowsocks
  plugins (`shadow-tls`, `restls`, `jls`, `kcptun`, `gost-plugin`)
  run in-process, so plugin-backed entries that used to fail T2
  now work. Fumox already rendered both correctly; only the engine
  gained the ability to honour them. Check the pinned release with
  `docker compose exec meow meow -v`: an engine older than 0.22.0
  cannot check these entries — they fail T2 and never reach the
  `ready` tier even though Fumox renders them correctly.
- `[meow].ipv6` (default `false`, matching meow-rs): rendered into
  the generated meow config; 0.22.0 made the key effective end-to-end
  (under `false` AAAA lookups are skipped). It matters solely on
  IPv6-only egress or an AAAA-only test URL.
- The probe screen shows the meow-rs kernel's live RSS (from
  `GET /memory`, refreshed whenever a T2 batch reloads the engine),
  with the OS memory limit and the share of it when one is set.
- The probe screen grew a *History rotation* panel: when the last
  retention run happened, how many rows each journal lost and holds
  now; before the first run it names the owner of the loop instead of
  rendering a blank.
- The dashboard's *fetches in 24h* card shows how long ago the
  scheduler's last sweep started (`last sweep: N s ago`), or that
  none has run yet; a hung sweep ages the line instead of looking
  healthy.
- The geo backfill runs on a schedule now (every six hours, five
  minutes of budget, never overlapping itself), not only at startup:
  a row whose host lookup failed once no longer keeps its NULL
  columns until the process restarts. The startup pass shares the
  `[geo].startup_download_budget_secs` budget.
- The backfill decides per fact, not per row: a row holding a country
  but no ASN is no longer counted as "already filled", so databases
  added later get their missing values stamped.
- The fetch journal records how long each attempt took
  (`fetch_log.duration_ms`, migration 0009), retries included; the
  admin fetch log renders it beside the timestamp.
- Enabling or disabling a source or profile is an in-place HTMX
  swap: a small POST (`/admin/sources/{id}/toggle`,
  `/admin/profiles/{id}/toggle`) re-renders the badge and the
  button without reloading the page, with the same CSRF token and
  the no-JavaScript form fallback the rest of the panel uses.
- A container smoke test for the runtime image
  (`scripts/container-smoke.sh`), run in CI on both architectures
  against the image the release just published.
- A cold-start e2e test for the kube layout
  (`scripts/kube-coldstart-smoke.sh`).
- A controller smoke test for the meow image
  (`scripts/meow-controller-smoke.sh`).

- The GeoLite2 channel is an operator decision now, not a baked-in URL:
  `[geo].auto_download` (default `true`), `[geo].download_urls` and
  `[geo].sha256`. `auto_download = false` keeps the "the files are
  provided by hand" model (a MaxMind mirror, an internal copy, a
  read-only volume): fumox then never writes into `db_dir` and never
  waits for a download at startup. `download_urls` maps a file name to
  the mirror it is fetched from, `sha256` maps a file name to the
  checksum the download has to match. The toggle is in the admin panel
  and in `config/app.toml`.
- `/healthz` names the geo state on a second line
  (`geo: off | no databases | degraded | ready`).
- The GeoLite2 databases are opened once per process and shared by the
  pipeline, the admin panel and the backfill; a database that arrives
  after the startup is picked up without a restart.
- `[retention].removed_proxies_days` (default `0`): the server's
  retention sweep now deletes proxies that have sat in the `removed`
  status for longer than the window, in the same bounded batches as
  the admin's *purge removed* button. The zero window is the opt-out:
  `removed` stays reversible until the operator presses the button.
  The deleted count shows on `/admin/probe`.

### Fixed

- `docker-compose.yml` declares its `default` network explicitly, so
  `podman-compose` no longer fails with `RuntimeError: missing networks:
  default`. The network remains project-scoped.
- Trace requests (and speed measurements) through ready proxies no longer
  fail with `trace request failed: error sending request`. meow-rs v0.29.0
  treats `listeners:` as a startup snapshot that `PUT /configs` cannot
  change, and has no per-listener `proxy:` override, so the per-row listeners
  the probe rendered into each batch config were never actually bound —
  the probe dialed a port with nothing listening on it. The measurement
  listeners are now declared once at kernel startup on ephemeral ports; the
  probe discovers their resolved ports through `GET /listeners` and pins
  each lane to the proxy under test with a hot-reloadable
  `IN-PORT,<port>,fumox-{id}` rule (verified against a live Cloudflare trace
  returning real egress `ip`/`colo`/`loc`). `[network].speed_concurrency`
  still bounds parallel lanes. The obsolete
  `[network].speed_listener_port_base` has been removed entirely.
- Speed results are actually stamped: the probe's SQLite write guard denied
  the `speed_mbps` column, so every successful download failed with
  `database error: (code: 23) not authorized` and left `speed_mbps`/`speed_at`
  empty. The column is probe-written like `speed_at` (the server only
  derives the egress GeoIP columns); the guard now allows it.
- Obsolete config shims are gone: the inert `[geo].db` selector and the
  one-release `[probe].refresh_check_limit` alias (moved to
  `[ingest].refresh_check_limit` in the 2026-10-28 wave) are no longer
  accepted. A config still carrying either key is now refused at load with
  the offending key named, so remove them before upgrading. The dead
  `set.geo_db`, `set.legacy` and `set.legacy_disabled` locale keys went with
  them; the shipped `app.toml` no longer documents an exception to
  `deny_unknown_fields`.

### Changed

- The default geo name template is now
  `"{flag} {egress_flag} {loc} · {speed} · {asn} {egress_asn} · {colo}"`.
  `{name}` is explicit-only: the original display name is inserted exactly
  where it appears and is no longer appended when it is absent, including
  when no geo or trace facts exist. **Migration:** add `{name}` to a custom
  template if the old node name must remain visible; saved templates that
  omit it now render without that name.
- The image is Alpine-based now: the builder and the runtime move from
  Debian (glibc) to Alpine (musl), the shipped binaries are statically
  linked, and the runtime carries no C library for the app itself. The
  meow wrapper image follows onto the same pinned base: its binary was
  static musl already, so only the base and the health check changed.
  The base images stay pinned by digest, and the built images shrink to a
  fraction of their size (the fumox image is 20 MB, the meow wrapper
  12 MB). A cold build takes longer than the glibc one did (the musl
  toolchain compiles the workspace slower). **Migration:** the image
  installs `tini` under `/sbin/tini`, the probe's and the kernel's
  health checks are busybox `nc` connects instead of bash ones, and a
  deployment that patches the image with `apt` has to use `apk`.
- Both images bump their own packages during the build: the runtime stage
  runs `apk upgrade -U --no-cache` before it installs anything, so the base
  image's own packages (busybox, musl, zlib) move with the mirror and a
  rebuild picks up an Alpine security update without a Dockerfile edit. The
  digest pins the base filesystem, not the package set on top of it, so two
  builds of the same commit can differ. The meow wrapper upgrades its
  runtime stage, not its fetch stage (that stage contributes one file, so
  there is nothing to gain there). The builder stage is left alone: the
  Rust toolchain in it is installed by rustup, not by apk, and none of its
  packages ship.
- CI is reusable by the Fumox image publisher and checks the releasing commit
  before building. Pull requests also build all three Docker images on
  amd64 and arm64 without starting containers. The quality gate includes
  the declared minimum Rust version, `cargo audit`, workflow validation,
  and pinned Python tooling maintained by Dependabot.
- The meow wrapper workflow no longer runs that Rust gate: the image
  packages a pinned, sha256-verified upstream binary rather than Fumox
  source, so a dispatch builds straight away. Publishing is still gated by
  the build's hash check and the candidate/verify/promote attestation flow.
- Image publishers attest and verify a uniquely tagged candidate before
  moving public tags. Publishing and retention share a concurrency group;
  failed runs no longer delete potentially shared image digests.

- A probe cycle is bounded now: a wall-clock budget (three quarters of
  the period) defers the lanes that start too late, a cycle that
  outlives the whole period is aborted, and the lanes share one check
  quota per group of work, so a cycle runs the number of checks
  `probe.sample_size` names instead of up to five times as many.
  Guarded by `a_spent_budget_defers_the_rows_of_the_lane`.
- The hosts of a cycle are resolved once: the tunnel lanes reuse the
  addresses the coverage lanes of the same cycle already vetted. Guarded by
  `the_hosts_of_a_cycle_are_resolved_once`.
- The engine's backoff says how long it is and when the lanes run
  again, and a recovery is logged as well.
- The controller of the proxy kernel is vetted before the first probe
  cycle: a public address aborts the start, a non-loopback controller
  must have a token, redirects are not followed, and the kernel-config
  write path must be absolute (its directory is created).
  **Migration:** a deployment that reaches the controller over a
  network (the compose stack does: `meow:9090`) has to set
  `FUMOX_MEOW__API_TOKEN`; a loopback controller keeps working without
  one. Guarded by `a_public_controller_address_is_refused`.
- An attempt the engine never judged is journaled under a kind of its
  own now (`t2_unverified`) instead of `t2`: a `t2` row is a verdict,
  a `t2_unverified` row the record of an attempt the engine could not
  complete. Both count as an attempt for the T2 recency queue.
  Migration `0011` carries the matching index.
- The list of the protocols meow-rs can tunnel lives in one place:
  a protocol it cannot express is treated as "not tunnelable" instead
  of being offered to the engine and dropped again.
- The dedup key now carries a version and is computed from one
  canonical form of a node instead of a fixed list of parameter names.
  Every parameter that changes how a client connects counts — including
  the `h2-opts`/`http-opts`/`grpc-opts`/`obfs-opts` blocks, xhttp's
  mode/path/extra, the snell protocol revision, hysteria2's port
  hopping, tuic's relay mode — while the cosmetic ones (the display
  name, the advertising tags, the bandwidth caps) stay out. Blocks and
  their flat spellings hash alike, and alternative spellings of one
  parameter (`servername`/`sni`, `network`/`net`, `cipher`/`scy`)
  count once.
  **Upgrade:** the stored keys are recomputed on the first start
  after the upgrade; rows keep their status, latency, geo facts and
  probe history. Duplicates the feeds spelled differently are merged
  into one row (the probe-judged one survives, its state filled from
  the row that goes away); a retired node keeps its verdict and comes
  back only through the usual revive paths. A node that *looks* twice
  because the connection genuinely differs (a different SNI, a
  different transport) counts apart on purpose — remove it with
  *Purge removed* if unwanted. A downgrade re-identifies the nodes on
  the next ingest, so downgrading is not recommended. Guarded by
  `two_rows_that_describe_the_same_node_are_merged`.
- `[probe].refresh_check_limit` moved to `[ingest].refresh_check_limit`
  (the priority queue belongs to the scheduler). The old key and the
  `FUMOX_PROBE__REFRESH_CHECK_LIMIT` variable were accepted for one release:
  the value was carried over and a warning named the key to rename. That
  window has now closed — see the removal in Unreleased.
- The T2 test URL is drawn once per probe cycle instead of once per
  check, so a proxy no longer gets opposite verdicts in two consecutive
  cycles. A batch in which every tunnel failed is read as a suspect
  endpoint rather than a dead fleet: the proxies are stamped unverified
  and the fail ladder does not grow. The shipped default is one neutral
  endpoint, and every `[meow].test_url` entry has to be an absolute
  `http(s)` URL: a private address needs
  `[probe].allow_private_targets = true`.
- The configuration is checked at startup instead of at first use.
  Every numeric setting has an explicit range, a value outside it
  aborts the boot with the key and the bound in the message, a
  `trust_proxy_ips` entry that trusts every peer (`0.0.0.0/0`, `::/0`)
  is a config error, and a panel on a public address that sends its
  session cookie without `Secure` warns at startup.
- A `FUMOX_*` variable that names no configuration key is refused
  instead of being ignored; the message names the variable and the
  closest key.
- The *Edit settings* page refuses a `[meow].test_url` the loader would
  reject (an empty list, a non-`http(s)` URL, a private address while
  the probe's guard is on) instead of writing a file that stops both
  binaries at the next start, and a save whose live reload failed tells
  the operator instead of only logging it.
- The shared volume was split by purpose and owner: `fumox-geo` for the
  GeoLite2 databases (written by the server alone) and `fumox-meow` for
  the kernel's configuration exchange (written by the probe, read by
  the kernel), mounted at `/shared/geo` and `/shared/meow`.
  `FUMOX_GEO__DB_DIR` follows the databases into their own volume.
  **Migration:** a deployment that keeps its own `.mmdb` files has to
  move them to the new volume.
- The nginx example serves every layout now. The server blocks moved
  into a template that the image's entrypoint renders, so the upstream
  addresses are a runtime choice
  (`FUMOX_UPSTREAM_PUBLIC`, `FUMOX_UPSTREAM_ADMIN`, `FUMOX_SERVER_NAME`);
  the `Host` header is normalised before it is forwarded, the SSE stream
  at `/admin/events` has its own location with the buffering off, and
  the redirect from `:80` goes to the normalised host, never to the raw
  client header.
- The quadlet units and the kube manifest declare resource limits: the
  server gets `MemoryMax=512M`, `CPUQuota=100%`, `TasksMax=256`, the
  probe and the kernel smaller quotas (in the `[Service]` section of
  the units, which systemd reads as its own options).
- The quadlet units run with a read-only root filesystem and explicit
  tmpfs mounts instead of podman's default set, so the non-root users
  can write to `/tmp` and the kernel can render its config in
  `/run/meow` without the whole filesystem becoming writable.

- `[ingest].drop_gate` defaults to `true` now. **Migration:** a
  deployment that relied on the old default (every source lingers,
  only the probe retires a proxy) keeps that behaviour only if it sets
  `drop_gate = false` explicitly. Under the new default a source with
  `drop` rules detaches the proxies those rules would have discarded on
  the next refresh; a source without drop rules is unaffected either
  way.
- The startup download budget of the GeoLite2 databases is capped at
  300 seconds (`[geo].startup_download_budget_secs`). A larger value
  in the file is clamped and named in a startup warning, so a
  hand-edited config cannot hold the boot hostage.
- The GeoLite2 download does not block the listener bind any more: the
  listeners bind as soon as the budget is spent, and the file lands
  later by an atomic rename. A country allowlist on a profile is the
  one hard dependency: with geo enabled, such a profile and no City
  database aborts the start with a message naming the state and the
  directory.
- A payload that parsed but could not be stored is journaled under its
  own error class (`storage`) and keeps the real HTTP status of the
  response, instead of being reported as an upstream failure with a
  substituted 500.
- The ingest report adds up: `proxies_found` is what was stored,
  `dropped` is what the source's own filters discarded, and
  `found = dropped + kept` holds in the real run as well as in the dry
  run.
- The geo lookup tells the three outcomes apart (a name that did not
  resolve, an address no database knows, a database read that failed);
  each has its own counter and its own rate-limited log line. The DNS
  step goes through the shared resolver under the same concurrency cap
  as the rest of the process.
- The *Proxies* browser pages with a cursor instead of a page number:
  the panel offers *First* / *Previous* / *Next*, the filters and the
  sort stay with the link, and each of the three sorts pages on its own
  key. **Migration:** the `page` parameter of `/admin/proxies` is
  ignored now — a bookmark that carries it shows the first page — while
  the *Fetch log* and the *Sources* screen keep their page numbers.
- A truncated export says so twice. `/export/alive/{token}` and
  `/export/ready/{token}` ship at most `[server].export_max_rows` rows
  (50 000 by default); the body names both numbers now
  (`# truncated: showing 50000 of 81234 — raise
  [server].export_max_rows`), and the response carries
  `X-Fumox-Export-Total` (the size of the tier) and
  `X-Fumox-Export-Truncated: true`, so even a client that holds nothing
  but the headers tells a full list from a truncated one. Guarded by
  `a_truncated_export_marks_itself_in_the_headers`.
- The export capability token is kept in process memory, read once at
  startup and shared by the admin panel and the public listener, so a
  rotation from the panel reaches both at once. `meta` stays the
  source of truth: the token survives a restart and is what a restore
  brings back.
- A source fetch has a wall-clock budget now (three minutes). The first
  attempt, every retry and every backoff sleep share it, and a backoff
  that would run past the budget is not slept through: the fetch ends
  with the cause of the failure and the note that the budget ran out. Guarded by
  `a_fetch_is_bounded_by_its_wall_clock_budget`.
- A refused request says why it was refused. A client error carries a
  reason beside the status code, and the text reaches `fetch_log.error`
  and the source's `last_error`. A chain that lost the source headers on
  the way (a redirect left the configured origin) now reports
  `client error: HTTP 403: headers withheld: redirect left the
  configured origin` instead of a bare `403`, which was
  indistinguishable from a refusal by the target itself. The reason
  is part of the stored error text. Guarded by
  `a_refused_redirect_states_that_the_headers_were_withheld`.
- The forwarding headers are read only when the operator names the family
  the trusted proxy writes. `[server].trust_proxy_header` and
  `[admin].trust_proxy_header` (default `"none"`; the values `"none"`,
  `"xff"`, `"forwarded"` and `"both"`) declare it: `none` honors no
  header at all and the peer address is the client, `xff` reads
  `X-Forwarded-For` (and `X-Forwarded-Host` / `X-Forwarded-Proto`
  beside it), `forwarded` reads the RFC 7239 `Forwarded` header, `both`
  reads the two and honors them only when they agree.
  **Migration:** a deployment behind a reverse proxy names the family the
  proxy writes (`trust_proxy_header = "xff"` for nginx's
  `$proxy_add_x_forwarded_for`) on every listener that sits behind it.
  Without the declaration the per-IP rate limit counts the proxy's own
  address (one budget for the whole fleet), the scheme hint is ignored
  and the forwarded host is not believed; a `trust_proxy_ips` without a
  `trust_proxy_header` is named in a startup warning. A chain of several
  trusted proxies has the same effect: name every hop in
  `trust_proxy_ips` and raise the limit that key shares.
- The session cookie carries the version of its format now
  (`v2.{expires}.{mac}`); the previous build's format is still accepted,
  so the upgrade costs no re-login, and a cookie minted before the
  revocation epoch existed is refused on purpose.
- The session cookie is scoped to the panel: it is issued and cleared
  with `Path=/admin` instead of `Path=/`, so the public listener never
  sees it. `HttpOnly`, `SameSite=Lax` and the `Secure` flag
  (`[admin].secure_cookies`) are unchanged.
- The login window counts the failed attempts only. A successful login
  gives its slot back and does not reset the window, so a correct guess
  between two wrong ones does not hand an attacker a fresh window.
- The dashboard's per-source table follows the status machine order:
  unknown, alive, ready, quarantine, removed. "Oldest alive" became
  "Oldest ready" (the age of the oldest tunnel-verified proxy), and the
  "Protocols" and "Countries" columns are gone (the split panels below
  already carry the breakdown).
- The pipeline builder is three tabs instead of one column of seven
  sections, grouped in the order the pipeline runs: *Input* (protocol
  filter), *Rules* (renaming and discarding) and *Output* (health, geo,
  sorting, limit). CSS-only; both the source and the profile form get
  the layout.
- Rule lists are capped in height and carry a live count; the list
  scrolls inside its pane instead of pushing the page down.
- The dashboard stat cards lost their per-metric colour stripe (it read
  as a status signal and it lied); status colour belongs to the badges.
- `/export/alive/{token}` and `/export/ready/{token}` render at most
  once per 30 s (`EXPORT_TTL_SECS`) and are served from the shared
  processed cache in between, like `/sub` and `/src`; a tier can lag a
  status change by up to 30 s.
- The two export links are capped at 50 000 rows, and the cap is a
  setting rather than a constant: `[server].export_max_rows`
  (`FUMOX_SERVER__EXPORT_MAX_ROWS`). The cut is marked by
  `X-Fumox-Export-Truncated` (and the size of the tier by
  `X-Fumox-Export-Total`); the admin badge stays uncapped, so the
  operator can see that the export is smaller than the tier. Guarded by
  `export_body_is_capped_in_sql`.
- Ingest resolves geo facts concurrently instead of one await per
  entry, under a cap of 32 in flight (`GEO_LOOKUP_CONCURRENCY`),
  keeping the input order the drop rules and the reconcile upsert rely
  on.
- The shipped `config/app.toml` no longer enables
  `[probe].allow_private_targets`: the probe dials targets carried by
  *feeds*, untrusted input. The Compose probe service passes the
  variable explicitly (`FUMOX_PROBE__ALLOW_PRIVATE_TARGETS`, default
  `false`) and `.env.example` documents it.
- `migration 0008` adds `idx_proxies_updated_at`, covering the admin
  proxies list's default sort; without it every page of the list and
  the matching `COUNT` walked the whole table.
- The minimum supported Rust toolchain is **1.98** (up from 1.94);
  `Cargo.toml`'s `rust-version` stays a floor, not a lock.
- The import answers with a redirect and a toast instead of a summary
  page: the totals (sources and profiles created, warnings) land in the
  flash message, every warning is logged as it happens.
- The import page states the limits it enforces: at most 500 rows per
  table and a document of at most 256 KiB, shown next to the upload
  control and the export button.
- The export says when its own file cannot be imported back: a file
  past those limits names the limit it exceeds in the file itself (an
  `import_limit` field) and warns in the log.
- The alive/ready export links on the import screen degrade instead of
  failing: the block is hidden and the reason goes to the log, so the
  screen stays usable.
- The import vets the URLs of the file with the policy of the
  deployment (`[admin].allow_private_urls`), like the source form does.
- The public subscription says what it could not deliver. An output
  format that cannot express an entry is served with the warning
  `X-Fumox-Warning: incompatible-entries-skipped` and the number of
  the skipped entries in `X-Fumox-Skipped`; a Clash document carries
  the same count as a `# skipped: N (unsupported scheme)` comment. The
  warning header may carry several values, comma-separated.
- The single-source endpoint reports the "everything is hidden" verdict
  too: a source whose proxies are all quarantined or removed is served
  with `X-Fumox-Warning: all-proxies-quarantined`.
- The graceful shutdown is bounded now: both listeners drain for at
  most 10 seconds on SIGTERM/SIGINT; a drain that runs over the
  deadline is abandoned with a warning.
- The health probe follows the configured bind address (`127.0.0.1`
  for `0.0.0.0`, `::1` for `::`, the bound address itself otherwise).
- A render that wedges no longer holds the cache claim forever: the
  background re-render has the same 30-second deadline as the inline
  one, and a burst of clients on a failing key costs one attempt.
- The export links in the admin panel state that both links carry the
  same token: one secret opens the alive and the ready tier, and a
  rotation revokes both links at once.
- The dashboard reads one snapshot: the per-status counters and the
  lists come from one grouped query in a single transaction, so the
  numbers describe the same moment as the table. Guarded by
  `dashboard_aggregates_stats_and_leads_with_source_errors`.
- The latency aggregates cover the live pool the panel shows: both
  read `status IN ('alive', 'ready') AND latency_ms IS NOT NULL`, so a
  slow dead node cannot drag the median of a healthy tier down.
- A source URL with a password shows the password masked on every
  screen; the stored address keeps the password, and a mask is only
  accepted back under the key it was rendered for. Guarded by
  `the_url_password_is_masked`.
- A profile's access token is a password field now
  (`type="password"`, `autocomplete="new-password"`); the field
  carries the placeholder and never the value, so an unchanged
  placeholder keeps the stored token. The panel also refuses a token
  shorter than 16 characters (the import floor) and the endpoint link
  got `rel="noreferrer noopener"`. Guarded by
  `a_short_typed_token_is_refused_like_in_the_import_path`.
- A profile and its composition are written in one transaction, and
  the profile cache is invalidated right after a successful update. Guarded by
  `the_public_output_follows_the_profile_writes`.
- The profile toggle is a targeted update (`UPDATE ... SET enabled =
  NOT enabled`), so a change made elsewhere in the meantime is no
  longer silently reverted.
- Changing a profile's slug warns in a toast that names the old and
  the new address.
- The proxy card refreshes the geo facts in the background; a dead
  host no longer makes the panel wait a DNS timeout.
- The purge of the removed proxies runs in batches with the lock
  released in between, and the event carries the peer the purge came
  from.
- Deleting a source retires only the proxies that source fed, and only
  under the strict policy: the orphan sweep is scoped to the links of
  the deleted source, and `[ingest].drop_gate = false` leaves the
  detached proxies alone. Guarded by
  `mark_source_orphans_removed_protects_listed_statuses`.
- The log filters are encoded in the pagination links (one
  percent-encoding helper), so a value with an `&` or a `#` can no
  longer break the link or smuggle a parameter. Guarded by
  `the_pagination_link_encodes_every_filter`.
- A pipeline `remove` that does not parse is a broken request now: the
  rows stay as they are. Guarded by `a_broken_remove_changes_nothing`.
- The probe cycle model moved into `fumox-core`: the dashboard's drain
  estimate and the daemon's cycle are computed by the same code.
- The probe screen reads its metadata through one helper, and a record
  that cannot be parsed is reported as such instead of being read as
  "no record".
- The proxy status filter has one source of truth, and a rejected
  status value is logged instead of silently dropped.
- The scheduler takes its retention windows from the parsed
  configuration handed over at the entry point.
- The journal retention sweep is one routine shared by the server and
  the probe daemon; a zero-day window is clamped to one day in both.
- The pipeline editor and the pipeline engine describe the same
  contract. The editor accepted a form the engine read differently —
  a trimmed rule text, a mistyped sort key, an unchecked checkbox read
  as "on" — so the preview could disagree with what the saved
  pipeline actually did. The editor reports the problems it finds in
  the field they came from, and a configuration the builder cannot
  represent is shown as raw JSON instead of being silently rewritten.
- The admin panel's script is a file. The inline bootstrap of
  `base.html` moved to `/admin/static/app.js` and every handler is
  delegated from there, so the content-security policy allows scripts
  from the origin only: no inline script and no inline event handler
  (`script-src 'self'`). Inline styles stay for now, the templates
  still carry a `<noscript>` block and a few style attributes. The
  panel works with JavaScript disabled as before; the file is what
  makes the policy a second barrier instead of a note.
- A locale file on disk overlays the built-in catalog **key by key**.
  Before, a file replaced the whole language: a partial translation
  (a single translated phrase) emptied every other key of that
  language, and the panel fell back to echoing the raw keys. The
  built-in catalog is the base now, the file wins for the keys it
  defines, and the keys it leaves out keep the built-in text. A file
  for a language the binary does not ship is the whole catalog, as
  before.
- The toast of a plain-browser action no longer rides on the redirect
  URL. The message used to travel as a `flash` query parameter, which
  put it into the address bar, the browser history and every copied
  link — and a crafted link could show a message of the attacker's
  choosing. It waits in the server-side session now, keyed by the
  session cookie, and is handed out once: a refresh or a copied link
  does not replay it, and a crafted link cannot add one.
- The refresh status says what a running refresh is doing. The card
  shows the seconds the refresh has been running and what it may cost
  (the wall-clock budget and the number of attempts), so a stalled
  refresh reads as stalled instead of as a spinner that never ends.
- The settings screen says what a save actually puts in force. The file
  is written and the panel shows the saved values, but only some of
  them are in force for the running processes:

  - **on the next request**: `[admin].token`, `[admin].session_ttl_hours`,
    `[admin].secure_cookies`;
  - **after a server restart**: the `[server]` keys (bind, allowed_hosts,
    trust_proxy_ips/header, export_max_rows, the two rate limits),
    the `[admin]` keys (bind, enabled, both rate limits, locales_dir,
    allowed_hosts, trust_proxy_ips/header, allow_private_urls),
    `[database].path`, `[log].server` and every key of `[geo]`, `[fetch]`,
    `[ingest]` and `[retention]`;
  - **after a probe restart**: every key of `[probe]`, plus
    `[geo].startup_download_budget_secs` and `[meow].ipv6`.

  A restart does not end the admin sessions; what ends them is a token
  rotation, or the logout button.

- The journal and source screens page with a cursor instead of a page
  number: the set under the reader does not move and the cost of a page
  does not grow with its number. `idx_fetch_time_id` replaces
  `idx_fetch_time`, which was a strict prefix of it.

### Fixed

- Both image workflows now update `latest` after a verified build from
  `main`. Previously, `docker.yml` published it only for the newest stable
  release tag, and `docker-meow.yml` did not publish it. Builds from other
  branches leave `latest` unchanged; the Fumox release-tag checks still apply.
- Release tags no longer implicitly publish `latest`: only stable tag
  pushes on main may publish release tags, and moving aliases cannot roll
  back to older versions. Non-main branch tags use a `branch-` prefix to
  avoid colliding with release aliases. Index validation requires one amd64 and
  one arm64 image rather than merely counting matching descriptors.
- GHCR cleanup protects nested manifests and recent retained indexes,
  preserves OCI referrer tags, and aborts before deletion if inventory or
  manifest inspection is incomplete. Registry login and deletion failures
  now fail the run instead of reporting success.
- The meow pin updater retries PR creation when a verified update branch
  exists without a PR, respects closed PRs, and refuses unexpected branch
  contents. Manual runs update the default branch's pins.
- The Dockerfile frontend directive is now the first line and pinned by
  digest in all three images, so the selected frontend actually takes
  effect.

- The redaction of a source URL missed the credential-bearing query
  names the feeds use in the wild: `sig`, `session` and `credential`
  are masked now, beside the stems that were already there (`token`,
  `key`, `auth`, `secret`, `pass`).
  Guarded by `credential_bearing_query_names_are_masked`.
- The error text of a failed fetch could carry the credentials of the
  source URL: the tail of the message is replaced now, so the
  credentials cannot survive a spelling difference of the URL. Guarded by
  `a_failing_fetch_does_not_leak_the_source_credentials`.
- The size cap counts the bytes *after* decompression: a gzip body
  that expands past the cap is refused. Guarded by
  `a_gzip_body_is_capped_after_decompression`.
- The retry ceiling is applied, not only documented: a configuration
  that asks for more retries than the process supports is capped at
  sixteen, and the wire sees seventeen attempts at most. Guarded by
  `the_retry_count_is_capped_at_the_supported_ceiling`.
- Every redirect hop is vetted again: a public first host with a
  private target is refused at the second hop. Guarded by
  `every_redirect_hop_is_vetted_again`.
- The client states that it ignores the environment proxy
  configuration (`no_proxy()`), so the SSRF check describes the path
  the request actually takes. Guarded by
  `the_client_ignores_the_environment_proxy_configuration`.

- The rendered-subscription cache is bounded by a byte budget now
  (64 MiB), not by entry count. Guarded by `the_cache_is_bounded_by_bytes`.
- The invalidation counter of a cache key can no longer be evicted
  together with the entry it guards (a render that started before a
  change could store its pre-change rows as fresh for a whole TTL). Guarded by
  `a_generation_outlives_the_entry_it_guards`.
- An invalidation of one source goes straight to the renderings that
  record it instead of scanning the whole cache. Guarded by
  `the_reverse_index_names_the_keys_of_a_source`.
- A returning host spends the log-window budget like any other, and a
  host the window could not warn about is named in the rollover
  summary. Guarded by `a_returning_host_does_not_bypass_the_window_budget`.
- A download that waited behind a stuck export render and gave up
  after the deadline now logs a warning naming the tier.
- Rows that could not be turned into an entry are skipped and reported
  in one line, with the count, instead of one warning per row.

- The restore of `scripts/revive-xhttp-proxies.sh` is safe now: the
  backup is validated before it touches anything (empty, failed
  `integrity_check`, wrong schema, behind a symlink — all refused), the
  exclusive lock is held for the whole copy, the copy is staged,
  verified and renamed into place with a rollback on a short copy, and
  any abort prints the snapshot's path and a rollback command.
- The restore could not tell that something still had the database open.
  The probe now checks the journal mode and treats a write-ahead log
  that survives the probe as a live connection; the refusal names the
  way to say "the daemon really is stopped"
  (`FUMOX_REVIVE_CONFIRM_STOPPED=1`).
- The selection of the same script matched rows whose `params` is not
  valid JSON (where `json_extract` raises); the selection is restricted
  to valid JSON now.
- The adoption target was picked by row order; the order is explicit
  now (id, then slug, then name), and a source whose id is not a plain
  nanoid is skipped rather than adopted.
- The backup of the same script is written by `VACUUM INTO` with the
  path as a quoted literal (a quote in the path can no longer change
  the command), and an existing file at the path stops the run.
- The flags `--adopt-source` and `--no-adopt` are refused (exit 64)
  without `--include-unlinked` instead of being silently ignored.
- `scripts/repair-geo-stamps.sh`: the backup is written by `VACUUM
  INTO`, the columns are cleared in batches, a running server is
  refused (exit 75, `FUMOX_ALLOW_RUNNING_SERVER=1` overrides it), and
  the header says STOP before and RESTART after.
- The migration-repair tool refuses a dirty migration and a migration
  that was never applied, and reports a write-ahead log it could not
  checkpoint.
- The T2 block flag of a proxy that had been failing before the flag
  existed stayed NULL and let the T1 lane check a proxy the tunnel lane
  had already condemned; migration `0013` backfills it from the probe
  history.
- One failing lane no longer cancels the whole probe cycle: the failing
  lane is logged with its error chain, the other lanes still run, and a
  T2 config that cannot be written is handled like a rejected reload. Guarded by
  `a_failing_lane_does_not_cancel_the_cycle`.
- The config the probe hands to the engine is written atomically now
  (temporary file, flush, rename; mode 0640, symlinks not followed), so
  the engine reads either the old or the new file and never a
  half-written one; a world-writable directory is refused. Guarded by
  `the_meow_config_is_renamed_into_place_inside_its_directory`.
- The fail ladder of a batch moves in one transaction, and the journal
  rows of the batch are inserted in one statement.
- An outage of the proxy kernel is no longer charged to the proxies
  under test: a *tunnel verdict* (503, 504, and a 400 whose message
  names a fault of the proxy) is the only outcome that spends a
  proxy's fail budget; everything else — a 404, a 405, a 401, a 429, an
  unreadable body, a refused request — is an engine fault, journaled
  unverified and never charged. The status code is kept in the journal. Guarded by
  `only_a_tunnel_verdict_is_charged_to_the_proxy`.
- A run of three transient engine errors in a row is escalated to an
  engine fault: journaled unverified, no proxy charged, engine into
  backoff. Guarded by `a_run_of_blips_escalates_to_an_engine_fault`.
- The probe cycle summary reports `blocked` and `engine_faults` per
  lane apart from the verdicts, and a batch of refused targets logs one
  aggregated warning. Guarded by
  `a_refused_target_is_counted_as_a_refusal_not_an_engine_fault`.
- The T1 connectivity check presents the node's own name as the TLS
  server name (a CDN node's `sni`/`servername`, an IP-literal host with
  a certificate name) instead of the stored host; an IP-literal host
  without a name of its own presents none. Guarded by
  `tls_check_presents_the_nodes_own_sni`.
- The check and the writers agree on whether a node speaks TLS (one
  shared decision instead of two vocabularies); an unknown non-empty
  `security` value is treated as TLS, never as plaintext.
  Guarded by `kind_decision_table`.
- A T1 check dials every vetted address of a node, the first one that
  completes wins; a failure on the first address no longer quarantines
  a working node. Guarded by `every_vetted_address_is_tried`.
- A TLS check against a server that does not speak TLS is named as a
  handshake failure in the journal, not as a generic connect error. Guarded by
  `tls_check_against_a_plain_listener_fails_with_a_tls_error`.
- The Clash and the sing-box writer could disagree about the same node:
  whether it needs TLS and which transport it speaks were answered
  twice, from two vocabularies (a `tls: true` reached one writer and
  not the other; a REALITY node without `security` was written as
  plaintext; a Clash-only transport spelling lost its path and host in
  the sing-box output). One shared decision answers both questions, and
  the transport is normalised to one spelling, so both outputs name the
  same transport. Guarded by `both_encoders_agree_on_tls`.
- The admin panel answered `403 err.cross_site` to the login form's own
  submit and could not be logged into at all: the `Referrer-Policy` is
  `same-origin` now, which still keeps the panel URL away from
  third-party origins.
- The *Edit settings* page carried a hardcoded English hint under the
  admin token field; the hint is the `set.token_keep_hint` catalog key
  now.
- A quarantined hysteria2 could never come back: its second-chance
  checks were plain TCP connects, which fail unconditionally on a QUIC
  port. Quarantined rows of the T2-revival schemes are re-checked
  through a real meow-rs tunnel now; success revives the row into the
  `ready` tier, an authoritative failure advances the same configured
  ladder, and a meow-rs outage is journaled unverified. Guarded by
  `quarantined_hysteria2_is_revived_by_a_tunnel_check`.
- A bare integer `rate_limit = 300` in `config/app.toml` aborted boot
  (the `RateLimit` visitor only implemented `visit_u64`). Guarded by
  `rate_limit_deserializes_from_bare_toml_integer`.
- An operator's `RUST_LOG` was silently overridden for sqlx; the
  silencer now lives in the fallback only, and an unparsable `RUST_LOG`
  falls back to the config level.
- A failed config-editor save could leak the tmp file (a full copy of
  the config carrying `[admin].token`), and a committed save was not
  durable across a crash; the tmp is removed on failure, fsynced
  before the rename, and the parent directory is synced after it.
- The settings editor accepted values that fail the next boot (a
  `[log]` level outside the canonical set, a `u64` above `i64::MAX`
  wrapped negative inside the `toml_edit` document).
- A database the revive script cannot read looked like an empty one
  ("Nothing to revive.", exit 0); the census is validated now — a
  sqlite3 failure exits 75, a census that is not four counts exits 70,
  and the abort advice comes from one `undo_hint`.
- A pipe in a source name shifted the revive script's adoption
  classification; the name is selected last now.
- The sing-box vmess output dropped a Clash-sourced cipher and alter
  id (`security: auto`, `alter_id: 0`); both spellings are read now.
- A Shadowsocks entry parsed from a Clash item without `cipher`
  serialized to an unparsable SIP002 userinfo; the export defaults
  `chacha20-ietf-poly1305` now, the same default the Clash writer
  applies.
- A raw `=` in a URI parameter key forged a parameter on round-trip;
  keys escape `=` now, values keep theirs byte-for-byte.
- `scripts/smoke-down.sh --keep-data` aborted on the stock macOS bash
  3.2 (unquoted empty-array expansion under `set -u`); both arrays
  carry the `${arr[@]+"${arr[@]}"}` guard now.
- A failed database lookup during a *Refresh now* click was folded into
  the "unknown source" warning; it is logged as an error naming the
  source now.
- The rate limiter's `refund` used the deprecated
  `AtomicU64::fetch_update`, which broke the CI clippy gate; replaced
  with a compare-and-swap loop.
- The probe heartbeat test asserts a range (600..=660 s) instead of an
  exact count recomputed from the wall clock.
- A bare integer `rate_limit = 300` in `config/app.toml` aborted boot
  (the `RateLimit` visitor only implemented `visit_u64`).
- An operator's `RUST_LOG` was silently overridden for sqlx. The
  `sqlx::query=warn` silencer was chained onto *every* filter, and
  `EnvFilter::add_directive` replaces a same-target directive, so
  `RUST_LOG=sqlx::query=debug` was downgraded to warn. The silencer
  now lives in the fallback only, and a `RUST_LOG` that does not parse
  falls back to the config level instead of leaving the process
  without a filter. Guarded by
  `explicit_rust_log_sqlx_directive_is_not_overridden`.
- A failed config-editor save could leak the tmp file, which is a
  full copy of the config carrying `[admin].token`, and a committed
  save was not durable across a crash: the tmp is removed on failure
  now, fsynced before the rename, and the parent directory is synced
  after it. Guarded by `failed_fallback_write_still_removes_the_tmp`.
- The settings editor accepted values that fail the next boot. A
  `[log]` level outside the canonical set aborted both binaries at the
  next start (the dropdowns now accept exactly what `LogLevel`
  deserializes), and a `u64` field above `i64::MAX` wrapped negative
  inside the `toml_edit` document, so the saved config failed
  `config::load` at the next start.
  Guarded by `apply_all_rejects_an_unknown_log_level`.
- A database the revive script cannot read looked like an empty one:
  an exclusive lock left the census empty and the run saying
  "Nothing to revive." with exit 0. The census is validated now: a
  sqlite3 failure exits 75 with instructions, a census that is not
  four counts exits 70, and any other read failure is reported as
  such; the post-backup abort advice comes from one `undo_hint`,
  never a bare `cp`, which the script's own header forbids.
- A pipe in a source name shifted the revive script's adoption
  classification: the name rode mid-row in the sqlite3 output, so a
  `foo|bar` name pushed the `enabled`/`drops` fields out of place and
  could route the adoption into the wrong safety branch. The name is
  selected last now.
- The sing-box vmess output dropped a Clash-sourced cipher and alter
  id: the writer read only the JSON spellings (`scy`/`aid`), so an
  entry parsed from Clash YAML (`cipher`/`alterId`) silently exported
  `security: auto` and `alter_id: 0`. Both spellings are read now.
  Guarded by `vmess_from_clash_input_keeps_cipher_and_alter_id`.
- A Shadowsocks entry parsed from a Clash item without `cipher`
  serialized to an unparsable SIP002 userinfo (no colon between method
  and password); the export defaults `chacha20-ietf-poly1305` now, the
  same default the Clash writer applies. Guarded by
  `clash_ss_without_cipher_defaults_the_method_on_export`.
- A raw `=` in a URI parameter key forged a parameter on round-trip:
  `parse_query` splits on the *first* `=`, so a key like
  `allowInsecure=x` re-parsed as a *present* `allowInsecure`
  parameter. Keys escape `=` now; values keep theirs byte-for-byte. Guarded by
  `equals_sign_in_a_param_key_is_escaped`.
- `scripts/smoke-down.sh --keep-data` aborted on the stock macOS bash
  3.2: an unquoted empty-array expansion is fatal under `set -u`,
  exactly the state `--keep-data` puts `VOLUME_FLAGS` in. Both arrays
  carry the `${arr[@]+"${arr[@]}"}` guard now.
- A failed database lookup during a *Refresh now* click was folded
  into the "unknown source" warning; it is logged as an error naming
  the source now, so a broken database does not masquerade as a stale
  panel id. Guarded by `refresh_lookup_failure_is_logged_as_an_error`.
- The rate limiter's `refund` used the deprecated
  `AtomicU64::fetch_update`, which failed `cargo clippy -D warnings`
  and broke the CI gate; replaced with a compare-and-swap loop.
- The probe heartbeat test asserts a range (600..=660 s) instead of an
  exact count recomputed from the wall clock.

- Every page heading collapsed to a character-wide column on a phone:
  `.page-head h1` carried `flex: 1`, whose zero flex-basis told the
  browser the heading occupies no space. The basis is `auto` now, so
  the heading claims its text width and the actions wrap below it.
- Ordinary words broke mid-word in table columns at phone width; name
  links and key-value labels opt out with `overflow-wrap: normal`, and
  the starved value columns carry min-width floors. URLs, addresses and
  hashes still break anywhere.
- The key-value tables stack label above value below 420px.
- Every `<select>` on the source and profile forms was 39px tall on a
  phone; selects now carry `min-height: 44px` at that breakpoint.
- The settings tabs named the wrong tab to assistive tech; a small
  listener mirrors the radio state onto the labels now.
- `[hidden]` stopped working wherever it met an author `display` (the
  pipeline rule counters rendered "0" instead of disappearing); the
  attribute is restated once, globally.
- A pipeline rule row wrapped over three ragged lines; `.ped-row
  select` is `width: auto` now, and the remove button keeps its own
  size on a phone instead of becoming an easy mis-tap.
- The dashboard's "new proxies over the last 7 days" chart labelled its
  columns with clipped timestamps: the columns carry a `day`-classed
  `<time>` that `localize()` formats date-only now, and the
  `aria-label` is plain text instead of interpolated markup.
- Source reconcile retired proxies that belonged to someone else: the
  sweep now runs before the `DELETE` and asks only about the links
  *this* pass removes. Guarded by
  `reconcile_of_another_source_leaves_protected_orphans_alone`.
- `check_failed` lost fail-count increments and could resurrect a
  retired row: the read and the write now run in one `BEGIN IMMEDIATE`
  transaction and repeat the `status IN ('unknown', 'alive', 'ready')`
  guard; a refused write reports `Transition::Unchanged`.
- A T1 success lifted the T2 suppression flag: only a T2 success clears
  `last_t2_failed_at` now, so after a failed T2 the proxy's T1 checks
  are skipped until the next successful T2. The releases between the
  change that introduced the flag (migration 0007) and this fix did not
  hold that rule — see the correction in the *2026-09-22* and *2026-09-21*
  entries.
- A meow-rs outage is no longer charged to the proxies it skipped: it
  is a distinct outcome that journals the attempt and demotes `ready`
  to `alive`, but leaves `fail_count` and the quarantine ladder
  untouched. The outage is charged to the engine instead (`BatchGuard`
  strikes, the exponential backoff, the log line). A
  `ServiceUnavailable` the engine *answers* is a per-request blip and
  remains an ordinary charged verdict. Guarded by
  `meow_outage_never_quarantines_a_healthy_proxy`.
- Every revival path left the row in no probe lane: the flag is now
  cleared with the rest of the lifecycle and the link predicate is
  applied, so a revived proxy is picked up again. *Reset status*
  additionally enqueues the row for priority checking.
- *Reset status* reported a proxy that still exists as nonexistent
  (a row that exists but belongs to no probe lane came back as
  `false`). That case is a rejected action now, with a message saying
  the status was left as it is because no probe can reach the row
  (`px.reset_unreachable`); a genuinely missing row still 404s.
- The probe priority queue no longer accepts rows no lane would ever
  drain: `enqueue_checks` applies the drain's own predicates. Guarded by
  `queue_drain_skips_rows_under_a_t2_block`.
- The admin *Logout* button was a CSRF-able POST; `/admin/logout` sat
  outside the protected nest, so an attacker page could sign the
  operator out at will. The route moved inside, where `require_auth`
  and `csrf_protect` both run.
- A `Host` header holding userinfo leaked the export token into a
  link (`name@evil.com` was emitted verbatim into the export URL).
  The link runs the same canonicalizer as the gate now.
- Config import accepted a pipeline 16× larger than the edit form
  allows; the `PIPELINE_BYTES` cap (65536) applies to the import
  validator now.
- A repeated source reference in one profile aborted the import
  halfway, leaving an empty profile behind a 500. A repeat now
  collapses to its first position; two *source rows* sharing one
  reference are a hard error instead (`val.dup_ref`).
- The *Edit source* form mangled header values containing a bullet: a
  typed value was silently replaced by the stored secret, and a renamed
  key had its secret dropped. The restore matches on the mask itself
  now, so a renamed key keeps its secret and a typed value is a value.
- The sing-box / Xray parser dropped every credential of a
  multi-user endpoint. The builders took `users.first()` and emitted
  one entry, silently and with no invalid counter to show for it, so a
  shared `vnext` / `servers` array yielded one proxy instead of one
  per user. Every user is now its own entry (per-user `flow`,
  `alterId`, `scy` stay on their own row), a junk element costs only
  itself, and an endpoint whose users are all unusable is counted as
  invalid instead of vanishing. Guarded by
  `every_user_of_an_xray_endpoint_becomes_an_entry`.
- Two Clash-advertised nodes differing only in a connection-defining
  field deduplicated into one row: the dedup key counted the URI
  spellings of a parameter only, so the Clash ones were invisible to it.
  The spellings that do have a URI form are canonicalized onto it now.
- Fingerprint pre-images could be forged from inside a value (the
  pairs were joined unescaped, so two different parameter sets hashed
  identically); keys and values are escaped now, `%` included. Guarded by
  `separator_bytes_in_values_cannot_forge_a_pair`.
- URI serialization emitted parameter values verbatim: a raw `&`
  spawned a bogus extra parameter and `#` swallowed the proxy name.
  Only the query delimiters, space and the C0 controls are escaped now. Guarded by
  `query_delimiters_in_values_do_not_corrupt_the_line`.
- SSRF policy missed two IPv6 spellings of a blocked address (the
  deprecated IPv4-compatible `::/96` form and the site-local block
  `fec0::/10`); both are vetted now.
  Guarded by `ipv4_compatible_and_site_local_v6_are_blocked`.
- A database path with a percent escape opened the wrong file (the
  path was interpolated into a `sqlite:` URL string and URI-parsed);
  the path now reaches SQLite as a `PathBuf`. Guarded by
  `connect_pool_opens_the_literal_path_without_uri_decoding`.
- `database.max_connections = 0` surfaced as a 30-second startup
  stall; it is rejected before the pool or the file exists. Guarded by
  `connect_pool_rejects_zero_max_connections`.
- The migration-checksum self-heal hid a possible DDL gap: the
  affected versions are now logged at `error` level with the
  instruction to ship a new migration file, and a repair that rewrote
  nothing re-raises the original mismatch. Guarded by
  `migrate_records_the_repaired_versions_in_meta`.
- The `repair_migration_checksums` example re-stamped rows that were
  already current and had its own copy of the UPDATE; it now calls
  `db::repair_migration_checksums` and refuses a database carrying a
  migration this build does not embed. Guarded by
  `repair_leaves_migrations_this_build_does_not_embed_alone`.
- With the geo resolver inactive, `drop_entries` zipped the entries
  against an *empty* stamp slice and returned nothing, so a source with
  any `drop` rule was reconciled empty and retired wholesale. The
  lookup is indexed with `geo.get(idx)` now: entries past the end of
  the slice count as unstamped and survive, and regex rules still fire. Guarded by
  `drop_entries_keeps_the_batch_when_the_geo_slice_is_short`.
- A parse or DB failure suppressed re-fetching a source for a whole
  TTL (the raw snapshot *is* the freshness marker); it is written only
  once the payload has parsed and reconciled. Guarded by
  `a_parse_failure_leaves_no_fresh_raw_snapshot`.
- A background re-render that started before an ingest committed
  stored its pre-commit rows with a full fresh TTL: every invalidation
  now bumps a per-key generation, and a rendering whose generation
  moved is dropped.
- A cached `/sub` and `/src` snapshot outlived an unrecoverable
  upstream error. Stale-while-revalidate spawned the re-render, the
  render returned the documented `http_client` verdict, and the stale
  body kept being served, so "return the upstream status code" never
  took effect for any client that had a cached copy. An unrecoverable
  answer now invalidates the key (transient server-side failures keep
  the last good snapshot). Guarded by
  `failed_revalidation_drops_the_cached_snapshot`.
- A source's `limit.count` was ignored on `/sub` unless that same
  source also set an explicit `sort`. The per-source pipeline ran only
  the steps that need sorting (`apply_per_source`), leaving the cap
  to the sort-winning `finalize`, so the cap was conditional on the
  sort; `/src`, one source and one `apply`, always honoured it. The
  full per-source run now applies, and the profile-level cap is
  applied again to the merged list.
- *Refresh now* was parked behind a whole scheduler sweep. The tick
  arm awaited `sweep` inline, and a sweep drains its entire
  `JoinSet`, so a manual refresh sat in the channel until every due
  source had finished: it was neither fetched nor marked in flight,
  and the status fragment the panel polls reported the previous fetch
  as the finished one. The sweep is detached now, behind a flag that
  keeps two sweeps from overlapping. Guarded by
  `refresh_now_is_not_parked_behind_a_running_sweep`.
- A stalled GeoLite2 mirror held the whole startup hostage. The
  download ran before the listeners bound and without a bound, so
  `/healthz` was unreachable for the sum of two per-file download
  budgets. Startup now waits at most
  `[geo].startup_download_budget_secs` (60 s, `0` = do not wait)
  and then leaves the task running: the install is an atomic
  rename, so a download finishing mid-run can never expose a
  half-written file, and the next start picks it up. Guarded by
  `a_stalled_geo_download_does_not_hold_startup`.
- A GeoLite2 file of the wrong kind was accepted. The content check
  was the MaxMind metadata marker alone, so a mirror serving the ASN
  database under the City name installed silently and every proxy
  got wrong country / AS facts; the check was also age-first, so a
  wrong-but-plausible file was kept for another month. The
  `database_type` the metadata block declares must now match the
  slot, and the type only counts *after* the marker (a city name in
  the data section is not a declaration). Guarded by
  `a_well_formed_file_of_the_wrong_kind_is_refreshed`.
- The unattended GeoLite2 download followed any redirect. The client
  used `Policy::limited(MAX_REDIRECTS)`, which follows off https and
  to any host, so a hijacked release or a mis-typed URL could deliver
  a foreign file into `db_dir`. Redirects are now https-only, capped,
  and restricted to `github.com` and the `*.githubusercontent.com`
  release-asset CDN. Guarded by `a_redirect_off_the_mirror_hosts_is_refused`.
- The smoke stand could overwrite the main stack's config. Named
  volumes are project-scoped but the `./config` bind mount is the
  same host directory for every compose project, so the smoke
  stand's admin panel wrote the main stack's `app.toml` through the
  *Edit settings* page. The mount is now parameterized by
  `FUMOX_CONFIG_ACCESS` (`rw` by default, unchanged for the main
  stack) and `scripts/smoke-up.sh` pins it to `ro`, a knob for the
  operator, not for the stand, the isolation guarantee is the point.
- The `latest` image tag was republished from every branch. The
  per-arch and merge jobs attached the raw `MEOW_VERSION` tag
  unconditionally, so a feature-branch build moved the tag everyone
  pulls. It is now attached only from `main` or a `v*` tag, the same
  ref gate `docker.yml` uses, and a `MEOW_VERSION` that names a
  release keeps the previous behaviour.
- A `ready` proxy rendered the `unknown` badge on the proxy detail
  card. The template's badge chain had no `ready` arm, so a
  tunnel-verified proxy fell through to the `else`.
- The admin panel's *Create from defaults* button could never work.
  Writability was tested by opening the path for write, which fails
  with `EISDIR` on a directory, and the handler hands it `config/` —
  so an operator with no `config/app.toml` got a "not writable" error
  about a directory the process could plainly write to. A directory is
  now answered with the `create_new` probe the missing-file branch
  already used. Guarded by `is_writable_returns_true_for_writable_directory`.
- The dedup key ignored TLS certificate pinning, so two nodes
  differing only in the certificate they pin shared one key and the
  second was overwritten by reconcile's `ON CONFLICT`, vanishing
  from the database and from every subscription. The pin now counts in
  either spelling (`pinSHA256`, with Clash's `fingerprint` folded onto
  it). Guarded by `cert_pin_is_security_relevant`.
- The dedup key ignored several more connection-defining parameters,
  so two nodes differing only in one of them collapsed onto one row
  and the upsert silently overwrote the first with the second. The
  dedup key now counts every connection-defining parameter: xhttp's
  `:authority` override, the snell `version` protocol revision,
  `obfs-host`, hysteria2's `ports` port-hopping range, tuic's
  `udp_relay_mode` and `disable_sni`; and for vmess the cipher and
  the alter id as Clash spells them (`cipher`/`alterId` folded onto
  the URI spellings `scy`/`aid`). The shared toggle vocabulary also
  learned the `yes`/`on` spellings: a Clash `allowInsecure: yes`
  used to contribute nothing to the pre-image and merged with the
  verification-on variant of the same node.
  Upgrade note: every node carrying one of these parameters or
  spellings hashes differently now. The stored rows are recomputed on
  the first start after the upgrade (see the *dedup key version* entry
  below), so the node keeps its row, its status and its probe history
  under the new key. Guarded by `newly_covered_security_params_split_nodes`.
- A vless proxy that arrived from a Clash YAML source was served to
  sing-box clients as plaintext. mihomo spells the toggle `tls: true`
  and the SNI `servername`; the sing-box writer's TLS decision read
  only `security`/`sni`, matched neither and emitted no `tls` object
  at all, while the same proxy as a `vless://` URI encoded correctly.
  The decision now reads an explicit `tls` toggle first and returns
  from it, so a `tls: false` carrying a stray `servername` stays
  plaintext too. Guarded by `vless_from_clash_input_keeps_tls_and_servername`.
- One malformed endpoint discarded every good one in an Xray
  outbound. The `vnext` and `servers` builders failed inside their
  per-element loop, so a two-endpoint vless whose first user was
  valid and second was not yielded zero entries. A bad element now
  costs only itself, and the failure is raised only when nothing at
  all was built, so a fully malformed outbound is still counted
  `invalid`.
  Guarded by `an_unusable_vnext_element_keeps_the_earlier_endpoints`.
- A Clash-sourced vless/vmess node was health-checked as plain TCP.
  The Clash parser stores `tls`/`servername` and never emits
  `security`, so the verdict read plain TCP: a node with broken TLS
  was marked `alive` and served, while the same node from a URI
  spelling was correctly walked to quarantine. The decision now
  accepts both producer vocabularies, case-insensitively. Guarded by
  `clash_and_uri_spellings_agree_on_tls`.
- An export→import round trip could silently strip a profile's slug.
  The two slugs live in separate namespaces (independent `UNIQUE`
  columns on two different tables), but one claim set was seeded from
  both tables, so a source always claimed a shared slug first: the
  profile was written without one and its `/sub/{slug}` URL became
  `/sub/{id}`, breaking every client already pointed at it, with only
  a warning in the import summary. The claim set is now per table. Guarded by
  `a_source_and_a_profile_may_hold_the_same_slug`.
- Opening a proxy card could wipe the country ingest had resolved.
  A host in the Cloudflare block resolves to an ASN with no country,
  and both the writer that bound all three columns unconditionally and
  the row handed to the template overwrote the stored facts with NULL,
  so the card showed `-` for a row the database still knew. The
  columns are now `COALESCE`d like the reconcile upsert, and the call
  site merges the stamp instead of replacing the row's fields with it. Guarded by
  `update_geo_full_keeps_stored_facts_a_partial_stamp_cannot_replace`.
- The probe ladder editor accepted values the server refuses to boot
  from. The editor checked only that each line parsed as an integer
  and that the list was non-empty, with no step cap and no range
  check, while the canonical loader enforces at most 16 steps each
  within a month and both binaries abort on a bad file. The panel
  reported success and the next restart of `fumox-server` and
  `fumox-probe` died on the file it had just written. The bounds are
  now the loader's. Guarded by
  `recheck_ladder_bounds_match_the_canonical_loader`.
- A source's own `limit.count` capped the entire merged profile. A
  two-source profile whose first source set `limit: {count: 2}` served
  2 nodes instead of 5. Only a profile-level cap now truncates the
  merged list. Behaviour change for operators: a multi-source profile
  whose source set `limit.count` will now serve more proxies than
  before, because each source's top is served up to that count. Both
  guides' `limit` row now says so. Guarded by
  `source_limit_does_not_truncate_the_other_sources`.
- Two overlapping settings submissions silently lost one change while
  both reported success. The editor's load → mutate → save ran
  unsynchronised, and the write button carries no double-submit guard,
  so a double-click issued two POSTs and the second rename published a
  document snapshotted before the first landed. The editor now holds a
  lock across the whole cycle, released on drop. That lock is not
  reentrant and the plain loader must never take it: the admin handler
  re-reads through `config::load_config` while the editor handle is
  alive, so a loader that took it would hang the request and the panel
  would stop saving. Guarded by
  `overlapping_edits_do_not_lose_the_first_change`.
- The same vmess node advertised as Clash YAML and as a `vmess://`
  link got two fingerprints, two rows and two entries in every
  subscription. The fold of Clash's `network` onto the URI spelling is
  per-scheme now, onto `net` for vmess and `type` for the rest. Guarded by
  `clash_and_uri_spellings_agree_for_vmess`.
- A Clash socks5 entry carrying only `username` was stored as
  `onlyuser` rather than `onlyuser:`, and both output writers split
  on the colon, so the outbound carried no username and no password
  and the authentication was lost silently. Credentials are now joined
  positionally, with an absent field keeping its slot. The leading slot
  is per-spec: socks5 keeps it, while shadowsocks does not, because its
  writers default the method only on a colon-less credential. Guarded
  by `a_password_only_socks5_keeps_its_credential`. Guarded by
  `a_password_only_socks5_keeps_its_credential`.
- Bulk revival enqueued the oldest proxies rather than the newest.
  It walked the caller's id list in chunks oldest-first, so the
  per-chunk `ORDER BY p.id DESC LIMIT ?` spent the whole limit on the
  first 500 ids and everything above that was never considered. It now
  chunks a descending-sorted, deduped copy. Guarded by
  `enqueue_prefers_the_newest_ids_across_chunk_boundaries`.
- A permanently dead source was re-fetched every 30 seconds for the
  life of the deployment. A failed fetch writes no timestamp and the
  scheduler read a NULL as due-now, with no failure backoff anywhere,
  so a 401, a dead DNS name or a body that no longer parses got the
  same cadence as a healthy source. The sweep now applies an
  exponential backoff read from the fetch journal, doubling from 60 s
  to a 3600 s cap. Guarded by `a_dead_source_is_not_refetched_on_every_sweep`.
- The probe could lose the only address family a proxy was reachable
  on. The vetted list was truncated to four before the caller picked a
  family, so a CDN hostname publishing four or more AAAA records had
  every working A record truncated away, and the probe dialled, or
  pinned meow-rs to, an address it could not use. The cap now reserves
  a slot for the first address of each family present; the list is
  still at most four long. Guarded by `vetted_address_cap_keeps_both_families`.
- Every T2 batch charged healthy TLS proxies a tunnel failure. The
  pin substitutes the vetted IP into `server`, and `sni`/`servername`
  is emitted only when the entry already carries it, so mihomo had no
  name to verify the certificate against and fell back to the IP
  literal, while the mapping deliberately does not force
  `skip-cert-verify`. Pinning now carries the entry's own server
  name, or failing that the pre-pin hostname, under the key the writer
  reads for that scheme; an entry already hosted on an IP literal is
  left alone. Guarded by `pinning_keeps_a_tls_server_name_for_a_bare_entry`.
- One probe cycle could charge a single dead proxy two failures. The
  queued lane and the random lane run back to back and their selectors
  overlapped completely, so the same proxy could reach the ladder's
  limit in one cycle instead of across three, and one that failed the
  queue lane and then passed the random lane had its counter reset in
  the same breath. The queue lane now hands its claimed ids to the
  random lane, which filters them out of the draw. Guarded by
  `queued_and_random_t1_lanes_do_not_double_charge_a_cycle`.
- A client could pick its own rate-limit key, including on the admin
  login brute-force cap, behind a `Forwarded`-emitting reverse proxy
  that leaves `X-Forwarded-For` alone. A forged header short-circuited
  the one the proxy actually signed. An exhausted all-trusted chain in
  one header is now evidence that the peer wrote that header, and the
  client named by the other wins. The trade-off is documented rather
  than hidden: when two proxies each write one header and they
  disagree, requests share the per-deployment bucket (5 requests per
  60 s by default). Guarded by
  `a_two_proxy_chain_writing_one_header_each_keeps_the_client_key`.
- A profile with an access token could never be saved again. The
  edit form re-renders the masked placeholder `abc…••••`, which the
  token charset check rejects, and the error was raised before the
  "unchanged mask keeps the stored secret" fixup, so the whole save
  aborted with 422 and the profile's name, slug, output format,
  country allowlist and source composition were all frozen. The mask
  is now matched exactly, so a token the operator typed is validated
  like any other value. Guarded by
  `a_typed_bullet_is_not_mistaken_for_the_mask`.
- Three admin screens answered `500` for a host the panel had
  already admitted. The router gates on `[admin].allowed_hosts` but
  built the serve links against the separate `[server].allowed_hosts`,
  so on a deployment that pins both lists *Import / Export*, *Sources*
  and *Profiles* were unreachable. The links are now built against the
  host that reached the panel. The link then carries the panel's own
  host, so on a split allowlist it still 404s when the public listener
  is clicked; that trade-off is documented in place of the 500. Guarded
  by `serve_link_pages_render_for_an_admin_allowlisted_host`. Guarded by
  `serve_link_pages_render_for_an_admin_allowlisted_host`.
- The copyable endpoint link on a token-protected profile's page
  answered 403 when clicked: the serve endpoint's token gate rejects
  a URL without `?token=`, and the link was built without one. The
  link now carries the token in its query string. The mask keeps the
  stored secret from casual display, while the link is the artifact the
  operator hands to clients and cannot work without the secret. The
  token charset cap (alphanumeric plus `-_.~`) keeps it URL-safe
  without escaping.
- A cold render could be cached as fresh for a full source TTL after
  an ingest. The cold path stored unconditionally, so a key with no
  entry yet — exactly an in-flight cold render — was invisible to the
  invalidation. The cold path now claims the key before rendering and
  stores through the same guarded put the stale path already used. The
  bump itself was a read-modify-write: two invalidations of the same
  key could both read G and write G+1, losing a bump; bumps are
  serialized now. Guarded by
  `inline_render_started_before_an_ingest_does_not_store_its_rendering`
  and `concurrent_invalidations_do_not_lose_a_generation`. Guarded by
  `revalidation_started_before_an_ingest_does_not_store_its_rendering`.
- `X-Fumox-Warning: all-proxies-quarantined` was sent for profiles
  where nothing was quarantined. The predicate counted `ready` as a
  hidden tier and read the pre-filter population, so a
  `filter.protocols` (or ASN, or drop-rule) filter that removed every
  ready proxy produced a health warning. Only `quarantine` and
  `removed` count now: a filter is a configuration fact, not a health
  one. Guarded by
  `a_filter_that_hides_every_ready_proxy_is_not_a_quarantine_warning`.
- A proxy the probe had already quarantined or removed kept being
  served. `/sub` and `/src` stamp their cache entry with the source
  fetch TTL, but the probe is a separate process that moves rows
  between tiers and nothing in the server reacts to it, so the window
  was the feed-download interval: an hour by default, up to 24 at the
  admin form's maximum. Rendered output is now capped at 30 s of
  freshness, and stale entries are still served immediately while
  being re-rendered in the background. Guarded by
  `rendered_output_is_not_fresh_for_a_whole_source_ttl`.
- A pipe in a host or credential could move a fingerprint field
  boundary. The pre-image joins its fields with a literal `|` and the
  escaping rewrote only `%`, `&` and `=`, so two malformed feed lines
  that both contained one collapsed into a single row and a node
  vanished from the subscription. The separator is escaped now, so the
  pre-image is injective in it. Guarded by
  `pipe_in_a_field_cannot_shift_the_pre_image_boundary`.
- The dashboard's "unprobeable (tuic/mieru)" sub-line could exceed
  the "Never checked yet" headline it sits under. The sub-line
  counted removed rows and the headline excluded them, so after
  *Remove unprobeable unknown* the panel read 0 with 300 beneath it.
  The sub-line now carries the headline's own population filter. Guarded
  by `unprobeable_count_excludes_rows_the_cleanup_button_retired`. Guarded by
  `unprobeable_count_excludes_rows_the_cleanup_button_retired`.
- At `[probe].sample_size = 0` the probe page's backlog banner
  reported the queue as a multiple of a sample that does not exist, so
  a 25-row queue read "25× the per-cycle sample" above a "sample
  0/cycle". Both triggers now stay off at zero: there is no sample to
  measure against, and the `all_idle` line already reports the state
  with the numbers an operator can act on. The config bounds table
  starts the sample at 1 and refuses the file at startup otherwise. Guarded by
  `sample_size_zero_reports_idleness_not_a_ratio_over_zero`.
- The banner's `cycle_interval_secs` recommendation could ask for a
  cycle faster than the daemon's own heartbeat floor. The period is
  `ceil(target / cycles)`, so a long queue and a tight
  `connect_timeout_secs + tls_timeout_secs` land on single-digit
  seconds. The daemon puts a `.max(5)` floor on its beat period, so
  the recommendation now stays silent below that instead of printing a
  value an operator should not set. The knob itself is unaffected: a
  period the model can certify at or above the floor still prints. Both
  guides' recommendation list says so. Guarded by
  `period_rec_never_lands_below_the_beating_floor` and
  `recs_stay_inside_the_range_the_form_accepts`, so no knob can print
  a value outside the settings form's own range.
- Drop rules corrupted the geo pairing of everything after the
  first dropped entry: the geo stamps were resolved for the list
  *before* the drop and paired by index with the shortened list, so
  every proxy past the first dropped entry was stored carrying a
  neighbouring host's country and ASN, one IP could end up stamped
  with several autonomous systems, and the admin ASN cleanup buttons
  then acted on that noise. The drop pass now returns the stamps that
  belong to exactly the surviving entries.
  `scripts/repair-geo-stamps.sh` rewrites the already-corrupted rows:
  it clears the three `geo_*` columns (after a backup) and lets the
  startup backfill re-resolve every row from its own host, verified
  on a copy of a production database: 0 wrong re-stamped rows and 0
  hosts carrying more than one ASN.
- The probe card's kernel RSS line reached the reader as literal
  HTML source: it was assembled with a `<time>` element inside and
  rendered through an escaping handle. The line is plain text now and
  the timestamp is rendered by the template as a proper `time` element
  beside it.
- `scripts/revive-xhttp-proxies.sh`: a one-shot repair for the
  vless+xhttp rows the pre-0.22 engine stranded in `removed` — the
  transport did not exist there and every T2 check failed, while
  Fumox rendered the transport correctly all along. Linked rows are
  revived and enqueued for priority checking; `--include-unlinked`
  also adopts link-less rows into a source, because every probe lane
  selects on the `proxy_source_links` row and a revived row without a
  link sits in no lane at all. `--adopt-source` names the adoptive
  source explicitly, `--no-adopt` revives without linking.
  `--restore` undoes a run safely: it verifies the backup before
  touching anything, refuses while anything has the database open,
  snapshots what it is about to overwrite, deletes the write-ahead log
  that would otherwise be replayed on top of the restored file, and
  integrity-checks the result. The bare `cp` the script used to
  suggest fails either loudly (`database disk image is malformed`) or,
  worse, quietly: the log fits, the copy "succeeds",
  `PRAGMA integrity_check` prints `ok`, and the database holds the
  pre-restore data after all.
- The admin event stream paid for events nobody consumed. It ran
  `count_by_status` when a connection opened and, every 30 s
  thereafter, the counts plus two `meta` reads, emitting `probe.stats`
  and `heartbeat` events; the panel reacts to `fetch.*` only,
  re-broadcast as `fumox:refresh`, so every admin tab held a query
  loop whose output was dropped on arrival. The tick is gone: the
  stream forwards bus events, keeps its keep-alive and idle hard cap,
  a lagged consumer logs what it lost, and the layout shows a
  connection chip instead: hidden until the `EventSource` opens,
  flipping to a *stale* state while the browser reconnects, announced
  via `role=status`. Guarded by `sse_stream_forwards_bus_events`.
- The probe screen judged the daemon against the *server's* config.
  `probe_heartbeat` carried only `{ts, pid, version}`, so the panel
  thresholded staleness with its own
  `[probe].heartbeat_interval_secs`, and the meow card rendered green
  for a `meow_last_ok` contact from any point in the past. Server and
  probe may read different config files (or env overlays), so a probe
  on a slower schedule than the server's copy turned its still-alive
  badge stale. The heartbeat now reports the daemon's effective beat
  and cycle periods; the panel prefers the reported values (falling
  back to its own config, floor 5 s), the heartbeat verdict keeps its
  3× rule, and the meow contact goes stale after three daemon cycles.
  Guarded by `heartbeat_threshold_mirrors_the_daemon_beat_period`,
  `meow_stale_threshold_is_three_cycles` and
  `heartbeat_payload_reports_the_effective_beat_and_cycle_periods`.
- Neither daemon said which database it opened. The resolved
  `[database].path` is otherwise visible only on *Settings*, so a
  stream of scratch instances, containers and volume mounts made
  "which file am I on" a guess. Both processes now log
  `database configured` at startup with the resolved path and the count
  of `FUMOX_*` overrides; the count, not the names or values, so a
  surprise override is attributable without logging secrets.
- A panic inside one scheduler sweep silently stopped every later
  one: an unwind left the overlap flag stuck and the loop skipped every
  future tick — no fetches, no error, only a dashboard staying quiet.
  The flag now travels in a drop guard that resets it on the normal
  path and on unwind alike. A panicked ingest task names its source
  instead of vanishing, and shutdown got its missing half: the refresh
  channel is dropped (closing it is the scheduler's shutdown signal),
  the loop is awaited for at most 5 s so a wedged sweep cannot hold the
  process past its budget, and the sources still in flight are named as
  abandoned mid-request, so a gap in `fetch_log` has an explanation in
  ours. Guarded by `sweep_guard_resets_the_flag_on_unwind`.
- `/healthz` answered `ok` with a dead database, so an instance whose
  only shared dependency was gone kept telling the orchestrator it was
  fine while every subscription 500'd. It now runs `SELECT 1` and
  answers `503 database unavailable` when the pool stops answering,
  and it *stays* after the public rate-limit layer on purpose: an
  exhausted window must not make the liveness probe answer 429 and
  restart a healthy instance. Guarded by
  `healthz_stays_outside_the_public_rate_limit` and
  `healthz_goes_red_when_the_database_is_closed`.
- A scanner sending random `Host` headers to the export links
  logged one warning per request. The gate runs before the token
  check, so the warn is the only signal a misconfigured allowlist
  leaves. Rejections now warn once per host per hour (repeats drop to
  debug) and the registry is capped at 1024 distinct hosts, aged out
  by the same window, so an unauthenticated flood can neither mirror
  itself into the log nor pin memory. Guarded by
  `host_reject_warns_once_per_host_per_window` and
  `host_reject_log_is_bounded_under_a_flood`.
- A burst of requests on a cold subscription key rendered it once
  per request, and the export links' 30 s window had the same hole:
  every request landing on an expired entry re-rendered the tier. Both
  paths now go through the cache's inline-render claim: the first
  request renders, the rest wake when its claim ends and serve the
  stored entry, claiming a render only when the leader stored none.
  The exports still never serve a stale body, not even to a waiter. Guarded by
  `concurrent_cold_requests_share_one_render`.
- The raw source cache stored whole fetched payloads nothing read:
  only `fetched_at` was ever consulted, so the last payload of every
  source sat in memory as dead weight; the layer now stores the
  freshness marker alone. Rendered bodies are shared instead of copied
  whole per request.
- A settings save could report success for a setting that was never
  written. A slot on disk holding a non-table value (say `server = 42`
  where the editor needs `[server]` to dive into) failed the write, and
  every call site discarded the result: the save wrote the untouched
  document back and the operator got a green toast. The failure now
  surfaces as a per-field error, and unrelated edits of the same save
  still apply. Guarded by
  `apply_all_surfaces_unsettable_slot_instead_of_swallowing_it`.
- A base64 subscription wrapped at 76 columns parsed as zero
  entries. Interior whitespace is not base64, broke the length-modulo
  check and made the payload fall back to being read as plain text,
  silently yielding nothing, while real producers do wrap, so a whole
  feed could count as empty. The decoder strips whitespace before
  decoding, under auto-detection and a pinned `base64` encoding alike. Guarded by
  `line_wrapped_base64_payload_decodes`.
- A vmess line could serialize with a host, port, name or
  credential different from the stored entry. The JSON writer inserted
  every pass-through parameter verbatim, so a stray `add` / `port` /
  `ps` / `id` parameter (a vmess JSON can carry `PS` next to `ps`)
  overwrote the structured fields in the emitted object. The reserved
  field names are skipped like `v` already was, case-insensitively. Guarded by
  `consumed_fields_win_over_colliding_params`.
- Clash-sourced entries serialized onto the URI list with mihomo
  field names, so exporting a Clash-fed source through the URI
  serializer produced lines that did not mean what the entry said.
  Entries without a source line now pass through a translation onto
  the canonical URI vocabulary first: `servername`→`sni`,
  `network`→`net` (vmess) / `type`, `ws-path`→`path`,
  `client-fingerprint`→`fp`, the structured blocks (`ws-opts`,
  `reality-opts`, `grpc-opts`, `h2-opts`, `http-opts`, `obfs-opts`)
  flattened onto their URI parameters, `tls` / `skip-cert-verify`
  booleans mapped onto the spellings each scheme's clients read, and
  the first occurrence winning a collision. For vless and trojan the
  `security` key is forced to `reality` whenever a public key is
  present, however `tls` was spelled: mihomo writes REALITY as
  `tls: true` plus `reality-opts`, which a client drops unless
  `security` says `reality`. URI-sourced entries keep their stored
  bytes untouched; the translation is output-only. Guarded by
  `clash_vless_item_serializes_onto_the_uri_vocabulary`,
  `clash_vless_reality_item_serializes_with_security_reality` and the
  sibling `clash_*` serialization tests. Guarded by
  `clash_spellings_are_security_relevant`.
- The certificate-verification toggles had a different spelling list
  per consumer. The sing-box and Clash writers did not recognize the
  underscore `allow_insecure`, the spelling sing-box and tuic links
  actually use, so those writers emitted no `insecure` flag for a node
  that requested one and the client then verified certificates the
  server never presented; the fingerprint normalization recognized the
  same three aliases, so the same server advertised once with
  `allow_insecure` and once with `skip-cert-verify` deduplicated as
  two rows; and the pipeline's forbid-insecure filter carried its own
  fourth copy of the list. One list and one truthiness rule now back
  all three. One-time churn to expect: `allow_insecure`-spelled nodes
  fingerprint differently than before, so the first ingest after
  upgrading re-inserts them as new rows and the old rows retire
  through the ordinary reconcile pass.
- Geo problems were invisible exactly where they mattered. A geo
  directory with no usable database, or one missing a single kind,
  produced one vague warn at best while rows silently stayed
  unenriched, and the startup backfill summary reported only the rows
  that happened to resolve, so "0 updated" read the same whether the
  pool was fully stamped or the resolver could answer nothing.
  Startup now names the files that opened, each missing kind gets its
  own warn naming the file and the directory, and the backfill summary
  carries the `remaining` count of rows with every geo column NULL,
  retried on the next start.
- Probe lanes vetted candidate hosts one DNS lookup at a time,
  ahead of every real verdict. Each lookup is bounded by
  `[geo].dns_timeout` (5 s by default) and the lanes ran them serially
  before spawning any check, so a batch full of dead names queued one
  timeout per candidate while the check semaphore sat idle. Vetting is
  now concurrent under the same `probe.concurrency` budget and
  order-preserving, in the T1 sample, the quarantine recheck and the
  T2 lanes alike; a closed lane or a panicked vetting task refuses
  that target so the row stays on the ordinary fail ladder. Guarded by
  `vet_hosts_preserves_order_and_policy`.
- The meow config file's 0600 mode was only applied at creation, so a
  `meow.yaml` from an older binary, a hand-copied sample or a restored
  backup kept whatever permissions it had while the daemon rewrote it
  in place with every proxy credential in plain text. The mode is
  re-asserted with an `fchmod` on the open file descriptor, so no
  second path resolution can be swapped in between. Guarded by
  `meow_config_permissions_are_reasserted_on_an_existing_file`.
- T2 outage cycles read as healthy batches. The batch folded every
  row into one `t2_checked` counter, including rows an engine-wide
  outage kept away from meow-rs and rows `clash::generate` could not
  serialize — exactly the situation the counter is watched for. The
  cycle log now separates them: `t2_checked` counts only rows that
  got a real verdict, `t2_aborted` the outage casualties and
  `t2_skipped` the unserializable ones. Guarded by
  `t2_outage_counters_report_aborted_not_checked` and
  `t2_live_engine_counters_count_real_checks`.
- A failed probe journal write logged at warn and vanished into the
  noise. The write failure means the history row for a verdict that
  *did* land is gone for good, and a burst of them is the only symptom
  when the database is locked or unwritable. The level is error now.
- Ingesting a large feed held the WAL write lock past the probe's
  patience. The reconcile transaction ran two statements per entry,
  so a refresh of tens of thousands of entries outlived the probe
  daemon's `busy_timeout` and its journals were dropped. The upsert is
  one multi-row `INSERT .. ON CONFLICT .. RETURNING` per 250 entries
  and the link sweep one per 500 (3 binds a row), keeping the lock
  span short; duplicate fingerprints inside a batch collapse onto one
  id as the per-row upserts did.
- Toasts for the plain-browser path did not exist. HTMX callers got
  `HX-Trigger` toasts, but a browser that posted a form without HTMX
  got a bare redirect with the message dropped, so on the shared pages
  (rotate the export token, purge removed) the action left no visible
  confirmation. Redirects now carry `flash` / `flash_level` query
  parameters that the layout turns into a toast and strips from the
  URL immediately, appended with `&` when the target already carries
  a query. The import form echoes the submitted payload back on a 422
  so a fix-and-retry does not start from an empty textarea, token
  rotation confirms through the same toast mechanism, the purge dialog
  shows how many `removed` rows it is about to delete, and the empty
  proxies list offers a *clear filters* link when a filter is what
  hid the rows. Guarded by `flash_redirect_merges_into_an_existing_query`.
- Accessibility of the admin's live pieces. The toggle swaps on
  sources and profiles replaced the badge and button without the
  `aria-live` / `aria-atomic` attributes and `aria-pressed` state the
  initial render carries, silently ending the announcements a screen
  reader had; keyboard focus fell to `<body>` after every toggle
  because the button that was activated is re-created, so focus is now
  restored onto the fresh button, only when it was not moved
  elsewhere in the meantime. The schema and country stat tables'
  colour-coded badges had `title` but no accessible name: a legend and
  per-badge `aria-label`s ("alive: 12") now name both. The dialogs on
  *Proxies*, *Sources* and *Profiles* gained `aria-labelledby`
  pointing at their headings.
- Placeholder cells rendered a bare comma. The timestamp tables and
  the proxies list's T1/T2 coverage column both returned `,` where
  they meant "no value", so the tables showed an orphan comma under
  "last seen" and a row with neither check got a `,` in the coverage
  cell. Both use the en dash the rest of the tables use.
- A proxy ingested while geo was unavailable bypassed the ASN
  filters. `exclude_asns` and the allowlist read the stored `geo_asn`,
  and a row that never got one matched neither, so the exclude list
  kept a proxy whose geo-enriched name printed the very AS it was
  supposed to be dropped for. Serving now resolves the missing ASN
  once per candidate before the filters run, and a stored ASN is never
  overwritten. Only a host that genuinely cannot be resolved stays
  unknown: the allowlist drops it, an exclude list keeps it, as
  documented.
- A host whose DNS failed once was cached as "unknown" forever, so a
  transient resolver outage kept the host out of every ASN filter and
  every `{asn}`-bearing name until the process restarted. Positive and
  negative entries now expire after six hours — the same cadence as
  the periodic backfill — so a recovered host is picked up without a
  restart.

- A failed geo lookup no longer eats the backfill budget of the fresh
  rows. A row whose host did not answer is marked (migration `0012`,
  the `geo_attempts` / `last_geo_attempt_at` columns) and left alone
  for six hours, so the hopeless hosts cannot starve the rows that were
  never tried; a row that gets its facts clears the mark.
- The geo backfill walks the whole backlog. A short page no longer ends
  the pass, and a budget that runs out before a lookup leaves the row
  unmarked (so it is tried again) instead of writing it off.
- The GeoLite2 download is verified before it is installed. A file whose
  SHA-256 is listed in `[geo].sha256` is installed only when the
  download matches it, and a mismatch leaves the previous database in
  place. A valid database from another provider is kept (the provider
  marker is an info line, not an error), and only a file without
  MaxMind metadata (a corrupt download, an HTML error page) is
  refused. The temporary file gets a unique name and is created
  exclusively, and the orphaned `GeoLite2-*.mmdb.*.tmp` files of a dead
  process are cleaned up at the start of a pass.
- A geo template with an unknown placeholder is refused where the
  template is saved (the admin panel and the config loader), instead
  of rendering a literal `{foo}` into every proxy name. A template
  without `{name}` gets the original name appended, and an empty
  template renders the name alone.
- The country of a proxy is the country MaxMind has a record for, or
  the registered country when there is none; a record that carries
  only a city is kept instead of thrown away.
- The T2 batch asked the probe journal for the newest entry of every
  candidate, so the batch that picks the least recently checked rows
  seeked into the largest table once per candidate. The stamp is
  denormalised onto the proxy row now (`last_t2_checked_at`, migration
  `0014`) and refreshed whenever a T2 attempt is journaled. The stamp
  is permanent: a rotated journal cannot push a proxy back into the
  "never checked" tier, which the lookup over the journal could do.
  Guarded by `the_t2_recency_stamp_follows_the_journal` and
  `the_t2_recency_stamp_survives_the_history_sweep`.
- The settings form shows the file, not the environment. The panel
  writes the file, so the values on the page are the file's own now
  (the file is parsed over the defaults, without the `FUMOX_*` layer
  that shadows it). A setting the environment overrides renders
  read-only and is left out of the write: the env layer wins over the
  file, so a value written there would never take effect. The page
  says which settings are locked and why. Guarded by
  `the_form_shows_the_file_and_not_the_environment`,
  `an_env_locked_field_is_not_written_back`,
  `an_env_lock_covers_the_halves_of_a_rate_limit_pair` and
  `an_env_locked_field_renders_read_only_with_a_reason`.
- A checkbox the browser did not post no longer resets its setting.
  Every boolean on the edit form is a checkbox plus a hidden
  `value="off"` input, so a field that did not arrive was written as
  `false` — a value nobody chose, applied to a setting nobody touched.
  The key is handled only when the form carried it. Guarded by
  `a_bool_the_form_did_not_carry_is_not_reset`.
- A rate limit whose pair reached the panel half-filled is refused
  instead of guessed. A form that lost one half of the pair is not a
  form the operator meant to send: the missing half is taken from the
  file for the check, the submit is refused with a field error, and
  the file is left byte-identical. Guarded by
  `a_partial_rate_limit_pair_is_refused_and_the_file_stays_untouched`
  and `a_partial_rate_limit_pair_without_the_limit_is_refused`.
- The admin token rotation is decided by the document, not by the
  submitted field. The panel compared the token of the running
  configuration with the one the form carried, so every save that
  did not touch the token ended the session that performed it. The
  comparison is between the token of the file before the write and the
  one after it now, so only an actual rotation revokes the sessions.
  A token the environment overrides is not a rotation at all: the
  panel runs under the environment's token whatever the file says, so
  the toast says so instead of claiming a success. Guarded by
  `a_save_the_environment_overrules_is_not_reported_as_a_success`.
- The settings save runs on the blocking pool. The load, the
  validation and the write are synchronous file work, and they held
  the async runtime while they ran, so a slow disk stalled the whole
  server. The *Create from defaults* button writes through the same
  atomic path a save takes (a temporary file in the same directory,
  fsynced, then renamed), and it refuses to overwrite a file that is
  already there. Guarded by
  `the_create_from_defaults_button_creates_a_missing_config_only`,
  `the_create_from_defaults_button_writes_the_reference_copy` and
  `the_create_from_defaults_button_refuses_a_read_only_directory`.
- A config the loader refuses is no longer written. The panel writes
  the file both binaries read at startup, and a file they refuse
  aborts both of them; the save is refused now, with the reason on the
  page, and the file stays byte-identical. The edit page also explains
  a config it could not read: the values below it are the running
  ones, not the file's. Guarded by
  `a_config_the_loader_refuses_is_not_written` and
  `the_edit_page_explains_a_config_it_could_not_read`.
- A logout that could not revoke the sessions says so. The epoch bump can
  fail (the database is locked, the row is gone), and the old answer was a
  plain redirect to the login screen: the browser's cookie was cleared,
  but a copy of it kept working until its TTL, and the operator had no
  way to learn that. The logout now redirects to `/admin/login?revoked=0`
  and the login screen carries a banner that names the failure, so the
  revocation can be repeated or the token changed.
- A database error while reading the session epoch is refused, not
  treated as an epoch of zero: a cookie minted before the first bump
  would verify again, which is exactly what the epoch exists to
  prevent, and a value that is not a number is the same case. Both
  answer `503` now instead of letting the session through.
- A malformed `Host` never reaches the serve link. The link builder
  canonicalised the header and then checked nothing else, so a
  malformed host ended up as the authority of a URL that carries the
  export token. The canonical form is checked against the host grammar
  now (a DNS name, an IPv4 literal, a bracketed IPv6 literal), and
  anything else falls back to the bound address.
- The serve link keeps the port the request came in on. The port of the
  `Host` header was dropped and the port of `[server].bind` was used
  instead, so a panel reached on a published port (a NAT mapping, a
  reverse proxy on 8443) offered a link to a port nothing listens on.
  Behind a trusted proxy the port of the request is the public authority
  and is used; without one the bound port stays.
- The forwarding headers are read as one header. A repeated
  `X-Forwarded-For` (or `Forwarded`) is one field with the values joined
  by commas, per RFC 7230; only the first value was read, so the entries
  a proxy appended after it were dropped without a word.
- The per-IP window exempts the static path only. Every `HEAD` request
  was exempt from the window, so the paths that matter (the login, the
  panel actions) had a free window on a method an attacker picks at
  will. A `HEAD` on `/admin/static/*` stays exempt, every other `HEAD`
  counts like the `GET` it stands for.
- The import writes in one transaction. The sources were written one by
  one and the profiles after them, each on its own, so a failure
  half-way through left the sources already in the database and no
  profiles: a configuration that was half imported and looked whole.
  The whole write phase runs in a single transaction now, so a failure
  leaves the database exactly as it was.
- The import no longer refuses a file because a name did not resolve.
  Every imported URL was resolved inside the request, and a timeout or
  a SERVFAIL counted as a hard error, so a source whose host was
  briefly unreachable could not be imported at all. A resolution
  failure that says nothing about the target is a warning now (the URL
  is vetted again at fetch time, on every request); only a policy
  violation (a private address) stays fatal. The name-resolution
  window is bounded as a whole now: at most 25 URLs are resolved per
  import and the window has a deadline of its own.
- The import rejects a document that is not a document. A body that is
  not JSON, or JSON without the `version` field, ended in an error page
  carrying the raw parser message. Both are refused with `422` and a
  localized message now, and nothing is written. A document past the
  256 KiB cap is refused the same way, before it is parsed at all.
- The `Authorization` header of a protected profile accepted only the
  exact spelling `Bearer`. The scheme is compared case-insensitively
  now, so `bearer <token>` opens the profile. Another scheme is not a
  bearer token at all: `Basic <token>` is refused like a missing token.
  The token itself is still compared verbatim against the stored hash.
- The failed-access-token log could be out-warned. A client that came
  back after its own window elapsed was warned again without spending
  the per-window budget, so a small set of rotating clients could flood
  the log past the budget the limiter enforces. The budget covers every
  warning of the window now, not only the ones issued to a client seen
  for the first time.
- A render logged one line per corrupt proxy row. The skipped rows are
  counted and reported in one line per render now (the count, the first
  row and the first reason), so a feed full of broken rows cannot
  flood the log.
- The upstream status of a broken source was substituted with a guess.
  When the real status is unknown (the fetch log could not be read, or
  the last attempt recorded no HTTP status), the substituted `502` goes
  to the log with the reason, so an operator reading the log sees why
  the answer is 502 and not 404.
- A failed read of the source list renders a server error. The profile
  form replaced it with an empty checklist, which reads as "there are
  no sources" and invites the operator to save a profile that composes
  nothing.
- The source edit form reads the stored row once. It read it twice and
  swallowed the second failure, so a row that could not be read left
  the form showing empty timestamps instead of an error.
- The admin write path does not own the fetcher's columns. Saving a
  source rewrote `last_fetched_at`, `last_error` and `error_class`
  with the values the form held, which were empty. The edit form writes
  the admin columns only, and the toggle is a targeted update, so a
  fetch that lands during the edit is not erased by it. Guarded by
  `set_enabled_flips_the_flag_without_rewriting_the_row`.
- A duplicate header key in the source form is a field error. The
  second value silently overwrote the first.
- A source deletion that cannot flag the orphans says so. The failure
  went to the log only, so the panel reported a clean delete while the
  proxies it fed were left in an unknown state. The warning toast
  names it now.
- The "refresh now" action answers with the real status fragment and
  `202 Accepted`. The state was rendered from a formatted string
  instead of the fragment the other actions use.
- A source lookup tells "not found" from "the database said no". Both
  answered with the same empty page, so a failing database looked like
  a deleted source.
- The probe backlog estimate cannot overflow: the retirement rate was
  multiplied by the check period without a saturating multiply, so a
  large rate and a large period wrapped around and reported a drain
  time of seconds.
- A quarantine queue that is not being drained is a warning. The panel
  reported "all idle" for a daemon whose sampling is disabled while
  its queue is non-empty, which is the opposite of what the operator
  needs to see.
- The pipeline editor read an unbounded number of rule rows from the
  form. A submission carrying thousands of `ped_rename_<i>_` fields
  was parsed row by row, so a programmatic client could make the panel
  spend its memory on the rows it was going to drop anyway. The cap is
  256 rows per section now; the limit is unreachable from the UI. Guarded by
  `from_form_caps_the_number_of_rows_per_section`.
- The pipeline editor trimmed the rule text it read. A regular
  expression or a replacement string that starts or ends with a space
  lost it, so the rule the operator typed was not the rule the
  pipeline ran. The rule fields (match, replace, flags, key, ASNs) and
  the geo template are read verbatim now; only the scalar fields (the
  target, the cap) are trimmed. A whitespace-only pattern survives in
  raw mode as well. Guarded by
  `from_form_keeps_the_rule_text_verbatim` and
  `ingest_keeps_a_whitespace_only_pattern_in_raw_mode`.
- The ASN fields of the pipeline editor accepted a list of separators
  as if it were an allowlist. A field holding only commas and spaces
  parsed into an empty list, and an empty list dropped every proxy
  that carries an ASN. The field means "no ASN list" when nothing
  survives the split now. Guarded by
  `an_asn_field_of_separators_is_not_an_allowlist`.
- A mistyped sort key or cap was dropped instead of reported. The
  editor fell back to the default, so the operator saw a working
  pipeline that ignored the key they had chosen. The raw value is kept
  now and the validation names the field it came from.
  Guarded by `an_unknown_sort_key_is_reported_and_kept` and
  `a_mistyped_cap_is_reported_from_the_field`.
- The checkboxes of the pipeline editor read an absent field as "on".
  A form that does not send the field at all turned the built-in
  default off. The switches are tri-state now: absent means "keep the
  default", and an unchecked box submits its own "off". Guarded by
  `the_built_in_default_switches_are_tri_state`.
- A profile pipeline of `null` overrode the pipeline it was supposed
  to extend. The null was read as "no pipeline", so the profile
  replaced the source pipeline with nothing. A null profile pipeline
  overrides nothing now. Guarded by `a_null_profile_pipeline_overrides_nothing`.
- The pipeline resolved the ASN of a proxy on every request, even when
  no ASN rule was in play, so a request spent a database lookup it did
  not need. The lookup happens only when a rule filters on an ASN; the
  missing ASNs are filled on the ingest side and by the backfill.
  Guarded by `a_pipeline_without_an_asn_rule_resolves_no_asn` and
  `a_proxy_without_a_stored_asn_still_honours_the_exclude_list`.
- The insecure-parameter filter ran before the rename rules, so a
  proxy whose insecure parameter was rewritten by a rename rule was
  dropped anyway. The filter runs after the renames now and sees the
  final parameters. Guarded by
  `the_insecure_filter_sees_the_renamed_parameters` and
  `a_stored_insecure_proxy_is_dropped_even_when_a_rename_rewrites_it`.
- A broken rename rule logged one line per proxy it skipped, so a
  broken pattern filled the log with one line per entry. The skips are
  counted per rule and reported in one WARN line per rule now (the
  rule index, the target, the count and a truncated sample of the
  value); the per-entry event stays at TRACE. Guarded by
  `a_broken_rename_rule_warns_once_per_rule`.
- The scheduler could not tell "no history" from "the history could
  not be read". A read error fell back to the TTL cadence, so a source
  whose journal was unreadable was fetched on every sweep. The source
  is held back now and the failure is logged. Guarded by
  `an_unreadable_history_holds_the_source_back_and_is_logged` and
  `the_history_is_read_only_for_the_sources_that_pass_the_ttl_check`.
- The retention sweep of the server ran inside the scheduler loop. A
  sweep that took longer than the tick blocked the source refreshes
  behind it. The sweep runs detached now, behind its own overlap
  guard, like the source sweep and the geo backfill.
- A tick that arrives while a background pass is still running was
  skipped silently. The skip is counted and reported at WARN now, so
  an operator sees that the loop is not keeping up with its own
  cadence. Guarded by `an_overlapping_pass_is_skipped_and_counted`.
- A source fetch could hold a concurrency permit forever. A hung
  upstream kept the permit and the in-flight mark, and the scheduler
  lost one of its slots until the process was restarted. The ingest
  runs under a budget derived from the fetch timeouts now; an attempt
  that exceeds it is abandoned, the permit and the mark are released
  and the failure is published to the admin panel. Guarded by
  `an_ingest_that_exceeds_its_budget_is_abandoned`.
- A background task that panicked took its failure with it. The
  scheduled sweep, the retention sweep, the geo backfill and the
  manual refresh now report a panic as a failed fetch instead of
  leaving the panel waiting for an answer that never comes.
- The proxy card showed the secret parts in full. The credential, the
  password in the proxy line and the values of the credential-bearing
  parameters were rendered as stored, so a shared screen or a
  screenshot in a ticket carried the working secret. They are masked
  now — `user:sec…••••` for a credential, `[redacted]` for a secret
  parameter value — and the card says that the value is a secret and
  never reaches the log.
- The sources screens showed the secret parts of a URL. A source whose
  address carries a password (`https://user:pass@host/sub`) or a
  secret query value (`?token=…`) showed it on the list, on the card
  and in the edit form. The password and the secret query values are
  masked now, the safe part of the address is printed as it is, and
  the stored values are put back where the mask was when the form is
  saved unchanged — the fetcher still gets the real address, and an
  edit of the name cannot silently drop the token.
- The export-token rotation was confirmed by a JavaScript dialog. The
  dialog was the only thing standing between the operator and the loss
  of both export links, and it did not work without JavaScript. The
  rotation has a page of its own now: it names both links that stop
  working, states that the old token cannot be recovered, and the
  confirmation is an ordinary form post.
- A refused form did not say which field was wrong. The message was
  rendered, but it had no id, the control did not point at it and it
  was not marked invalid, so a screen reader read the text without
  saying which input it belonged to. The message carries an id now,
  the control points at it (`aria-describedby`) and is marked invalid
  (`aria-invalid`), and the message itself is announced
  (`role="alert"`).
- A refused settings save opened the wrong tab. The message was
  rendered on the field it belongs to, but the editor's panes are
  tabs, and the pane holding the error was usually not the open one —
  the operator was shown a form that looked fine. The pane that holds
  the first error opens now, and every pane with an error is marked in
  the tab strip, so a second broken pane is not silently wrong.
- The confirmation dialogs put the focus on the destructive button. The
  first thing a keyboard or a screen reader met inside an open dialog
  was the button that removes the rows. The cancel button takes the
  focus now (the heading, where the dialog has one).
- The live regions were re-created on every swap. A container that
  carries `aria-live` was replaced together with its content, so the
  announcement was cut off and the whole table was read out again on
  every poll. The wrapper is stable now and only its content changes.
- The enable/disable toggles mixed two state semantics. The button
  label changed with the state while the button kept a fixed
  `aria-pressed`, so the accessible state contradicted the visible
  one. One of the two is used now.

### Security

- The SQLite the app links is compiled from the bundled amalgamation now
  (sqlx 0.9.1 over libsqlite3-sys 0.40, SQLite 3.54.1): the release that
  fixes CVE-2026-119375 (RUSTSEC-2026-0459). The build needs no system
  SQLite headers and cannot fall back to the system library any more, so
  the patched version is the one that ships.
- The backups the repair scripts write hold the whole database, the
  credentials included. They are created under `umask 077` with mode
  0600 now, a backup path that already exists is refused instead of
  overwritten, and a backup in a directory others may write to is refused
  as well: the file could be swapped for another one between the check
  and the write.
- The repair scripts follow a symlink at the database or the backup path.
  A symlink is refused now: the operator asked for a database, not for
  whatever the link points at.
- The settings editor re-enabled toggles on a failed save: the
  failed-save replay read the hidden `value="off"` inputs as *present*,
  so the replayed form came back with every toggle ticked.
  Save and replay now share one `parse_bool_literal` (`on`/`true`/`1`
  against `off`/`false`/`0`/empty, anything else refused). Guarded by
  `checkbox_replay_reads_the_literals_the_save_parser_accepts`.
- `scripts/revive-xhttp-proxies.sh` interpolated `--adopt-source` raw
  into its sqlite SQL, so a quote in the name dropped the `proxies`
  table even under `--dry-run`. The value's single quotes are doubled
  now, the resolved source id is shape-checked against a plain nanoid
  before its first literal, and `FUMOX_REFRESH_CHECK_LIMIT` must be a
  plain number before it reaches the `LIMIT` clause. A legitimate name
  carrying an apostrophe still matches.
- The YAML alias guard's boundary set missed `?`: in flow context
  libyaml scans `?*a` as an alias even without a space, so an
  alias-bomb payload hid behind a `?`. `?` joined the boundary set and
  the bomb-payload regression list.
- Config import accepted access tokens outside the URL charset; import
  now enforces the profile form's unreserved-ASCII rule
  (`A-Za-z0-9-_.~`). Guarded by `import_rejects_tokens_outside_the_url_charset`.
- Admin sessions are revocable now: a revocation epoch persisted in the
  `meta` table is mixed into the session key, so a bump (on logout and
  on token rotation) invalidates every cookie minted before it at once,
  and it survives a restart. Pre-epoch cookies are rejected on purpose,
  so the first login after the upgrade costs one re-login.
- The admin middleware rejects cross-site requests before auth, CSRF
  and rate limiting, answering `403` (`err.cross_site`) without
  charging the rate-limit window. A request is cross-site when
  `Sec-Fetch-Site: cross-site` says so (top-level `navigate` document
  GETs are exempt, so opening `/admin` from a link still works), or,
  for clients without Fetch Metadata, when it carries an `Origin` that
  does not belong to the panel (`Origin: null`, an unparsable origin,
  or a host:port that differs from `Host`). Requests with none of these
  headers (curl, monitoring, health checks) are unaffected. A proxy
  that rewrites `Host` away from the origin the browser sees makes
  non-browser integrations that send an `Origin` header answer `403`
  (they must drop the header, or the proxy must pass the original
  `Host` through: the same requirement `host_gate` already imposed).
- The container stack runs with the least privilege it can run with:
  every service declares `user: "999:999"` (the kernel: `998:999`),
  `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]` and
  `read_only: true`, and the writable paths are tmpfs mounts (`/tmp`,
  `/run/meow`) or volumes. The quadlet units say the same in their own
  dialect (`User=`, `Group=`, `NoNewPrivileges=true`, `ReadOnly=true`,
  explicit `Tmpfs=`), and the kube manifest carries a `securityContext`
  with `runAsNonRoot`, `allowPrivilegeEscalation: false`,
  `readOnlyRootFilesystem: true` and `capabilities: drop: ["ALL"]`.
- The admin token no longer reaches the probe: the quadlet stack
  splits the environment in two (`fumox.env` for the shared runtime
  variables, `fumox-admin.env` for the panel's login token, read by
  the server alone), and the kube manifest does the same with the
  `fumox-env` and `fumox-admin` secrets.
- The admin panel moved into its own network namespace: the quadlet and
  kube layouts became two pods — `fumox` (the server alone) and
  `fumox-worker` (the probe and the proxy kernel). The kernel handles
  untrusted proxy traffic and its configuration is writable by the
  probe, so it must not be able to reach the panel; the two pods need
  no network path to each other and exchange everything through the
  shared SQLite volume. The public listener stays on 8080 and the
  admin panel on 127.0.0.1:8081.
- The meow-rs external-controller is authenticated and unreachable from
  outside its pod: the kernel refuses to start without a controller
  secret (`FUMOX_MEOW__API_TOKEN`, random, checked against
  `[A-Za-z0-9._-]`), the probe presents it as `Authorization: Bearer
  <token>`, and the controller is bound to the pod loopback
  (`127.0.0.1:9090`). The port is published nowhere, and the bootstrap
  config lost its `mixed-port: 7890`.
- The exchange directory is not world-writable any more (the old
  layout gave `/shared` mode 1777): the directories are split by
  purpose and owner (`/shared/geo`, the server's; `/shared/meow`, the
  probe's), the exchange directory is group-writable for the shared
  gid (0770) and the files inside it are 0640.
- The images are pinned to immutable identifiers: the compose file
  names them by digest (`image: …@sha256:…`), and the meow wrapper
  pins its upstream release to a concrete version whose SHA256 sums
  the build verifies against a file in this repository.
- The example secrets in the documentation are generated, not literal:
  the quadlet examples ship an empty `FUMOX_ADMIN__TOKEN=` next to
  the `openssl rand -hex 32` step that fills it, the kube instructions
  create the secrets from a random value instead of the `change-me`
  placeholder, and the env files are installed with mode 600.
- The session and CSRF keys follow the token as it stands: they are
  derived per request from the live token now, so a rotation ends the
  sessions of every browser at once.
- The admin host allowlist is one rule for the whole panel: a request
  whose `Host` is not on `[admin].allowed_hosts` is refused with `400`
  before it reaches the rate limiter, the authentication gate or any
  handler, on every route, and the same host is what the serve links
  are built from. A request through a trusted proxy is judged by the
  host that proxy forwarded (`X-Forwarded-Host`, or `Forwarded:
  host=`), read only from a trusted peer and only from the header
  family the operator declared. The startup log names the accepted
  hosts, and a non-empty allowlist is a breaking change for a
  deployment that relied on every host being served.
- The content-security policy of the admin panel allowed inline script
  (`'unsafe-inline'`), so an injected markup ran in the panel's own
  origin — with the session cookie and the CSRF token of the operator.
  The panel's script is a file now (`/admin/static/app.js`), every
  handler is delegated from there, and the policy is `script-src
  'self'`. Inline styles stay for now.
- The probe daemon could write the subscription (SQLite has no roles:
  every process that opens the file may write every table). The
  daemon's connections now run behind a SQLite authorizer whose rules
  are an allow-list: the `proxies` table carries the subscription
  content, so only its health columns are writable (`status`,
  `fail_count`, the check and ladder timestamps, `latency_ms`), the
  daemon's own bookkeeping tables stay writable, and a table added
  later is denied by default. The server keeps full write access to the
  same file.
- The template engine pulled in an unmaintained parser
  (RUSTSEC-2026-0374): askama's `config` feature brings the abandoned
  `basic-toml` parser along, and this project has no `askama.toml`. The
  dependency is built with `default-features = false` and the
  `derive`, `std` and `urlencode` features.

### Docs

- The user guide describes the image as it is now: Alpine instead of
  Debian, `apk` instead of `apt` in the backup command, and no system
  SQLite package in the build requirements (the library is bundled).
- The podman guide describes the deployment as it is now: the quadlet
  variant installs two environment files, the kube variant creates two
  `podman secret`s from random values, the cookie note moved into the
  shared preparation part, and the upgrade section grew the case of
  units that name the GHCR image directly (`podman pull … && systemctl
  --user restart …`) together with the warning to back up the database
  first. A new section explains how to put the nginx TLS front in front
  of the pod layouts, with the upstream names each variant needs
  (`127.0.0.1:8080` / `127.0.0.1:8081` inside the server pod, `server:
  8080` / `server:8081` for compose). The guide also spells out what
  the two pods do at start: the server applies the schema and the probe
  waits for the database with its own backoff, so a `database is locked`
  error never takes the probe down.
- The guides' alive-linger rule contradicted the reconciler: the link
  survives for `alive`, `ready`, `unknown` and `quarantine` rows, and
  only a source carrying `drop` rules under `[ingest].drop_gate = true`
  retires its links on the next refresh. Both language versions state
  the real set now.
- `config/app.toml` described the shipped recheck ladder as
  "10m → 15m" while shipping `recheck_delays_secs = [900]`; the
  comment matches the list again.
- The settings form advertised a range it never enforced: only the
  browser's own number validation checked the four rate-limit inputs,
  so a POST that skipped the browser wrote `0/min`. The bounds are
  enforced server-side now, and the three fields that rendered no error
  line have one.
- Every bounded setting now shows its range under the input, taken
  from the same table the save handler enforces, so the number an
  operator reads before typing and the number in the rejection after
  saving cannot differ. The recheck ladder states its own bound (up to
  16 steps, each 1..=30 days).
- The accepted range of a setting now lives in one place,
  `config::bounds`, instead of three (save handler, template
  attributes, `config/app.toml` prose); a test fails if a number input
  appears with no row, if a row stops being rendered, or if the
  template grows a literal bound again.
- The number and unit halves of a rate limit sit on one line now, going
  back to a full-width stack on phones.
- The i18n key scanner matched `t("…")` anywhere in a template,
  including the tail of a helper whose name ended in `t`; the pattern
  is word-bounded now.

- `config/app.toml` documented what each key *does* but never what
  values it accepts. Every key now opens its comment block with the
  range it is actually held to, and the keys the form does not edit say
  so instead of implying a bound they do not have.
- The guide told operators to drop GeoLite2 `.mmdb` files into
  `./config`; the shipped Compose stack sets
  `FUMOX_GEO__DB_DIR=/shared` and the environment outranks the file, so
  that directory was never scanned. The compose header,
  `config/app.toml` and both guides now point at the geo volume
  (`fumox-geo`) and say that the manual step is optional on a stock
  stack; the alternative (drop the override and set `[geo].db_dir`) is
  named there too.
- Both guides described `./config` as mounted read-only; the server
  container mounts it read-write so the admin *Edit settings* page can
  save, and `FUMOX_CONFIG_ACCESS` is in the `.env` table now.
- The reverse-proxy note still described the serve links as being built
  against the **public** host list, which made the *Import / Export*,
  *Sources* and *Profiles* screens answer `500` on the shipped loopback
  quickstart. The links are built from the **panel's own host** now,
  validated against `[admin].allowed_hosts`. The two lists stay
  separate: every host that should reach the public endpoints
  (`/sub`, `/src`, `/export/*`) goes into `[server].allowed_hosts`,
  every host that should reach the panel into
  `[admin].allowed_hosts`, and the panel host in both if the serve
  links must work when clicked. The shipped configuration leaves both
  lists empty, which admits every host.
- The *Settings* page was described as rendering "the complete
  effective config". Two keys have no rendered field:
  `[server].export_max_rows` and
  `[geo].startup_download_budget_secs`; the guides now name them as the
  exception.
- `[server].export_max_rows = 0` was undocumented. It does not mean
  unlimited: the value clamps up to 1 row, so the body serves a
  single node. The config reference (both languages) now says so,
  next to the sibling keys that do give `0` a meaning.
- The export links were first documented as "rendered at most once
  every 30 s", then corrected to "that holds per request, not per
  window". That correction is itself superseded now: the render behind
  a cold or expired export entry *is* single-flighted, so a burst
  landing exactly on the boundary runs one render and the rest wait for
  its fresh entry.
- Corrected code comments that asserted more than the code delivers:
  the `check_ip` policy, `render_tier`, `pipeline_size` and the
  real-`.mmdb` age assertion (which read the developer's own file
  mtimes and went red on untouched machines after a month).
- The pipeline tables in both guides described `limit.count` as
  capping "the final, deduplicated and sorted list" on a source as well
  as on a profile. A source-level cap applies to that source's own
  proxies, before the merge, so a multi-source profile serves each
  source's top up to that count, i.e. more than `count` in total. Both
  tables now say which is which.
- The root READMEs (English and Russian) missed the geo rework: they
  still told operators to download the GeoLite2 `.mmdb` files into
  `config/` as a required ritual, which on a stock `docker compose up`
  was a no-op (the stack pins `FUMOX_GEO__DB_DIR=/shared` and the
  environment outranks the file). The READMEs now lead with the
  automatic download, keep the MaxMind signup steps as the optional
  "ship your own files" path, and say where those files have to go
  under Compose (`docker compose cp GeoLite2-City.mmdb server:/shared/`).
  The production checklist item no longer phrases the download as an
  operator step.
- `docker/README.ru.md` missed the same geo correction; the Russian text
  mirrors the English one now (the config directory is app.toml only,
  geo points at the geo volume (`fumox-geo`), the manual step is
  optional).
- The documentation batch that landed after the last antislop audit
  carried eighteen English em dashes across `CHANGELOG.md`,
  `USERGUIDE.md`, `README.md`, `.env.example` and `docker/README.md`.
  All are rewritten to colons, commas or parentheses; facts and anchors
  unchanged.
- The guides and the container examples describe what a reverse proxy in
  front of the server needs. Three keys per listener decide it:
  `trust_proxy_ips` (the addresses that may speak for a client),
  `trust_proxy_header` (the header family that proxy writes) and
  `allowed_hosts` (the names the deployment serves), and what breaks
  without each of them.
- The user guide (both languages) documents what the public endpoints
  answer now: the `X-Fumox-Skipped` header and the
  `incompatible-entries-skipped` warning, that the warning header may
  carry several values, the quarantined verdict of `/src`, the 10-second
  bound on the shutdown drain and the address the `--health-check`
  probe uses.
- The user guide (both languages) documents what the admin panel does
  with a secret and what it does with a deleted source: a password
  inside a source URL is masked on every screen while the stored address
  keeps it, a profile's access token is a password field with a floor of
  16 characters, and a new *Deleting a source* section explains the two
  orphan policies (`[ingest].drop_gate`).
- The changelog had two `### Changed` sections inside one release
  block, so the second one rendered as a stray heading; the two are
  merged into one section.
- The user guide (both languages) documents what the admin panel does
  with a secret, with a refused form and with a keyboard: the
  content-security policy (`script-src 'self'`), the mask formats the
  panel uses, and a new *Keyboard and screen reader* section (the
  message sits on its field, the settings editor opens the pane with
  the first error, what a confirmation dialog focuses).
- Both user guides now describe the status tiers the way the code
  computes them: `unknown`, `alive` and `ready` are the three live
  verdicts, `quarantine` and `removed` the two states that keep a
  proxy out of the output. The two export links follow the tiers
  exactly, so a `ready` proxy appears in `/export/ready/{token}` and
  never in `/export/alive/{token}`; `health.exclude_statuses` accepts
  all five statuses, and the default still drops only the two retired
  ones.
- The guides grew a *Source settings* subsection that tables the fields
  of the source form and states what the TTL really is (the source's
  scheduler refresh period, not only a cache lifetime). The `[probe]`
  table grew `allow_private_targets` and
  `backlog_target_drain_minutes`.
- The `.env` table states what the admin token really does:
  `docker-compose.yml` refuses to start without `FUMOX_ADMIN__TOKEN`,
  while the binary's own default is `change-me`, which is not a
  credential: the panel stays off until a real token is set and
  `/admin` answers 404. Both guides also warn that the plain-HTTP
  quickstart needs `FUMOX_ADMIN__SECURE_COOKIES=false`, because Compose
  sets it to `true` and the browser then drops the session cookie (the
  symptoms: the redirect loop after a successful login and the panel's
  `403`).
- Both guides say plainly that meow-rs is not part of the image and has
  to be started separately for the T2 checks: without it only the T1
  checks run, and the `ready` tier and the T2 confirmation are absent.
  The meow test URL got one source of truth as well: the default is the
  single HTTPS endpoint `https://www.gstatic.com/generate_204` (the
  seven-address rotation of one vendor is gone), the `.env` table points
  at the configuration reference instead of implying a rotation, and the
  reference states the accepted value formats (one URL, a TOML array or
  a comma-separated list) and the fact that the probe draws one URL per
  cycle.
- The config-write guarantee is stated precisely now: the atomic
  replacement holds on the successful `rename` path only, and the
  fallback that writes through the original inode is called unsafe. The
  backlog worked example is recomputed with the formula of section 10.
- Section 11 names where the GeoLite2 databases come from: the public
  P3TERX release assets, which is why no MaxMind key is needed by
  default. A MaxMind key is only required when the operator points
  `[geo].download_urls` at MaxMind's own authenticated URLs.
- The guides still described the meow-rs release as a floating `latest`
  that the build resolved through the GitHub API. The build resolves
  nothing: `docker/meow/Dockerfile` pins `MEOW_VERSION` together with
  the two sha256 sums of the release archives, the build refuses a
  download whose hash differs, and `latest` is refused outright. Both
  guides name the command that shows the running engine's version
  (`docker compose exec meow meow -v`).
- The guides state the relative-path rule of the configuration file (a
  relative path resolves against the working directory), and section 12
  grew a Compose subsection for the database: the path inside the
  container (`/app/data/fumox.db` on the `fumox-data` volume) and the
  WAL-safe backup from a one-shot container that carries the `sqlite3`
  CLI, together with the warning that a copy of the `.db` file taken
  while the WAL is active is not a backup. The endpoint table also
  names, per endpoint, which source error class speaks for the answer.

## 2026-09-23 · sha-b72b03f

### Fixed

- *Edit settings* page: the page used to render stale `state.config`
  (frozen at startup) instead of the just-saved file, so every
  checkbox / select / spinbutton reverted to the value the running
  server loaded an hour ago even when the file on disk held the new
  value. The handler now calls `AppConfig::load(path)` on every
  `GET /admin/settings/edit`, `raw_from_state(state)` is replaced
  by `raw_from_config(&cfg)`, with a `state_appconfig(state)`
  fallback for the unwritable / load-error paths. ENV overrides
  keep their priority because figment merges them on top of the
  file in `AppConfig::load`. Regression guarded by the unit test
  `raw_from_config_reflects_post_save_file_state`.
- *Settings* overview and any handler that wants the effective
  config now pick up the just-saved values without a server
  restart. `AdminState` carries a fresh
  `live_config: Arc<RwLock<AppConfig>>` populated from
  `AppConfig::load(path)` (figment-merge: defaults → file →
  `FUMOX_*` env); `settings_update` and `settings_create` call
  `refresh_live_config(path)` after every successful write so the
  next `GET /admin/settings` (which clones via `with_fresh_config`)
  renders the post-save state, with the destructured `state.admin`
  / `state.fetch` / … fields refreshed on the spot. Defaults from
  the `Serialized::defaults` figment layer are written back into
  the in-memory view (so e.g. a page that never set
  `[ingest].removed_as_unknown` still shows its default value),
  and ENV overrides keep winning on top because the figment merge
  runs every refresh. The destructured fields frozen at startup
  are intentionally left alone: `server_bind` socket address and
  the HMAC keys derived from the admin token stay put (silently
  rebinding the listener or invalidating every active session
  would be a footgun). Regression guarded by the unit test
  `live_config_refresh_picks_up_post_save_state`.

## 2026-09-22 · sha-61fc56c

### Added

- Admin *Edit settings* page at `/admin/settings/edit`: a
  form-based editor backed by `toml_edit` that round-trips
  `config/app.toml` in place and preserves every existing comment
  (RU/EN pairs, banners, hints). Operates through a single POST
  that writes the file atomically (`<path>.tmp.<pid>` + rename,
  with a direct-write fallback for filesystems that reject
  `rename`). ENV overrides (`FUMOX_SECTION__KEY`) keep winning at
  runtime per the existing figment merge. Sections are grouped by
  owning process (Server / Probe / Shared) via CSS-only tabs (no
  JS). Disabled when the file is missing or not writable; a
  separate *Create from defaults* button on the overview
  generates the file from the embedded reference copy when
  absent. All edits are restart-required (probe must be restarted
  alongside server). No runtime-config DB overlay is introduced,
  that would not help probe, which still re-reads the file at
  startup.
- Pipeline editor gained a `target: "asn"` drop-rule option: a
  proxy whose resolved autonomous-system number matches any AS
  listed in the rule's `asns` array (with or without the `AS`
  prefix) is discarded at ingestion and from `/sub` output.
  Unresolved ASNs are kept, matching the existing
  `filter.exclude_asns` semantics. Drop rules now run after ASN
  resolution, so the dry-run previews ASN-driven discards too.
  The pipeline editor's drop section exposes the new target as a
  fifth dropdown option; the `match`/`flags`/`key` fields are
  hidden on ASN rows and replaced by a single AS-number input.
  Regex and ASN rules live side by side in the same `drop`
  array.
- Admin *Revival* panel on `/admin/proxies`: a fourth dialog
  mirroring the existing *Cleanup* panel, but moving rows in the
  opposite direction. Operators can return `removed` proxies of
  a chosen country, `removed` proxies of a chosen AS, `removed`
  proxies that never received a probe verdict, and every
  `quarantine` proxy back to `unknown`. Each action resets the
  lifecycle fields (`fail_count=0`,
  `quarantined_at` / `ladder_at` / `removed_at=NULL`,
  `ladder_step=0`) the same way `revive_removed` already does
  for the ingest-driven `[ingest].removed_as_unknown` path, and
  the returned ids are enqueued into `probe_requests` so the
  probe picks them up on the next cycle rather than waiting for
  the random sample to come around. Nothing is physically deleted:
  the *Purge removed* button stays the only hard-delete.

### Changed

- T1 checks are now suppressed after a T2 failure: when a proxy's
  most recent T2 attempt fails (bad credentials, meow-rs
  unreachable, the target hit the SSRF policy, or a
  `ServiceUnavailable` from the engine), subsequent T1 checks
  for that proxy are skipped until the next successful T2; the
  T2 recency selector is the only path back into the T1 rotation.
  A T1 failure (a closed TCP port) does not trigger the
  suppression because it is not a property of the tunnel.
  **Correction:** the rule above is the intent of this change, but
  the code did not hold it in this release: `check_succeeded` cleared
  the T2 failure marker on *any* success, so a successful T1 lifted
  the suppression as well and the skipping ended with the first T1
  verdict. The fix lands in the *Unreleased* section ("A T1 success
  lifted the T2 suppression flag"), where the rule is the current
  behaviour.
- Pipeline editor's row layout now follows the `target` selector
  live: changing `name` / `host` / `port` / `param` / `asn` in a
  drop or rename row fires an htmx round-trip that swaps the row
  in place, so the regex ↔ ASN switch is immediate and the `asns`
  input appears without an explicit add button. The round-trip
  carries `?render=1` so it never grows the row count: only the
  explicit *Add rule* / *Add drop rule* buttons append.
- Pipeline preview now updates on every keystroke. The wrapper
  around the JSON preview listens for `change, input` events
  with a 300 ms debounce, so typing into the `match`, `replace`,
  `asns`, or filter fields updates the validation verdict and the
  generated JSON live instead of waiting for the field to lose
  focus.
- Admin *Sources → Delete* action is now conservative on `ready`
  proxies when `[ingest].drop_gate = false` (the default): a
  tunnel-verified row is left alone instead of being retired
  just because its source was removed: the probe keeps being
  the only authority on its lifecycle. With `drop_gate = true`
  the strict policy applies and every orphan retires, including
  `ready`.
- T2 batch abort is now reserved for real engine outages. Three
  independent guards collapse the "first `ServiceUnavailable`
  kills the whole batch" failure mode: `check_delay_with_retry`
  re-issues `ServiceUnavailable` outcomes once after a 100 ms
  backoff; every `ServiceUnavailable` is followed by a cheap
  `/version` ping and a healthy engine leaves the rest of the
  batch untouched; the in-batch `AtomicBool` is replaced by a
  `BatchGuard` carrying a consecutive-failure counter and a
  3-strike threshold. Genuine engine crashes still abort and
  back off.
- `unknown` proxies now survive the same upstream churn that
  `alive`/`ready` already do. The `keep_alive_linger` filter in
  `reconcile_source` extended its protected set from
  `('alive', 'ready')` to `('alive', 'ready', 'unknown')`: an
  `unknown` row that vanished from a single fetch is no longer
  retired in the same transaction. The admin *Delete source*
  action passes `unknown` alongside `ready` to
  `mark_orphans_removed` when `[ingest].drop_gate = false` (the
  default); with `drop_gate = true` the strict policy still
  retires every orphan.
- `db::migrate()` now self-heals from `sqlx::migrate!()`
  checksum mismatches: when an applied migration file has been
  edited in place (typically a comment-only change), the SHA-384
  stored in `_sqlx_migrations.checksum` is re-stamped from the
  on-disk content and `migrate()` is retried. The schema on disk
  is unchanged; only the bookkeeping column is rewritten. Any
  other sqlx error (`Dirty`, `VersionMissing`, structural
  mismatch, real DDL failure) propagates to the caller untouched.

### Fixed

- `db` migration on existing databases: the checksum repair now
  runs cleanly on first start after the bookkeeping column
  rewrite, and the migration order is verified end-to-end.
- Pipeline UI: the live preview of a drop / rename row no longer
  leaves a stale regex block in place after the operator
  switches the row's `target` to ASN, and the ASN `asns` input
  feeds straight into the JSON preview.
- Meow-rs batch processing: a single bad delay response on one
  proxy no longer abandons the rest of the cycle. The operator-
  visible `probe_results.error` text distinguishes `meow-rs
  transient error`, `meow-rs unavailable mid-batch`, and
  `aborted: meow-rs became unavailable mid-batch` accordingly.
- *Save source* for proxies still in `unknown`: the previous
  code path threw on missing T1/T2 rows; the handler now writes
  through and lets the next probe cycle fill the verdict.
- *Settings* UI: the operator-facing strings now carry the
  explanation of how the file editor and ENV overrides
  interact, so the page renders `FUMOX_SECTION__KEY` precedence
  inline instead of leaving the operator to read the source.
- Docker CI: image build pipeline changes for the new config
  editor (the editor needs `toml_edit` and the
  `EditableConfig::save()` atomic-rename path), the `.dockerignore`
  now excludes the editor's scratch artifacts, and a follow-up
  plumbing fix landed on the same day.

## 2026-09-21 · sha-e998d5c

### Added

- Trusted-proxy CIDRs for both public and admin listeners:
  `[server].trust_proxy_ips` and `[admin].trust_proxy_ips`
  (default `[]`). When the request comes from a CIDR listed in
  either array, `X-Forwarded-For` and RFC 7239 `Forwarded: for=…`
  are honored for the per-IP rate-limit key. Empty disables
  forwarded-header trust (the historical behavior behind a
  direct connection), any caller can otherwise spoof the key.
  This closes a security audit finding.

### Changed

- Probe state machine: when a proxy's most recent T2 attempt
  fails, subsequent T1 checks for that proxy are skipped until
  the next successful T2. The T2 recency selector is the only
  path back into the T1 rotation. A T1 failure (a closed TCP
  port) does not trigger the suppression because it is not a
  property of the tunnel.
  **Correction:** the rule above is the intent of this change, but
  the code did not hold it in this release: `check_succeeded` cleared
  the T2 failure marker on *any* success, so a successful T1 lifted
  the suppression as well and the skipping ended with the first T1
  verdict. The fix lands in the *Unreleased* section ("A T1 success
  lifted the T2 suppression flag"), where the rule is the current
  behaviour.

## 2026-09-20 · sha-47b8873

### Added

- Settings view: the admin *Settings* screen now renders every config
  key, with new `[server]`, `[database]`, `[geo]`, `[admin]` and `[log]`
  panels plus the previously missing `[probe].allow_private_targets`.
  Rate limits are shown in the canonical `N/unit` form, response caps
  human-readable, and the legacy `[geo].db` is marked as ignored. The
  admin token is the only value never rendered.

## 2026-09-19 · sha-82689c5

### Added

- Removed-as-unknown: a new `[ingest].removed_as_unknown` ingestion
  control (default `false`). With it enabled, a `removed` proxy the
  feed still carries is revived on the next refresh: the row resets
  to a pristine `unknown` with the fail counter and quarantine fields
  cleared, and walks the checks again as if it had just been inserted.
  With the default, `removed` stays terminal.

### Fixed

- Settings display: the fetch-options row on the *Settings* panel no
  longer mis-formats the per-source URL override and encoding fields.

## 2026-09-18 · sha-9349ec3

### Changed

- Manual updated to cover the latest probe output and pipeline
  behavior; minor config tweaks to ship the same defaults in the
  release image. No breaking changes.

## 2026-09-13 · sha-55ae806

### Added

- Changelog file: this file. A rolling image-snapshot index that pairs
  every published `ghcr.io/viktor45/fumox:sha-<hash>` tag with the
  source commit (generated by `git-cliff` and stitched by
  `scripts/make-changelog.py`).
- Fumox docker-nginx example: a ready-made nginx container in
  `docker/nginx/` terminates HTTPS for both `/sub` and `/admin`. A
  ready-to-uncomment service stub is dropped into `docker-compose.yml`
  (certificates mount into `/certs`, ACME challenges are served on
  port 80).

### Fixed

- Geo pipeline: City and ASN databases are now merged into one
  pipeline (City carries every fact the previous Country database
  had), and GeoLite2-Country is retired: the server no longer
  downloads or reads it, an existing `GeoLite2-Country.mmdb` is
  ignored, and `[geo].db` remains accepted in configs but does
  nothing. The six placeholders (`{flag}`, `{country}`, `{city}`,
  `{asn}`, `{asn_org}`, `{name}`) all work in one name template at
  the same time.
- UI import / export: the alive/ready endpoints are now a compact
  table with live proxy counts; the import form gained a JSON file
  picker that loads the chosen file into the payload field (manual
  paste still works without JavaScript).

## 2026-09-12 · sha-29be180

### Fixed

- Admin source and profile cards: serve links now display correctly
  with the public hostname, and the user guide picked up the
  follow-up corrections to match.

## 2026-09-11 · sha-b13bd56

### Added

- Tweakable stats: dashboard time windows (last 1 h / 6 h / 24 h /
  7 d, defaults to 10) are now interactive on the panel, and a couple
  of UI tweaks flowed in alongside the CI plumbing.

### Fixed

- Docker CI: image build pipeline changes and the GHCR cleanup
  workflow, plus a follow-up plumbing fix on the same day.
- UI and manual: corrections after the dashboard / stats merge.

## 2026-09-10 · sha-a4e7b67

### Added

- T1 / T2 selector: the admin panel gets explicit T1 (direct TCP/TLS)
  and T2 (tunnel through meow-rs) probe selectors, and T2 processing
  now survives meow-rs lookup failures with a backoff schedule.
- T2 ready tier: a `ready` tier (proxies that successfully completed
  both T1 and T2 checks) is wired alongside `alive`, with its own
  live export endpoint.

### Fixed

- Dashboard merged with stats: the dashboard and the stats page are
  now one screen, with the proxy T1 / T2 splits and the per-source
  breakdown exposed directly.
- Pipeline editor and manual: editor follow-ups after the T2 tier
  landed, plus manual updates to match.

## 2026-09-09 · sha-b040416

### Fixed

- Insecure-proxy filtering: subscriptions advertising `insecure` /
  `allowInsecure` / `skip-cert-verify` toggles are dropped by default.
  A security-hardening round on admin auth and SSRF guards followed
  on the same day.

### Changed

- Default `config/app.toml` retuned to match the new filtering
  defaults.

## 2026-09-08 · sha-960b8d2

### Added

- Proxy card actions by ASN and status: the proxies browser card
  now drives actions keyed off ASN or status directly. The Docker
  Compose file is also adjusted for Podman rootless compatibility.
- Pipeline: ASN filter and output limit, the pipeline now exposes
  an ASN allowlist (`asns` / `exclude_asns`), and an output-limit
  step (`{ "limit": { "count": N } }`) caps the final deduplicated
  and sorted list.

## 2026-09-07 · sha-41573c8

### Fixed

- Config validation and defaults tweak: strict validation was
  preserved, but a few defaults were rebalanced and a couple of
  unknown-key warnings became hard errors at startup.

## 2026-09-06 · sha-0c56bd5

### Added

- Sing-box / JSON subscription parsing, with a configurable state
  machine: fail limits, the second-chance window, and the recheck
  ladder are all exposed in `[ingest]` and `[probe]` config.
- Docker CI: image publishing to GHCR with build-provenance
  attestations, plus the meow-rs wrapper image
  (`ghcr.io/viktor45/fumox-meow:latest`). The wrapper is published
  manually via a workflow dispatch.
- Docker CI action: the first formal Docker-image CI step on the
  server side, plus the matching fix-up on the meow-rs side.

### Changed

- T2 state machine: a tuning pass on the second-chance and recheck
  parameters.

### Fixed

- Docker image CI: bug fixes in the new pipeline landed on the same
  day.
- Manual and Podman manual: a cross-cutting correction pass, with
  Podman now first-class alongside the Docker Compose docs.
- Settings UI and security audit: follow-up from the prior audit
  pass.

## 2026-09-04 · sha-7bf7d49

### Added

- Pipeline rename / drop rules by type: the pipeline now supports
  dropping and renaming proxies by `name`, `host`, `port`, and
  individual `param:KEY` (case-insensitive, e.g. `param:fp`,
  `param:path`). Drops throw the proxy away; renames flow through
  the URI's percent-encoded form.
- Linger-alive (`[ingest].drop_gate`): a new option. With `true`,
  an `alive` proxy of a source with `drop` rules leaves on the next
  refresh once a rule catches it; with `false` (default), every
  source lingers, and the probe alone retires proxies.

## 2026-09-03 · sha-c54fe1d

### Fixed

- `url_list` output header: the response's `Content-Type` and the
  metadata block now line up so plain-URI clients don't trip over
  extra bytes or a missing header.

## 2026-09-02 · sha-189eb64

### Added

- Stats page and geo enrichment with the City and ASN databases:
  every fact is persisted at ingestion time, and one name template
  can use any of `{flag}`, `{country}`, `{city}`, `{asn}`, `{asn_org}`,
  `{name}` at the same time.

### Fixed

- Proxy geo info is now persisted and surfaced on the proxy card.
- Mobile UI refinements; Docker CI plumbing.

## 2026-09-01 · sha-8d321f4

### Fixed

- Code cleanup pass: small style and dead-code cuts across the admin
  and pipeline layers. No behavior change.

## 2026-08-31 · sha-d6963ba

### Added

- Pipeline editor: a visual builder in the admin panel under
  *Profiles → Pipeline*, with a raw-JSON toggle, presets, and live
  preview. Validation stays strict: unknown keys and uncompiling
  regexes are rejected on save.

## 2026-08-30 · sha-333092c

### Fixed

- Docker environment handling: env-var resolution inside the
  Compose stack is now consistent across server, probe, and meow.
- Proxy state machine: the reconciler no longer touches statuses it
  did not verify itself, removing a class of false-`alive`
  promotions when a source refresh fails.

## 2026-08-29 · sha-39da896

### Added

- Probe priority queue: newly synced proxies are checked first,
  ahead of the random sample. Unprobeable schemes are never queued;
  a proxy that leaves `unknown` through the random path simply
  drops out of the queue.
- Profile country filter: include / exclude lists on a profile
  (`Countries`), case-insensitive.
- Rotating multiple `test_url`s for T2 checks: a TOML array or a
  comma-separated string under `[meow].test_url` is supported, and
  the probe picks one URL at random per check.
- Per-source IP-family selection for fetching: `ipv4` / `ipv6` /
  `any`, with `any` as the default.
- Live data export link suitable for scaling: a single
  `/export/alive/{token}` URL (and its `ready` counterpart) that
  clients can poll instead of recomputing subscriptions.

### Fixed

- T1 / T2 check priority: ordering now matches the queue updates,
  so a never-checked proxy is no longer stuck behind an
  already-verified `alive` one in the random sample.
- Strict config validation: unknown keys are rejected (a typo in a
  section name no longer silently falls back to the default).

### Docs

- Podman deployment example: a systemd-managed podman pod as the
  canonical alternative to Docker Compose, using quadlet units or
  a kube-play manifest.

## 2026-08-28 · sha-68e4cb6

### Added

- First working draft: source fetching, proxy parsing across
  multiple formats, SQLite (WAL) storage and migrations, the
  `/sub/{id}` and `/src/{id}` endpoints, the admin panel, the
  `fumox-probe` health-check daemon, and the meow-rs T2
  integration. The user guide lands in this drop too.

### Fixed

- UI soft-wrap, source / subscription link rendering, YAML/JSON
  pipeline output, and the alive-source output encoding.

### Docs

- Manual updated with the new user guide.

## 2026-08-19 · sha-8302bfb

### Changed

- Initial commit and the README that bootstrapped the project.
