# Changelog

Fumox ships as rolling image snapshots (`ghcr.io/viktor45/fumox:sha-<hash>`
plus the moving `latest`); this changelog lists what each published batch
of changes contains, newest first. Match the `sha-` tag of the image you
pulled (`docker images`) to the hash in a section header, or just diff
your pull date against the section dates.

The categories follow [Keep a Changelog](https://keepachangelog.com/);
`Docs` covers the user guide and READMEs, `Internal` (dependency bumps,
CI plumbing) is omitted — it never changes the shipped image.

## Unreleased (2026-09-29)

Defect fixes in the working tree, not yet on a published image.

### Added

- `[geo].startup_download_budget_secs` (default 60, `0` = do not
  wait): the ceiling on how long startup blocks on the GeoLite2
  download before it binds the listeners. The budget is an upper
  bound on a stalled mirror, not a promise that geo is ready — past
  it the download continues detached and that run serves without geo
  enrichment until the next start. Tunable like every other key
  (`FUMOX_GEO__STARTUP_DOWNLOAD_BUDGET_SECS`).

### Fixed

- The dashboard's "new proxies over the last 7 days" chart labelled its
  columns with clipped timestamps. Each bar is a midnight-UTC day bucket,
  but it was rendered through the shared `<time class="ts">` helper, which
  base.html's `localize()` rewrites into a full local timestamp — so every
  label spent its 64 px on `00:00:00` and the browser cut the date down to
  `09/23/202…`. The columns now carry a `day`-classed `<time>` that
  `localize()` formats date-only, and the tooltip still carries the full
  instant and zone. The same column's `aria-label` had the `<time>`
  element interpolated into the attribute, so screen readers were handed
  the raw markup; it is plain text now. Covered by
  `day_element_omits_the_time_part`.
- Source reconcile retired proxies that belonged to someone else. The
  end-of-pass sweep asked a global question ("is this row link-less?")
  and therefore swept up the deliberate residue the admin *Delete
  source* click leaves behind under `drop_gate = false`, where
  `mark_orphans_removed` protects `ready` and `unknown` rows and
  leaves them link-less on purpose. Reconciling an unrelated source
  one tick later retired them, undoing the operator's choice. The
  sweep now runs before the `DELETE` and asks only about the links
  *this* pass removes: a stale link of this source and no link that
  survives it. Guarded by
  `reconcile_of_another_source_leaves_protected_orphans_alone`.
- `check_failed` lost fail-count increments and could resurrect a
  retired row. The `fail_count` read and the write that acts on it
  were two pool-level statements: overlapping checks of the same row
  lost an increment, and the write carried no status guard, so a row
  that had meanwhile been driven to `removed` with a second chance
  scheduled was pulled back into `quarantine`. Both statements now
  run in one `BEGIN IMMEDIATE` transaction (`SQLITE_BUSY_SNAPSHOT` is
  outside `busy_timeout`) and repeat the `status IN ('unknown',
  'alive', 'ready')` guard; a refused write reports
  `Transition::Unchanged` instead of the attempted transition.
- A T1 success lifted the T2 suppression flag. `check_succeeded`
  cleared `last_t2_failed_at` on any success, so a proxy that had just
  failed its tunnel check re-entered the T1 rotation on a plain
  TCP/TLS verdict — the exact case the flag (migration 0007) exists
  to suppress. Only a T2 success does now, and `ready` is the T2
  success tier.
- A meow-rs outage was charged to the proxies it skipped. The
  journal-and-fail path ran the whole fail ladder for every due proxy
  when the engine was down at `ping`/`reload_config` or died
  mid-batch, and with the shipped `fail_limit = 2` two outage cycles
  quarantined a proxy that had failed no check at all — dropping a
  healthy row out of both T2 selectors and out of `/export/alive` for
  the sidecar's fault. An outage is now a distinct outcome:
  `journal_engine_fault` still writes the `probe_kind='t2'` record
  (the entry that un-sticks the head of the recency queue) and stamps
  `last_t2_failed_at` with a `ready` → `alive` demote, so the
  tunnel-verified tier still does not outlive an outage, but
  `fail_count` and the quarantine ladder stay untouched. The outage
  is charged to the engine instead — `BatchGuard` strikes, the
  exponential backoff, the log line. The boundary is the
  post-failure `/version` ping: a `ServiceUnavailable` the engine
  *answers* is a per-request blip and remains an ordinary charged
  verdict. Guarded by
  `meow_outage_never_quarantines_a_healthy_proxy`.
- Every revival path left the row in no probe lane. `reset_status`,
  `revive_removed` and its country / ASN / no-probe-history variants
  and `revive_quarantine` put the row back to `unknown` but kept
  `last_t2_failed_at` set, and the revival predicates did not require
  a `proxy_source_links` row — so a revived proxy no T1 lane selects
  (`last_t2_failed_at IS NULL`) and no T2 sample offers (`alive` /
  `ready`) would ever look at again. The flag is now cleared with the
  rest of the lifecycle and the link predicate is applied. *Reset
  status* additionally enqueues the row for priority checking, the
  handoff the bulk paths hand their callers.
- *Reset status* reported a proxy that still exists as nonexistent.
  `reset_status` returns one boolean for two different outcomes: a row
  that is gone, and a row that exists but belongs to no probe lane (no
  `proxy_source_links` row left after reconciliation retired it, or a
  scheme no lane checks — `tuic`, `mieru`). Both came back as `false`
  and both were answered with `err.proxy_not_found`, so an operator
  pressing the button on a proxy sitting right there on the screen was
  told it did not exist. The second case is now a rejected action
  rather than a 404: the panel answers with the unchanged
  `#status-badge` fragment (which is what the form's `hx-target`
  expects) and a message saying the status was left as it is because no
  probe can reach the row (`px.reset_unreachable`, both catalogs). A
  genuinely missing row still 404s, and a database error still 500s.
- The probe priority queue accepted rows no lane would ever drain: an
  id with no `proxy_source_links` row and an id under a T2 block.
  `enqueue_checks` now applies the drain's own predicates, so the
  revival paths cannot leave dead weight in the table. Guarded by
  `queue_drain_skips_rows_under_a_t2_block`.
- The admin *Logout* button was a CSRF-able POST. `/admin/logout`
  sat outside the protected nest, so an attacker page that could
  auto-submit a cross-site form signed the operator out at will. The
  route moved inside, where `require_auth` and `csrf_protect` both
  run; the form in `base.html` already ships the `_csrf` field. Guarded
  by `logout_requires_session_and_csrf`.
- The *Import / Export* screen built its serve links against
  `[admin].allowed_hosts` while the export endpoints gate on
  `[server].allowed_hosts`. The two lists could diverge silently: a
  host allowlisted for the panel but not for the public listener
  produced `/export/alive/{token}` links that answer 404 "link not
  found" on every click, and the reverse direction rendered a host
  the export gate had never agreed to serve. `serve_base` validates
  against the list the public listener actually gates on. Guarded by
  `serve_base_validates_against_the_server_host_allowlist`.
- A `Host` header holding userinfo leaked the export token into a
  link. The link-builder stripped the port with its own parser and
  never canonicalized, so `name@evil.com` was emitted verbatim into
  `http://name@evil.com/export/alive/{token}` — the link sends the
  operator, and anyone who clicks it, to an attacker-controlled host
  with the token as the query. It runs the same canonicalizer as the
  gate, even with the empty allowlist the gate itself skips. Guarded
  by `build_serve_link_host_never_emits_userinfo`.
- Config import accepted a pipeline 16× larger than the edit form
  allows. The `PIPELINE_BYTES` cap (65536) was applied by the source
  and profile forms but not by the import validator, so a file could
  plant a pipeline up to the 1 MiB body limit; the stored JSON is
  re-rendered into every edit form and recompiled by the preview.
- A repeated source reference in one profile aborted the import
  halfway. `profile_sources` is keyed by `(profile_id, source_id)`,
  so a hand-edited file naming the same reference twice failed the
  whole composition insert *after* the profile row was committed,
  leaving an empty profile behind a 500. A repeat now collapses to
  its first position. Two *source rows* sharing one reference are a
  new hard error instead: the reference is the join key that binds
  the rows together and the write phase keys new ids by it, so the
  file does not say which row a profile composition means
  (`val.dup_ref` in both catalogs). `/admin/export` never emits
  either shape, so this only ever sees a hand-edited file. Guarded
  by `repeated_source_reference_stores_the_source_once`.
- The *Edit source* form mangled header values containing a bullet.
  The mask restore matched on `value.contains('•')` and looked the
  original up by header name, so a real value the operator typed with
  a bullet in it (`tok•en`) was silently replaced by the stored
  secret, and a secret whose key the operator renamed was dropped and
  the literal mask `abc…••••` was sent upstream. The restore now
  matches on the mask itself, so a renamed key keeps its secret and a
  typed value is a value.
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
  field deduplicated into one row. The fingerprint's
  `SECURITY_PARAMS` list held the URI spellings only, so the Clash
  ones (`servername`, `network`, `ws-path`, `client-fingerprint`,
  `grpc-service-name`, plus the URI-less `ws-headers`, `ws-opts` and
  `reality-opts` blocks, stored verbatim) were invisible to the
  dedup key and the upsert overwrote one node with the other. The
  spellings that do have a URI form are now canonicalized onto it
  (`canonical_key`), so the same node advertised as Clash YAML and as
  a URI still deduplicates together. Guarded by
  `clash_spellings_are_security_relevant`,
  `clash_structured_fields_are_security_relevant` and
  `clash_and_uri_spellings_agree`.
- Fingerprint pre-images could be forged from inside a value. The
  pairs were joined with `&` and `k=v` unescaped, so
  `path=/search` + `host=evil` and the single parameter
  `host=evil&path=/search` hashed identically — attacker-controlled
  feed text choosing which of two nodes a dedup keeps. Keys and
  values are now escaped, `%` included, so escaping is reversible.
  Guarded by `separator_bytes_in_values_cannot_forge_a_pair`.
- URI serialization emitted parameter values verbatim. The Clash and
  sing-box parsers feed the same `Param` list with *decoded* text
  from YAML / JSON scalars, so a value can carry a raw `&` or `#`:
  `&` spawned a bogus extra parameter and `#` swallowed the proxy
  name (everything after the first `#` is the fragment). Only the
  query delimiters, space and the C0 controls are escaped now; `%`
  is deliberately left alone, which is what keeps a value the URI
  parsers stored still percent-encoded byte-exact. Guarded by
  `query_delimiters_in_values_do_not_corrupt_the_line` and
  `already_encoded_values_are_not_double_encoded`.
- SSRF policy missed two IPv6 spellings of a blocked address. Only
  the mapped form (`::ffff:0:0/96`) was vetted, so `[::a9fe:a9fe]` —
  the metadata endpoint in the deprecated IPv4-compatible `::/96` form
  — walked past the policy; the deprecated site-local block
  `fec0::/10` was not blocked at all, despite being routable unicast
  space an internal service can be addressed on. `::/96` is now vetted
  as the embedded IPv4 (`::8.8.8.8` stays public, it is not a blanket
  prefix ban). Guarded by
  `ipv4_compatible_and_site_local_v6_are_blocked`.
- A database path with a percent escape opened the wrong file. The
  path was interpolated into a `sqlite:` URL string and sqlx
  URI-parsed it, so a database file named `pl%2Fain.db` was opened as
  `pl/ain.db` — a file that does not exist, or worse one that does
  and was never chmod'ed to 0600, while the file
  `pre_create_db_file` had just created with mode 0600 sat unused.
  The path now reaches SQLite as a `PathBuf`. Guarded by
  `connect_pool_opens_the_literal_path_without_uri_decoding`.
- `database.max_connections = 0` surfaced as a 30-second startup
  stall. sqlx accepts a zero-sized pool and then fails every
  acquisition with `PoolTimedOut` after its acquire timeout, so a
  typo in `[database]` cost the operator a stall and an error that
  never named the offending key. It is rejected before the pool or
  the file exists. Guarded by `connect_pool_rejects_zero_max_connections`.
- The migration-checksum self-heal hid a possible DDL gap. sqlx
  hashes the whole file and never re-runs an applied migration, so a
  re-stamp cannot tell a comment edit from a DDL edit: the boot
  recovered with a single `warn` and the schema stayed behind the
  files, discoverable only by noticing a missing column much later.
  The affected versions are now logged at `error` level with the
  instruction to ship a new migration file, and recorded under
  `meta.migrations_repaired` so the fact survives the boot log. A
  repair that rewrote nothing re-raises the original mismatch instead
  of claiming a repair that did not happen. The gap itself is *not*
  closed and is not meant to be: the re-stamp is bookkeeping only, so
  an edited already-applied migration is still never applied — only a
  new migration file can bring the schema up to date, which is why
  the repair now shouts instead of helping. Guarded by
  `migrate_records_the_repaired_versions_in_meta`.
- The `repair_migration_checksums` example re-stamped rows that were
  already current, reported them as repairs, and had its own copy of
  the UPDATE — the `success = 1 AND checksum != ?2` guards could
  drift from the copy `migrate()` uses. It now calls
  `db::repair_migration_checksums`, says "already current" for the
  rest, and refuses a database carrying a migration this build does
  not embed (a newer Fumox) instead of leaving `migrate()` to fail
  with `VersionMissing`. Guarded by
  `repair_leaves_migrations_this_build_does_not_embed_alone`.
- With the geo resolver inactive — geo disabled, or the `.mmdb` files
  absent, the default configuration — `drop_entries` zipped the
  entries against an *empty* stamp slice and returned nothing, so a
  source with any `drop` rule was reconciled empty and retired
  wholesale. The lookup is indexed with `geo.get(idx)`: entries past
  the end of the slice count as unstamped and survive, and regex
  rules (which need no stamp) still fire. Guarded by
  `drop_entries_keeps_the_batch_when_the_geo_slice_is_short`.
- A parse or DB failure suppressed re-fetching a source for a whole
  TTL. The raw snapshot was written right after the fetch, before
  anything was parsed or reconciled, but it *is* the freshness marker
  (`Caches::raw_is_fresh`) — so one bad payload stopped every
  non-forced fetch until the TTL elapsed while the scheduler kept
  reporting successful ingests. It is now written only once the
  payload has parsed and reconciled. Guarded by
  `a_parse_failure_leaves_no_fresh_raw_snapshot`.
- A background re-render that started before an ingest committed
  stored its pre-commit rows with a full fresh TTL. The put landed
  after `invalidate_processed_for_source` and the invalidated key
  served the old rows as fresh until the TTL expired — the very
  staleness the invalidation had just ended. Every invalidation now
  bumps a per-key generation, the re-render claims the generation
  before it starts, and `processed_put_revalidated` drops a rendering
  whose generation moved (including one that moved between the check
  and the insert). Guarded by
  `revalidation_started_before_an_ingest_does_not_store_its_rendering`.
- A cached `/sub` and `/src` snapshot outlived an unrecoverable
  upstream error. Stale-while-revalidate spawned the re-render, the
  render returned the documented `http_client` verdict, and the stale
  body kept being served — so "return the upstream status code" never
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
  and then leaves the task running — the install is an atomic
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
  the data section is not a declaration). This is a format and
  identity check, not provenance: the mirrors publish no checksum to
  pin here. Guarded by
  `a_well_formed_file_of_the_wrong_kind_is_refreshed`.
- The unattended GeoLite2 download followed any redirect. The client
  used `Policy::limited(MAX_REDIRECTS)`, which follows off https and
  to any host, so a hijacked release or a mis-typed URL could deliver
  a foreign file into `db_dir`. Redirects are now https-only, capped,
  and restricted to `github.com` and the `*.githubusercontent.com`
  release-asset CDN. Guarded by
  `a_redirect_off_the_mirror_hosts_is_refused`.
- The smoke stand could overwrite the main stack's config. Named
  volumes are project-scoped but the `./config` bind mount is the
  same host directory for every compose project, so the smoke
  stand's admin panel wrote the main stack's `app.toml` through the
  *Edit settings* page. The mount is now parameterized by
  `FUMOX_CONFIG_ACCESS` (`rw` by default, unchanged for the main
  stack) and `scripts/smoke-up.sh` pins it to `ro` — a knob for the
  operator, not for the stand, the isolation guarantee is the point.
- The `latest` image tag was republished from every branch. The
  per-arch and merge jobs attached the raw `MEOW_VERSION` tag
  unconditionally, so a feature-branch build moved the tag everyone
  pulls. It is now attached only from `main` or a `v*` tag — the same
  ref gate `docker.yml` uses, and a `MEOW_VERSION` that names a
  release keeps the previous behaviour.
- A `ready` proxy rendered the `unknown` badge on the proxy detail
  card. The template's badge chain had no `ready` arm, so a
  tunnel-verified proxy fell through to the `else`. Guarded by the
  admin-side assertion added next to the existing `/export/ready/`
  card check.

### Docs

- The guide told operators to drop GeoLite2 `.mmdb` files into
  `./config`; the shipped Compose stack has set
  `FUMOX_GEO__DB_DIR=/shared` since 338929e, and the environment
  outranks the file, so that directory was never scanned. The compose
  header, `config/app.toml` and both guides now point at the
  `meow-shared` volume and say plainly that the manual step is
  optional on a stock stack (the server downloads the databases into
  `/shared` at startup anyway).
- Both guides described `./config` as mounted read-only. The server
  container mounts it read-write precisely so the admin *Edit
  settings* page can save, which is the change this batch
  introduced; the probe is the `:ro` one. `FUMOX_CONFIG_ACCESS` —
  the knob that this change added — was documented in the compose
  file, the changelog and `scripts/smoke-up.sh` but in neither
  guide, so it is now in the `.env` table too.
- The reverse-proxy note told operators to set both
  `[server].allowed_hosts` and `[admin].allowed_hosts` "to the
  hostname the proxy serves". The admin panel builds the links
  behind *Import / Export*, *Sources* and *Profiles* against the
  **public** list, so the shipped loopback quickstart
  (`http://127.0.0.1:8081/admin`) plus a pinned public domain makes
  exactly those three screens answer `500`. The note, both guides'
  configuration tables and both troubleshooting sections now spell
  out the second list to add.
- The *Settings* page was described as rendering "every
  `config/app.toml` knob except the admin token" and "the complete
  effective config". Two keys have no rendered field:
  `[server].export_max_rows` and
  `[geo].startup_download_budget_secs`. Both apply from the file as
  documented; the guides now name them as the exception instead of
  claiming completeness.
- `[server].export_max_rows = 0` was undocumented. It does not mean
  unlimited — the value clamps up to 1 row, so the body serves a
  single node. The config reference (both languages) now says so,
  next to the sibling keys that do give `0` a meaning.
- The export links were documented as "rendered at most once every
  30 s". That holds per request, not per window: the cache has no
  single-flight claim, so a burst landing on the boundary renders
  once per request (the pool caps the concurrency, so the cost is
  latency rather than throughput). Wording corrected in both guides
  and on the code.
- Corrected code comments that asserted more than the code
  delivers: the `check_ip` policy no longer claims to cover "every
  IPv6 form that carries an IPv4 address" (the IPv4-translated
  `::ffff:0:0:0/96` and Teredo `2001:0000::/32` are not matched, and
  were not before either); `render_tier` no longer claims a
  truncated download "documents itself" (the body carries no
  truncation marker, only the `nodes count` header does);
  `pipeline_size` no longer claims to match *both* form modes (the
  raw form measures pretty-printed JSON, so a document in the window
  between the two sizes imports and then fails to save); and the
  real-`.mmdb` test says that its assertion also covers file age, so
  it goes red with "looks stale" once a developer's copies are a
  month old.

### Changed

- `/export/alive/{token}` and `/export/ready/{token}` re-read and
  re-serialized the whole tier on every download. Both now render at
  most once per 30 s (`EXPORT_TTL_SECS`) and are served from the
  shared processed cache in between, like `/sub` and `/src`; the
  entries carry no source id, so per-source invalidation never
  touches them. The exports have no source TTL to inherit and no
  invalidation trigger (the probe owns the tiers), so the window is
  fixed and short, and an expired entry is re-rendered inline rather
  than served stale — a download is a snapshot by definition, and a
  quietly outdated one is worse than a slow request. A tier can
  therefore lag a status change by up to 30 s.
- The two export links are now capped at 50 000 rows, and the cap is
  a setting rather than a constant: `[server].export_max_rows`
  (`FUMOX_SERVER__EXPORT_MAX_ROWS`), defaulting to the number the
  hard-coded `EXPORT_MAX_ROWS` used, so a deployment that never sets
  it changes nothing and a bigger tier can be shipped whole. The
  window above bounds the *rate* of rendering; nothing bounded the
  *size*. Unlike `/sub` and `/src`, which a profile's `limit.count` and
  a source's pipeline cap already bound, these two have no upstream
  cap, so one download on a public cacheable URL meant an unbounded
  `fetch_all`, an unbounded serialization and an unbounded body. The
  cap is a `LIMIT ?` in the backing query (`list_alive` /
  `list_ready`), not a post-read truncate, and it truncates the stable
  id order (lowest ids first), so two renders of the same tier agree.
  The `nodes count` header reports what the body really carries, so a
  truncated download documents itself; the admin badge (`count_alive` /
  `count_ready`) stays uncapped on purpose, so the operator can still
  see that the export is smaller than the tier. The cap is applied
  after the host and token gates: a rejected request cannot tell a
  capped render from a full one, and costs no query. Guarded by
  `export_body_is_capped_in_sql`,
  `cap_is_applied_after_the_host_and_token_gates`,
  `export_cap_follows_the_configured_setting` and
  `server_export_max_rows_is_configurable`.
- Ingest resolves geo facts concurrently instead of one await per
  entry. Every unseen host costs up to `[geo].dns_timeout` (5 s by
  default) when DNS hangs, so a feed of dead hosts cost the sum of
  them. Lookups now overlap under a cap of 32 in flight
  (`GEO_LOOKUP_CONCURRENCY`), keeping the input order the drop rules
  and the reconcile upsert rely on (`buffered`, not
  `buffer_unordered`).

## 2026-09-23 · sha-b72b03f

### Fixed

- *Edit settings* page: the page used to render stale `state.config`
  (frozen at startup) instead of the just-saved file, so every
  checkbox / select / spinbutton reverted to the value the running
  server loaded an hour ago even when the file on disk held the new
  value. The handler now calls `AppConfig::load(path)` on every
  `GET /admin/settings/edit` — `raw_from_state(state)` is replaced
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
  are intentionally left alone — `server_bind` socket address and
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
  alongside server). No runtime-config DB overlay is introduced —
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
  the random sample to come around. Nothing is physically deleted
  — the *Purge removed* button stays the only hard-delete.

### Changed

- T1 checks are now suppressed after a T2 failure: when a proxy's
  most recent T2 attempt fails (bad credentials, meow-rs
  unreachable, the target hit the SSRF policy, or a
  `ServiceUnavailable` from the engine), subsequent T1 checks
  for that proxy are skipped until the next successful T2 — the
  T2 recency selector is the only path back into the T1 rotation.
  A T1 failure (a closed TCP port) does not trigger the
  suppression because it is not a property of the tunnel.
- Pipeline editor's row layout now follows the `target` selector
  live: changing `name` / `host` / `port` / `param` / `asn` in a
  drop or rename row fires an htmx round-trip that swaps the row
  in place, so the regex ↔ ASN switch is immediate and the `asns`
  input appears without an explicit add button. The round-trip
  carries `?render=1` so it never grows the row count — only the
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
  just because its source was removed — the probe keeps being
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
  is unchanged — only the bookkeeping column is rewritten. Any
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
  direct connection) — any caller can otherwise spoof the key.
  This closes a security audit finding.

### Changed

- Probe state machine: when a proxy's most recent T2 attempt
  fails, subsequent T1 checks for that proxy are skipped until
  the next successful T2. The T2 recency selector is the only
  path back into the T1 rotation. A T1 failure (a closed TCP
  port) does not trigger the suppression because it is not a
  property of the tunnel.

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
  feed still carries is revived on the next refresh — the row resets
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
  had), and GeoLite2-Country is retired — the server no longer
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
- Pipeline — ASN filter and output limit: the pipeline now exposes
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
