# Changelog

Fumox ships as rolling image snapshots (`ghcr.io/viktor45/fumox:sha-<hash>`
plus the moving `latest`); this changelog lists what each published batch
of changes contains, newest first. Match the `sha-` tag of the image you
pulled (`docker images`) to the hash in a section header, or just diff
your pull date against the section dates.

The categories follow [Keep a Changelog](https://keepachangelog.com/);
`Docs` covers the user guide and READMEs, `Internal` (dependency bumps,
CI plumbing) is omitted: it never changes the shipped image.

## Unreleased (2026-10-04)

Changes in the working tree, not yet on a published image.

### Added

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
  the sing-box outbound set has no type for either, so emitting one
  would hand the client a block it cannot start.
- meow-rs 0.22.0 gains for T2, with no further Fumox change: the
  `xhttp` transport is a real outbound (0.21.x had no XHTTP at all,
  so such entries could not be checked), and SIP003 Shadowsocks
  plugins (`shadow-tls`, `restls`, `jls`, `kcptun`, `gost-plugin`)
  run in-process instead of spawning a helper binary the `fumox-meow`
  image does not ship, so plugin-backed entries that used to fail T2
  now work. Fumox already rendered both correctly; only the engine
  gained the ability to honour them.
- `[meow].ipv6` (default `false`, matching meow-rs): rendered into
  the generated meow config. 0.22.0 made the key effective
  end-to-end: under `false` AAAA lookups are skipped and the direct
  outbound answers IPv4-only, where 0.21.x resolved both families
  whatever the key said. Only the test-URL host goes through the
  resolver (proxy servers are pinned to a vetted IP literal), so it
  matters solely on IPv6-only egress or an AAAA-only test URL.
- The probe screen shows the meow-rs kernel's live RSS (from
  `GET /memory`, refreshed whenever a T2 batch reloads the engine),
  with the OS memory limit and the share of it when one is set.
- The probe screen grew a *History rotation* panel. The daemon's
  retention loop deleted old `probe_results` and `fetch_log` rows
  with nothing but a per-run info line to show for it, so a probe
  whose retention loop had wedged looked identical to one on
  schedule until the database grew. The loop now stamps a
  `last_rotation` record on every run, including runs that deleted
  nothing, so the age of the stamp itself is the "retention is
  alive" signal. The panel renders it: when the last rotation
  ran, how many rows each journal lost, and how many rows each
  holds now. Before the first run it says the probe daemon owns the
  loop instead of rendering a blank.
- The dashboard's *fetches in 24h* card shows how long ago the
  scheduler's last sweep started (`last sweep: N s ago`), or that
  none has run yet. A scheduler that died or wedged mid-run left
  the card reading `0 / 0` with nothing to separate it from an
  idle deployment, exactly the state an operator cannot see from
  outside. The sweep stamps `server_cycle` at its start, so a hung
  sweep ages the line instead of looking healthy.

### Fixed

- Every page heading collapsed to a character-wide column on a phone.
  `.page-head h1` carried `flex: 1`, which is `flex: 1 1 0%`: a zero
  flex-basis tells the browser the heading occupies no space, so the row
  never wraps, the action buttons take the whole width and the heading is
  left with the few leftover pixels. With the body-level
  `overflow-wrap: anywhere` that rendered "Proxies total: 4638" as
  `Pr / ox / ie / s / to / tal: / 46 / 38`. The basis is `auto` now, so
  the heading claims its text width and the actions wrap below it, while
  `flex-grow` still keeps them right-aligned on a wide screen. All 13
  templates that use `.page-head` were affected, not just the proxies
  list.
- Ordinary words broke mid-word in table columns at phone width. The body
  sets `overflow-wrap: anywhere` so that unbreakable tokens (URLs, SHA
  fingerprints, raw proxy lines) cannot blow a column out, but it also
  split names once a column got tight: "FlareFeed" as "FlareFe / ed" in
  the source and profile name columns, "Endpoint" as "Endpo / int" in
  the key-value tables, and `false` as `fal / se` in a value column
  squeezed to 49px by a sentence-long label beside it. Name links and
  key-value labels now opt out with `overflow-wrap: normal`, and the
  starved value columns carry min-width floors so a long label can no
  longer take the row. URLs, addresses and hashes still break anywhere,
  which is what the global rule is for.
- The key-value tables could not keep a two-column shape below 420px: a
  sentence-long label plus a `nowrap` timestamp need more than the
  ~255px a panel has, and squeezing them both split words and pushed the
  table past the panel edge. Each row now stacks below that width, label
  above value.
- Every `<select>` on the source and profile forms was 39px tall on a
  phone. The 16px font rule (there so iOS does not zoom the page on
  focus) only lifts a select to 39px, under the 44px target. Selects now
  carry `min-height: 44px` at that breakpoint, including the dashboard
  Top-N picker and the pipeline rule-row target selects.
- The settings tabs named the wrong tab to assistive tech. The panes swap
  on the hidden radio's `:checked`, but `aria-selected` was rendered
  server-side and never updated, so after switching to *Probe* the DOM
  still announced *Server* as selected. A small listener now mirrors the
  radio state onto the labels.
- `[hidden]` silently stopped working anywhere it met an author `display`.
  `.badge { display: inline-block }` outranks the user-agent stylesheet,
  so the pipeline rule counters rendered "0" instead of disappearing.
  The attribute is restated once, globally.
- A pipeline rule row wrapped over three ragged lines. The rows sit
  inside a `.field`, so `.field select { width: 100% }` handed the
  target select the full panel width. `.ped-row select` is `width: auto`
  now, and on a phone the remove button keeps its own size instead of
  becoming a full-width row of its own, which was an easy mis-tap on a
  destructive action.
- The dashboard's "new proxies over the last 7 days" chart labelled its
  columns with clipped timestamps. Each bar is a midnight-UTC day bucket,
  but it was rendered through the shared `<time class="ts">` helper, which
  base.html's `localize()` rewrites into a full local timestamp, so every
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
  TCP/TLS verdict, the exact case the flag (migration 0007) exists
  to suppress. Only a T2 success does now, and `ready` is the T2
  success tier.
- A meow-rs outage was charged to the proxies it skipped. The
  journal-and-fail path ran the whole fail ladder for every due proxy
  when the engine was down at `ping`/`reload_config` or died
  mid-batch, and with the shipped `fail_limit = 2` two outage cycles
  quarantined a proxy that had failed no check at all, dropping a
  healthy row out of both T2 selectors and out of `/export/alive` for
  the sidecar's fault. An outage is now a distinct outcome:
  `journal_engine_fault` still writes the `probe_kind='t2'` record
  (the entry that un-sticks the head of the recency queue) and stamps
  `last_t2_failed_at` with a `ready` → `alive` demote, so the
  tunnel-verified tier still does not outlive an outage, but
  `fail_count` and the quarantine ladder stay untouched. The outage
  is charged to the engine instead: `BatchGuard` strikes, the
  exponential backoff, the log line. The boundary is the
  post-failure `/version` ping: a `ServiceUnavailable` the engine
  *answers* is a per-request blip and remains an ordinary charged
  verdict. Guarded by
  `meow_outage_never_quarantines_a_healthy_proxy`.
- Every revival path left the row in no probe lane. `reset_status`,
  `revive_removed` and its country / ASN / no-probe-history variants
  and `revive_quarantine` put the row back to `unknown` but kept
  `last_t2_failed_at` set, and the revival predicates did not require
  a `proxy_source_links` row, so a revived proxy no T1 lane selects
  (`last_t2_failed_at IS NULL`) and no T2 sample offers (`alive` /
  `ready`) would ever look at again. The flag is now cleared with the
  rest of the lifecycle and the link predicate is applied. *Reset
  status* additionally enqueues the row for priority checking, the
  handoff the bulk paths hand their callers.
- *Reset status* reported a proxy that still exists as nonexistent.
  `reset_status` returns one boolean for two different outcomes: a row
  that is gone, and a row that exists but belongs to no probe lane (no
  `proxy_source_links` row left after reconciliation retired it, or a
  scheme no lane checks (`tuic`, `mieru`)). Both came back as `false`
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
- A `Host` header holding userinfo leaked the export token into a
  link. The link-builder stripped the port with its own parser and
  never canonicalized, so `name@evil.com` was emitted verbatim into
  `http://name@evil.com/export/alive/{token}`: the link sends the
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
  `host=evil&path=/search` hashed identically, so attacker-controlled
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
  the mapped form (`::ffff:0:0/96`) was vetted, so `[::a9fe:a9fe]`,
  the metadata endpoint in the deprecated IPv4-compatible `::/96` form,
  walked past the policy; the deprecated site-local block
  `fec0::/10` was not blocked at all, despite being routable unicast
  space an internal service can be addressed on. `::/96` is now vetted
  as the embedded IPv4 (`::8.8.8.8` stays public, it is not a blanket
  prefix ban). Guarded by
  `ipv4_compatible_and_site_local_v6_are_blocked`.
- A database path with a percent escape opened the wrong file. The
  path was interpolated into a `sqlite:` URL string and sqlx
  URI-parsed it, so a database file named `pl%2Fain.db` was opened as
  `pl/ain.db`, a file that does not exist, or worse one that does
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
  an edited already-applied migration is still never applied; only a
  new migration file can bring the schema up to date, which is why
  the repair now shouts instead of helping. Guarded by
  `migrate_records_the_repaired_versions_in_meta`.
- The `repair_migration_checksums` example re-stamped rows that were
  already current, reported them as repairs, and had its own copy of
  the UPDATE, and the `success = 1 AND checksum != ?2` guards could
  drift from the copy `migrate()` uses. It now calls
  `db::repair_migration_checksums`, says "already current" for the
  rest, and refuses a database carrying a migration this build does
  not embed (a newer Fumox) instead of leaving `migrate()` to fail
  with `VersionMissing`. Guarded by
  `repair_leaves_migrations_this_build_does_not_embed_alone`.
- With the geo resolver inactive (geo disabled, or the `.mmdb` files
  absent, the default configuration), `drop_entries` zipped the
  entries against an *empty* stamp slice and returned nothing, so a
  source with any `drop` rule was reconciled empty and retired
  wholesale. The lookup is indexed with `geo.get(idx)`: entries past
  the end of the slice count as unstamped and survive, and regex
  rules (which need no stamp) still fire. Guarded by
  `drop_entries_keeps_the_batch_when_the_geo_slice_is_short`.
- A parse or DB failure suppressed re-fetching a source for a whole
  TTL. The raw snapshot was written right after the fetch, before
  anything was parsed or reconciled, but it *is* the freshness marker
  (`Caches::raw_is_fresh`), so one bad payload stopped every
  non-forced fetch until the TTL elapsed while the scheduler kept
  reporting successful ingests. It is now written only once the
  payload has parsed and reconciled. Guarded by
  `a_parse_failure_leaves_no_fresh_raw_snapshot`.
- A background re-render that started before an ingest committed
  stored its pre-commit rows with a full fresh TTL. The put landed
  after `invalidate_processed_for_source` and the invalidated key
  served the old rows as fresh until the TTL expired, the very
  staleness the invalidation had just ended. Every invalidation now
  bumps a per-key generation, the re-render claims the generation
  before it starts, and `processed_put_revalidated` drops a rendering
  whose generation moved (including one that moved between the check
  and the insert). Guarded by
  `revalidation_started_before_an_ingest_does_not_store_its_rendering`.
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
  tunnel-verified proxy fell through to the `else`. Guarded by the
  admin-side assertion added next to the existing `/export/ready/`
  card check.
- The admin panel's *Create from defaults* button could never work.
  `is_writable` tested writability by opening the path for write,
  which fails with `EISDIR` on a directory, and the handler hands it
  `config/`, the directory, while the same call on the *file* path in
  `admin/mod.rs` takes the missing-file branch and answers true. The
  button's state and its handler disagreed about one question, so an
  operator with no `config/app.toml` got a "not writable" error about
  a directory the process could plainly write to. A directory is now
  answered with the `create_new` probe the missing-file branch
  already used. Guarded by
  `is_writable_returns_true_for_writable_directory`.
- The dedup key ignored TLS certificate pinning, so two nodes
  differing only in the certificate they pin shared one key and the
  second was overwritten by reconcile's `ON CONFLICT`, vanishing
  from the database and from every subscription. `pinSHA256` is now in
  `SECURITY_PARAMS`, and Clash's `fingerprint` is folded onto it so
  the pin counts in either spelling; listing both keys instead would
  have split a node published as Clash YAML from the same node
  published as a URI. Guarded by `cert_pin_is_security_relevant`.
- A vless proxy that arrived from a Clash YAML source was served to
  sing-box clients as plaintext. mihomo spells the toggle `tls: true`
  and the SNI `servername`; the sing-box writer's TLS decision read
  only `security`/`sni`, matched neither, and emitted no `tls` object
  at all, while the same proxy as a `vless://` URI encoded
  correctly and the Clash writer kept both spellings. The decision now
  reads an explicit `tls` toggle first and returns from it, so a
  `tls: false` carrying a stray `servername` stays plaintext too.
  Guarded by `vless_from_clash_input_keeps_tls_and_servername` and
  `clash_tls_false_outranks_a_stray_servername`.
- One malformed endpoint discarded every good one in an Xray
  outbound. The `vnext` and `servers` builders returned `Err` from
  inside their per-element loop, and the caller turned that into a
  single `invalid` count without keeping the entries already built,
  so a two-endpoint vless whose first user was valid and second was
  not, yielded zero entries. A bad element now costs only itself, and
  `Err` is raised once after the loop, only when nothing at all was
  built, so a fully malformed outbound is still counted `invalid`.
  Guarded by `an_unusable_vnext_element_keeps_the_earlier_endpoints`
  and `a_malformed_xray_server_element_keeps_the_earlier_endpoints`.
- A Clash-sourced vless/vmess node was health-checked as plain TCP.
  `t1::check_kind` decided TCP-vs-TLS from `security` alone, but the
  Clash parser never emits that key (it stores `tls`/`servername`),
  so a node with broken TLS was marked `alive` and served, while the
  same node from a URI spelling was correctly walked to quarantine.
  The verdict depended on which feed the node arrived in. The
  decision now accepts both producer vocabularies, case-insensitively,
  mirroring the Clash writer that already understood both. Guarded by
  `clash_and_uri_spellings_agree_on_tls`.
- An export→import round trip could silently strip a profile's slug.
  `apply_import` seeded one `taken_slugs` set from both the sources
  and the profiles tables and handed it to every object, but the two
  slugs live in separate namespaces (independent `UNIQUE` columns on
  two different tables, resolved per table). A source always claimed a
  shared slug first, so the profile was written without one and its
  `/sub/{slug}` URL became `/sub/{id}`, breaking every client already
  pointed at it, with only a warning in the import summary. The claim
  set is now per table. A comment in the same function naming
  `/sub/{slug}` for both sides was wrong about the routes too, and is
  corrected. Guarded by `a_source_and_a_profile_may_hold_the_same_slug`.
- Opening a proxy card could wipe the country ingest had resolved.
  The geo resolver needs only one backend to hit, so a host in the
  Cloudflare block returned an ASN with no country, and both
  `update_geo_full`, which bound all three columns unconditionally,
  unlike every other writer in the tree, and the `ProxyRow` handed
  to the template, overwrote the stored facts with NULL. The card
  showed `-` for a row the database still knew. The columns are now
  `COALESCE`d like the reconcile upsert, and the call site merges the
  stamp instead of replacing the row's fields with it. Guarded by
  `update_geo_full_keeps_stored_facts_a_partial_stamp_cannot_replace`
  and `a_partial_stamp_does_not_clear_the_rendered_geo_fields`.
- The probe ladder editor accepted values the server refuses to boot
  from. `i64_list_field` checked only that each line parsed as an
  integer and that the list was non-empty, with no step cap and no
  range check, while the canonical loader enforces at most 16 steps
  each within a month and both binaries abort on a bad file. The
  panel reported success and the next restart of `fumox-server` and
  `fumox-probe` died on the file it had just written. The bounds are
  now the loader's, and the test beside it pins that an accepted
  ladder round trips through `config::load_config` while a rejected
  one never reaches the file. Guarded by
  `recheck_ladder_bounds_match_the_canonical_loader`.
- A source's own `limit.count` capped the entire merged profile. When
  a profile declared no explicit sort, the sort winner was a
  *source's* compiled pipeline, and its `finalize` truncated the
  merged cross-source vector, so a two-source profile whose first
  source set `limit: {count: 2}` served 2 nodes instead of 5,
  contradicting the comment above the code. Only a profile-level cap
  now truncates the merged list. Behaviour change for operators: a
  multi-source profile whose source set `limit.count` will now serve
  more proxies than before, because each source's top is served up to
  that count. Both guides' `limit` row now says so. Guarded by
  `source_limit_does_not_truncate_the_other_sources`.
- Two overlapping settings submissions silently lost one change while
  both reported success. The editor's load → mutate → save ran
  unsynchronised (the temp-file counter in `save` covered only the
  rename half of the race), and the write button carries no
  double-submit guard, so a double-click issued two POSTs and the
  second rename published a document snapshotted before the first
  landed. `EditableConfig` now holds a lock across the whole cycle,
  released on drop. That lock is not reentrant, and the plain loader
  must never take it: the admin handler re-reads through
  `config::load_config` while the editor handle is alive, so a loader
  that took it would hang the request and the panel would stop saving.
  Both rules are pinned by a test. Guarded by
  `overlapping_edits_do_not_lose_the_first_change`.
- The same vmess node advertised as Clash YAML and as a `vmess://`
  link got two fingerprints, two rows and two entries in every
  subscription. `canonical_key` folds Clash's `network` onto `type`
  to stop exactly that, but vmess's other spellings call the same
  field `net`, a separate entry in `SECURITY_PARAMS`; the fold is
  per-scheme now, onto `net` for vmess and `type` for the rest. The
  alias test beside it only ever covered vless, whose URI spelling
  really is `type`. Guarded by
  `clash_and_uri_spellings_agree_for_vmess`.
- A Clash socks5 entry carrying only `username` was stored as
  `onlyuser` rather than `onlyuser:`, and both output writers guard
  on `split_once(':')`, so the outbound carried no username and no
  password and the authentication was lost silently. Credentials are
  now joined positionally, with an absent field keeping its slot. The
  leading slot is per-spec: socks5 keeps it, because both writers
  treat an empty first part as absent, while shadowsocks does not,
  because its writers default the method only on a colon-less
  credential. Guarded by
  `a_password_only_socks5_keeps_its_credential`.
- Bulk revival enqueued the oldest proxies rather than the newest.
  `enqueue_checks` claims in its comment that the newest ids win the
  limit, but it walked the caller's id list in chunks oldest-first, so
  the per-chunk `ORDER BY p.id DESC LIMIT ?` spent the whole limit on
  the first 500 ids and everything above that was never considered. It
  now chunks a descending-sorted, deduped copy, so chunking and
  newest-wins can agree at all. Guarded by
  `enqueue_prefers_the_newest_ids_across_chunk_boundaries`.
- A permanently dead source was re-fetched every 30 seconds for the
  life of the deployment. A failed fetch writes no timestamp (the
  column is documented as *last successful fetch* and a test pins
  that), and the scheduler read a NULL as due-now, with no failure
  backoff anywhere, so a 401, a dead DNS name or a body that no longer
  parses got the same cadence as a healthy source. The sweep now
  applies an exponential backoff read from the fetch journal,
  doubling from 60 s to a 3600 s cap, and consults the journal only
  for sources whose recorded error class says the last attempt
  failed, so a healthy source pays no extra query. Guarded by
  `a_dead_source_is_not_refetched_on_every_sweep`.
- The probe could lose the only address family a proxy was reachable
  on. `vet_probe_host_addrs` truncated the vetted list to four before
  the caller picked a family, and `pick_vetted` falls back to the
  first address, so a CDN hostname publishing four or more AAAA
  records had every working A record truncated away, and the probe
  dialled, or pinned meow-rs to, an address it could not use. The cap
  now reserves a slot for the first address of each family present.
  The list is still at most four long, so the dial budget the cap
  exists to bound is unchanged, and the fetcher path, which filters
  by family before vetting, was never affected. Guarded by
  `vetted_address_cap_keeps_both_families`.
- Every T2 batch charged healthy TLS proxies a tunnel failure. The
  pin substitutes the vetted IP into `server`, and `sni`/`servername`
  is emitted only when the entry already carries it (the normal
  shape of a `trojan://pass@example.com:443#n` line), so mihomo had
  no name to verify the certificate against and fell back to the IP
  literal, while the mapping deliberately does not force
  `skip-cert-verify`. Pinning now carries the entry's own server
  name, or failing that the pre-pin hostname, under the key the writer
  reads for that scheme; an entry already hosted on an IP literal is
  left alone. Guarded by
  `pinning_keeps_a_tls_server_name_for_a_bare_entry`.
- One probe cycle could charge a single dead proxy two failures. The
  queued lane and the random lane run back to back and their
  selectors overlapped completely (claiming a row only deletes the
  queue row, it does not change the proxy's status), so the same proxy
  could reach the ladder's limit in one cycle instead of across
  three, and one that failed the queue lane and then passed the
  random lane had its counter reset in the same breath. The queue lane
  now hands its claimed ids to the random lane, which filters them
  out of the draw; the overlap is closed in the probe rather than in
  the core selectors it reads through. Guarded by
  `queued_and_random_t1_lanes_do_not_double_charge_a_cycle`.
- A client could pick its own rate-limit key, including on the admin
  login brute-force cap, behind a `Forwarded`-emitting reverse proxy
  that leaves `X-Forwarded-For` alone. `client_key` tried XFF first
  and only fell through to `Forwarded` when XFF yielded nothing, and
  `walk_xff` cannot tell a client-authored entry from a
  proxy-appended one, so a forged header short-circuited the one the
  proxy actually signed. An exhausted all-trusted chain in one header
  is now evidence that the peer wrote that header, and the client
  named by the other wins. The trade-off is documented rather than
  hidden: when two proxies each write one header and they disagree,
  requests share the per-deployment bucket (5 requests per 60 s by
  default), the cost of not being able to tell which header the
  deployment's proxy writes. Guarded by
  `a_two_proxy_chain_writing_one_header_each_keeps_the_client_key`.
- A profile with an access token could never be saved again. The
  edit form re-renders the masked placeholder `abc…••••`, which the
  token charset check rejects, and the error was raised before the
  "unchanged mask keeps the stored secret" fixup, so the whole save
  aborted with 422 and the profile's name, slug, output format,
  country allowlist and source composition were all frozen. The mask
  is now matched exactly, the rule the sources page already used for
  header secrets, so a token the operator actually typed is validated
  like any other value. Guarded by
  `a_typed_bullet_is_not_mistaken_for_the_mask`.
- Three admin screens answered `500` for a host the panel had
  already admitted. The router gates on `[admin].allowed_hosts` but
  builds the serve links against the separate `[server].allowed_hosts`,
  and all three callers turned that rejection into an internal error,
  so on a deployment that pins both lists, which is the reason both
  exist, *Import / Export*, *Sources* and *Profiles* were
  unreachable. The links are now built against the host that reached
  the panel. Note that the link then carries the panel's own host, so
  on a split allowlist it still 404s when the public listener is
  clicked; that trade-off is documented in place of the 500.
  Guarded by `serve_link_pages_render_for_an_admin_allowlisted_host`.
- The copyable endpoint link on a token-protected profile's page
  answered 403 when clicked: the serve endpoint's token gate rejects
  a URL without `?token=`, and the link was built without one. The
  link now carries the token in its query string. Deliberate despite
  the masked token row beside it: the mask keeps the stored secret
  from casual display, while the link is the artifact the operator
  hands to clients and cannot work without the secret. The token
  charset cap (alphanumeric plus `-_.~`) keeps it URL-safe without
  escaping.
- A cold render could be cached as fresh for a full source TTL after
  an ingest. The generation counter exists so an invalidation drops a
  rendering computed from pre-ingest rows, but the cold path stored
  unconditionally and `invalidate_processed_for_source` could only
  bump keys it found by iterating existing entries, so a key with no
  entry yet, which is exactly an in-flight cold render, was invisible
  to it. The cold path now claims the key before rendering and stores
  through the same guarded put the stale path already used. The bump
  itself was a read-modify-write: two invalidations of the same key
  (two sources feeding one profile, ingesting at once) could both
  read G and write G+1, losing a bump and letting a render claimed
  in between store behind the second one; bumps are serialized now.
  Guarded by
  `inline_render_started_before_an_ingest_does_not_store_its_rendering`
  and `concurrent_invalidations_do_not_lose_a_generation`.
- `X-Fumox-Warning: all-proxies-quarantined` was sent for profiles
  where nothing was quarantined. The predicate counted `ready` as a
  hidden tier, contradicting the comment three lines above it, and
  read the pre-filter population, so a `filter.protocols` (or ASN,
  or drop-rule) filter that removed every ready proxy produced a
  health warning. Only `quarantine` and `removed` count now: a
  filter is a configuration fact, not a health one. Guarded by
  `a_filter_that_hides_every_ready_proxy_is_not_a_quarantine_warning`.
- A proxy the probe had already quarantined or removed kept being
  served. `/sub` and `/src` stamp their cache entry with the source
  fetch TTL, but the probe is a separate process that moves rows
  between tiers and nothing in the server reacts to it, so the only
  ingest-time drop is gated on a fetch having changed something. The
  window was therefore the feed-download interval: an hour by
  default, up to 24 at the admin form's maximum. Rendered output is
  now capped at 30 s of freshness, the same bound `alive_export`
  already used for exactly this reason, and stale entries are still
  served immediately while being re-rendered in the background.
  Guarded by `rendered_output_is_not_fresh_for_a_whole_source_ttl`.
- A pipe in a host or credential could move a fingerprint field
  boundary. The pre-image joins its fields with a literal `|` and the
  escaping rewrote only `%`, `&` and `=`, so two malformed feed lines
  that both contained one collapsed into a single row and a node
  vanished from the subscription, while the comment beside it
  claimed the escaping made separators unforgeable. The separator is
  escaped now, so the pre-image is injective in it, and the over-claim
  is narrowed to what the code does: the scheme and the port are
  written unescaped, one being a fixed enum literal and the other a
  number by type. Guarded by
  `pipe_in_a_field_cannot_shift_the_pre_image_boundary`.
- The dashboard's "unprobeable (tuic/mieru)" sub-line could exceed
  the "Never checked yet" headline it sits under. The sub-line
  counted removed rows and the headline excluded them, so after
  *Remove unprobeable unknown* the panel read 0 with 300 beneath it.
  The sub-line now carries the headline's own population filter.
  Guarded by
  `unprobeable_count_excludes_rows_the_cleanup_button_retired`.
- At `[probe].sample_size = 0` the probe page's backlog banner
  reported the queue as a multiple of a sample that does not exist:
  the two sample-proportional triggers divided the quarantine depth
  by a `.max(1)` stand-in while the snapshot underneath printed the
  real `0`, so a 25-row queue read "25× the per-cycle sample" above a
  "sample 0/cycle". Both triggers now stay off at zero: there is no
  sample to measure against, and the `all_idle` line already reports
  the state with the numbers an operator can act on. Guarded by
  `sample_size_zero_reports_idleness_not_a_ratio_over_zero`.
- The banner's `cycle_interval_secs` recommendation could ask for a
  cycle faster than the daemon's own heartbeat floor. The period is
  `ceil(target / cycles)`, so a queue long enough to need many cycles
  and a tight `connect_timeout_secs + tls_timeout_secs` land on
  single-digit seconds: with `sample_size = 100`, `concurrency = 64`,
  1 s timeouts and a 60 s cycle, a 10 000-row queue produced
  `cycle_interval_secs = 2`. A cycle is several `SELECT`s across the
  pool plus its writes, and the daemon already puts a `.max(5)` floor
  on its beat period, so the recommendation now stays silent below
  that instead of printing a value an operator should not set. The
  knob itself is unaffected: a period the model can certify at or
  above the floor still prints. Both guides' recommendation list
  says so. Guarded by
  `period_rec_never_lands_below_the_beating_floor`, and the whole
  value space is swept by `recs_stay_inside_the_range_the_form_accepts`
  so no knob can print a value outside the settings form's own range.
- Drop rules corrupted the geo pairing of everything after the
  first dropped entry. The ingest path handed `reconcile_source` the
  entry list after a source's pipeline drop rules had shortened it,
  together with the geo stamps resolved for the list *before* the
  drop. The two are paired by index, so every proxy past the first
  dropped entry was stored carrying a neighbouring host's country
  and ASN, so one IP could end up stamped with several autonomous
  systems, and the admin ASN cleanup buttons then acted on that
  noise. The drop pass now returns the stamps that belong to exactly
  the surviving entries.
  `scripts/repair-geo-stamps.sh` rewrites the already-corrupted
  rows: it clears the three `geo_*` columns (after a backup) and
  lets the startup backfill re-resolve every row from its own host,
  verified on a copy of a production database, 23249 rows
  re-stamped, 1162784 stamped rows re-checked against the resolver,
  0 wrong, and the number of hosts carrying more than one ASN went
  2510 → 0.
- The probe card's kernel RSS line reached the reader as literal
  HTML source: it was assembled with a `<time>` element inside and
  rendered through an escaping handle, so the card showed
  `<time class="ts" …>` text wrapped over four lines. The line is
  plain text now (`RSS 24.5 MiB · 1.2% / 2.0 GiB`) and the timestamp
  is rendered by the template as a proper `time` element beside it.
- `scripts/revive-xhttp-proxies.sh`: a one-shot repair for the
  vless+xhttp rows the pre-0.22 engine stranded in `removed`: the
  transport did not exist there, every T2 check failed, the fail
  ladder ran its course, and only the terminal status is wrong
  (Fumox rendered the transport correctly all along). Linked rows
  are revived and enqueued for priority checking;
  `--include-unlinked` also adopts link-less rows into a source,
  because every probe lane selects on the `proxy_source_links` row,
  a revived row without a link sits in no lane at all and stays dead
  whatever its feed does later. `--adopt-source` names the adoptive
  source explicitly, `--no-adopt` revives without linking.
  `--restore` undoes a run safely: it verifies the backup before
  touching anything, refuses while anything has the database open,
  snapshots what it is about to overwrite, deletes the write-ahead
  log that would otherwise be replayed on top of the restored file,
  and integrity-checks the result. The bare `cp` the script used to
  suggest fails either loudly (`database disk image is malformed`) or,
  worse, quietly: the log fits, the copy "succeeds",
  `PRAGMA integrity_check` prints `ok`, and the database holds the
  pre-restore data after all.
- The admin event stream paid for events nobody consumed. It ran
  `count_by_status` when a connection opened and, every 30 s
  thereafter, the counts plus two `meta` reads, emitting
  `probe.stats` and `heartbeat` events; no
  template ever listened to either (the panel reacts to `fetch.*`
  only, re-broadcast as `fumox:refresh`), so every admin tab held a
  query loop whose output was dropped on arrival. The tick is gone:
  the stream forwards bus events, keeps its keep-alive and idle
  hard cap, a lagged consumer logs what it lost instead of assuming
  a periodic tick repairs state (nothing did), and the layout shows
  a connection chip instead: hidden until the `EventSource` opens,
  flipping to a *stale* state while the browser reconnects,
  announced via `role=status`. Guarded by
  `sse_stream_forwards_bus_events`.
- The probe screen judged the daemon against the *server's* config.
  `probe_heartbeat` carried only `{ts, pid, version}`, so the panel
  thresholded staleness with its own `[probe].heartbeat_interval_secs`,
  and the meow card rendered green for a `meow_last_ok` contact from
  any point in the past. Server and probe may read different config
  files (or env overlays), and a probe on a slower schedule than the
  server's copy turned its still-alive badge stale. The heartbeat now
  reports the daemon's effective beat and cycle periods, the panel
  prefers the reported values (falling back to its own config, floor
  5 s), the heartbeat verdict keeps its 3× rule, and the meow contact
  goes stale after three daemon cycles. Guarded by
  `heartbeat_threshold_mirrors_the_daemon_beat_period`,
  `meow_stale_threshold_is_three_cycles` and
  `heartbeat_payload_reports_the_effective_beat_and_cycle_periods`.
- Neither daemon said which database it opened. The resolved
  `[database].path` is otherwise visible only on *Settings*, so a
  stream of scratch instances, containers and volume mounts made
  "which file am I on" a guess, and pointing the probe at a
  different file than the server surfaced only when the journals
  diverged. Both processes now log `database configured` at startup
  with the resolved path and the count of `FUMOX_*` overrides; the
  count, not the names or values, so a surprise override is
  attributable without logging secrets.
- A panic inside one scheduler sweep silently stopped every later
  one. The detached sweep task reset the overlap flag after the
  `await`, so an unwind left `sweeping` stuck at `true` and the loop
  skipped every future tick: no fetches, no error, only a dashboard
  staying quiet. The flag now travels in a drop guard that resets it
  on the normal path and on unwind alike. A panicked ingest task
  names its source instead of vanishing into `is_some()`, and
  shutdown got its missing half: `main` drops the refresh channel
  (closing it is the scheduler's shutdown signal), awaits the loop
  for at most 5 s so a wedged sweep cannot hold the process past its
  budget, and names the sources still in flight as abandoned
  mid-request, so a gap in `fetch_log` or an upstream's request log
  has an explanation in ours. Guarded by
  `sweep_guard_resets_the_flag_on_unwind`.
- `/healthz` answered `ok` with a dead database. The route returned
  a static string, so an instance whose only shared dependency was
  gone kept telling the orchestrator it was fine while every
  subscription 500'd. It now runs `SELECT 1` and answers
  `503 database unavailable` when the pool stops answering, and it
  *stays* after the public rate-limit layer on purpose: an exhausted
  window must not make the liveness probe answer 429 and restart a
  healthy instance. Both properties are pinned by tests that
  exercise the layering without binding listeners:
  `healthz_stays_outside_the_public_rate_limit`,
  `healthz_goes_red_when_the_database_is_closed`.
- A scanner sending random `Host` headers to the export links
  logged one warning per request. The gate runs before the token
  check, so the warn is the only signal a misconfigured allowlist
  leaves, but it was also a line a sweep of random hosts could
  amplify indefinitely. Rejections now warn once per host per hour
  (repeats drop to debug) and the registry is capped at 1024
  distinct hosts, aged out by the same window, so an
  unauthenticated flood can neither mirror itself into the log nor
  pin memory. Guarded by
  `host_reject_warns_once_per_host_per_window`,
  `host_reject_log_is_bounded_under_a_flood`.
- A burst of requests on a cold subscription key rendered it once
  per request. Each caller ran the full render (database reads plus
  serialization) and all but one dropped the result, and the export
  links' 30 s window had the same hole: every request landing on an
  expired entry re-rendered the tier. Both paths now go through the
  cache's inline-render claim: the first request renders, the rest
  wake when its claim ends and serve the stored entry, claiming a
  render only when the leader stored none (it failed, or an
  invalidation superseded its put). The exports still never serve a
  stale body, not even to a waiter. Guarded by
  `concurrent_cold_requests_share_one_render`.
- The raw source cache stored whole fetched payloads nothing read.
  Only `fetched_at` was ever consulted (`raw_is_fresh` checked the
  age and nothing wanted the snapshot back), so the last payload of
  every source sat in memory as dead weight; the layer now stores
  the freshness marker alone. Rendered bodies are `Bytes` instead
  of `Vec<u8>`, so concurrent responses of one cached rendering
  share an allocation instead of copying the whole body per
  request.
- A settings save could report success for a setting that was never
  written. `EditableConfig::set` fails when the slot on disk holds a
  non-table value (say `server = 42` where the editor needs
  `[server]` to dive into), and every call site discarded the
  result: the save wrote the untouched document back and the
  operator got a green toast. The failure now surfaces as a
  per-field error, and unrelated edits of the same save still
  apply. Guarded by
  `apply_all_surfaces_unsettable_slot_instead_of_swallowing_it`.
- A base64 subscription wrapped at 76 columns parsed as zero
  entries. Interior whitespace is not base64, broke the
  length-modulo check and made the payload fall back to being read
  as plain text, silently yielding nothing, while real producers
  do wrap (email-style line breaks, stray blank lines), so a whole
  feed could count as empty. The decoder strips whitespace before
  decoding, under auto-detection and a pinned `base64` encoding
  alike. Guarded by `line_wrapped_base64_payload_decodes`.
- A vmess line could serialize with a host, port, name or
  credential different from the stored entry. The JSON writer lays
  the structured fields down first and then inserted every
  pass-through parameter verbatim, so a stray `add` / `port` /
  `ps` / `id` parameter (Clash passes unknown fields through; a
  vmess JSON can carry `PS` next to `ps`) overwrote them in the
  emitted object. The reserved field names are skipped like `v`
  already was, case-insensitively. Guarded by
  `consumed_fields_win_over_colliding_params`.
- Clash-sourced entries serialized onto the URI list with mihomo
  field names. An entry that never had a source line (Clash YAML,
  sing-box JSON) carries mihomo spellings (`network`, `servername`,
  `client-fingerprint`, multi-line `ws-opts` YAML blocks) that a
  URI client either ignores (`network` selects no transport,
  `tls=true` enables no TLS) or cannot parse at all, so exporting a
  Clash-fed source through the URI serializer produced lines that
  did not mean what the entry said. Entries without a source line
  now pass through a translation onto the canonical URI vocabulary
  first: `servername`→`sni`, `network`→`net` (vmess) / `type`,
  `ws-path`→`path`, `client-fingerprint`→`fp`, the structured
  blocks (`ws-opts`, `reality-opts`, `grpc-opts`, `h2-opts`,
  `http-opts`, `obfs-opts`) flattened onto their URI parameters,
  `tls` / `skip-cert-verify` booleans mapped onto the spellings each
  scheme's clients read, and the first occurrence winning a
  collision. REALITY initially escaped that treatment: mihomo writes
  it as `tls: true` + `reality-opts`, so the flattened `pbk`/`sid`
  sat next to `security=tls` (or no `security` at all) and the
  client dropped the REALITY keys. For vless and trojan the
  `security` key is forced to `reality` whenever a public key is
  present, however `tls` was spelled.
  URI-sourced entries keep their stored bytes untouched;
  the translation is output-only. Guarded by
  `clash_vless_item_serializes_onto_the_uri_vocabulary`,
  `clash_vless_reality_item_serializes_with_security_reality` and the
  sibling `clash_*` serialization tests.
- The certificate-verification toggles had a different spelling list
  per consumer. `formats::is_insecure` (behind the sing-box and
  Clash writers) recognized three aliases, and its comment claimed
  the underscore `allow_insecure`, the spelling sing-box and tuic
  links actually use, as "never arrives from parsed feeds", so those
  writers emitted no `insecure` flag for a node that requested one
  and the client then verified certificates the server never
  presented; the fingerprint normalization recognized the same
  three, so the same server advertised once with `allow_insecure`
  and once with `skip-cert-verify` deduplicated as two rows; and
  the pipeline's forbid-insecure filter carried its own fourth copy
  of the list. One list (`models::INSECURE_ALIASES`) and one
  truthiness rule now back all three. One-time churn to expect:
  `allow_insecure`-spelled nodes fingerprint differently than
  before, so the first ingest after upgrading re-inserts them as
  new rows and the old rows retire through the ordinary reconcile
  pass.
- Geo problems were invisible exactly where they mattered. A geo
  directory with no usable database, or one missing a single kind,
  produced one vague warn at best while rows silently stayed
  unenriched, and the startup backfill summary reported only the
  rows that happened to resolve, so "0 updated" read the same
  whether the pool was fully stamped or the resolver could answer
  nothing. Startup now names the files that opened (one info line),
  each missing kind gets its own warn naming the file and the
  directory, and the backfill summary carries the `remaining` count
  of rows with every geo column NULL, retried on the next start,
  so a broken directory is visible instead of indistinguishable
  from a healthy run.
- Probe lanes vetted candidate hosts one DNS lookup at a time,
  ahead of every real verdict. Each lookup is bounded by
  `[geo].dns_timeout` (5 s by default) and the lanes ran them
  serially in their select loops before spawning any check, so a
  batch full of dead names queued one timeout per candidate while
  the check semaphore sat idle. Vetting is now concurrent under the
  same `probe.concurrency` budget and order-preserving, in the T1
  sample, the quarantine recheck and the T2 lanes alike; a closed
  lane or a panicked vetting task refuses that target so the row
  stays on the ordinary fail ladder. Guarded by
  `vet_hosts_preserves_order_and_policy`.
- The meow config file's 0600 mode was only applied at creation.
  `create(true).mode(0o600)` leaves a pre-existing file's mode
  alone, so a `meow.yaml` from an older binary, a hand-copied
  sample or a restored backup kept whatever permissions it had
  while the daemon rewrote it in place with every proxy credential
  in plain text. The mode is re-asserted with an `fchmod` on the
  open file descriptor, after the open has resolved the path, so
  no second path resolution can be swapped in between. Guarded by
  `meow_config_permissions_are_reasserted_on_an_existing_file`.
- T2 outage cycles read as healthy batches. The batch folded
  every row into one `t2_checked` counter, including rows an
  engine-wide outage kept away from meow-rs (ping/reload failure,
  the mid-batch abort guard) and rows `clash::generate` could not
  serialize, exactly the situation the counter is watched for. The
  cycle log now separates them: `t2_checked` counts only rows that
  got a real verdict, `t2_aborted` the outage casualties and
  `t2_skipped` the unserializable ones. Guarded by
  `t2_outage_counters_report_aborted_not_checked`,
  `t2_live_engine_counters_count_real_checks`.
- A failed probe journal write logged at warn and vanished into
  the noise. The write failure means the history row for a verdict
  that *did* land is gone for good (the lifecycle transition
  succeeds regardless), and a burst of them is the only symptom
  when the database is locked or unwritable. The level is error
  now.
- Ingesting a large feed held the WAL write lock past the probe's
  patience. The reconcile transaction ran two statements per entry
  (upsert, then link stamp), so a refresh of tens of thousands of
  entries outlived the probe daemon's `busy_timeout` and its
  journals were dropped. The upsert is one multi-row
  `INSERT .. ON CONFLICT .. RETURNING` per 250 entries and the
  link sweep one per 500 (3 binds a row), keeping the lock span
  short while the transaction still makes the link sweep sound;
  duplicate fingerprints inside a batch collapse onto one id as
  the per-row upserts did.
- Toasts for the plain-browser path did not exist. HTMX callers
  got `HX-Trigger` toasts, but a browser that posted a form without
  HTMX got a bare redirect with the message dropped, so on the
  shared pages (rotate the export token, purge removed) the action
  left no visible confirmation. Redirects now carry `flash` /
  `flash_level` query parameters that the layout turns into a toast
  and strips from the URL immediately, so a refresh or a copied URL
  does not replay it. Appended with `&` when the target already
  carries a query. The import form echoes the submitted payload
  back on a 422 so a fix-and-retry does not start from an empty
  textarea, token rotation confirms through the same toast
  mechanism, the purge dialog shows how many `removed` rows it is
  about to delete (unfiltered, the count it acts on), and the empty
  proxies list offers a *clear filters* link when a filter is what
  hid the rows. Guarded by `flash_redirect_merges_into_an_existing_query`.
- Accessibility of the admin's live pieces. The toggle swaps on
  sources and profiles replaced the badge and button without the
  `aria-live` / `aria-atomic` attributes and `aria-pressed` state
  the initial render carries, silently ending the announcements a
  screen reader had; keyboard focus fell to `<body>` after every
  toggle because the button that was activated is re-created, so
  focus is now restored onto the fresh button, only when it was
  not moved elsewhere in the meantime. The schema and country stat
  tables' colour-coded badges had `title` but no accessible name
  and their dot colours were unexplained: a legend and per-badge
  `aria-label`s ("alive: 12") now name both. The dialogs on
  *Proxies*, *Sources* and *Profiles* gained `aria-labelledby`
  pointing at their headings.
- Placeholder cells rendered a bare comma. `fmt_opt_ts_element(None)`
  and the proxies list's T1/T2 coverage column both returned `,`
  where they meant "no value", so the timestamp tables showed an
  orphan comma under "last seen" and a row with neither check got a
  `,` in the coverage cell. Both use the en dash the rest of the
  tables use.

### Docs

- The settings form advertised a range it never enforced. The four
  rate-limit inputs carried `min="1" max="1000000"`, but the only thing
  that ever checked them was the browser's own number validation, so a
  POST that skipped the browser wrote `0/min` and left every public
  route behind a zero budget. The bounds are enforced server-side now,
  and three of the four fields (`admin.rate_limit`,
  `admin.login_rate_limit`, `server.auth_fail_rate_limit`) additionally
  rendered no error line at all, so the message had nowhere to appear;
  they have one, for the number and the unit.
- Every bounded setting now shows its range under the input, taken
  from the same table the save handler enforces, so the number an
  operator reads before typing and the number in the rejection after
  saving cannot be different values. The recheck ladder, which is a
  list rather than a number, states its own bound (up to 16 steps,
  each 1..=30 days) next to its existing hint.
- The accepted range of a setting now lives in one place,
  `config::bounds`, instead of three: literal arguments at the save
  site, literal `min`/`max` attributes in the template, and prose in
  `config/app.toml`. The form and the validator read the same rows, the
  quarantine ladder's 16-step and 30-day limits are now shared with the
  config deserializer that enforces them at load, and a test fails if a
  number input appears with no row, if a row stops being rendered, or
  if the template grows a literal bound again.
- The number and unit halves of a rate limit sat on two lines with the
  unit select spanning the whole panel: the `.field` rule gives every
  input `width: 100%`, and two of those inside a wrapping flex row each
  claim a line. They are one control and now sit on one line, going back
  to a full-width stack on phones where a 120px number would leave the
  unit too narrow to read.
- The i18n key scanner matched `t("…")` anywhere in a template,
  including the tail of a helper whose name ended in `t`, so
  `self.range_text("probe.sample_size")` was read as a catalog lookup
  for the key `probe.sample_size`. The pattern is word-bounded now;
  it was a false positive waiting for any helper to grow a `t`.

- `config/app.toml` documented what each key *does* but never what
  values it accepts, and the accepted range is not discoverable from
  the file: the bounds live in the admin form's `min`/`max`
  attributes, so a hand-edited config had no way to learn that
  `probe.recheck_delays_secs` fails to load past 16 steps or 30 days
  per step, that `[server].export_max_rows = 0` serves one row rather
  than everything, or that the daemon raises a sub-second heartbeat
  period to 5 s. Every key now opens its comment block with the range
  it is actually held to, and the keys the form does not edit say so
  instead of implying a bound they do not have. The two keys whose
  prose admitted no range (the `host:port` sockets, the paths, the
  token) say that plainly in words instead.
  The `[probe]` block also carried the `allow_private_targets` SSRF
  explanation above `connect_timeout_secs`, next to a commented-out
  duplicate of a key that lives 50 lines further down; it now sits
  with the key it describes, and the stray commented-out copy is gone.
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
  introduced; the probe is the `:ro` one. `FUMOX_CONFIG_ACCESS`,
  the knob that this change added, was documented in the compose
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
  unlimited: the value clamps up to 1 row, so the body serves a
  single node. The config reference (both languages) now says so,
  next to the sibling keys that do give `0` a meaning.
- The export links were first documented as "rendered at most once
  every 30 s", then corrected to "that holds per request, not per
  window" (the cache had no single-flight claim). That correction is
  itself superseded now: the render behind a cold or expired export
  entry *is* single-flighted, so a burst landing exactly on the
  boundary runs one render and the rest wait for its fresh entry.
  Both guides state the current behaviour.
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
  real-`.mmdb` test asserts content only: its old age assertion
  read the developer's own file mtimes and went red with "looks
  stale" on untouched machines after a month, so freshness is
  covered deterministically (via `set_modified`) by the fresh/stale
  test above instead.
- The pipeline tables in both guides described `limit.count` as
  capping "the final, deduplicated and sorted list" on a source as well
  as on a profile. A source-level cap applies to that source's own
  proxies, before the merge, the behaviour the serving code's own
  comment described, and the one this batch's `limit` fix made true,
  so a multi-source profile serves each source's top up to that count,
  i.e. more than `count` in total. Both tables now say which is which.

### Changed

- The pipeline builder is three tabs instead of one column of seven
  sections. The sections are grouped in the order the pipeline runs:
  *Input* (protocol filter), *Rules* (renaming and discarding, the lists
  that grow) and *Output* (health, geo, sorting, limit). Each tab states
  in one line what it is for, and *Output* lays its four sections out
  two-up on a wide screen. The tabs are CSS-only like the settings
  editor (hidden radios drive the panes, no JavaScript). One component
  renders both the source and the profile form, so both get the layout,
  and the profile keeps its tri-state controls on renaming and
  discarding.
- Rule lists are capped in height and carry a live count. Ten discard
  rules used to push the add button, the second list and the preview a
  screen down; the list now scrolls inside its pane and a counter beside
  each heading shows how many rules it holds. The count is recomputed
  after every HTMX settle, and blank lines do not count: the rename
  editor deliberately keeps one empty line as a place to start typing,
  and an empty line emits no rule.
- The dashboard stat cards lost their per-metric colour stripe. It read
  as a status signal and it lied: green under "checks in 24h" over a
  0/12, amber under a healthy median latency. Status colour belongs to
  the badges, which mark a real state, and the cards now match every
  other panel.
- `/export/alive/{token}` and `/export/ready/{token}` re-read and
  re-serialized the whole tier on every download. Both now render at
  most once per 30 s (`EXPORT_TTL_SECS`) and are served from the
  shared processed cache in between, like `/sub` and `/src`; the
  entries carry no source id, so per-source invalidation never
  touches them. The exports have no source TTL to inherit and no
  invalidation trigger (the probe owns the tiers), so the window is
  fixed and short, and an expired entry is re-rendered inline rather
  than served stale: a download is a snapshot by definition, and a
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
- The shipped `config/app.toml` no longer enables
  `[probe].allow_private_targets`. The probe dials targets carried
  by *feeds*, untrusted input, so the example now ships the same
  `false` the built-in default uses, with the comment rewritten to
  say what the flag actually disables (loopback / RFC1918 /
  link-local / CGNAT) and that `true` is an explicit opt-in for
  isolated test infrastructure. The Compose probe service passes
  the variable explicitly
  (`FUMOX_PROBE__ALLOW_PRIVATE_TARGETS`, default `false`, so the
  environment outranks a hand-edited file the way every other key
  does) and `.env.example` documents it.
- `migration 0008` adds `idx_proxies_updated_at`, covering the
  admin proxies list's default `ORDER BY p.updated_at DESC, p.id
  DESC` (the id tiebreaker is part of the index, it is part of the
  order). Without it every page of the list, and the matching
  `COUNT`, walked the whole table.

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
