# Changelog

Fumox ships as rolling image snapshots (`ghcr.io/viktor45/fumox:sha-<hash>`
plus the moving `latest`); this changelog lists what each published batch
of changes contains, newest first. Match the `sha-` tag of the image you
pulled (`docker images`) to the hash in a section header, or just diff
your pull date against the section dates.

The categories follow [Keep a Changelog](https://keepachangelog.com/);
`Docs` covers the user guide and READMEs, `Internal` (dependency bumps,
CI plumbing) is omitted — it never changes the shipped image.

## Unreleased (2026-09-17)

### Added

- `[ingest].removed_as_unknown` (default `false`): a `removed` proxy the
  feed still carries can be revived — the row resets to the pristine
  `unknown` state (fail count and quarantine fields cleared) and walks
  the checks again, joining the priority-probe queue like a fresh
  insert. With the default, `removed` stays terminal.
- `[server].trust_proxy_ips` (default `[]`): CIDRs whose
  `X-Forwarded-For` / `Forwarded for=` headers are honored for the
  public per-IP rate-limit key. Empty disables forwarded-header trust
  for the public listener (the historical behavior behind a direct
  connection).
- `[server].allowed_hosts` (default `[]`): Hostnames / IPs allowed to
  reach the public listener, including the alive/ready export
  endpoints.
- `[admin].trust_proxy_ips` (default `[]`): same semantics on the
  admin listener.
- `[admin].allowed_hosts` (default `[]`): same semantics on the admin
  listener.
- Admin *Revival* panel on `/admin/proxies`: a fourth dialog mirroring
  the existing *Cleanup* panel, but moving rows in the opposite
  direction. Operators can return `removed` proxies of a chosen
  country, `removed` proxies of a chosen AS, `removed` proxies that
  never received a probe verdict, and every `quarantine` proxy back to
  `unknown`. Each action resets the lifecycle fields (`fail_count=0`,
  `quarantined_at` / `ladder_at` / `removed_at=NULL`, `ladder_step=0`)
  the same way `revive_removed` already does for the ingest-driven
  `[ingest].removed_as_unknown` path, and the returned ids are
  enqueued into `probe_requests` so the probe picks them up on the
  next cycle rather than waiting for the random sample to come around.
  Nothing is physically deleted — the *Purge removed* button stays the
  only hard-delete. Locale strings `px.revive_*` mirror `px.cleanup_*`.

### Changed

- T1 checks are now suppressed after a T2 failure: when a proxy's most
  recent T2 attempt fails (bad credentials, meow-rs unreachable, the
  target hit the SSRF policy, or a `ServiceUnavailable` from the
  engine), subsequent T1 checks for that proxy are skipped until the
  next successful T2 — the T2 recency selector is the only path back
  into the T1 rotation. A T1 failure (a closed TCP port) does not
  trigger the suppression because it is not a property of the tunnel.
  New column `proxies.last_t2_failed_at` (migration 0007) plus the
  `idx_proxies_t2_block` index; `select_t1_candidates` now filters on
  `last_t2_failed_at IS NULL`. See SPEC §8.3 for the rationale.
- The admin *Settings* screen now renders the **complete** effective
  config: new `[server]`, `[database]`, `[geo]`, `[admin]` and `[log]`
  panels next to the existing probe/ingest/fetch/meow ones, plus the
  previously missing `[probe].allow_private_targets`. Rate limits are
  shown in the canonical `N/unit` form, response caps human-readable,
  the legacy `[geo].db` is marked as ignored — and the admin token is
  never rendered.
- The admin *Sources → Delete* action is now conservative on `ready`
  proxies when `[ingest].drop_gate = false` (the default): a tunnel-
  verified row is left alone instead of being retired just because its
  source was removed — the probe keeps being the only authority on its
  lifecycle. With `drop_gate = true` the strict policy applies and
  every orphan retires, including `ready`. `mark_orphans_removed` now
  takes a list of protected statuses; the admin path passes `["ready"]`
  in the conservative mode and an empty list in the strict one.
- Pipeline `drop` rules now accept `target: "asn"` with an `asns`
  array: a proxy whose resolved autonomous-system number matches any
  listed AS (with or without the `AS` prefix) is discarded at
  ingestion and from `/sub` output. Unresolved ASNs are kept, matching
  the existing `filter.exclude_asns` semantics. Drop rules now run
  after ASN resolution, so the dry-run previews ASN-driven discards
  too. The pipeline editor's drop section exposes the new target as a
  fifth dropdown option; the `match`/`flags`/`key` fields are hidden
  on ASN rows and replaced by a single AS-number input. Regex and ASN
  rules live side by side in the same `drop` array.
- The pipeline editor's row layout now follows the `target` selector
  live: changing `name` / `host` / `port` / `param` / `asn` in a drop
  or rename row fires an htmx round-trip that swaps the row in place,
  so the regex ↔ ASN switch is immediate and the asns input appears
  without an explicit add button. The round-trip carries `?render=1` so
  it never grows the row count — only the explicit `+ правило` /
  `+ правило отбрасывания` buttons append.
- The pipeline preview now updates on every keystroke. The wrapper
  around the JSON preview listens for `change, input` events with a
  300 ms debounce, so typing into the `match`, `replace`, `asns`, or
  filter fields updates the validation verdict and the generated JSON
  live instead of waiting for the field to lose focus.
- `db::migrate()` now self-heals from `sqlx::migrate!()` checksum
  mismatches: when an applied migration file has been edited in place
  (typically a comment-only change), the SHA-384 stored in
  `_sqlx_migrations.checksum` is re-stamped from the on-disk content
  and `migrate()` is retried. The schema on disk is unchanged — only the
  bookkeeping column is rewritten. Any other sqlx error
  (`Dirty`, `VersionMissing`, structural mismatch, real DDL failure)
  propagates to the caller untouched. A standalone `cargo run
  --example repair_migration_checksums` remains available for manual
  recovery.
- T2 batch abort is now reserved for real engine outages. Three
  independent guards collapse the "first `ServiceUnavailable` kills the
  whole batch" failure mode that surfaced as `aborted: meow-rs became
  unavailable mid-batch` on the `probe_results` rows:
  (a) `check_delay_with_retry` re-issues `ServiceUnavailable` outcomes
      once after a 100 ms backoff, so transport blips and one-shot
      malformed payloads never reach the abort counter;
  (b) every `ServiceUnavailable` is followed by a cheap `/version` ping,
      and a healthy engine — `engine_alive = true` — leaves the proxy
      with a `meow-rs transient error` record and the rest of the batch
      untouched;
  (c) the in-batch `AtomicBool` is replaced by a `BatchGuard` carrying a
      consecutive-failure counter and a 3-strike threshold, so only a
      sustained outage pattern flips the abort flag and engages
      `backoff_meow`, and only on that exact transition. With these
      guards, a single bad delay response on one proxy no longer
      abandons the rest of the cycle; genuine engine crashes still
      abort and back off, and the operator-visible `probe_results.error`
      text distinguishes `meow-rs transient error`, `meow-rs
      unavailable mid-batch`, and `aborted: meow-rs became unavailable
      mid-batch` accordingly.
- `unknown` proxies now survive the same upstream churn that
  `alive`/`ready` already do. The `keep_alive_linger` filter in
  `reconcile_source` extended its protected set from `('alive',
  'ready')` to `('alive', 'ready', 'unknown')`: an `unknown` row that
  vanished from a single fetch is no longer retired in the same
  transaction — the probe queue (`probe_requests`) and the random T1
  sample still pick it up via the `EXISTS (... link ...)` predicate,
  so the row gets its verdict eventually. A subsequent refresh that
  re-lists the proxy re-stamps the link cleanly; a verdict that moves
  the row to `quarantine` (or `ready`) ends the linger normally. The
  admin *Delete source* action now also passes `unknown` alongside
  `ready` to `mark_orphans_removed` when `[ingest].drop_gate = false`
  (the default): with `drop_gate = true` the strict policy still
  retires every orphan. The intent is symmetrical — the probe is the
  only authority on the lifecycle of a verified proxy, the priority
  queue is the only authority on a not-yet-checked one, and a single
  upstream blip or a single admin click should not deny either of
  them their verdict.

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
