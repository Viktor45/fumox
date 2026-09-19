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

## 2026-09-14 · sha-bba0ed6

### Added

- TLS reverse-proxy example: `docker/nginx/` (nginx.conf + Dockerfile)
  terminates HTTPS for both `/sub` and `/admin` in front of the compose
  stack; a ready-to-uncomment service stub was added to
  `docker-compose.yml` (certificates mount into `/certs`, ACME
  challenges are served on port 80).

### Fixed

- Import/export screen reworked: the alive/ready endpoints are now a
  compact table with live proxy counts, and the import form gained a
  JSON file picker that loads the chosen file into the payload field
  (manual paste still works without JavaScript).

## 2026-09-13 · sha-45458b6

### Changed

- Geo enrichment now merges the City and ASN databases, so `{country}`,
  `{city}`, `{asn}` and `{asn_org}` all work in one name template at the
  same time. The pipeline editor hint lists all six placeholders.
- GeoLite2-Country is retired: City carries every fact it has. The server
  no longer downloads or reads it; an existing `GeoLite2-Country.mmdb` is
  ignored. `[geo].db` remains accepted in configs but does nothing.

## 2026-09-12 · sha-29be180

### Fixed

- Admin source/profile cards: serve links display, user guide follow-ups.

## 2026-09-11 · sha-b13bd56

### Added

- Dashboard stats are tweakable (interactive time windows).

### Fixed

- Docker CI: image build and the GHCR cleanup workflow.
- UI and manual corrections after the stats merge.

## 2026-09-10 · sha-a4e7b67

### Added

- T2 (tunnel) verification is fully wired: the meow-rs queue, the ready
  tier, T1/T2 selectors in the admin panel.
- T2 processing survives meow lookup failures with a backoff schedule.

### Fixed

- Dashboard merged with the stats page; pipeline editor and manual fixes;
  mobile UI and security hardening from the audit round.

## 2026-09-09 · sha-b040416

### Security

- Insecure-proxy filtering: proxies advertising `insecure` /
  `allowInsecure` / `skip-cert-verify` toggles are dropped by default.
- Security hardening round (admin auth, SSRF guards).

### Changed

- Default `config/app.toml` retuned.

## 2026-09-08 · sha-960b8d2

### Added

- Proxy card actions by ASN and status; docker-compose adjusted for
  Podman rootless.
- Pipeline AS-number filter and the output limit step.

## 2026-09-07 · sha-41573c8

### Fixed

- Config validation and defaults tweak.

## 2026-09-06 · sha-0c56bd5

### Added

- Sing-box JSON subscription parsing; the state machine is configurable
  (fail limits, second-chance window, recheck ladder).
- Docker CI: image publishing to GHCR with attestations, plus the meow-rs
  wrapper image.

### Changed

- T2 state machine adjustments.

### Fixed

- Docker image CI, Podman manual, settings UI; security audit fixes.

## 2026-09-04 · sha-7bf7d49

### Added

- Pipeline rename/drop rules by type (name, host, port, parameter).
- Alive-linger: a source refresh no longer retires a proxy the probe
  still confirms; the `[ingest].drop_gate` option controls the drop-rule
  interplay.

## 2026-09-03 · sha-c54fe1d

### Fixed

- `url_list` output header handling.

## 2026-09-02 · sha-189eb64

### Added

- Stats page and geo enrichment with the City/ASN databases.

### Fixed

- Proxy geo info persistence; mobile UI and Docker CI.

## 2026-09-01 · sha-8d321f4

### Fixed

- Code cleanup pass.

## 2026-08-31 · sha-d6963ba

### Added

- Visual pipeline editor in the admin panel (builder + raw JSON modes,
  presets, live preview), with security hardening.

## 2026-08-30 · sha-333092c

### Fixed

- Docker environment handling; the proxy state machine no longer
  reconciles statuses it did not verify itself.
- Time display in the admin panel.

## 2026-08-29 · sha-39da896

### Added

- Priority probe queue: newly synced proxies get checked first.
- Profile country filter (include/exclude lists).
- Rotating multiple `test_url`s for T2 checks.
- Per-source IP family selection (IPv4/IPv6) for fetching.
- Live data export link suitable for scaling.

### Fixed

- T1/T2 check priority; strict config validation (unknown keys rejected).

### Docs

- Podman deployment example.

## 2026-08-28 · sha-68e4cb6

### Added

- First working draft: fetching, parsing, SQLite storage, subscriptions,
  admin panel, probe daemon, meow-rs T2 integration, user guide.

### Fixed

- UI soft-wrap, source/subscription links, YAML/JSON pipeline output,
  alive source output.

## 2026-08-19 · sha-8302bfb

### Changed

- Repository initialized, README.
