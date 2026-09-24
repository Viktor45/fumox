# Fumox

*Русская версия: [README.ru.md](./README.ru.md)*

Fumox fetches proxy lists from many sources, filters and refines them in real time, and serves clean, structured subscriptions to clients.

---

## Quick Start

The project is in active development.

**Fastest start — prebuilt images from GHCR** (multi-arch `linux/amd64` +
`linux/arm64`, build-provenance attested; the meow-rs wrapper image is
refreshed by a manual workflow):

```bash
cp .env.example .env   # set a real FUMOX_ADMIN__TOKEN
docker compose up -d   # pulls the images and starts the whole stack
```

Subscriptions: `http://<host>:8080/sub/{id}` · admin panel:
<http://127.0.0.1:8081/admin> (log in with the token).

**Build from source instead?** Add `--build` to compile the images locally:

```bash
docker compose up -d --build
```

or run the binaries without containers:

```bash
cargo build                 # tests: cargo test
cargo run -p fumox-server   # subscription server + admin panel (http://127.0.0.1:8081/admin)
cargo run -p fumox-probe    # proxy health-check daemon
```

On Podman instead of Docker? [`docker/README.md`](./docker/README.md) deploys
the same stack as a systemd-managed podman pod (quadlet units or a kube-play
manifest).

See [`USERGUIDE.md`](./USERGUIDE.md)
for the details.

Configuration lives in [`config/app.toml`](./config/app.toml); every key has a
default and can be overridden through the environment: `FUMOX_SECTION__KEY`
(e.g. `FUMOX_ADMIN__TOKEN=secret`).

MaxMind GeoLite2 databases (`.mmdb`) are not part of the repository — download
them into `config/` separately:

1. Sign up at <https://www.maxmind.com/en/geolite2/signup> (free account).
2. Download the databases you need via
   [Account → Manage License Keys / Download Databases](https://dev.maxmind.com/geoip/docs/databases/):
   `GeoLite2-City.mmdb` for country flags/names and city names
   (`GeoLite2-ASN.mmdb` adds AS numbers/organizations — every database
   present is merged, so they combine in one name template).
3. Place each file in `config/` under its canonical name.

Without a database file, geo enrichment disables itself automatically (a
warning is logged) and the server keeps running. MaxMind databases are updated
weekly.

---

## Security

`[admin].token` is the only critical secret on a fresh install — change it
before exposing the admin panel to anything other than `127.0.0.1`. **Behind
a reverse proxy, two config keys must be set** so the per-IP rate limit and
the `Host`-header allowlist behave correctly:

- `[server].trust_proxy_ips` and `[admin].trust_proxy_ips`: the proxy's
  CIDR (e.g. `["127.0.0.1/32"]` for nginx on the same host). Without
  these, every request shares the proxy's IP and the rate limit collapses
  to one budget.
- `[server].allowed_hosts` and `[admin].allowed_hosts`: your public
  hostname (e.g. `["fumox.example.com"]`). Without these, the `Host`
  header is honored as-is for the alive/ready export token URLs and the
  rendered admin URLs — an attacker that can poison `Host` reaching the
  listener can render URLs pointing at a host they control.

Both keys default to `[]` to preserve the historical behavior behind a
direct connection. See the [User Guide](./USERGUIDE.md#8-configuration-reference)
configuration reference and the production checklist for context.

- `[admin].secure_cookies` (or the matching `FUMOX_ADMIN__SECURE_COOKIES`
  env override): keep `false` when the panel is reached over plain HTTP
  (the `docker-compose.yml` default — `http://127.0.0.1:8081`). Browsers
  silently drop `Secure` cookies on `http://`, so a successful login
  (`admin logged in` in logs) gets followed by a permanent redirect to
  `/admin/login`. Set `true` only when TLS is terminated at a reverse
  proxy.

---

## Documentation

The **[User Guide](./USERGUIDE.md)** is the place to start: what Fumox is,
how it works, deployment (Docker Compose / image / source), the full
configuration reference, and day-to-day usage. Russian version:
[USERGUIDE.ru.md](./USERGUIDE.ru.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

All trademarks are the property of their respective owners.

- [meow-rs](https://github.com/meow-rs/meow-rs) A high-performance Rust implementation of the mihomo (Clash Meta) proxy kernel.

Database Copyright (c) [MaxMind](https://www.maxmind.com/), Inc.
- [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula)
- [GeoIP2 End User License Agreement](https://www.maxmind.com/en/end-user-license-agreement)
- [Creative Commons Corporation Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/)