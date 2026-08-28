# Fumox 🥋⚡

*Русская версия: [README.ru.md](./README.ru.md)*

`Fumox` is a blazing-fast, lightweight tool built for **real-time subscription data filtering and refinement**.

It applies ultimate algorithmic mastery to chaotic live data streams, ensuring subscribers receive only clean, precise, and structured updates instantly on the fly.

---

## 💡 What's in a Name?

The name **Fumox** represents an optimized, modern fusion of Eastern discipline and ancient Roman speed:

* **Fu** *(Chinese 工夫)* — Meaning *"mastery"* or *"skill attained through discipline"*. This stands for the stealth-like efficiency, routing accuracy, and precision of our filtering algorithms.
* **Mox** *(Latin)* — Meaning *"immediately"*, *"instantly"*, or *"at once"*. This reflects the absolute **real-time** nature of the stream engine.

### The Four Pillars of Fumox:
1. **The Prism (Clarity)** — It slices and refracts incoming massive datasets into clean, isolated subscription topics.
2. **The Forge (Power)** — It instantly melts down invalid payloads and recasts broken logs into strict, predictable schemas before they hit subscribers.
3. **The Trampoline (Velocity)** — It catches real-time events and instantly launches targeted updates directly to active webhooks or consumers with zero lag.
4. **The Pompon (Softness)** — It acts as a gentle, soft buffer that smooths out extreme data spikes and traffic surges, preventing subscribers from being overwhelmed.

---

## Quick Start

The project is in active development.

```bash
# Build and tests
cargo build
cargo test

# Subscription server + admin panel (http://127.0.0.1:8081/admin)
cargo run -p fumox-server

# Proxy health-check daemon
cargo run -p fumox-probe
```

Prefer containers? A [`docker-compose.yml`](./docker-compose.yml) builds and
runs the whole stack — `fumox-server`, `fumox-probe`, and a `meow-rs` tunnel
checker — in one command:

```bash
cp .env.example .env   # set FUMOX_ADMIN__TOKEN
docker compose up -d --build
```

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
   `GeoLite2-Country.mmdb` is used by default (`GeoLite2-City.mmdb` and
   `GeoLite2-ASN.mmdb` are optional).
3. Place each file in `config/` under its canonical name.

Without a database file, geo enrichment disables itself automatically (a
warning is logged) and the server keeps running. MaxMind databases are updated
weekly.

---

## 📖 Documentation

The **[User Guide](./USERGUIDE.md)** is the place to start: what Fumox is,
how it works, deployment (Docker Compose / image / source), the full
configuration reference, and day-to-day usage. Russian version:
[USERGUIDE.ru.md](./USERGUIDE.ru.md).
