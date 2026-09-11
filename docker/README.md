# Quadlet (podman/systemd) — running Fumox without docker compose

Quadlet-unit equivalents of `docker-compose.yml`: systemd manages a pod with
three containers (fumox-server, fumox-probe, meow-rs) just like compose did.
Two variants to choose from:

| Folder     | Variant                                          | When it fits                                                                                                                       |
| ---------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `quadlet/` | `fumox.pod` + three `.container` + two `.volume` | The native quadlet way — optimal: explicit units, precise per-container volume mounts, `Restart` per container, per-service status |
| `kube/`    | `fumox.kube` + `fumox-pod.yaml`                  | A single, k8s-shaped manifest; handy if YAML is what you know best                                                                 |

Requires podman ≥ 4.4 (5.x preferred). Everything below assumes **rootless**
podman (recommended); rootful differences are at the end.

## Preparation (both variants)

Quadlet does not build images — the units reference the local names
`localhost/fumox:local` and `localhost/fumox-meow:local`. Prepare them either
way:

**Option 1 — pull the published GHCR images (fastest):**

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
podman pull ghcr.io/viktor45/fumox-meow:latest
podman tag ghcr.io/viktor45/fumox-meow:latest localhost/fumox-meow:local
```

`ghcr.io/viktor45/fumox` is published by `.github/workflows/docker.yml` on
`v*` tags and manual `workflow_dispatch` (see the in-file header for the
current tag rules — there is no automatic rebuild on push to `main`).
`ghcr.io/viktor45/fumox-meow` is packaged manually by `docker-meow.yml`. To
skip the retagging, edit the `Image=` lines of the units to the GHCR names
directly — that is also where you pin a version (`ghcr.io/viktor45/fumox:0.2.0`)
instead of `latest`.

**Option 2 — build from source** (from the repository root):

```sh
podman build -t localhost/fumox:local .
podman build -t localhost/fumox-meow:local docker/meow
```

The configuration directory (app.toml + optional GeoLite2-*.mmdb) must live
at a stable absolute path, e.g. `~/fumox/config`:

```sh
mkdir -p ~/fumox/config
cp config/app.toml ~/fumox/config/
cp config/GeoLite2-*.mmdb ~/fumox/config/   # optional: geo enrichment
```

## Variant A: `quadlet/` (recommended)

1. Environment variables (the `.env` equivalent):

   ```sh
   mkdir -p ~/.config/fumox
   cp docker/quadlet/fumox.env.example ~/.config/fumox/fumox.env
   $EDITOR ~/.config/fumox/fumox.env          # set FUMOX_ADMIN__TOKEN
   ```

   Besides `FUMOX_ADMIN__TOKEN`, the file can set `FUMOX_CONFIG` — the path
   to the TOML config file inside the container (default:
   `/app/config/app.toml` from the mounted config directory). Unit-level
   `Environment=` values outrank this file, which is exactly why the path is
   not fixed in the units — configure it here.

2. Install the units (every file from the folder — into one unit directory):

   ```sh
   mkdir -p ~/.config/containers/systemd
   cp docker/quadlet/fumox.pod docker/quadlet/*.volume \
      docker/quadlet/*.container ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox-pod.service
   ```

   Starting the pod pulls up all three containers (probe starts after the
   server via the quadlet pod dependency; the server migrates the DB on
   first connect, and the probe retries on `database is locked` with its
   own backoff).

3. Autostart without an active login session: `loginctl enable-linger $USER`.

Check: `curl -s http://127.0.0.1:8080/healthz` → `ok`; admin panel at
<http://127.0.0.1:8081/admin> (only loopback is published to the host, same
as compose). Logs: `journalctl --user -u fumox-server -u fumox-probe -u fumox-meow -f`.

## Variant B: `kube/`

1. Images — as above.
2. The variables secret (the `.env` equivalent):

   ```sh
   printf 'FUMOX_ADMIN__TOKEN=change-me\n' | podman secret create fumox-env -
   ```

3. In `fumox-pod.yaml` adjust the `config` directory `hostPath` (currently
   `/opt/fumox/config`).
4. Install and start:

   ```sh
   cp docker/kube/fumox.kube docker/kube/fumox-pod.yaml \
      ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox.service
   ```

On first start podman automatically backs the `fumox-data` and `meow-shared`
PVCs with named volumes (see `podman volume ls`). The admin port is declared
with `hostIP: 127.0.0.1` — after start verify with `podman port fumox`;
older podman releases (without `hostIP` support) publish 8081 on every
interface — close it with a firewall or upgrade.

## Differences from docker compose

- `FUMOX_MEOW__API_ADDR: meow:9090` → `127.0.0.1:9090`: a pod shares one
  network namespace, there are no per-service DNS names. 9090 is not
  published to the host, same as compose.
- Images are either pulled from GHCR or built manually (`podman build`);
  compose does both for you (`up -d` pulls, `up --build` builds).
- Podman named volumes (`fumox-data`, `meow-shared`) are not the same
  storage as docker's. Migrating the DB from compose:

  ```sh
  docker volume ls | grep fumox          # a name like <project>_fumox-data
  podman volume mount fumox-data         # path is printed
  cp "$(docker volume inspect <name> --format '{{ .Mountpoint }}')/fumox.db" \
     "$(podman volume mount fumox-data)/"
  podman volume unmount fumox-data
  ```

  (the docker volume mountpoint may require root; on macOS/OrbStack the
  data lives inside the docker VM.)
- `restart: unless-stopped` → `Restart=on-failure` in the `[Service]`
  sections (systemd does not restart explicitly stopped units — the
  semantics match).
- The `FUMOX_ADMIN__TOKEN` secret is kept not in a `.env` next to the
  compose file but in `~/.config/fumox/fumox.env` (variant A) or a
  `podman secret` (variant B).

## Upgrading

With the GHCR images (option 1 of Preparation):

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
systemctl --user restart fumox-pod.service   # variant B: fumox.service
```

With locally built images:

```sh
git pull
podman build -t localhost/fumox:local .
systemctl --user restart fumox-pod.service   # variant B: fumox.service
```

(The `fumox-meow` wrapper is refreshed the same way when you want a newer
meow-rs release.)

## Rootful (system podman)

The same files go into `/etc/containers/systemd/`; `%h` then expands to
`/root` (adjust `EnvironmentFile=` and the volume paths to system-wide
locations), replace `default.target` with `multi-user.target` in
`[Install]`, and manage it with
`systemctl daemon-reload && systemctl start fumox-pod` (without `--user`).
