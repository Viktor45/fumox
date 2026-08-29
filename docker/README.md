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

Quadlet does not build images — build them once from the repository root:

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

2. Install the units (every file from the folder — into one unit directory):

   ```sh
   mkdir -p ~/.config/containers/systemd
   cp docker/quadlet/fumox.pod docker/quadlet/*.volume \
      docker/quadlet/*.container ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox-pod.service
   ```

   Starting the pod pulls up all three containers (probe waits for the
   server to migrate the DB first — the `depends_on` of compose).

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
- Images are built manually (`podman build`), not by `compose up --build`.
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

```sh
git pull
podman build -t localhost/fumox:local .
systemctl --user restart fumox-pod.service   # variant B: fumox.service
```

## Rootful (system podman)

The same files go into `/etc/containers/systemd/`; `%h` then expands to
`/root` (adjust `EnvironmentFile=` and the volume paths to system-wide
locations), replace `default.target` with `multi-user.target` in
`[Install]`, and manage it with
`systemctl daemon-reload && systemctl start fumox-pod` (without `--user`).
