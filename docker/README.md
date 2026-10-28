# Quadlet (podman/systemd): running Fumox without docker compose

Quadlet-unit equivalents of `docker-compose.yml`: systemd manages the same
three containers (fumox-server, fumox-probe, meow-rs), split over two pods so
that the proxy kernel can never reach the admin panel.
Two variants to choose from:

| Folder     | Variant                                          | When it fits                                                                                                                       |
| ---------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `quadlet/` | `fumox.pod` + `fumox-worker.pod` + three `.container` + three `.volume` | The native quadlet way, optimal: explicit units, precise per-container volume mounts, `Restart` per container, per-service status |
| `kube/`    | `fumox.kube` + `fumox-pod.yaml`                  | A single, k8s-shaped manifest; handy if YAML is what you know best                                                                 |

Requires podman ≥ 4.4 (5.x preferred). Everything below assumes **rootless**
podman (recommended); rootful differences are at the end.

The pods publish plain HTTP only: terminate HTTPS with a reverse proxy in
front of the server listener. `docker/nginx/` holds a ready nginx example,
shared with the docker-compose setup (see "HTTPS for quadlet/kube" below for
the podman flavour).

## Preparation (both variants)

Quadlet does not build images: the units reference the local names
`localhost/fumox:local` and `localhost/fumox-meow:local`. Prepare them either
way:

**Option 1: pull the published GHCR images (fastest):**

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
podman pull ghcr.io/viktor45/fumox-meow:latest
podman tag ghcr.io/viktor45/fumox-meow:latest localhost/fumox-meow:local
```

`ghcr.io/viktor45/fumox` is published by `.github/workflows/docker.yml` on
`v*` tags and manual `workflow_dispatch` (see the in-file header for the
current tag rules, so there is no automatic rebuild on push to `main`).
`ghcr.io/viktor45/fumox-meow` is packaged manually by `docker-meow.yml`. To
skip the retagging, edit the `Image=` lines of the units to the GHCR names
directly, which is also where you pin a version (`ghcr.io/viktor45/fumox:0.2.0`)
instead of `latest`.

**Option 2: build from source** (from the repository root):

```sh
podman build -t localhost/fumox:local .
podman build -t localhost/fumox-meow:local docker/meow
```

The configuration directory (app.toml; the GeoLite2-*.mmdb files do
**not** go here, see below) must live at a stable absolute path,
e.g. `~/fumox/config`:

```sh
mkdir -p ~/fumox/config
cp config/app.toml ~/fumox/config/
```

### Tokens and secrets

Two independent secrets are needed, and they are never stored together:

| Secret               | Read by                    | Purpose                                              |
| -------------------- | -------------------------- | ---------------------------------------------------- |
| `FUMOX_ADMIN__TOKEN` | the server only            | the admin panel's login token                        |
| `FUMOX_MEOW__API_TOKEN` | the probe and the kernel | the meow-rs external-controller secret                |

In the pod layouts the server reads the shared env file as well, so it
sees the controller secret too — it needs no access to it, but that file
is the one the three containers have in common. The admin token is never
in it.

Generate both at random — the literal placeholder `change-me` is **not** a
token: the server refuses to start with it on a non-loopback bind, and an
empty value disables the panel entirely:

```sh
printf 'FUMOX_ADMIN__TOKEN=%s\n' "$(openssl rand -hex 32)"
printf 'FUMOX_MEOW__API_TOKEN=%s\n' "$(openssl rand -hex 32)"
```

The controller secret may only contain `[A-Za-z0-9._-]`; the kernel's
entrypoint refuses anything else.

Variant A (quadlet) keeps them in two environment files, variant B (kube) in
two `podman secret`s — the split is what keeps the admin token away from the
probe and the kernel. Both files are created with mode 600: they hold a
secret and must not be readable by other users.

### Geo enrichment and the shared volumes

Geo enrichment points at its own volume, not the config directory: both
variants (and the kube manifest) set `FUMOX_GEO__DB_DIR=/shared/geo`, the
volume that belongs to the server alone (quadlet: `fumox-geo.volume`,
`VolumeName=fumox-geo`; kube: the `fumox-geo` PVC). The environment
outranks `[geo].db_dir`, so `.mmdb` files dropped into the config
directory are silently never scanned. The server downloads the
GeoLite2 databases into `/shared/geo` at startup, so the manual step is
optional; to ship your own files instead, copy them into that volume
(`podman volume mount fumox-geo` prints the host path, the same
pattern the DB migration below uses).

The kernel's configuration exchange is a second, separate volume
(`fumox-meow.volume`, `VolumeName=fumox-meow`; kube: the `fumox-meow` PVC):
the probe renders the T2 batch to `/shared/meow/meow.yaml` and hot-reloads
the kernel through its REST API. The kernel does not need the GeoLite2
databases and the server does not need the kernel's configuration, so the
two are not mixed.

### Cookie security on plain HTTP

Both variants publish the admin panel on `127.0.0.1:8081` over plain HTTP.
`[admin].secure_cookies` therefore must stay `false`, otherwise the browser
silently drops the `Secure` session cookie, every login attempt looks like a
successful `admin logged in` in `journalctl` followed by a permanent redirect
to `/admin/login`. Override only when TLS is terminated at a reverse proxy:

- variant A: `FUMOX_ADMIN__SECURE_COOKIES=true` in `fumox-admin.env`
- variant B: `FUMOX_ADMIN__SECURE_COOKIES=true` in the `fumox-admin` secret

The env layer outranks the file (the same figment merge that powers the rest
of the override hierarchy). Rotating `[admin].token` or flipping
`secure_cookies` invalidates every active session on the next request, so
plan token rotations for a quiet window.

## Variant A: `quadlet/` (recommended)

1. Environment variables — two files, one per audience:

   ```sh
   mkdir -p ~/.config/fumox
   install -m 600 docker/quadlet/fumox.env.example ~/.config/fumox/fumox.env
   install -m 600 docker/quadlet/fumox-admin.env.example ~/.config/fumox/fumox-admin.env
   $EDITOR ~/.config/fumox/fumox.env          # FUMOX_MEOW__API_TOKEN
   $EDITOR ~/.config/fumox/fumox-admin.env    # FUMOX_ADMIN__TOKEN
   ```

   `fumox.env` holds the shared runtime variables (the controller secret,
   and optionally `FUMOX_CONFIG`, `FUMOX_MEOW__TEST_URL`,
   `FUMOX_PROBE__ALLOW_PRIVATE_TARGETS`); `fumox-admin.env` holds the panel
   variables (the login token, the cookie flag, the SSRF guard for source
   URLs) and is read by the server only. `FUMOX_CONFIG` is the path to the
   TOML config file inside the container (default: `/app/config/app.toml`
   from the mounted config directory). Unit-level `Environment=` values
   outrank these files, which is exactly why the path is not fixed in the
   units, configure it here.

2. Install the units (every file from the folder, into one unit directory):

   ```sh
   mkdir -p ~/.config/containers/systemd
   cp docker/quadlet/fumox.pod docker/quadlet/fumox-worker.pod \
      docker/quadlet/*.volume docker/quadlet/*.container \
      ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox-pod.service        # the server
   systemctl --user start fumox-worker-pod.service  # the probe + the kernel
   ```

3. Autostart without an active login session: `loginctl enable-linger $USER`.

Check: `curl -s http://127.0.0.1:8080/healthz` → `ok`; admin panel at
<http://127.0.0.1:8081/admin> (only loopback is published to the host, same
as compose). Logs: `journalctl --user -u fumox-server -u fumox-probe -u fumox-meow -f`.

### The two pods, and what runs when

`fumox.pod` holds the server alone; `fumox-worker.pod` holds the probe and
the kernel. They exchange nothing over the network: the server and the
probe talk through the shared SQLite volume, the probe and the kernel
through the shared config volume. The split is deliberate — the kernel
handles untrusted proxy traffic and its configuration is writable by the
probe, so it must not be able to reach the admin panel even inside a
shared network namespace.

The two pods start at the same time and neither waits for the other. The
server creates and migrates the schema before it binds its listeners; the
probe reads the proxy list from the database and writes the health verdicts
back, so it does not need the server to be up. The one shared resource is
the schema, and both sides apply it on startup: SQLite serializes the two
writers and the loser retries until the lock is free (see
`connect_probe_pool` in `crates/fumox-core/src/db.rs`). The probe therefore
never crashes on `database is locked` — it backs off and retries, and the
unit stays up.

### Editing `app.toml` from the admin panel

`fumox-server.container` mounts the config directory as `:rw,Z`, so the
admin *Edit settings* page (`/admin/settings/edit`) writes
`/app/config/app.toml` in place through the `toml_edit`-backed editor.
Comments survive every save; ENV overrides (`FUMOX_SECTION__KEY`) keep
winning per the figment merge; both server and probe must be restarted
after a save. `fumox-probe.container` stays read-only: the probe only
reads the file at startup and never writes it. If you prefer the editor
off entirely, change the server mount to `:ro,Z`; the page will render
disabled with a red `set.edit_unwritable` banner explaining why.

## Variant B: `kube/`

1. Images: as above.
2. The two env secrets (the `.env` equivalent), each with a random value:

   ```sh
   printf 'FUMOX_ADMIN__TOKEN=%s\n' "$(openssl rand -hex 32)" \
     | podman secret create fumox-admin -
   printf 'FUMOX_MEOW__API_TOKEN=%s\n' "$(openssl rand -hex 32)" \
     | podman secret create fumox-env -
   ```

   The `fumox-env` secret carries what the probe and the kernel share (the
   controller secret, and optionally `FUMOX_MEOW__TEST_URL` /
   `FUMOX_PROBE__ALLOW_PRIVATE_TARGETS`). The `fumox-admin` secret carries
   the panel's login token and is attached to the server container only, so
   neither the probe nor the kernel can reach the panel. Add
   `FUMOX_ADMIN__SECURE_COOKIES=false` to `fumox-admin` when the panel is
   opened over plain HTTP (the default posture of this variant), or `true`
   when TLS is terminated in front of it.

3. In `fumox-pod.yaml` adjust the `config` directory `hostPath` (currently
   `/opt/fumox/config`).
4. Install and start:

   ```sh
   cp docker/kube/fumox.kube docker/kube/fumox-pod.yaml \
      ~/.config/containers/systemd/
   systemctl --user daemon-reload
   systemctl --user start fumox.service
   ```

On first start podman automatically backs the `fumox-data`, `fumox-geo` and
`fumox-meow` PVCs with named volumes (see `podman volume ls`). The admin
port is declared with `hostIP: 127.0.0.1`; after start verify with
`podman port fumox`; older podman releases (without `hostIP` support)
publish 8081 on every interface, so close it with a firewall or upgrade.

### Start order and the cold start

`podman kube play` starts the containers of both pods at once. An init
container cannot wait for the server here: init containers run *before* the
app containers, so a "wait for /healthz" init container would deadlock the
pod. It is not needed either — the probe does not depend on the server: it
reads the proxy list from the database and writes the health verdicts back.
The one shared resource is the schema, and both sides apply it on startup:
SQLite serializes the two writers and the loser retries until the lock is
free (`connect_probe_pool` in `crates/fumox-core/src/db.rs`). The compose
layout gates the probe on the server's health check instead; the pod layout
does not need it.

The cold start therefore looks like this: the server migrates the schema and
binds, the probe waits for the database to be readable (retrying with its own
backoff) and then begins its cycles. Neither container exits during that
window, so the restart count stays at 0.

## HTTPS for quadlet/kube

`docker/nginx/` holds an nginx image that terminates TLS in front of both
listeners. It is parameterised, so the same image serves every layout:

| Variable                | Compose           | Podman pod (inside `fumox.pod`) |
| ----------------------- | ----------------- | ------------------------------- |
| `FUMOX_UPSTREAM_PUBLIC` | `server:8080`     | `127.0.0.1:8080`                |
| `FUMOX_UPSTREAM_ADMIN`  | `server:8081`     | `127.0.0.1:8081`                |
| `FUMOX_SERVER_NAME`     | your domain       | your domain                     |

The compose flavour resolves the service names through Docker's embedded DNS
(`127.0.0.11`), the podman flavour needs no resolver at all because the
upstream is a literal loopback address. The flavour is chosen at build time:

```sh
# compose (the default flavour)
podman build -t localhost/fumox-nginx:local docker/nginx

# podman: the nginx runs INSIDE the server pod, next to the server
podman build --build-arg NGINX_FLAVOUR=podman \
  -t localhost/fumox-nginx:local docker/nginx
```

Running it inside the server pod (quadlet) means the nginx container shares
the pod's network namespace with the server, so the upstreams are the
loopback addresses and nothing else has to be reachable. A container that
joins a pod's namespace cannot publish ports itself, so the pod publishes
the TLS port: add these lines to `fumox.pod` and reload it

```ini
PublishPort=80:80
PublishPort=443:443
```

```sh
systemctl --user daemon-reload
systemctl --user restart fumox-pod.service
```

and then start the front:

```sh
podman run -d --name fumox-nginx \
  --network pod:fumox \
  --read-only \
  --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev,mode=1777,size=32m \
  --tmpfs /var/run:rw,noexec,nosuid,nodev,mode=1777,size=8m \
  -v ~/fumox/certs:/certs:ro \
  -e FUMOX_UPSTREAM_PUBLIC=127.0.0.1:8080 \
  -e FUMOX_UPSTREAM_ADMIN=127.0.0.1:8081 \
  -e FUMOX_SERVER_NAME=fumox.example.com \
  localhost/fumox-nginx:local
```

The kube variant is the same idea in YAML: the nginx becomes a third
container of the `fumox` pod, which shares the pod's network namespace by
definition, so the loopback upstreams hold and the pod publishes the port:

```yaml
    - name: nginx
      image: localhost/fumox-nginx:local
      env:
        - name: FUMOX_UPSTREAM_PUBLIC
          value: "127.0.0.1:8080"
        - name: FUMOX_UPSTREAM_ADMIN
          value: "127.0.0.1:8081"
        - name: FUMOX_SERVER_NAME
          value: fumox.example.com
      ports:
        - containerPort: 443
          hostPort: 443
          protocol: TCP
      volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
```

(The `certs` volume is a `hostPath` pointing at the directory with
`fullchain.pem` and `privkey.pem`.)

With TLS in front of the panel, set `FUMOX_ADMIN__SECURE_COOKIES=true`
(variant A: `fumox-admin.env`; variant B: the `fumox-admin` secret), or
browsers will drop the session cookie.

Which host names the front accepts is decided by Fumox itself:
`[server].allowed_hosts` (`FUMOX_SERVER__ALLOWED_HOSTS`). The nginx front
normalises the `Host` header (the default ports are dropped, a non-default
port is kept, and a Host that is not a plain hostname is replaced by the
canonical name), so a crafted Host cannot end up in a generated link.

## Differences from docker compose

- `FUMOX_MEOW__API_ADDR: meow:9090` → `127.0.0.1:9090`: a pod shares one
  network namespace, there are no per-service DNS names. 9090 is not
  published to the host, same as compose.
- The compose stack is one network with two networks (`default` + `meow`);
  the pod layout achieves the same separation by splitting the pods.
- Images are either pulled from GHCR or built manually (`podman build`);
  compose does both for you (`up -d` pulls, `up --build` builds).
- Podman named volumes (`fumox-data`, `fumox-geo`, `fumox-meow`) are not
  the same storage as docker's. Migrating the DB from compose:

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
  sections (systemd does not restart explicitly stopped units, the
  semantics match).
- The `FUMOX_ADMIN__TOKEN` secret is kept not in a `.env` next to the
  compose file but in `~/.config/fumox/fumox-admin.env` (variant A) or a
  `podman secret` (variant B).

## Upgrading

**Back up the database first.** The server migrates the schema at startup,
and the migration runs in the same process that serves the requests: a
failed migration leaves the volume with a half-applied schema. Copy
`fumox.db` (and its `-wal` / `-shm` siblings) out of the volume before the
restart, e.g. with `podman volume mount fumox-data` and a plain `cp`.

With the GHCR images (option 1 of Preparation):

```sh
podman pull ghcr.io/viktor45/fumox:latest
podman tag ghcr.io/viktor45/fumox:latest localhost/fumox:local
systemctl --user restart fumox-pod.service        # variant B: fumox.service
systemctl --user restart fumox-worker-pod.service  # variant B: the same unit
```

With units that name the GHCR image directly (no retagging), pull and
restart — the `podman tag` step does not apply:

```sh
podman pull ghcr.io/viktor45/fumox:0.2.0
systemctl --user restart fumox-pod.service
```

With locally built images:

```sh
git pull
podman build -t localhost/fumox:local .
systemctl --user restart fumox-pod.service        # variant B: fumox.service
systemctl --user restart fumox-worker-pod.service  # variant B: the same unit
```

(The `fumox-meow` wrapper is refreshed the same way when you want a newer
meow-rs release.)

## Rootful (system podman)

The same files go into `/etc/containers/systemd/`; `%h` then expands to
`/root` (adjust `EnvironmentFile=` and the volume paths to system-wide
locations), replace `default.target` with `multi-user.target` in
`[Install]`, and manage it with
`systemctl daemon-reload && systemctl start fumox-pod` (without `--user`).
