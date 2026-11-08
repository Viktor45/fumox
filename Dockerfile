# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Dependabot does not track syntax directives; update this digest manually.
#
# Fumox container image.
#
# Ships both binaries: `fumox-server` (default CMD) and `fumox-probe`
# (override the command: `docker run ghcr.io/viktor45/fumox fumox-probe`).
#
# Runtime layout:
#   /app/config  : mount point for app.toml and the GeoLite2 .mmdb files
#   /app/data    : mount point for the SQLite database (fumox.db)
#   /app/locales : admin UI translation catalogs (<code>.toml); drop an extra
#                  file in and restart to add a language (embedded fallbacks
#                  keep the panel working if the directory is removed)
#   /shared/geo  : mount point for the GeoLite2 databases (server only)
#   /shared/meow : mount point for the config exchange with the meow kernel
#
# The image runs as uid 999 / gid 999 (the `fumox` user). The gid is shared
# with the meow image, whose user has uid 998 and the same gid: the proxy
# kernel reads the generated config through the group and never touches the
# database, which the probe writes under the same uid as the server.
#
# The root filesystem is meant to be mounted read-only (the compose and kube
# definitions do it): every path the binaries write to is a volume or a
# bind mount, /tmp is the only writable path on the image itself.
#
# Configuration is resolved from built-in defaults, then a TOML file (by
# priority: --config, the FUMOX_CONFIG environment variable, or
# /app/config/app.toml if mounted), then FUMOX_SECTION__KEY environment
# overrides. The image sets:
#   FUMOX_DATABASE__PATH=/app/data/fumox.db
#   FUMOX_ADMIN__BIND=0.0.0.0:8081   (upstream default is loopback-only)
# The admin panel stays off until a token is set: FUMOX_ADMIN__TOKEN is
# mandatory only when the mounted app.toml carries an empty [admin].token.
# The placeholder "change-me" is not a token: the server refuses to start
# with it on a non-loopback bind.
#
# Build speed (measured, amd64 dev machine, source-only change rebuild):
#   ~7.5 min -> ~1.7 min via:
#   * cargo-chef comes as a checksum-pinned prebuilt release binary instead
#     of `cargo install` (which recompiled ~200 crates, 88 s, every cold
#     build);
#   * the mold linker replaces the stock ld (linking used to be ~40 % of
#     the workspace compile step);
#   * BUILD_CACHE selects the dependency-caching strategy:
#       - layers (default): the classic cargo-chef image-layer caching,
#         works on every builder (docker, podman, CI);
#       - mounts: persistent BuildKit cache mounts hold the cargo registry
#         and target dir and compile a source-only change down to just the
#         touched crates, docker compose passes this (docker-compose.yml /
#         FUMOX_BUILD_CACHE in .env.example). It also relaxes the release
#         profile (no LTO, 16 codegen units) because the persistent target
#         dir is what makes those rebuilds cheap anyway.
# CI deliberately stays on `layers`: BuildKit does not export cache-mount
# contents through the type=gha backend, so the `mounts` incremental win
# does not exist on a GitHub runner and would only cost the shared layer
# cache. `layers` is also the only mode every builder (podman-compose)
# understands.
# The build is architecture-agnostic: linux/amd64 and linux/arm64 compile
# natively (.github/workflows/docker.yml); mold and the prebuilt cargo-chef
# ship for both.

# Global build args (usable in the FROM lines below).
#
# The rust base image is NOT an ARG: Dependabot's docker parser only reads
# literal FROM lines and never substitutes ${...}, so an ARG-indirected
# reference is invisible to it and the pin would freeze. The reference
# lives in the FROM line of the chef stage below instead.
ARG BUILD_CACHE=layers
ARG CARGO_CHEF_VERSION=v0.1.78

# ---- Stage 1: toolchain + cargo-chef ---------------------------------------
# sqlx links the system SQLite (not bundled), so headers are needed at build;
# curl + xz-utils fetch and unpack the cargo-chef tarball; mold is the linker.
#
# The DIGEST is what pins the bytes — the multi-arch INDEX digest, so both
# CI architectures resolve to the same image and a rebuild cannot silently
# pick up a rebuilt tag.
#
# The TAG is deliberately NOT pinned to the patch level (it was 1.98.1):
# a fixed patch tag never moves, so Dependabot could never propose a bump
# and the toolchain would stay frozen until a human noticed. `1.98` is the
# floating minor channel of the MSRV declared in Cargo.toml
# (rust-version = "1.98"), so a patch release moves the tag, Dependabot
# proposes the digest bump, and the builder stays on the declared MSRV
# series instead of drifting onto a newer toolchain. It does invalidate
# the chef layer and the whole type=gha cache (~7 min per architecture to
# recover) once per patch release — that is the price of the toolchain
# actually getting its fixes, and it is a one-off per bump rather than a
# permanent freeze.
# `-slim-trixie` matches the runtime base below (Debian 13) explicitly
# instead of relying on what the plain `-slim` tag happens to alias to.
FROM rust:1.98-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS chef
# Validate BUILD_CACHE first, before the apt and cargo-chef work: without this
# a typo in FUMOX_BUILD_CACHE (.env) surfaces much later as BuildKit's
# "unknown stage build-foo" from `FROM build-${BUILD_CACHE}`.
ARG BUILD_CACHE
RUN case "${BUILD_CACHE}" in \
        layers|mounts) ;; \
        *) echo "invalid BUILD_CACHE='${BUILD_CACHE}': expected 'layers' or 'mounts'" >&2; exit 1 ;; \
    esac
# The apt packages are NOT pinned to exact versions. The base image is
# pinned by digest, but `apt-get update` pulls the CURRENT Debian index on
# top of it, so an exact-version pin was the only thing between the image
# and the security updates Debian publishes for these packages — and it
# bought nothing: the digest already freezes the base filesystem, while the
# apt layer lands on whatever the mirror serves. Pinning the versions
# turned every Debian security update into a build outage ("no such
# version") that a human had to clear, and left the image on a known
# vulnerable package until they did.
# The package SET is still fixed (the same libraries on amd64 and arm64);
# only the patch level floats with the mirror. The consequence is that the
# image is not bit-for-bit reproducible across rebuilds: the base is frozen
# by digest, the apt layer follows the mirror.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libsqlite3-dev \
        pkg-config \
        xz-utils \
        mold \
    && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
ARG CARGO_CHEF_VERSION
# Prebuilt cargo-chef instead of `cargo install`: the sha256-pinned tarball
# (~2 s) replaces compiling ~200 crates (88 s) on every cold build.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) triple=x86_64-unknown-linux-gnu \
               checksum=70ef940ef90d04d122f0176fdb8d6c39069191b484a1eaa29b327370c2e1c3c0 ;; \
        arm64) triple=aarch64-unknown-linux-gnu \
               checksum=a47e13fba89c2895f5a5c3d0844acd2a5fd416eceb3a6f9dfb26e28155099f4e ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
        "https://github.com/LukeMathWalker/cargo-chef/releases/download/${CARGO_CHEF_VERSION}/cargo-chef-${triple}.tar.xz" \
        -o /tmp/cargo-chef.tar.xz; \
    echo "${checksum}  /tmp/cargo-chef.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/cargo-chef.tar.xz -C /tmp; \
    install -m 0755 "/tmp/cargo-chef-${triple}/cargo-chef" /usr/local/cargo/bin/cargo-chef; \
    rm -rf /tmp/cargo-chef.tar.xz "/tmp/cargo-chef-${triple}"; \
    cargo chef --version
# mold links every cargo invocation in the stages below (rustc already
# defaults to lld on linux-gnu; mold links this workspace faster still).
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold"
WORKDIR /app

# ---- Stage 2: dependency recipe ---------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Stage 3a: layer-cached build (default) ----------------------------------
# The classic cargo-chef flow: `cook` builds only the workspace dependencies
# into a cacheable image layer, the workspace compiles after the sources are
# copied in. Selected via BUILD_CACHE=layers.
FROM chef AS build-layers
COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
# Stripping is done by the release profile itself (Cargo.toml: strip = true).
RUN cargo build --release --locked \
    && mkdir -p /out \
    && cp target/release/fumox-server target/release/fumox-probe /out/

# ---- Stage 3b: cache-mount build (docker compose) -----------------------------
# Same cook/build split, but through persistent BuildKit cache mounts keyed
# by architecture: the cargo registry and target dir outlive image layers, so
# a source-only change recompiles just the workspace crates. The binaries
# are copied to /out inside the same RUN, a mounted dir is not part of the
# image.
FROM chef AS build-mounts
ARG TARGETARCH
# This stage exists for fast LOCAL rebuilds (docker compose passes
# BUILD_CACHE=mounts), so it trades runtime performance for compile speed:
# with a persistent target dir below, LTO off + more codegen units means a
# source-only change relinks quickly instead of re-running ThinLTO over the
# whole workspace graph. The shipped-image path (BUILD_CACHE=layers, used by
# CI) keeps the optimized profile from Cargo.toml untouched.
ENV CARGO_PROFILE_RELEASE_LTO=false \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
COPY --from=planner /app/recipe.json .
RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,id=cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo build --release --locked \
    && mkdir -p /out \
    && cp target/release/fumox-server target/release/fumox-probe /out/

# ---- Stage 3 selection --------------------------------------------------------
# BUILD_CACHE picks 3a (layers, default) or 3b (mounts); docker compose
# overrides it through its build args.
FROM build-${BUILD_CACHE} AS builder

# ---- Stage 4: minimal runtime -------------------------------------------------
# trixie-slim matches the rust:1.98-slim (Debian 13) build-stage glibc, and
# is pinned by digest like the chef stage above (the multi-arch index, so
# both CI architectures resolve to the same bytes). Bump the pin together
# with security updates; the meow image's stages pin the same digest.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime
# The runtime libraries float with the mirror, same reasoning as the chef
# stage above: the digest pins the base, the apt layer follows Debian.
# libsqlite3-0 is the one library the build stage has to agree with: the
# chef stage installs libsqlite3-dev, the runtime installs the shared
# object. A patch-level drift between the two stages is harmless — the
# SONAME (libsqlite3.so.0) is stable across the whole 3.x series, so the
# runtime satisfies the link the build stage made.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libsqlite3-0 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    # The uid and the gid are pinned, not left to the allocator: the meow
    # image runs its user under the same gid (999) with another uid (998),
    # and the two share a volume. A random system uid would silently break
    # that arrangement (or collide with it). useradd fails loudly when the
    # uid is already taken, which is the intended behaviour.
    && groupadd --system --gid 999 fumox \
    && useradd --system --uid 999 --gid 999 --home-dir /app --shell /usr/sbin/nologin fumox \
    && mkdir -p /app/config /app/data \
    && chown -R fumox:fumox /app \
    # The shared roots, split by purpose and owner:
    #   /shared/geo   the GeoLite2 databases, written by the server alone
    #   /shared/meow  the config exchange with the proxy kernel
    # Both are volume mount points, so the mode below is what a fresh volume
    # inherits. The exchange directory is group-writable (0770): the probe
    # writes the generated config into it and the kernel reads it, and
    # whichever of the two creates the volume first must not lock the other
    # out. The group is the only reader besides the owner (the files inside
    # are 0640), so the credentials stay out of reach of anyone else.
    && mkdir -p /shared/geo /shared/meow \
    && chown fumox:fumox /shared/geo /shared/meow \
    && chmod 0750 /shared/geo \
    && chmod 0770 /shared/meow

COPY --from=builder /out/fumox-server /usr/local/bin/fumox-server
COPY --from=builder /out/fumox-probe /usr/local/bin/fumox-probe
# Absolute destination: the runtime WORKDIR /app comes only after these
# lines, so a bare ./locales/ would land in /locales where the server
# (which resolves [admin].locales_dir against its working directory)
# never looks, the extra-catalog feature would silently not work.
COPY --from=builder /app/locales/ /app/locales/

WORKDIR /app
USER fumox

ENV FUMOX_DATABASE__PATH=/app/data/fumox.db \
    FUMOX_ADMIN__BIND=0.0.0.0:8081

# 8080: public /sub and /src endpoints; 8081: admin panel.
EXPOSE 8080 8081
VOLUME ["/app/config", "/app/data"]

# tini forwards SIGTERM so the server shuts down gracefully; no curl/wget is
# installed, so point orchestrator health probes at GET /healthz instead.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["fumox-server"]
