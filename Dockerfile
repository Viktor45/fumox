# syntax=docker/dockerfile:1
#
# Fumox container image.
#
# Ships both binaries: `fumox-server` (default CMD) and `fumox-probe`
# (override the command: `docker run ghcr.io/<owner>/fumox fumox-probe`).
#
# Runtime layout:
#   /app/config  — mount point for app.toml and the GeoLite2 .mmdb files
#   /app/data    — mount point for the SQLite database (fumox.db)
#   /app/locales — admin UI translation catalogs (<code>.toml); drop an extra
#                  file in and restart to add a language (embedded fallbacks
#                  keep the panel working if the directory is removed)
#
# Configuration is resolved from built-in defaults, then /app/config/app.toml
# if mounted, then FUMOX_SECTION__KEY environment overrides. The image sets:
#   FUMOX_DATABASE__PATH=/app/data/fumox.db
#   FUMOX_ADMIN__BIND=0.0.0.0:8081   (upstream default is loopback-only)
# You must additionally provide FUMOX_ADMIN__TOKEN to enable the admin panel.
#
# Build speed (measured, amd64 dev machine, source-only change rebuild):
#   ~7.5 min -> ~1.7 min via:
#   * cargo-chef comes as a checksum-pinned prebuilt release binary instead
#     of `cargo install` (which recompiled ~200 crates, 88 s, every cold
#     build);
#   * the mold linker replaces the stock ld (linking used to be ~40 % of
#     the workspace compile step);
#   * BUILD_CACHE selects the dependency-caching strategy:
#       - layers (default): the classic cargo-chef image-layer caching —
#         works on every builder (docker, podman, CI);
#       - mounts: persistent BuildKit cache mounts hold the cargo registry
#         and target dir and enable incremental release builds, so a
#         source-only change recompiles just the touched crates — docker
#         compose passes this (docker-compose.yml / FUMOX_BUILD_CACHE in
#         .env.example).
# The build is architecture-agnostic: linux/amd64 and linux/arm64 compile
# natively (.github/workflows/docker.yml); mold and the prebuilt cargo-chef
# ship for both.

# Global build args (usable in the FROM lines below).
ARG RUST_VERSION=1.98-slim
ARG BUILD_CACHE=layers
ARG CARGO_CHEF_VERSION=v0.1.78

# ---- Stage 1: toolchain + cargo-chef ---------------------------------------
# sqlx links the system SQLite (not bundled), so headers are needed at build;
# curl + xz-utils fetch and unpack the cargo-chef tarball; mold is the linker.
FROM rust:${RUST_VERSION} AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl libsqlite3-dev pkg-config xz-utils mold \
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
# are copied to /out inside the same RUN — a mounted dir is not part of the
# image.
FROM chef AS build-mounts
ARG TARGETARCH
# The persistent target dir below makes incremental release builds pay off:
# a source-only change then recompiles just the touched crate instead of the
# whole workspace (the stock release profile has incremental disabled).
ENV CARGO_PROFILE_RELEASE_INCREMENTAL=true
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
# trixie-slim matches the rust:1.98-slim (Debian 13) build-stage glibc.
FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libsqlite3-0 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fumox \
    && useradd --system --gid fumox --home-dir /app --shell /usr/sbin/nologin fumox \
    && mkdir -p /app/config /app/data \
    && chown -R fumox:fumox /app

COPY --from=builder /out/fumox-server /usr/local/bin/fumox-server
COPY --from=builder /out/fumox-probe /usr/local/bin/fumox-probe
# Absolute destination: the runtime WORKDIR /app comes only after these
# lines, so a bare ./locales/ would land in /locales where the server
# (which resolves [admin].locales_dir against its working directory)
# never looks — the extra-catalog feature would silently not work.
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
