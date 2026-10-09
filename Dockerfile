# Frontend pinned by digest, not by the floating `:1` tag: an unpinned
# frontend is re-resolved on every build (14 MB image, ~19 s on a cold
# cache here) and a future release could change build semantics under us.
# Bump both parts together: `docker buildx imagetools inspect docker/dockerfile:<ver>`.
# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
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
#
# Configuration is resolved from built-in defaults, then a TOML file (by
# priority: --config, the FUMOX_CONFIG environment variable, or
# /app/config/app.toml if mounted), then FUMOX_SECTION__KEY environment
# overrides. The image sets:
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
# RUST_VERSION is a full image reference, pinned to the patch level on
# purpose: a bare 1.98 tag floats, and any 1.98.x patch release rebuilds the
# chef layer, which invalidates `cargo chef cook` and the whole type=gha
# cache in CI (~7 min per architecture to recover). Bump it deliberately
# when you want a toolchain update. `-slim-trixie` matches the runtime base
# below (Debian 13) explicitly instead of relying on what the plain `-slim`
# tag happens to alias to.
ARG RUST_VERSION=1.98.1-slim-trixie
ARG BUILD_CACHE=layers
ARG CARGO_CHEF_VERSION=v0.1.78

# ---- Stage 1: toolchain + cargo-chef ---------------------------------------
# sqlx links the system SQLite (not bundled), so headers are needed at build;
# curl + xz-utils fetch and unpack the cargo-chef tarball; mold is the linker.
FROM rust:${RUST_VERSION} AS chef
# Validate BUILD_CACHE first, before the apt and cargo-chef work: without this
# a typo in FUMOX_BUILD_CACHE (.env) surfaces much later as BuildKit's
# "unknown stage build-foo" from `FROM build-${BUILD_CACHE}`.
ARG BUILD_CACHE
RUN case "${BUILD_CACHE}" in \
        layers|mounts) ;; \
        *) echo "invalid BUILD_CACHE='${BUILD_CACHE}': expected 'layers' or 'mounts'" >&2; exit 1 ;; \
    esac
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
