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
# The multi-stage build uses cargo-chef so dependency layers are cached;
# it is architecture-agnostic and builds natively for linux/amd64 and
# linux/arm64 (see .github/workflows/docker.yml).

ARG RUST_VERSION=1.98-slim

# ---- Stage 1: toolchain + cargo-chef ---------------------------------------
# sqlx links the system SQLite (not bundled), so headers are needed at build.
FROM rust:${RUST_VERSION} AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsqlite3-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ---- Stage 2: dependency recipe ---------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Stage 3: build ----------------------------------------------------------
# `cook` builds only the workspace dependencies (cache-friendly layer);
# the full workspace is compiled after sources are copied in.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked \
    && strip target/release/fumox-server target/release/fumox-probe

# ---- Stage 4: minimal runtime -------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libsqlite3-0 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fumox \
    && useradd --system --gid fumox --home-dir /app --shell /usr/sbin/nologin fumox \
    && mkdir -p /app/config /app/data \
    && chown -R fumox:fumox /app

COPY --from=builder /app/target/release/fumox-server /usr/local/bin/fumox-server
COPY --from=builder /app/target/release/fumox-probe /usr/local/bin/fumox-probe
COPY --from=builder /app/locales/ ./locales/

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
