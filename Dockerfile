# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Dependabot does not track syntax directives; update this digest manually
#
# Fumox image: ships both binaries, `fumox-server` (default CMD) and
# `fumox-probe` (override: `docker run ghcr.io/viktor45/fumox fumox-probe`)
#
# Runtime layout:
#   /app/config  : app.toml and the GeoLite2 .mmdb files
#   /app/data    : SQLite database (fumox.db)
#   /app/locales : admin UI catalogs (<code>.toml); drop a file in and restart
#                  to add a language (embedded fallbacks keep the panel
#                  working if the directory is removed)
#   /shared/geo  : GeoLite2 databases (server only)
#   /shared/meow : config exchange with the meow kernel
#
# Runs as uid 999 / gid 999 (`fumox`); the meow image's user (uid 998) shares
# the gid: the proxy kernel reads the generated config through the group and
# never touches the database the probe writes.
# The root filesystem is meant to be read-only (compose and kube do it):
# every path the binaries write to is a volume or bind mount, /tmp is the
# only writable path on the image itself
#
# Config resolution: built-in defaults, then a TOML file (--config, the
# FUMOX_CONFIG env, or /app/config/app.toml if mounted), then
# FUMOX_SECTION__KEY env overrides. The image sets:
#   FUMOX_DATABASE__PATH=/app/data/fumox.db
#   FUMOX_ADMIN__BIND=0.0.0.0:8081   (upstream default is loopback-only)
# The admin panel stays off until a token is set: FUMOX_ADMIN__TOKEN is
# mandatory only when the mounted app.toml carries an empty [admin].token;
# the placeholder "change-me" is refused on a non-loopback bind
#
# BUILD_CACHE selects the dependency-caching strategy:
#   layers (default): classic cargo-chef image-layer caching, works on every
#     builder (docker, podman, CI)
#   mounts: persistent BuildKit cache mounts hold the cargo registry and
#     target dir, a source-only change recompiles just the touched crates
#     (docker compose, FUMOX_BUILD_CACHE in .env.example); also relaxes the
#     release profile (no LTO, 16 codegen units), the persistent target dir
#     is what makes those rebuilds cheap
# CI deliberately stays on `layers`: BuildKit does not export cache-mount
# contents through the type=gha backend, so the `mounts` incremental win
# does not exist on a GitHub runner and would only cost the shared layer
# cache. linux/amd64 and linux/arm64 compile natively; mold and the prebuilt
# cargo-chef ship for both

ARG BUILD_CACHE=layers
ARG CARGO_CHEF_VERSION=v0.1.78
# The rust base is NOT an ARG: Dependabot's docker parser reads only literal
# FROM lines, never ${...}; the pin lives in the chef stage's FROM below

FROM rust:1.100-alpine3.24@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS chef
# Alpine base: the Rust toolchain in it is a native musl build, so the
# binaries are statically linked and the runtime stage needs no C library.
# gcc and musl-dev ship in the base, so sqlx's `sqlite` feature compiles the
# bundled SQLite amalgamation; the system headers are deliberately absent,
# so the build cannot silently fall back to the system SQLite (older than
# the CVE-2026-119375 fix). curl + xz fetch the cargo-chef tarball; mold is
# the linker
# The DIGEST is the multi-arch INDEX digest, so both CI architectures
# resolve to the same image and a rebuild cannot silently pick up a
# rebuilt tag
# The TAG floats on the minor channel, not the patch level: a fixed patch
# tag never moves, Dependabot could never propose a bump and the toolchain
# would freeze; a patch release moves the tag and brings the newest fixes
# (one-off invalidation of the chef layer and the type=gha cache,
# ~7 min per architecture per bump)
# The builder is AHEAD of the MSRV (rust-version = "1.98") on purpose: the
# MSRV promises what a SOURCE build needs and stays below stable (the `msrv`
# CI job installs exactly that version and is only meaningful while testing
# a toolchain older than stable), while the image carries the newest stable
# series. The dependency floor is 1.94.0 (sqlx 0.9.1), so 1.98 leaves
# headroom for `cargo update`. `alpine3.24` matches the runtime base
# explicitly instead of whatever the floating `alpine` tag aliases to
# Validate BUILD_CACHE before the apk and cargo-chef work: otherwise a typo
# in FUMOX_BUILD_CACHE (.env) surfaces much later as BuildKit's "unknown
# stage build-foo" from `FROM build-${BUILD_CACHE}`
ARG BUILD_CACHE
RUN case "${BUILD_CACHE}" in \
        layers|mounts) ;; \
        *) echo "invalid BUILD_CACHE='${BUILD_CACHE}': expected 'layers' or 'mounts'" >&2; exit 1 ;; \
    esac
# apk packages are NOT pinned to exact versions: the base is digest-frozen,
# but `apk add` pulls the current Alpine index, so a version pin only turned
# every Alpine security update into a build outage a human had to clear
# while leaving a known-vulnerable package in place. The package SET is
# fixed (same libraries on amd64 and arm64), only the patch level floats
# with the mirror, so the image is not bit-for-bit reproducible across
# rebuilds. gcc and musl-dev are already in the rust:alpine base; mold
# comes from the community repository
# No `apk upgrade` here, unlike the runtime stage: the toolchain is
# rustup's, an upgrade cannot move the compiler the tag names, and none of
# the builder's packages ship, the runtime stage installs its own
RUN apk add --no-cache \
        ca-certificates \
        curl \
        mold \
        xz \
    && rm -rf /var/cache/apk/*
ARG TARGETARCH
ARG CARGO_CHEF_VERSION
# sha256-pinned prebuilt cargo-chef replaces `cargo install`, which
# recompiled ~200 crates on every cold build; the musl build is used because
# the toolchain in this base is musl-native, the gnu binary would not run
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) triple=x86_64-unknown-linux-musl \
               checksum=aca691abfbfbbe00d482e0ed2249eec3091b65e96a0ce92947fb5b254d48b16d ;; \
        arm64) triple=aarch64-unknown-linux-musl \
               checksum=cd59b90fce5fa84c4189648fec33404ec5491791eebdb812df5e7fca8336408d ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
        "https://github.com/LukeMathWalker/cargo-chef/releases/download/${CARGO_CHEF_VERSION}/cargo-chef-${triple}.tar.xz" \
        -o /tmp/cargo-chef.tar.xz; \
    echo "${checksum}  /tmp/cargo-chef.tar.xz" | sha256sum -c -; \
    xz -dc /tmp/cargo-chef.tar.xz | tar -x -C /tmp; \
    install -m 0755 "/tmp/cargo-chef-${triple}/cargo-chef" /usr/local/cargo/bin/cargo-chef; \
    rm -rf /tmp/cargo-chef.tar.xz "/tmp/cargo-chef-${triple}"; \
    cargo chef --version
# mold links every cargo invocation in the stages below (rustc already
# defaults to lld on linux-gnu; mold links this workspace faster still)
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold"
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Classic cargo-chef flow: `cook` builds only the workspace dependencies into
# a cacheable image layer, the workspace compiles after the sources are
# copied in. Selected via BUILD_CACHE=layers
FROM chef AS build-layers
COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
# Stripping is done by the release profile itself (Cargo.toml: strip = true)
RUN cargo build --release --locked \
    && mkdir -p /out \
    && cp target/release/fumox-server target/release/fumox-probe /out/

# Same cook/build split through persistent BuildKit cache mounts keyed by
# architecture: the registry and target dir outlive image layers. The
# binaries are copied to /out inside the same RUN, a mounted dir is not part
# of the image
FROM chef AS build-mounts
ARG TARGETARCH
# Exists for fast LOCAL rebuilds (docker compose passes
# BUILD_CACHE=mounts), so it trades runtime performance for compile speed:
# with a persistent target dir, LTO off + more codegen units relinks a
# source-only change instead of re-running ThinLTO over the whole workspace.
# The shipped-image path (BUILD_CACHE=layers, used by CI) keeps the
# optimized profile from Cargo.toml untouched
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

# BUILD_CACHE picks build-layers (default) or build-mounts; docker compose
# overrides it through its build args
FROM build-${BUILD_CACHE} AS builder

# Runtime base is Alpine, same family as the chef stage: the binaries are
# musl-static, so the image needs no C library for the app. Pinned by the
# multi-arch index digest like the chef stage; the meow image pins the same
# base and the same digest, bump the pins together
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime
# Runtime packages float with the mirror, same reasoning as the chef stage;
# `apk upgrade` runs first, so the base image's own packages (busybox, musl,
# zlib) move with the mirror too: the digest pins the base filesystem, not
# the package set on top of it
# sqlite-libs stays for tools that reach for the system SQLite: the app does
# not link it, sqlx's `sqlite` feature compiles the bundled amalgamation
# (see the chef stage). tini comes from the community repository, which the
# base image enables
RUN apk upgrade -U --no-cache \
    && apk add --no-cache \
        ca-certificates \
        sqlite-libs \
        tini \
    && rm -rf /var/cache/apk/* \
    # The uid and the gid are pinned, not left to the allocator: the meow
    # image runs its user under the same gid (999) with another uid (998),
    # and the two share a volume; a random system uid would silently break
    # or collide with that. adduser fails loudly when the uid is taken,
    # which is the intended behaviour
    # Alpine's base image gives gid 999 to the `ping` group, dropped first:
    # it exists for a setgid ping applet this image does not ship (busybox's
    # /bin/ping is a plain symlink here), while gid 999 is the contract with
    # the meow image; renumbering the shared group instead would strand the
    # gid on every volume already created
    && delgroup ping \
    && addgroup --system --gid 999 fumox \
    && adduser --system --uid 999 --ingroup fumox --home /app --shell /sbin/nologin fumox \
    && mkdir -p /app/config /app/data \
    && chown -R fumox:fumox /app \
    # Shared roots, split by purpose and owner: /shared/geo is written by the
    # server alone, /shared/meow is the config exchange with the proxy
    # kernel. Both are volume mount points, so the mode below is what a
    # fresh volume inherits. The exchange directory is group-writable
    # (0770): the probe writes the generated config into it and the kernel
    # reads it, and whichever of the two creates the volume first must not
    # lock the other out; the files inside are 0640, so the credentials
    # stay out of reach of anyone else
    && mkdir -p /shared/geo /shared/meow \
    && chown fumox:fumox /shared/geo /shared/meow \
    && chmod 0750 /shared/geo \
    && chmod 0770 /shared/meow

COPY --from=builder /out/fumox-server /usr/local/bin/fumox-server
COPY --from=builder /out/fumox-probe /usr/local/bin/fumox-probe
# Absolute destination: WORKDIR /app comes only after this line, a bare
# ./locales/ would land in /locales where the server (which resolves
# [admin].locales_dir against its working directory) never looks, the
# extra-catalog feature would silently not work
COPY --from=builder /app/locales/ /app/locales/

WORKDIR /app
USER fumox

ENV FUMOX_DATABASE__PATH=/app/data/fumox.db \
    FUMOX_ADMIN__BIND=0.0.0.0:8081

# 8080 public /sub and /src, 8081 admin panel
EXPOSE 8080 8081
VOLUME ["/app/config", "/app/data"]

# tini forwards SIGTERM so the server shuts down gracefully; no curl/wget is
# installed, so point orchestrator health probes at GET /healthz. The path
# is Alpine's: the tini package installs /sbin/tini
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["fumox-server"]
