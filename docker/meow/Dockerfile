# syntax=docker/dockerfile:1
#
# Minimal image for meow-rs (https://github.com/meow-rs/meow-rs), the
# mihomo-compatible proxy kernel Fumox uses for T2 tunnel health checks.
#
# meow-rs publishes static release binaries but NO official container image,
# so this wraps a release binary. The release is PINNED: MEOW_VERSION names
# a concrete tag and MEOW_SHA256_AMD64 / MEOW_SHA256_ARM64 carry the sums
# the upstream release publishes for the two musl archives. The build
# verifies the download against those sums and fails on a mismatch, so the
# image carries a binary whose hash is known before the download even
# starts. A new upstream release is picked up by editing the three
# arguments here (and in .github/workflows/docker-meow.yml), never by
# resolving "latest" at build time: a floating version makes the published
# image an unverifiable artefact, and the GitHub API that "latest" needs
# would turn an API outage into a broken build.
#
# The musl build is fully static; the runtime base only adds ca-certificates
# (meow-rs performs outbound TLS to proxies and to [meow].test_url) and tini
# for signal forwarding.
#
# The Clash external-controller REST API is enabled by config.yaml.template
# and bound to 0.0.0.0:9090 by default, so fumox-probe can reach it over
# the container network. It is intentionally NOT published to the host, and
# it answers only to a caller that presents the controller secret
# (FUMOX_MEOW__API_TOKEN): the entrypoint refuses to start without one.
#
# CI packages this image on demand: .github/workflows/docker-meow.yml
# (workflow_dispatch only) pushes ghcr.io/viktor45/fumox-meow, attested per
# platform.
#
# Ready-to-use local build, with the current pin values from the ARG block
# below (keep the three build args in sync with those ARGs when bumping the
# release). The build context is THIS directory, docker/meow — the command
# is meant to be run from the repository root:
#
#   docker build \
#     --build-arg MEOW_VERSION=v0.27.0 \
#     --build-arg MEOW_SHA256_AMD64=38343bc0832d36d97967296a5c7d488c0ba9509186b6a7a4deef5355ff45e2d3 \
#     --build-arg MEOW_SHA256_ARM64=42f12dac9313a3c70bc4e8da7faca863a673d393d6e6f9274274a045d40f431b \
#     -t fumox-meow \
#     -f docker/meow/Dockerfile docker/meow
#
# Multi-arch: BuildKit supplies TARGETARCH (linux/amd64, linux/arm64).
#
# Base image: debian:trixie-slim, the same base as the fumox-server runtime
# stage, so both containers in the compose stack share a distro and glibc.
# Nothing meow-rs needs is distro-sensitive (the binary is static musl; the
# base only contributes ca-certificates and tini).

ARG MEOW_VERSION=v0.27.0
# sha256 of meow-<version>-<target>.tar.gz, as published in the release's
# checksum file. Bump together with MEOW_VERSION.
ARG MEOW_SHA256_AMD64=38343bc0832d36d97967296a5c7d488c0ba9509186b6a7a4deef5355ff45e2d3
ARG MEOW_SHA256_ARM64=42f12dac9313a3c70bc4e8da7faca863a673d393d6e6f9274274a045d40f431b

# ---- Stage 1: fetch the release binary ---------------------------------------
# trixie-slim pinned by digest — the same multi-arch index the fumox image's
# runtime stage pins, so the compose stack shares one distro snapshot. Bump
# the pin deliberately, together with security updates.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS fetch
ARG MEOW_VERSION
ARG MEOW_SHA256_AMD64
ARG MEOW_SHA256_ARM64
ARG TARGETARCH
# apt pins, same discipline as the root Dockerfile: exact versions (identical
# on linux/amd64 and linux/arm64), so a rebuild fetches the same helper
# binaries; a superseded pin fails loudly instead of drifting.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates=20250419+deb13u1 \
        curl=8.14.1-2+deb13u7 \
        file=1:5.46-5 \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    # The target triple is part of the asset name: without it the download
    # URL would silently point at the wrong architecture.
    if [ -z "${TARGETARCH:-}" ]; then \
        echo "TARGETARCH is empty: build with buildx (docker buildx build --platform ...)" >&2; \
        exit 1; \
    fi; \
    case "${TARGETARCH}" in \
        amd64) target=x86_64-unknown-linux-musl; machine=x86-64; expected="${MEOW_SHA256_AMD64:-}" ;; \
        arm64) target=aarch64-unknown-linux-musl; machine=aarch64; expected="${MEOW_SHA256_ARM64:-}" ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    # No pinned sum for this version/architecture: the build stops here
    # instead of downloading an artefact nobody can verify.
    if [ -z "$expected" ]; then \
        echo "no pinned sha256 for meow ${MEOW_VERSION} on ${TARGETARCH}:" >&2; \
        echo "set MEOW_SHA256_AMD64 / MEOW_SHA256_ARM64 to the sums the release publishes" >&2; \
        exit 1; \
    fi; \
    asset_name="meow-${MEOW_VERSION}-${target}.tar.gz"; \
    asset_url="https://github.com/meow-rs/meow-rs/releases/download/${MEOW_VERSION}/${asset_name}"; \
    echo "fetching $asset_url"; \
    curl -fsSL -o "/tmp/${asset_name}" "$asset_url"; \
    # The pinned sum is the one that decides: it lives in this repository,
    # not next to the download, so a tampered asset or a tampered
    # checksum file cannot pass the check.
    echo "${expected}  /tmp/${asset_name}" | sha256sum -c -; \
    mkdir -p /tmp/meow-extract; \
    tar -xzf "/tmp/${asset_name}" -C /tmp/meow-extract; \
    binary=$(find /tmp/meow-extract -type f -name meow | head -n 1); \
    [ -n "$binary" ] || { echo "meow binary not found in the release archive" >&2; exit 1; }; \
    # The archive carries the binary for the requested target: a mismatch
    # would fail at runtime, on the wrong CPU.
    file "$binary" | grep -q "ELF 64-bit" || { echo "the downloaded binary is not an ELF executable" >&2; exit 1; }; \
    file "$binary" | grep -q "$machine" || { echo "the downloaded binary is not for ${machine}" >&2; exit 1; }; \
    install -m 0755 "$binary" /usr/local/bin/meow; \
    rm -rf "/tmp/${asset_name}" /tmp/meow-extract

# ---- Stage 2: minimal runtime ------------------------------------------------
# Same pinned digest as the fetch stage above.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates=20250419+deb13u1 \
        tini=0.19.0-3+b8 \
    && rm -rf /var/lib/apt/lists/* \
    # The gid is shared with the fumox image (999), the uid is not: the
    # proxy kernel reads the generated config through the group and must
    # not be able to open the SQLite database, which the probe writes under
    # uid 999. The uid and the gid are pinned, not allocated, so the two
    # images agree on them no matter what the base image ships.
    && groupadd --system --gid 999 meow \
    && useradd --system --uid 998 --gid 999 --home-dir /etc/meow --shell /usr/sbin/nologin meow \
    && mkdir -p /etc/meow \
    # The exchange volume root, shared with the probe: group-writable, so
    # the probe can write the generated config and the kernel can read it,
    # whichever of the two creates the volume first. The files inside are
    # 0640 (owner and group only), the directory itself hides everything
    # else. The 1777 of the old layout is gone: it let every user on the
    # host write into the kernel's configuration.
    && mkdir -p /shared/meow \
    && chown meow:meow /shared/meow \
    && chmod 0770 /shared/meow \
    # The render target exists in the image, so the entrypoint finds it
    # even when the orchestrator mounts no tmpfs over it. With a tmpfs
    # (the shipped layouts) the mount's own mode replaces this one.
    && mkdir -p /run/meow \
    && chown meow:meow /run/meow \
    && chown -R meow:meow /etc/meow

COPY --from=fetch /usr/local/bin/meow /usr/local/bin/meow
COPY config.yaml.template /etc/meow/config.yaml.template
COPY --chmod=0755 entrypoint.sh /usr/local/bin/meow-entrypoint

WORKDIR /etc/meow
USER meow

# Clash external-controller REST API (fumox-probe only; not published).
EXPOSE 9090

# The entrypoint renders the config template into the tmpfs the
# orchestrator mounts at /run/meow (the rendered file carries the
# controller secret, so it must not land on a disk) and then execs the
# kernel with the data directory on the same tmpfs.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/meow-entrypoint"]
