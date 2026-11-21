# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# Minimal image for meow-rs (https://github.com/meow-rs/meow-rs), the
# mihomo-compatible proxy kernel Fumox uses for T2 tunnel health checks.
# meow-rs publishes static release binaries but NO official container image,
# so this wraps a release binary. The release is PINNED: MEOW_VERSION names
# a concrete tag and MEOW_SHA256_AMD64 / MEOW_SHA256_ARM64 carry the sums
# the upstream release publishes for the two musl archives; the build
# verifies the download against those sums, so the image carries a binary
# whose hash is known before the download even starts. A new upstream
# release is picked up by editing the three arguments (here and in
# .github/workflows/docker-meow.yml), never by resolving "latest" at build
# time: a floating version makes the published image an unverifiable
# artefact, and the GitHub API that "latest" needs would turn an API outage
# into a broken build
#
# The musl build is fully static; the runtime base only adds
# ca-certificates (meow-rs performs outbound TLS to proxies and to
# [meow].test_url) and tini for signal forwarding. The base is Alpine, the
# same pinned digest the fumox image's runtime stage uses, so the two
# containers of the stack share one distro and one musl snapshot; nothing
# meow-rs needs is distro-sensitive. The health check that looks for the
# controller uses busybox nc: an Alpine image ships neither bash nor curl
#
# The Clash external-controller REST API is enabled by config.yaml.template
# and bound to 0.0.0.0:9090 by default, so fumox-probe can reach it over
# the container network. It is intentionally NOT published to the host, and
# it answers only to a caller that presents the controller secret
# (FUMOX_MEOW__API_TOKEN): the entrypoint refuses to start without one
#
# CI packages this image on demand: .github/workflows/docker-meow.yml
# (workflow_dispatch only) pushes ghcr.io/viktor45/fumox-meow, attested per
# platform
#
# Local build, with the current pin values from the ARG block below (keep
# the three build args in sync with those ARGs when bumping the release);
# the build context is THIS directory, docker/meow:
#
#   docker build \
#     --build-arg MEOW_VERSION=v0.29.0 \
#     --build-arg MEOW_SHA256_AMD64=92fe902cca5e95799af02a42fcda9a4f9195aa61ec126057b51b15a8d2116ca2 \
#     --build-arg MEOW_SHA256_ARM64=6fa37f13ddeaafae605e65bc9f2ab0c538b9ab3fad11c8b12180f0a52b4c06b7 \
#     -t fumox-meow \
#     -f docker/meow/Dockerfile docker/meow
#
# Multi-arch: BuildKit supplies TARGETARCH (linux/amd64, linux/arm64)

ARG MEOW_VERSION=v0.29.0
# sha256 of meow-<version>-<target>.tar.gz, as published in the release's
# checksum file; bump together with MEOW_VERSION
ARG MEOW_SHA256_AMD64=92fe902cca5e95799af02a42fcda9a4f9195aa61ec126057b51b15a8d2116ca2
ARG MEOW_SHA256_ARM64=6fa37f13ddeaafae605e65bc9f2ab0c538b9ab3fad11c8b12180f0a52b4c06b7

# alpine:3.24 pinned by digest, the same multi-arch index the fumox image
# pins; bump the pin deliberately, together with security updates
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS fetch
ARG MEOW_VERSION
ARG MEOW_SHA256_AMD64
ARG MEOW_SHA256_ARM64
ARG TARGETARCH
# The helper packages float with the mirror, same reasoning as the root
# Dockerfile: the digest pins the base, the apk layer follows Alpine, and an
# exact-version pin would only turn every security update into a build
# outage. The package SET is fixed, so both architectures fetch the same
# helpers. What the fetch actually depends on is verified separately: the
# release archive is checked against the pinned sha256 below, so the
# version of curl cannot influence what lands in the image
# No `apk upgrade` here: this stage contributes one file (the meow binary),
# so upgrading its base packages would only cost build time
RUN apk add --no-cache \
        ca-certificates \
        curl \
        file \
    && rm -rf /var/cache/apk/*
RUN set -eux; \
    # The target triple is part of the asset name: without it the download
    # URL would silently point at the wrong architecture
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
    # instead of downloading an artefact nobody can verify
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
    # not next to the download, so a tampered asset or a tampered checksum
    # file cannot pass the check
    echo "${expected}  /tmp/${asset_name}" | sha256sum -c -; \
    mkdir -p /tmp/meow-extract; \
    tar -xzf "/tmp/${asset_name}" -C /tmp/meow-extract; \
    binary=$(find /tmp/meow-extract -type f -name meow | head -n 1); \
    [ -n "$binary" ] || { echo "meow binary not found in the release archive" >&2; exit 1; }; \
    # The archive must carry the binary for the requested target: a
    # mismatch would fail at runtime, on the wrong CPU
    file "$binary" | grep -q "ELF 64-bit" || { echo "the downloaded binary is not an ELF executable" >&2; exit 1; }; \
    file "$binary" | grep -q "$machine" || { echo "the downloaded binary is not for ${machine}" >&2; exit 1; }; \
    install -m 0755 "$binary" /usr/local/bin/meow; \
    rm -rf "/tmp/${asset_name}" /tmp/meow-extract

# Same pinned digest as the fetch stage above
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime
# The runtime packages float with the mirror, same reasoning as above;
# `apk upgrade` first, so the base image's own packages move with the mirror
# as well: the digest pins the base filesystem, not the package set on top
# of it (a no-op for a base that is already current)
RUN apk upgrade -U --no-cache \
    && apk add --no-cache \
        ca-certificates \
        tini \
    && rm -rf /var/cache/apk/* \
    # The gid is shared with the fumox image (999), the uid is not: the
    # proxy kernel reads the generated config through the group and must
    # not be able to open the SQLite database, which the probe writes under
    # uid 999. The uid and the gid are pinned, not allocated, so the two
    # images agree on them no matter what the base image ships.
    # Alpine's base image gives gid 999 to the `ping` group, so it is
    # dropped first, for the same reason the fumox image drops it: the gid
    # is a contract between the two images, and the setgid ping applet this
    # image does not ship would otherwise hold it
    && delgroup ping \
    && addgroup --system --gid 999 meow \
    && adduser --system --uid 998 --ingroup meow --home /etc/meow --shell /sbin/nologin meow \
    && mkdir -p /etc/meow \
    # The exchange volume root, shared with the probe: group-writable, so
    # the probe can write the generated config and the kernel can read it,
    # whichever of the two creates the volume first. The files inside are
    # 0640 (owner and group only), the directory itself hides everything
    # else. The 1777 of the old layout is gone: it let every user on the
    # host write into the kernel's configuration
    && mkdir -p /shared/meow \
    && chown meow:meow /shared/meow \
    && chmod 0770 /shared/meow \
    # The render target exists in the image, so the entrypoint finds it
    # even when the orchestrator mounts no tmpfs over it; with a tmpfs (the
    # shipped layouts) the mount's own mode replaces this one
    && mkdir -p /run/meow \
    && chown meow:meow /run/meow \
    && chown -R meow:meow /etc/meow

COPY --from=fetch /usr/local/bin/meow /usr/local/bin/meow
COPY config.yaml.template /etc/meow/config.yaml.template
COPY --chmod=0755 entrypoint.sh /usr/local/bin/meow-entrypoint

WORKDIR /etc/meow
USER meow

# meow-rs (v0.27+) publishes a controller-discovery file for meow-cli
# (<pid>.json: the controller address, the API secret and the config path)
# under $HOME/.cache/meow/controllers. This image's HOME (/etc/meow) sits on
# the root filesystem, which every shipped layout mounts read-only, so the
# default path fails with "Read-only file system" on every start. The file
# carries the controller secret, so it belongs on the same tmpfs the
# orchestrators already mount at /run/meow: RAM only. The kernel creates the
# directory itself with mode 0700, so it stays private on the mode=1777
# mount (meow-cli is not shipped here; the variable only keeps the kernel
# quiet on a read-only root)
ENV MEOW_RUNTIME_DIR=/run/meow/controllers

# Clash external-controller REST API (fumox-probe only; not published)
EXPOSE 9090

# The entrypoint renders the config template into the tmpfs the
# orchestrator mounts at /run/meow (the rendered file carries the
# controller secret, so it must not land on a disk) and then execs the
# kernel with the data directory on the same tmpfs. The path is Alpine's:
# the tini package installs /sbin/tini
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/meow-entrypoint"]
