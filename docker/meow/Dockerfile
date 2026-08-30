# syntax=docker/dockerfile:1
#
# Minimal image for meow-rs (https://github.com/meow-rs/meow-rs), the
# mihomo-compatible proxy kernel Fumox uses for T2 tunnel health checks.
#
# meow-rs publishes static release binaries but NO official container image,
# so this wraps a release binary. By default the LATEST release is resolved
# at build time through the GitHub API (one unauthenticated API call per
# build); set MEOW_VERSION to a tag (e.g. v0.21.2) to pin one instead. The
# musl build is fully static; the runtime base only adds ca-certificates
# (meow-rs performs outbound TLS to proxies and to [meow].test_url) and tini
# for signal forwarding.
#
# The Clash external-controller REST API is enabled by config.yaml and bound
# to 0.0.0.0:9090 so fumox-probe can reach it over the compose network. It is
# intentionally NOT published to the host.
#
# Multi-arch: BuildKit supplies TARGETARCH (linux/amd64, linux/arm64).

ARG MEOW_VERSION=latest

# ---- Stage 1: fetch the release binary ---------------------------------------
FROM debian:bookworm-slim AS fetch
ARG MEOW_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) target=x86_64-unknown-linux-musl ;; \
        arm64) target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    if [ "$MEOW_VERSION" = "latest" ]; then \
        asset_url=$(curl -fsSL https://api.github.com/repos/meow-rs/meow-rs/releases/latest \
            | grep "browser_download_url" | cut -d '"' -f 4 \
            | grep -- "-${target}\.tar\.gz" | head -n 1); \
        [ -n "$asset_url" ] || { echo "no meow-rs release asset for ${target}" >&2; exit 1; }; \
    else \
        asset_url="https://github.com/meow-rs/meow-rs/releases/download/${MEOW_VERSION}/meow-${MEOW_VERSION}-${target}.tar.gz"; \
    fi; \
    echo "fetching $asset_url"; \
    curl -fsSL -o /tmp/meow.tar.gz "$asset_url"; \
    mkdir -p /tmp/meow-extract; \
    tar -xzf /tmp/meow.tar.gz -C /tmp/meow-extract; \
    binary=$(find /tmp/meow-extract -type f -name meow | head -n 1); \
    [ -n "$binary" ] || { echo "meow binary not found in the release archive" >&2; exit 1; }; \
    install -m 0755 "$binary" /usr/local/bin/meow; \
    rm -rf /tmp/meow.tar.gz /tmp/meow-extract

# ---- Stage 2: minimal runtime ------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system meow \
    && useradd --system --gid meow --home-dir /etc/meow --shell /usr/sbin/nologin meow \
    && mkdir -p /etc/meow /shared \
    && chmod 1777 /shared \
    && chown -R meow:meow /etc/meow

COPY --from=fetch /usr/local/bin/meow /usr/local/bin/meow
COPY config.yaml /etc/meow/config.yaml

WORKDIR /etc/meow
USER meow

# Clash external-controller REST API (fumox-probe only; not published).
EXPOSE 9090

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["meow", "-f", "/etc/meow/config.yaml", "-d", "/shared"]
