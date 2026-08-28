# syntax=docker/dockerfile:1
#
# Minimal image for meow-rs (https://github.com/meow-rs/meow-rs), the
# mihomo-compatible proxy kernel Fumox uses for T2 tunnel health checks.
#
# meow-rs publishes static release binaries but NO official container image,
# so this wraps a pinned release binary. The musl build is fully static; the
# runtime base only adds ca-certificates (meow-rs performs outbound TLS to
# proxies and to [meow].test_url) and tini for signal forwarding.
#
# The Clash external-controller REST API is enabled by config.yaml and bound
# to 0.0.0.0:9090 so fumox-probe can reach it over the compose network. It is
# intentionally NOT published to the host.
#
# Multi-arch: BuildKit supplies TARGETARCH (linux/amd64, linux/arm64).

ARG MEOW_VERSION=v0.21.2

# ---- Stage 1: fetch the pinned static binary --------------------------------
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
    curl -fsSL -o /tmp/meow.tar.gz \
        "https://github.com/meow-rs/meow-rs/releases/download/${MEOW_VERSION}/meow-${MEOW_VERSION}-${target}.tar.gz"; \
    tar -xzf /tmp/meow.tar.gz -C /tmp; \
    install -m 0755 "/tmp/meow-${MEOW_VERSION}-${target}/meow" /usr/local/bin/meow; \
    rm -rf /tmp/meow.tar.gz "/tmp/meow-${MEOW_VERSION}-${target}"

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
CMD ["meow", "-f", "/etc/meow/config.yaml"]
