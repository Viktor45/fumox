# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# TLS front for Fumox (docker/nginx/nginx.conf): terminates HTTPS and
# proxies to the Fumox listeners, the public subscription listener and
# the admin panel, which upstream keeps loopback-only on the host.
#
# Certificates are NOT baked into the image: mount them at runtime,
# read-only,
#     ./docker/nginx/certs:/certs:ro
# with the two files fullchain.pem / privkey.pem (Let's Encrypt layout,
# e.g. from certbot's /etc/letsencrypt/live/<domain>/). The config reloades
# them without restart on SIGHUP; for ACME automation run certbot
# (or an acme.sh companion container) on the host and point the mount at
# the live directory.
#
# HTTP (80) answers ACME challenges (/.well-known/acme-challenge/) and
# redirects everything else to HTTPS.
#
# Not published to GHCR: this is an example, build it locally with
# docker compose (see the nginx service in docker-compose.yml comments)
# or:
#     docker build -t fumox-nginx -f docker/nginx/Dockerfile docker/nginx
#
# Flavour (ARG NGINX_FLAVOUR):
#   compose  the upstreams are the compose service names ("server"),
#            resolved through Docker's embedded DNS. Default.
#   podman   the upstreams are the pod loopback (run this nginx inside
#            the server pod, see docker/README.md), no resolver needed.
#
# Startup race note: the server blocks use a `resolver` + variable in
# proxy_pass (instead of a plain `proxy_pass http://server:8080`), so
# nginx starts before the `server` container registers its DNS name and
# survives its restarts. A plain upstream would abort on the first start.

# Base pinned by digest — the multi-arch INDEX digest, so both linux/amd64
# and linux/arm64 resolve to it. A floating tag rebuilds the image on
# whatever the registry serves that day; bump the pin deliberately (it
# prints the digest) together with security updates, e.g. via Dependabot's
# docker ecosystem (.github/dependabot.yml).
#
# The tag is the rolling `stable` channel, not a fixed nginx version, so
# Dependabot sees it move and proposes the digest bump. `stable` is the
# right channel for a TLS front: it is the series that gets the security
# backports, and `mainline` would move the build semantics underneath the
# image on every release.
FROM nginx:stable-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311

ARG NGINX_FLAVOUR=compose

# The stock image ships a default server block bound to 80; replace the
# whole config with ours (it keeps the mime.types include).
COPY nginx.conf /etc/nginx/nginx.conf

# The server blocks are a template: the entrypoint renders it into
# /etc/nginx/conf.d/ with the container's environment, so the upstream
# addresses are a runtime choice (see nginx.conf).
COPY templates/ /etc/nginx/templates/

# The resolver belongs to the flavour: compose resolves the service
# names, the podman flavour resolves nothing (the upstream is a literal
# loopback address).
COPY resolver-compose.conf /etc/nginx/resolver-compose.conf
COPY resolver-podman.conf /etc/nginx/resolver-podman.conf
RUN set -eux; \
    case "${NGINX_FLAVOUR}" in \
        compose) cp /etc/nginx/resolver-compose.conf /etc/nginx/resolver.conf ;; \
        podman)  cp /etc/nginx/resolver-podman.conf  /etc/nginx/resolver.conf ;; \
        *) echo "unknown NGINX_FLAVOUR: ${NGINX_FLAVOUR} (compose|podman)" >&2; exit 1 ;; \
    esac; \
    rm -f /etc/nginx/resolver-compose.conf /etc/nginx/resolver-podman.conf

# The upstream addresses and the canonical name of the deployment.
# Override them at runtime (docker run -e / compose environment:).
ENV FUMOX_UPSTREAM_PUBLIC=server:8080 \
    FUMOX_UPSTREAM_ADMIN=server:8081 \
    FUMOX_SERVER_NAME=fumox.example.com

# Certificates and per-deployment overrides arrive via mounts:
#   /certs         , fullchain.pem + privkey.pem (required at runtime)
#   /etc/nginx/conf.d/*.conf, optional extra server blocks
RUN mkdir -p /certs

# 443: HTTPS front; 80: ACME + redirect.
EXPOSE 443 80
