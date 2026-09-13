# syntax=docker/dockerfile:1
#
# TLS front for Fumox (docker/nginx/nginx.conf): terminates HTTPS and
# proxies to the `server` service on the compose network — the public
# subscription listener (8080) and the admin panel (8081), which upstream
# keeps loopback-only on the host.
#
# Certificates are NOT baked into the image: mount them at runtime,
# read-only —
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
# Startup race note: nginx.conf uses a `resolver` + variable in
# proxy_pass (instead of a plain `proxy_pass http://server:8080`), so
# nginx starts before the `server` container registers its DNS name and
# survives its restarts. A plain upstream would abort on the first start.

FROM nginx:stable-alpine

# The stock image ships a default server block bound to 80; replace the
# whole config with ours (it keeps the mime.types include).
COPY nginx.conf /etc/nginx/nginx.conf

# Certificates and per-deployment overrides arrive via mounts:
#   /certs          — fullchain.pem + privkey.pem (required at runtime)
#   /etc/nginx/conf.d/*.conf — optional extra server blocks
RUN mkdir -p /certs

# 443: HTTPS front; 80: ACME + redirect.
EXPOSE 443 80
