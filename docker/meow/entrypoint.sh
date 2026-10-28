#!/bin/sh
# Render the meow-rs bootstrap config and start the kernel.
#
# The controller can rewrite the proxy kernel's configuration, so it must
# answer only to the probe: the secret is mandatory and the container
# refuses to start without one. The rendered config holds the secret, so it
# is written to a tmpfs (never to a disk) and stays readable by the kernel
# user alone.
set -eu

TEMPLATE="${FUMOX_MEOW_CONFIG_TEMPLATE:-/etc/meow/config.yaml.template}"
CONFIG_FILE="${FUMOX_MEOW_CONFIG_FILE:-/run/meow/config.yaml}"
DATA_DIR="${FUMOX_MEOW_DATA_DIR:-/run/meow/data}"
API_BIND="${FUMOX_MEOW_API_BIND:-0.0.0.0:9090}"

secret="${FUMOX_MEOW__API_TOKEN:-}"
if [ -z "$secret" ]; then
    echo "error: FUMOX_MEOW__API_TOKEN is not set: the external-controller would" >&2
    echo "       answer every request without authentication" >&2
    exit 1
fi
# The secret is substituted into the template, so it has to survive the
# substitution unchanged: only characters that are inert in a YAML double
# quoted scalar and in the substitution itself are allowed.
case "$secret" in
    *[!A-Za-z0-9._-]*)
        echo "error: FUMOX_MEOW__API_TOKEN may only contain letters, digits," >&2
        echo "       dot, underscore and dash" >&2
        exit 1
        ;;
esac
case "$API_BIND" in
    *:*) ;;
    *)
        echo "error: FUMOX_MEOW_API_BIND must be host:port, got '${API_BIND}'" >&2
        exit 1
        ;;
esac

if [ ! -r "$TEMPLATE" ]; then
    echo "error: the config template ${TEMPLATE} is missing" >&2
    exit 1
fi

# The data dir and the rendered config are the only writable paths of the
# container; both live on the tmpfs the orchestrator mounts.
umask 077
mkdir -p "$(dirname "$CONFIG_FILE")" "$DATA_DIR"

sed -e "s|__FUMOX_MEOW_API_SECRET__|${secret}|g" \
    -e "s|__FUMOX_MEOW_API_BIND__|${API_BIND}|g" \
    "$TEMPLATE" >"$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"

exec meow -f "$CONFIG_FILE" -d "$DATA_DIR"
