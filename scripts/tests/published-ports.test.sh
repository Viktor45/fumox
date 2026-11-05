#!/usr/bin/env bash
# Test for the published-port wiring of the pod layouts: the ports the
# quadlet pod (docker/quadlet/fumox.pod) and the kube manifest
# (docker/kube/fumox-pod.yaml) expose to the host.
#
# Needs nothing but bash: it parses the two files, no container engine and
# no network. The invariants it guards are the isolation design of the pod
# layout — the admin panel loopback-only, the kernel's controller (9090)
# and the meow proxy port (7890) never published:
#
#   - fumox.pod declares exactly two PublishPort lines;
#   - the admin mapping (8081) carries the 127.0.0.1: prefix;
#   - no published host port anywhere is 9090 or 7890;
#   - the worker pod publishes nothing at all;
#   - in the kube manifest, the hostPort 8081 entry carries
#     hostIP: "127.0.0.1".
#
# Run directly:  bash scripts/tests/published-ports.test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
POD="$ROOT/docker/quadlet/fumox.pod"
WORKER_POD="$ROOT/docker/quadlet/fumox-worker.pod"
KUBE="$ROOT/docker/kube/fumox-pod.yaml"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  ok: $*"; }

for f in "$POD" "$WORKER_POD" "$KUBE"; do
    [ -f "$f" ] || fail "$f not found"
done

# --- quadlet pod ---------------------------------------------------------------
mapfile -t publishes < <(grep -E '^PublishPort=' "$POD" || true)
count="${#publishes[@]}"

[ "$count" -eq 2 ] || fail "$POD must declare exactly two PublishPort lines, found $count"
note "fumox.pod declares exactly two PublishPort lines"

[ -n "$(printf '%s\n' "${publishes[@]}" | grep -E '^PublishPort=127\.0\.0\.1:8081:8081$')" ] \
    || fail "the admin mapping must be 'PublishPort=127.0.0.1:8081:8081', got: ${publishes[*]}"
note "the admin mapping is loopback-only (127.0.0.1:8081)"

[ -n "$(printf '%s\n' "${publishes[@]}" | grep -E '^PublishPort=8080:8080$')" ] \
    || fail "the public mapping must be 'PublishPort=8080:8080', got: ${publishes[*]}"
note "the public mapping is 8080:8080"

if printf '%s\n' "${publishes[@]}" | grep -E 'PublishPort=[0-9.]*:?9090:|PublishPort=[0-9.]*:?7890:' >/dev/null; then
    fail "the kernel's controller (9090) or the meow port (7890) must never be published: ${publishes[*]}"
fi
note "no published port is 9090 or 7890"

if grep -qE '^PublishPort=' "$WORKER_POD"; then
    fail "fumox-worker.pod must publish nothing (the kernel's controller is pod-internal)"
fi
note "the worker pod publishes nothing"

# --- kube manifest -------------------------------------------------------------
# hostPort 8081 must sit inside an entry that also declares hostIP 127.0.0.1.
if ! grep -E 'hostPort: 8081' -A2 "$KUBE" | grep -E 'hostIP: "127\.0\.0\.1"' >/dev/null; then
    fail "the kube manifest must declare hostPort 8081 with hostIP \"127.0.0.1\""
fi
note "kube hostPort 8081 is pinned to 127.0.0.1"

if grep -E 'hostPort: (9090|7890)\b' "$KUBE" >/dev/null; then
    fail "the kube manifest must not publish 9090 or 7890 to the host"
fi
note "no kube hostPort is 9090 or 7890"

echo
echo "published-ports: all checks passed"
