#!/usr/bin/env bash
# Validate and normalise the meow_version input of docker-meow.yml.
#
# The value reaches the release download URL, the published tag list and
# the image itself, and both the build and the merge job must accept
# exactly the same spellings — so the rule lives here, not inline in the
# workflow where the two copies could drift apart. The input is
# whitespace-trimmed and must then be an explicit versioned tag like
# `v0.27.0` or `0.27.0`: `latest` is NOT a version, a wrapper image whose
# tag silently moves to a new upstream release is not a reproducible
# artefact.
#
# Usage:
#   scripts/validate-meow-version.sh <meow_version>
#
# Prints the normalised version on stdout and exits 0, or writes a
# `::error::` workflow command to stderr and exits 1.

set -euo pipefail

usage() {
    echo "usage: scripts/validate-meow-version.sh <meow_version>" >&2
}

if [ $# -ne 1 ]; then
    usage
    exit 64
fi

MEOW_VERSION="${1//[[:space:]]/}"
# Whitespace is stripped above; anything else outside the release-tag
# alphabet is rejected before it can reach the download URL, the
# published tag list, or the image itself (supply-chain hygiene: the
# value is operator input, but fail fast anyway).
if ! [[ "$MEOW_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # The raw value stays out of the `::error::` line: a workflow command
    # runs to the end of the line, and an unvalidated value must not
    # carry one. It is printed quoted, on a plain line of its own,
    # instead (the same pattern scripts/cleanup-ghcr.sh uses).
    echo "::error::meow_version must be a tag like v0.27.0" >&2
    printf 'meow_version as given: %q\n' "$1" >&2
    exit 1
fi

printf '%s\n' "$MEOW_VERSION"
