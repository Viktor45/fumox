#!/usr/bin/env bash
# Bump the pinned meow-rs release in every file that carries it.
#
# docker/meow/Dockerfile refuses to build without an explicit MEOW_VERSION
# and the two sha256 sums of its musl archives, and the same three values
# are duplicated as the compose build defaults (docker-compose.build.yml)
# and the .env.example template. A bump that reaches only some of them
# leaves the local build and the published image shipping different
# kernels, so this rewrites all of them in one pass and fails when an
# anchor is missing rather than half-applying the change.
#
# The sums are read from the `.sha256` assets the release publishes AND
# checked against the downloaded archives before anything is written. No
# workflow builds the meow image on a pull request (docker-meow.yml is
# dispatch-only, docker.yml runs on tags), so this is the only place a bad
# pin is caught before it merges. The published sum and the archive come
# from the same release, so this proves the download is intact and the pin
# is the one upstream published — reviewing the resulting PR remains the
# trust boundary.
#
# Usage:
#   scripts/update-meow-pin.sh [--version <tag>]
#
# Without --version the newest meow-rs/meow-rs release is used: GitHub's
# `releases/latest` endpoint skips drafts and prereleases, so a rolling
# `Prerelease-Alpha` tag can never become the pin. Needs `gh` for the
# lookup (authenticated, or GH_TOKEN set) and `curl` for the assets;
# --version skips the lookup but still reads the sums.
#
# Writes `updated`, `version`, `previous_version`, `sha256_amd64` and
# `sha256_arm64` to $GITHUB_OUTPUT when it is set, so the calling workflow
# can decide whether to open a pull request. An already-current pin is
# not an error: it exits 0 with updated=false, leaves the tree alone and
# downloads only the two tiny checksum files, not the archives.

set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
    echo "usage: scripts/update-meow-pin.sh [--version <tag>]" >&2
}

VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || { usage; exit 64; }
            VERSION="$2"
            shift 2
            ;;
        --help | -h) usage; exit 0 ;;
        *) usage; exit 64 ;;
    esac
done

DOCKERFILE=docker/meow/Dockerfile
COMPOSE=docker-compose.build.yml
ENV_EXAMPLE=.env.example
GUIDES=(USERGUIDE.md USERGUIDE.ru.md)

for f in "$DOCKERFILE" "$COMPOSE" "$ENV_EXAMPLE" "${GUIDES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "::error::$f is missing: run this from a full checkout" >&2
        exit 1
    fi
done

if [ -z "$VERSION" ]; then
    VERSION="$(gh api repos/meow-rs/meow-rs/releases/latest --jq .tag_name)"
fi
# The same rule the build and merge jobs of docker-meow.yml apply, so a
# tag this script accepts is a tag they accept.
VERSION="$(scripts/validate-meow-version.sh "$VERSION")"

# One ARG per value: `sed -n` printing two lines would make the comparison
# below succeed against a concatenated string.
read_pin() { # read_pin <arg name>
    local value
    value="$(sed -n "s/^ARG $1=//p" "$DOCKERFILE")"
    if [ -z "$value" ] || [ "$(printf '%s\n' "$value" | wc -l)" -ne 1 ]; then
        echo "::error::expected exactly one ARG $1= line in $DOCKERFILE" >&2
        exit 1
    fi
    printf '%s\n' "$value"
}

CURRENT_VERSION="$(read_pin MEOW_VERSION)"
CURRENT_AMD64="$(read_pin MEOW_SHA256_AMD64)"
CURRENT_ARM64="$(read_pin MEOW_SHA256_ARM64)"

emit() { # emit <key> <value>
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
    fi
}

emit version "$VERSION"
emit previous_version "$CURRENT_VERSION"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-update-meow-pin.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

RELEASE_BASE="https://github.com/meow-rs/meow-rs/releases/download/${VERSION}"

# GNU coreutils on the runner, `shasum` on a stock macOS: the script is
# exercised locally by scripts/tests/update-meow-pin.test.sh, so both
# spellings have to work.
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | awk '{print $1}'; }
else
    sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

# The sum the release publishes for one archive. The asset is in
# `sha256sum` format, "<sum>  <asset name>"; the name is checked too, so a
# sum published for another target cannot be read as this one's.
published_sum() { # published_sum <target triple>
    local asset="meow-${VERSION}-$1.tar.gz"
    local sum
    curl -fsSL -o "$WORK/$asset.sha256" "$RELEASE_BASE/$asset.sha256"
    sum="$(awk -v name="$asset" '
        { file = $2; sub(/^\*/, "", file) }
        file == name { print $1 }
    ' "$WORK/$asset.sha256")"
    if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]]; then
        echo "::error::no usable sha256 for $asset in the release's .sha256 asset" >&2
        exit 1
    fi
    printf '%s\n' "$sum"
}

# Download the archive and prove it hashes to the published sum. Only
# reached when the pin actually moves, so a scheduled no-op run does not
# pull 16 MB of archives it has no use for.
verify_archive() { # verify_archive <target triple> <published sum>
    local asset="meow-${VERSION}-$1.tar.gz" published="$2" actual
    curl -fsSL -o "$WORK/$asset" "$RELEASE_BASE/$asset"
    actual="$(sha256_of "$WORK/$asset")"
    if [ "$actual" != "$published" ]; then
        echo "::error::$asset does not match the sum the release publishes" >&2
        printf 'published: %s\nactual:    %s\n' "$published" "$actual" >&2
        exit 1
    fi
    printf 'verified %s against the published sum\n' "$asset" >&2
}

AMD64="$(published_sum x86_64-unknown-linux-musl)"
ARM64="$(published_sum aarch64-unknown-linux-musl)"

emit sha256_amd64 "$AMD64"
emit sha256_arm64 "$ARM64"

if [ "$VERSION" = "$CURRENT_VERSION" ] && [ "$AMD64" = "$CURRENT_AMD64" ] && [ "$ARM64" = "$CURRENT_ARM64" ]; then
    emit updated false
    echo "meow-rs $VERSION is already pinned; nothing to do"
    exit 0
fi

verify_archive x86_64-unknown-linux-musl "$AMD64"
verify_archive aarch64-unknown-linux-musl "$ARM64"

# Literal replacement with an occurrence-count assertion: a renamed ARG
# or a reformatted comment must fail the bump instead of leaving some of
# the files on the old release.
rewrite() { # rewrite <file> <old> <new> <expected occurrences>
    local file="$1" old="$2" new="$3" want="$4" got
    got="$(grep -oF -- "$old" "$file" | wc -l | tr -d '[:space:]')" || got=0
    if [ "$got" -ne "$want" ]; then
        echo "::error::expected $want occurrence(s) of the current pin in $file, found $got" >&2
        exit 1
    fi
    # Both values are validated (a version tag and a hex sha256), so the
    # only regex metacharacter they can carry is the dot.
    sed -i.bak "s/${old//./\\.}/${new}/g" "$file"
    rm -f "$file.bak"
}

# The guides document the default in the MEOW_VERSION row of the env-var
# table. Only that cell is a pin: the prose example of the dispatch input
# further down is illustrative and stays as it is.
rewrite_guide() { # rewrite_guide <file>
    local file="$1"
    local row="^| \`MEOW_VERSION\`"
    local cell="\`${CURRENT_VERSION//./\\.}\`"
    if ! grep -q "$row.*$cell" "$file"; then
        echo "::error::the MEOW_VERSION table row in $file does not document $CURRENT_VERSION" >&2
        exit 1
    fi
    sed -i.bak "/$row/s/$cell/\`${VERSION}\`/" "$file"
    rm -f "$file.bak"
}

# The Dockerfile carries each value twice: the ARG block and the
# ready-to-use `docker build` example in its header, which claims to show
# the current pin.
rewrite "$DOCKERFILE" "$CURRENT_VERSION" "$VERSION" 2
rewrite "$DOCKERFILE" "$CURRENT_AMD64" "$AMD64" 2
rewrite "$DOCKERFILE" "$CURRENT_ARM64" "$ARM64" 2
rewrite "$COMPOSE" "$CURRENT_VERSION" "$VERSION" 1
rewrite "$COMPOSE" "$CURRENT_AMD64" "$AMD64" 1
rewrite "$COMPOSE" "$CURRENT_ARM64" "$ARM64" 1
rewrite "$ENV_EXAMPLE" "$CURRENT_VERSION" "$VERSION" 1
rewrite "$ENV_EXAMPLE" "$CURRENT_AMD64" "$AMD64" 1
rewrite "$ENV_EXAMPLE" "$CURRENT_ARM64" "$ARM64" 1
for guide in "${GUIDES[@]}"; do
    rewrite_guide "$guide"
done

emit updated true
echo "meow-rs pin: $CURRENT_VERSION -> $VERSION"
echo "  sha256 amd64: $AMD64"
echo "  sha256 arm64: $ARM64"