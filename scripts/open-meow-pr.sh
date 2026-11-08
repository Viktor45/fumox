#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?}" "${PREVIOUS:?}" "${BASE:?}" "${SHA256_AMD64:?}" "${SHA256_ARM64:?}"
VERSION="$(bash scripts/validate-meow-version.sh "$VERSION")"
git check-ref-format "refs/heads/$BASE"
branch="bot/meow-${VERSION}"
existing="$(gh pr list --state all --head "$branch" --base "$BASE" --json number,state,url)"
if [ "$(jq length <<<"$existing")" -gt 0 ]; then
    jq -r '.[] | "Leaving PR #\(.number) (\(.state)) unchanged: \(.url)"' <<<"$existing"
    exit 0
fi

files=(docker/meow/Dockerfile docker-compose.build.yml .env.example USERGUIDE.md USERGUIDE.ru.md)
if git ls-remote --exit-code --heads origin "refs/heads/$branch" >/dev/null; then
    remote="refs/remotes/origin/$branch"
    git fetch --no-tags origin "refs/heads/$branch:$remote"
    for file in "${files[@]}"; do
        if [ "$(git rev-parse "$remote:$file")" != "$(git hash-object "$file")" ]; then
            echo "error: existing branch differs from the verified update in $file; refusing to overwrite it" >&2
            exit 1
        fi
    done
    changed="$(git diff --name-only "refs/remotes/origin/$BASE...$remote")"
    while IFS= read -r file; do
        case "$file" in
            ''|docker/meow/Dockerfile|docker-compose.build.yml|.env.example|USERGUIDE.md|USERGUIDE.ru.md) ;;
            *) echo "error: existing branch contains unrelated changes: $file" >&2; exit 1 ;;
        esac
    done <<<"$changed"
else
    status=$?
    [ "$status" -eq 2 ] || { echo 'error: could not query the update branch' >&2; exit "$status"; }
    git switch -c "$branch"
    git add -- "${files[@]}"
    git -c user.name='github-actions[bot]' \
        -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
        commit -m "build(deps): bump meow-rs from ${PREVIOUS} to ${VERSION}"
    git push -u origin "$branch"
fi

release="https://github.com/meow-rs/meow-rs/releases/tag/${VERSION}"
body="$(printf '%s\n' \
    "Bumps the pinned meow-rs kernel from \`${PREVIOUS}\` to \`${VERSION}\`." \
    '' "Release: ${release}" '' \
    '| archive | sha256 |' '| --- | --- |' \
    "| x86_64-unknown-linux-musl | \`${SHA256_AMD64}\` |" \
    "| aarch64-unknown-linux-musl | \`${SHA256_ARM64}\` |" \
    '' 'Both archives were checked against the upstream release checksums before changing the pins. The archive and checksum share an upstream trust boundary; review the release notes.' \
    '' "After merging, dispatch \`docker-meow.yml\` with \`${VERSION}\` and these checksums. This PR publishes no images." \
    '' 'If GitHub holds the bot-created PR checks for approval, approve the workflow run before merging.' \
)"
if ! gh pr create --base "$BASE" --head "$branch" \
    --title "build(deps): bump meow-rs from ${PREVIOUS} to ${VERSION}" --body "$body"; then
    echo 'error: PR creation failed; the verified branch is retained for retry.' >&2
    echo 'Check Actions > General > Workflow permissions > Allow GitHub Actions to create and approve pull requests, and the token permissions.' >&2
    exit 1
fi
