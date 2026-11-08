#!/usr/bin/env bash
set -euo pipefail

: "${IMAGE:?}"
DIGEST_DIR="${DIGEST_DIR:-/tmp/digests}"

case "${1:-}" in
    candidate)
        sources=()
        for file in "$DIGEST_DIR"/*; do
            digest="${file##*/}"
            [ -f "$file" ] && [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 1
            sources+=("${IMAGE}@sha256:${digest}")
        done
        [ "${#sources[@]}" -eq 2 ] || { echo 'expected two platform digests' >&2; exit 1; }
        candidate="${IMAGE}:sha-${GITHUB_SHA:0:7}-candidate-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
        docker buildx imagetools create -t "$candidate" "${sources[@]}"
        digest="$(docker buildx imagetools inspect "$candidate" --format '{{ .Manifest.Digest }}')"
        [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
        printf 'digest=%s\n' "$digest" >>"$GITHUB_OUTPUT"
        ;;
    verify)
        : "${INDEX_DIGEST:?}"
        docker buildx imagetools inspect "${IMAGE}@${INDEX_DIGEST}" --raw | jq -e '
            .schemaVersion == 2 and (.manifests | type == "array")
            and all(.manifests[];
                (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")))
            and ([.manifests[] | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest")
                | .platform.os + "/" + .platform.architecture] | sort == ["linux/amd64", "linux/arm64"])
            and all(.manifests[] | select(.annotations["vnd.docker.reference.type"] == "attestation-manifest");
                .platform.os == "unknown" and .platform.architecture == "unknown")
        '
        for file in "$DIGEST_DIR"/*; do
            gh attestation verify "oci://${IMAGE}@sha256:${file##*/}" -R "$GITHUB_REPOSITORY"
        done
        gh attestation verify "oci://${IMAGE}@${INDEX_DIGEST}" -R "$GITHUB_REPOSITORY"
        ;;
    promote)
        : "${INDEX_DIGEST:?}"
        tags=()
        while IFS= read -r tag; do
            [ -n "$tag" ] || continue
            tags+=(-t "$tag")
        done <<<"${TAGS:?}"
        [ "${#tags[@]}" -gt 0 ] || exit 1
        docker buildx imagetools create "${tags[@]}" "${IMAGE}@${INDEX_DIGEST}"
        while IFS= read -r tag; do
            [ -n "$tag" ] || continue
            actual="$(docker buildx imagetools inspect "$tag" --format '{{ .Manifest.Digest }}')"
            [ "$actual" = "$INDEX_DIGEST" ] || { echo "unexpected digest for $tag" >&2; exit 1; }
        done <<<"$TAGS"
        ;;
    *) echo 'usage: image-release.sh candidate|verify|promote' >&2; exit 64 ;;
esac
