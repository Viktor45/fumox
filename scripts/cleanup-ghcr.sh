#!/usr/bin/env bash
# Manifest-aware GHCR retention for the Fumox container images.
#
# The build workflow pushes per-arch images BY DIGEST (untagged) and then
# runs a merge job that stitches them, plus the provenance attestation
# manifests, into one multi-arch index tagged with `latest`, semver
# (`0.2.0`, `0.2`), `main` and a transient `sha-<shortsha>`. The per-arch
# children therefore have NO tags of their own, and every live tag
# references them.
#
# A naive "delete anything not `latest`", or "delete anything untagged",
# cleanup breaks the merged manifest list: the per-arch digests it
# references would disappear and `docker pull` of `latest`/semver starts
# failing with manifest-unknown (and `gh attestation verify` loses its
# targets). So this script deletes ONLY:
#   - versions whose tag list contains ONLY `sha-*` entries, older than
#     RETENTION_DAYS (default 30), these are the merged indexes of past
#     builds nobody consumes anymore;
#   - untagged versions, ONLY when PRUNE_UNTAGGED is enabled AND the
#     version's digest is not referenced by ANY kept tag's manifest list
#     AND is not an attestation manifest (or the subject one vouches for)
#     AND older than RETENTION_DAYS (the age gate also covers the race
#     against a merge job that is mid-run). Disabled by default: run a
#     `dry_run` pass first and check the output before enabling.
# All other tags (`latest`, `main`, `0.x.y`) and ALL other untagged
# versions (the children of live tags, attestations) are kept.
#
# Usage:
#   scripts/cleanup-ghcr.sh --owner <name> --packages a,b \
#       [--retention-days 30] [--dry-run|--no-dry-run] [--prune-untagged]
#
# Needs `gh` (with packages:read and packages:write) and `docker` (for
# `buildx imagetools inspect`).

set -euo pipefail

OWNER=""
PACKAGES=""
RETENTION_DAYS=30
DRY_RUN=true
PRUNE_UNTAGGED=false

usage() {
    echo "usage: scripts/cleanup-ghcr.sh --owner <name> --packages a,b \\
    [--retention-days 1-365] [--dry-run|--no-dry-run] [--prune-untagged]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --owner) OWNER="${2:-}"; shift 2 ;;
        --packages) PACKAGES="${2:-}"; shift 2 ;;
        --retention-days) RETENTION_DAYS="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --no-dry-run) DRY_RUN=false; shift ;;
        --prune-untagged) PRUNE_UNTAGGED=true; shift ;;
        --help | -h) usage; exit 0 ;;
        *) usage; exit 64 ;;
    esac
done

if [ -z "$OWNER" ] || [ -z "$PACKAGES" ]; then
    usage
    exit 64
fi
if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || [ "$RETENTION_DAYS" -lt 1 ] || [ "$RETENTION_DAYS" -gt 365 ]; then
    echo "::error::retention_days must be an integer in [1, 365], got: $RETENTION_DAYS" >&2
    exit 1
fi

# GNU date on the runner, BSD date on macOS. The script is exercised
# locally by scripts/tests/cleanup-ghcr.test.sh, so both spellings have
# to work.
if date -u -d "@0" +%s >/dev/null 2>&1; then
    DATE_FLAVOUR=gnu
else
    DATE_FLAVOUR=bsd
fi

# The cutoff: the moment before which a version counts as stale.
cutoff_epoch() { # cutoff_epoch <days>
    if [ "$DATE_FLAVOUR" = "gnu" ]; then
        date -u -d "-$1 days" +%s
    else
        date -u -v-"$1"d +%s
    fi
}

# An RFC-3339 timestamp -> epoch seconds. Fails (non-zero) when the
# value cannot be parsed, so the caller can skip the version instead
# of treating it as epoch 0 (which would make it deletable).
iso_epoch() { # iso_epoch <RFC3339>
    local value="$1"
    case "$value" in
        *.*[0-9]Z | *.*[0-9][0-9]*Z) value="${value%%.*}Z" ;;
    esac
    if [ "$DATE_FLAVOUR" = "gnu" ]; then
        date -u -d "$value" +%s
    else
        date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$value" +%s
    fi
}

CUTOFF="$(cutoff_epoch "$RETENTION_DAYS")"
if [ "$DRY_RUN" = "true" ]; then
    echo "DRY-RUN: listing versions older than $RETENTION_DAYS days (no delete)"
else
    echo "Deleting versions older than $RETENTION_DAYS days"
fi
if [ "$PRUNE_UNTAGGED" = "true" ]; then
    echo "Untagged-orphan pruning is ENABLED (reference-checked against every kept tag)"
fi

# The packages API is path-scoped: user-owned packages live under
# /users/<name>, org-owned under /orgs/<name>. Detect the owner type
# once: GET /users/<name> resolves both, and the /orgs/<name> call is
# the fallback for an owner /users does not know.
detect_api_root() {
    local type=""
    if type="$(gh api "/users/${OWNER}" --jq .type 2>/dev/null)"; then
        case "$type" in
            Organization) echo "/orgs"; return 0 ;;
            User) echo "/users"; return 0 ;;
        esac
    fi
    if gh api "/orgs/${OWNER}" --jq .type >/dev/null 2>&1; then
        echo "/orgs"
        return 0
    fi
    echo "/users"
}
API_ROOT="$(detect_api_root)"
echo "Owner ${OWNER} → ${API_ROOT}/${OWNER}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-ghcr-cleanup.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ERR_FILE="$WORK/err"
REF_FILE="$WORK/ref"

packages_processed=0
packages_skipped=0

# --- helpers ------------------------------------------------------------------

# One jq call turns a version page into TSV: id, digest, created_at, tags
# (the tags joined by commas -- a container tag cannot contain one).
# The caller checks the shape of the response separately: an empty array
# is a package with no versions, not a broken response.
parse_versions() { # parse_versions <json>
    jq -r '
        .[]
        | [
            (.id | tostring),
            (.name // ""),
            (.created_at // ""),
            ((.metadata.container.tags // []) | join(","))
          ]
        | @tsv
    ' <<<"$1" 2>/dev/null
}

# The digest of a version: the API's `name` field carries it.
version_digest() { # version_digest <tsv line> -> the digest
    printf '%s' "$1" | cut -f2
}
version_id() { # version_id <tsv line>
    printf '%s' "$1" | cut -f1
}
version_created() { # version_created <tsv line>
    printf '%s' "$1" | cut -f3
}
version_tags() { # version_tags <tsv line>
    printf '%s' "$1" | cut -f4
}

# The raw manifest of a digest, or nothing when it cannot be read.
manifest_raw() { # manifest_raw <package> <digest>
    docker buildx imagetools inspect "ghcr.io/${OWNER,,}/$1@$2" --raw 2>/dev/null || true
}

# The subject of an attestation manifest: the digest it vouches for.
# Empty for anything that is not an attestation.
attestation_subject() { # attestation_subject <package> <digest>
    manifest_raw "$1" "$2" | jq -r '.subject.digest // empty' 2>/dev/null || true
}

# --- per package --------------------------------------------------------------

process_package() { # process_package <package>
    local pkg="$1"
    local page=1
    local page_json=""
    local status
    local tsv
    local line
    local versions_file="$WORK/versions.$pkg"

    echo
    echo "=== ${OWNER}/${pkg} ==="
    : >"$versions_file"

    # --- collect the pages ---------------------------------------------------
    while :; do
        set +e
        page_json="$(gh api -H "Accept: application/vnd.github+json" \
            "${API_ROOT}/${OWNER}/packages/container/${pkg}/versions?per_page=100&page=${page}" \
            2>"$ERR_FILE")"
        status=$?
        set -e
        if [ "$status" -ne 0 ] || [ -z "$page_json" ]; then
            local gh_err
            gh_err="$(cat "$ERR_FILE" 2>/dev/null || true)"
            case "$gh_err" in
                *"404"*)
                    if [ "$page" -eq 1 ]; then
                        echo "  skip: $pkg not found on ${API_ROOT}/${OWNER}" >&2
                        echo "         (does it exist? token can read it?)" >&2
                        packages_skipped=$((packages_skipped + 1))
                        return 1
                    fi
                    echo "  page $page returned 404: assuming end-of-list"
                    break
                    ;;
                *"403"*)
                    if [ "$page" -eq 1 ]; then
                        echo "  skip: $pkg private/no read access (403)" >&2
                        echo "         (use a PAT with packages:read.)" >&2
                        packages_skipped=$((packages_skipped + 1))
                        return 1
                    fi
                    break
                    ;;
                *)
                    printf '%s\n' "$gh_err" | sed 's/^/  gh: /' >&2
                    printf '%s\n' "$page_json" | head -c 200 | sed 's/^/  body: /' >&2 || true
                    echo "  skip: $pkg: gh api exited $status" >&2
                    packages_skipped=$((packages_skipped + 1))
                    return 1
                    ;;
            esac
        fi

        # The response has to be the documented shape. A page that is not
        # an array is an unknown response; treating its versions as
        # untagged would delete them.
        if ! printf '%s' "$page_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
            echo "  skip: $pkg: the version list on page $page does not match the expected schema" >&2
            packages_skipped=$((packages_skipped + 1))
            return 1
        fi
        tsv="$(parse_versions "$page_json")" || {
            echo "  skip: $pkg: the version list on page $page does not match the expected schema" >&2
            packages_skipped=$((packages_skipped + 1))
            return 1
        }
        # Every line must carry the four fields; a short line means the
        # response is not what the API documents.
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            if [ "$(printf '%s' "$line" | awk -F'\t' '{print NF}')" -ne 4 ]; then
                echo "  skip: $pkg: a version on page $page does not match the expected schema" >&2
                packages_skipped=$((packages_skipped + 1))
                return 1
            fi
            printf '%s\n' "$line" >>"$versions_file"
        done <<<"$tsv"

        local count
        count="$(printf '%s' "$page_json" | jq 'length' 2>/dev/null || echo 0)"
        if [ "$count" -lt 100 ]; then
            break
        fi
        page=$((page + 1))
    done

    packages_processed=$((packages_processed + 1))

    # --- the protected set ---------------------------------------------------
    # The digests that must survive: the index of every kept tag, the
    # children that index points at, the attestation manifests, and the
    # subjects those attestations vouch for.
    : >"$REF_FILE"
    local protected
    protected=0
    if [ "$PRUNE_UNTAGGED" = "true" ]; then
        echo "${GH_TOKEN:-}" | docker login ghcr.io -u "${OWNER}" --password-stdin >/dev/null 2>&1 || true
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            local tags digest
            tags="$(version_tags "$line")"
            digest="$(version_digest "$line")"
            [ -n "$digest" ] || continue
            # A kept tag: its own digest and the digests of its children.
            local tag
            local has_kept=false
            local IFS_SAVE="$IFS"
            IFS=','
            for tag in $tags; do
                case "$tag" in
                    "" | null | sha-*) ;;
                    *) has_kept=true ;;
                esac
            done
            IFS="$IFS_SAVE"
            if [ "$has_kept" = "true" ]; then
                local ref="ghcr.io/${OWNER,,}/${pkg}:${tags%%,*}"
                # The index's own digest ...
                docker buildx imagetools inspect "$ref" --format '{{ .Manifest.Digest }}' 2>/dev/null \
                    >>"$REF_FILE" || true
                # ... and the digests of the children it points at.
                docker buildx imagetools inspect "$ref" --raw 2>/dev/null \
                    | jq -r 'select(.manifests) | .manifests[].digest' 2>/dev/null >>"$REF_FILE" || true
                protected=$((protected + 1))
            fi
        done <"$versions_file"
    fi

    # The attestation manifests: an untagged version of their own that
    # vouches for the image manifest named in its `subject`. Both are
    # protected: deleting the attestation breaks `gh attestation verify`,
    # deleting the subject breaks the attestation.
    if [ "$PRUNE_UNTAGGED" = "true" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            [ -z "$(version_tags "$line")" ] || continue
            local digest subject
            digest="$(version_digest "$line")"
            [ -n "$digest" ] || continue
            subject="$(attestation_subject "$pkg" "$digest")"
            if [ -n "$subject" ]; then
                printf '%s\n' "$digest" >>"$REF_FILE"
                printf '%s\n' "$subject" >>"$REF_FILE"
                protected=$((protected + 1))
            fi
        done <"$versions_file"
        local ref_count
        ref_count="$(sort -u "$REF_FILE" | wc -l | tr -d ' ')"
        echo "  protected set: ${ref_count} digest(s)"
        if [ "$ref_count" -eq 0 ]; then
            echo "  fail-closed: untagged versions are KEPT for this package" >&2
            PRUNE_UNTAGGED=false
        fi
    fi

    # --- the walk ------------------------------------------------------------
    local deleted_total=0
    local real_deleted_total=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local id tags created_at created_epoch reason
        id="$(version_id "$line")"
        tags="$(version_tags "$line")"
        [ -n "$id" ] || continue

        if [ -n "$tags" ]; then
            # Has at least one real tag. Keep if any non-sha-* tag is
            # present (externally consumed via latest/main/semver).
            local keep=false
            local IFS_SAVE="$IFS"
            IFS=','
            local tag
            for tag in $tags; do
                case "$tag" in
                    "" | null | sha-*) ;;
                    *) keep=true ;;
                esac
            done
            IFS="$IFS_SAVE"
            if [ "$keep" = "true" ]; then
                continue
            fi
            created_at="$(version_created "$line")"
            created_epoch="$(iso_epoch "$created_at")" || {
                echo "  skip: id=$id: unparseable created_at: ${created_at}" >&2
                continue
            }
            if [ "$created_epoch" -ge "$CUTOFF" ]; then continue; fi
            reason="sha-*-only, created_at=$created_at"
        else
            # Untagged: by default KEEP, it is a child/attestation of a
            # live index. The opt-in path deletes only orphans that
            # (a) no kept tag's manifest list references and
            # (b) are older than the retention window (grace against
            # a merge job running concurrently).
            if [ "$PRUNE_UNTAGGED" != "true" ]; then continue; fi
            local digest
            digest="$(version_digest "$line")"
            if [ -n "$digest" ] && grep -qxF "$digest" "$REF_FILE" 2>/dev/null; then
                continue   # referenced by a kept tag, not an orphan
            fi
            created_at="$(version_created "$line")"
            created_epoch="$(iso_epoch "$created_at")" || {
                echo "  skip: id=$id, unparseable created_at: ${created_at}" >&2
                continue
            }
            if [ "$created_epoch" -ge "$CUTOFF" ]; then continue; fi
            reason="untagged orphan (not referenced by any kept tag), created_at=$created_at"
        fi

        if [ "$DRY_RUN" = "true" ]; then
            echo "  [dry-run] would delete id=$id: $reason"
        else
            echo "  deleting id=$id: $reason"
            set +e
            gh api -X DELETE \
                -H "Accept: application/vnd.github+json" \
                "${API_ROOT}/${OWNER}/packages/container/${pkg}/versions/${id}" \
                2>"$ERR_FILE"
            status=$?
            set -e
            if [ "$status" -ne 0 ] && grep -q "404" "$ERR_FILE"; then
                echo "  (already gone: race with another job)"
            elif [ "$status" -ne 0 ]; then
                printf '%s\n' "$(cat "$ERR_FILE")" | sed 's/^/  gh: /' >&2
                echo "  error: gh api DELETE exited with status $status" >&2
                break
            else
                real_deleted_total=$((real_deleted_total + 1))
            fi
        fi
        deleted_total=$((deleted_total + 1))
    done <"$versions_file"

    if [ "$DRY_RUN" = "true" ]; then
        echo "  $pkg: $deleted_total version(s) would be deleted"
    else
        echo "  $pkg: $deleted_total version(s) deleted"
    fi
    echo "  $pkg: $protected protected digest(s)"
    return 0
}

for pkg in ${PACKAGES//,/ }; do
    [ -n "$pkg" ] || continue
    process_package "$pkg" || true
done

echo
echo "packages processed: ${packages_processed}, skipped: ${packages_skipped}"
if [ "$packages_processed" -eq 0 ]; then
    echo "error: no package was processed; the cleanup did nothing" >&2
    exit 1
fi
echo "Done."
