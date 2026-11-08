#!/usr/bin/env bash
# Incomplete inventories or manifest graphs must never authorize deletion.
set -euo pipefail

OWNER=""
PACKAGES=""
RETENTION_DAYS=30
DRY_RUN=true
PRUNE_UNTAGGED=false

usage() {
    echo 'usage: scripts/cleanup-ghcr.sh --owner <name> --packages a,b [--retention-days 1-365] [--dry-run|--no-dry-run] [--prune-untagged]' >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --owner|--packages|--retention-days)
            [ $# -ge 2 ] || { usage; exit 64; }
            case "$1" in
                --owner) OWNER="$2" ;;
                --packages) PACKAGES="$2" ;;
                --retention-days) RETENTION_DAYS="$2" ;;
            esac
            shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --no-dry-run) DRY_RUN=false; shift ;;
        --prune-untagged) PRUNE_UNTAGGED=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage; exit 64 ;;
    esac
done

if ! [[ "$OWNER" =~ ^[A-Za-z0-9-]+$ ]] || [ -z "$PACKAGES" ]; then
    usage
    exit 64
fi
if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || [ "$RETENTION_DAYS" -lt 1 ] || [ "$RETENTION_DAYS" -gt 365 ]; then
    echo '::error::retention_days must be an integer in [1, 365]' >&2
    printf 'retention_days as given: %q\n' "$RETENTION_DAYS" >&2
    exit 1
fi
MAX_INSPECTS="${FUMOX_GHCR_MAX_INSPECTS:-200}"
if ! [[ "$MAX_INSPECTS" =~ ^[0-9]+$ ]] || [ "$MAX_INSPECTS" -lt 1 ]; then
    echo 'error: FUMOX_GHCR_MAX_INSPECTS must be a positive integer' >&2
    exit 64
fi

if date -u -d '@0' +%s >/dev/null 2>&1; then
    DATE_FLAVOUR=gnu
    CUTOFF="$(date -u -d "-$RETENTION_DAYS days" +%s)"
else
    DATE_FLAVOUR=bsd
    CUTOFF="$(date -u -v-"${RETENTION_DAYS}"d +%s)"
fi
iso_epoch() {
    local value="$1"
    case "$value" in *.*Z) value="${value%%.*}Z" ;; esac
    if [ "$DATE_FLAVOUR" = gnu ]; then
        date -u -d "$value" +%s
    else
        date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$value" +%s
    fi
}

detect_api_root() {
    local type=""
    if type="$(gh api "/users/${OWNER}" --jq .type 2>/dev/null)"; then
        case "$type" in
            Organization) echo /orgs; return ;;
            User) echo /users; return ;;
        esac
    fi
    if gh api "/orgs/${OWNER}" --jq .type >/dev/null 2>&1; then
        echo /orgs
    else
        echo /users
    fi
}
API_ROOT="$(detect_api_root)"
echo "Owner ${OWNER} → ${API_ROOT}/${OWNER}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fumox-ghcr-cleanup.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ERR_FILE="$WORK/err"

run_with_timeout() {
    local seconds="$1" pid ticks=0
    shift
    "$@" &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$ticks" -ge "$((seconds * 10))" ]; then
            kill "$pid" 2>/dev/null || true
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
        ticks=$((ticks + 1))
    done
    wait "$pid"
}

get_manifest() {
    local digest="$1"
    MANIFEST="$package_work/$digest.json"
    [ ! -f "$MANIFEST" ] || return 0
    if [ "$inspections" -ge "$MAX_INSPECTS" ]; then
        echo "error: inspection cap ($MAX_INSPECTS) reached; no versions deleted for $pkg" >&2
        return 1
    fi
    inspections=$((inspections + 1))
    if ! run_with_timeout 60 docker buildx imagetools inspect "ghcr.io/${OWNER,,}/${pkg}@${digest}" --raw >"$MANIFEST.tmp"; then
        echo "error: cannot inspect $digest; no versions deleted for $pkg" >&2
        return 1
    fi
    if ! jq -e '
        def digest: type == "string" and test("^sha256:[0-9a-f]{64}$");
        type == "object" and .schemaVersion == 2
        and (has("manifests") or has("config"))
        and (if has("manifests") then
            (.manifests | type == "array" and length > 0 and all(.[]; .digest | digest))
            else (.config.digest | digest) and (.layers | type == "array") end)
        and (if has("subject") then (.subject.digest | digest) else true end)
    ' "$MANIFEST.tmp" >/dev/null; then
        echo "error: invalid manifest $digest; no versions deleted for $pkg" >&2
        return 1
    fi
    mv "$MANIFEST.tmp" "$MANIFEST" || return 1
}

protect_digest() {
    local digest="$1" reference refs
    if grep -qxF "$digest" "$protected_file"; then return 0; fi
    printf '%s\n' "$digest" >>"$protected_file" || return 1
    get_manifest "$digest" || return 1
    refs="$package_work/$digest.refs"
    jq -r '.manifests[]?.digest, .subject.digest? | select(. != null)' "$MANIFEST" >"$refs" || return 1
    while IFS= read -r reference; do
        protect_digest "$reference" || return 1
    done <"$refs"
}

process_package() {
    local pkg="$1" page=1 count line id digest created tags epoch tag keep
    local package_work="$WORK/$pkg" inspections=0 MANIFEST
    local versions_file="$package_work/versions" protected_file="$package_work/protected"
    local candidates="$package_work/candidates" roots="$package_work/roots"
    local tag_list=()
    if ! [[ "$pkg" =~ ^[a-z0-9][a-z0-9._-]*$ ]]; then
        echo 'error: invalid package name' >&2
        return 1
    fi
    mkdir -p "$package_work" || return 1
    : >"$versions_file" || return 1
    : >"$protected_file" || return 1
    : >"$candidates" || return 1
    : >"$roots" || return 1
    echo "=== ${OWNER}/${pkg} ==="
    while :; do
        if ! gh api -H 'Accept: application/vnd.github+json' \
            "${API_ROOT}/${OWNER}/packages/container/${pkg}/versions?per_page=100&page=${page}" \
            >"$package_work/page.json" 2>"$ERR_FILE"; then
            cat "$ERR_FILE" >&2
            echo "error: incomplete inventory on page $page; no versions deleted for $pkg" >&2
            return 1
        fi
        if ! jq -e '
            type == "array" and all(.[];
                (.id | type == "number" and . > 0 and floor == .)
                and (.name | type == "string" and test("^sha256:[0-9a-f]{64}$"))
                and (.created_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$"))
                and (.metadata.container.tags | type == "array"
                    and all(.[]; type == "string" and test("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"))))
        ' "$package_work/page.json" >/dev/null; then
            echo "error: version list on page $page does not match the expected schema" >&2
            return 1
        fi
        jq -r '.[] | [.id, .name, .created_at, (.metadata.container.tags | join(","))] | @tsv' \
            "$package_work/page.json" >>"$versions_file" || return 1
        count="$(jq length "$package_work/page.json")" || return 1
        [ "$count" -ge 100 ] || break
        page=$((page + 1))
    done

    while IFS=$'\t' read -r id digest created tags; do
        [ -n "$id" ] || continue
        epoch="$(iso_epoch "$created")" || return 1
        if [ -n "$tags" ]; then
            keep=false
            IFS=',' read -r -a tag_list <<<"$tags"
            for tag in "${tag_list[@]}"; do
                # sha256-* tags can be OCI referrer fallback indexes, not disposable builds.
                case "$tag" in sha-*) ;; *) keep=true ;; esac
            done
            if [ "$keep" = true ] || [ "$epoch" -ge "$CUTOFF" ]; then
                printf '%s\n' "$digest" >>"$roots" || return 1
            else
                printf '%s\t%s\n' "$id" "$digest" >>"$candidates" || return 1
            fi
        elif [ "$PRUNE_UNTAGGED" = true ] && [ "$epoch" -lt "$CUTOFF" ]; then
            printf '%s\t%s\n' "$id" "$digest" >>"$candidates" || return 1
        else
            printf '%s\n' "$digest" >>"$roots" || return 1
        fi
    done <"$versions_file"

    if [ -n "${GH_TOKEN:-}" ]; then
        if ! printf '%s\n' "$GH_TOKEN" | docker login ghcr.io -u "$OWNER" --password-stdin >/dev/null; then
            echo "error: registry login failed; no versions deleted for $pkg" >&2
            return 1
        fi
    fi
    while IFS= read -r digest; do
        protect_digest "$digest" || return 1
    done <"$roots"
    if [ "$PRUNE_UNTAGGED" = true ]; then
        while IFS=$'\t' read -r id digest created tags; do
            [ -z "$tags" ] || continue
            get_manifest "$digest" || return 1
            if jq -e 'has("subject")' "$MANIFEST" >/dev/null; then
                protect_digest "$digest" || return 1
            fi
        done <"$versions_file"
    fi

    while IFS=$'\t' read -r id digest; do
        if grep -qxF "$digest" "$protected_file"; then continue; fi
        if [ "$DRY_RUN" = true ]; then
            echo "  [dry-run] would delete id=$id: $digest"
        elif gh api -X DELETE -H 'Accept: application/vnd.github+json' \
            "${API_ROOT}/${OWNER}/packages/container/${pkg}/versions/${id}" 2>"$ERR_FILE"; then
            echo "  deleted id=$id: $digest"
        elif grep -q 'HTTP 404' "$ERR_FILE"; then
            echo "  already gone: id=$id"
        else
            cat "$ERR_FILE" >&2
            echo "error: DELETE failed for id=$id" >&2
            return 1
        fi
    done <"$candidates"
}

packages_processed=0
packages_skipped=0
for pkg in ${PACKAGES//,/ }; do
    if process_package "$pkg"; then
        packages_processed=$((packages_processed + 1))
    else
        packages_skipped=$((packages_skipped + 1))
    fi
done
echo "packages processed: ${packages_processed}, skipped: ${packages_skipped}"
if [ "$packages_skipped" -ne 0 ] || [ "$packages_processed" -eq 0 ]; then
    echo 'error: cleanup did not complete for every package' >&2
    exit 1
fi
echo 'Done.'
