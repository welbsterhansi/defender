#!/usr/bin/env bash
# Target runtime: Linux / WSL on the client (bash 4+ guaranteed).
# `env bash` keeps this portable across dev machines.
#
# Strict mode: every failure is fatal by default. Commands that may legitimately
# return non-zero (grep with no match, az with 2>/dev/null, etc.) are wrapped
# with `|| true` or checked in an `if`. `pipefail` catches upstream failures
# in pipelines that end with `head`, `tr`, etc.
set -euo pipefail

# Default values:
MIN_SCORE=9
MAX_SCORE=10
REPOSITORY=""
REPOSITORIES=""
ACR_NAME=""
DRY_RUN=false
DEBUG=false
AUTO_APPROVE=false
BLOCK_IMAGES=false
UNBLOCK=false
UNBLOCK_ALL=false
LIST_BLOCKED=false
IMAGE=""
SCAN_IMAGE=""
REPORT_FILE="vulnerable_images_report.csv"

# Function to classify severity based on CVSS score
# CVSS v3.0 severity ratings:
#   Critical: 9.0 - 10.0
#   High:     7.0 - 8.9
#   Medium:   4.0 - 6.9
#   Low:      0.1 - 3.9
#   None:     0.0

# ---------------------------------------------------------------------------
# CSV row helper — escapes embedded quotes and collapses newlines
# ---------------------------------------------------------------------------
csv_field() {
    local v="$1"
    v="${v//\"/\'}"
    v="${v//$'\n'/ }"
    v="${v//$'\r'/ }"
    printf '"%s"' "$v"
}

csv_write_row() {
    local sep="" f
    for f in "$@"; do
        printf '%s' "${sep}$(csv_field "$f")"
        sep=","
    done
    printf '\n'
}

classify_severity() {
    local score=$1
    if (( $(echo "$score >= 9.0" | bc -l) )); then
        echo "Critical"
    elif (( $(echo "$score >= 7.0" | bc -l) )); then
        echo "High"
    elif (( $(echo "$score >= 4.0" | bc -l) )); then
        echo "Medium"
    elif (( $(echo "$score > 0" | bc -l) )); then
        echo "Low"
    else
        echo "None"
    fi
}

# ---------------------------------------------------------------------------
# Elapsed-time helper for per-page instrumentation (task #42, PR-0).
# Preferred source: bash 5's $EPOCHREALTIME (seconds.microseconds).
# Fallback: `date +%s.%N` from GNU coreutils (Linux/WSL — the client's
# runtime — is guaranteed to have it). BSD `date` (macOS default) returns
# a literal `%N`; we detect and degrade to 0 so ms fields stay parseable.
# ---------------------------------------------------------------------------
_now_realtime() {
    if [ -n "${EPOCHREALTIME:-}" ]; then
        printf '%s' "$EPOCHREALTIME"
        return
    fi
    local ts
    ts=$(date +%s.%N 2>/dev/null || echo "0")
    case "$ts" in
        *%N|""|0) printf '0' ;;   # BSD date or no date
        *)        printf '%s' "$ts" ;;
    esac
}
_elapsed_ms() {
    local start="${1:-0}"
    local now
    now=$(_now_realtime)
    awk -v s="$start" -v n="$now" 'BEGIN {
        if (s == "" || s == "0" || n == "0") { print 0; exit }
        d = n - s
        if (d < 0) d = 0
        printf "%d", d * 1000
    }'
}

# ---------------------------------------------------------------------------
# List repositories with an explicit upper bound (default `az acr repository
# list` returns only 100). 5000 is the server-side max for the wrapper; if
# an ACR ever grows beyond that a warning is emitted so the operator can
# switch to REST `_catalog` pagination via `az rest`.
# ---------------------------------------------------------------------------
ACR_REPO_PAGE_LIMIT=5000
list_all_repositories() {
    local acr="$1"
    local repos
    repos=$(az acr repository list --name "$acr" --top "$ACR_REPO_PAGE_LIMIT" \
              --output tsv 2>/dev/null)
    local count
    count=$(printf '%s\n' "$repos" | grep -c . || true)
    if [ "$count" -ge "$ACR_REPO_PAGE_LIMIT" ]; then
        echo "WARNING: repository list hit the ${ACR_REPO_PAGE_LIMIT} row limit." >&2
        echo "         Some repositories may be missing from the scan." >&2
        echo "         Consider REST-based pagination via 'az rest' for this ACR." >&2
    fi
    # Avoid trailing empty line when the registry is empty.
    [ -n "$repos" ] && printf '%s\n' "$repos"
}

# ---------------------------------------------------------------------------
# Convert an ACR repository path to the dashed form used inside Defender's
# `resourceDetails.Id` for `SoftwareUpdate` assessments (Leg B of the KQL).
# Example: "base-images/ubi9-openjdk17" → "base-images-ubi9-openjdk17".
# Extracted so both filter sites use the same conversion and the intent is
# obvious at the call site.
# ---------------------------------------------------------------------------
repo_to_dashed_path() {
    printf '%s' "$1" | tr '/' '-'
}

# ---------------------------------------------------------------------------
# Parse a comma-separated repository list into one-per-line output.
# Strict semantics (task #38 — --repositories is a CONTROLLED list):
#   - trim whitespace on each entry
#   - empty entries (e.g. `app,,payments` or trailing comma) → exit 2
#   - duplicate entries → exit 2
# Errors go to stderr so the caller can surface them; stdout stays clean.
# Example (ok):     "  app , payments , catalog " → "app\npayments\ncatalog"
# Example (fail):   "app,,payments"               → exit 2, "empty entry" stderr
# Example (fail):   "app,payments,app"            → exit 2, "duplicate: app" stderr
# ---------------------------------------------------------------------------
parse_repo_list() {
    local raw="$1"
    local -a items=()
    local -A seen=()
    local field trimmed
    # Piping through `tr ','` preserves empty fields (including trailing ones)
    # unlike a bash for-loop with IFS=',' which silently drops them.
    while IFS= read -r field; do
        trimmed="${field#"${field%%[![:space:]]*}"}"   # ltrim
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}" # rtrim
        if [ -z "$trimmed" ]; then
            echo "Error: --repositories has an empty entry (check for trailing commas or ',,')" >&2
            return 2
        fi
        if [ -n "${seen[$trimmed]:-}" ]; then
            echo "Error: --repositories has a duplicate entry: '$trimmed'" >&2
            return 2
        fi
        seen[$trimmed]=1
        items+=("$trimmed")
    done < <(printf '%s\n' "$raw" | tr ',' '\n')
    if [ "${#items[@]}" -eq 0 ]; then
        echo "Error: --repositories is empty" >&2
        return 2
    fi
    printf '%s\n' "${items[@]}"
}

# ---------------------------------------------------------------------------
# Build a KQL exact-match list filter for Leg A.
#   build_repos_in_expr "prop.name" app payments  →
#     prop.name in ("app", "payments")
# Returns empty string when no repos are passed.
# ---------------------------------------------------------------------------
build_repos_in_expr() {
    local prop="$1"; shift
    [ "$#" -eq 0 ] && { printf ''; return 0; }
    local expr="${prop} in (" sep=""
    for r in "$@"; do
        expr+="${sep}\"${r}\""
        sep=", "
    done
    expr+=")"
    printf '%s' "$expr"
}

# ---------------------------------------------------------------------------
# Build an anchored Leg B filter that emulates exact match against the
# `repositories-<dashed>-images-` segment inside `resourceDetails.Id`.
# The `repositories-…-images-` bracketing guarantees `app` does NOT capture
# `app-backend` or `myapp` (the shorter substring cannot appear between
# those anchors for a different repo).
#   build_repos_id_anchor_expr "prop.Id" app team/service  →
#     prop.Id contains "repositories-app-images-"
#       or prop.Id contains "repositories-team-service-images-"
# ---------------------------------------------------------------------------
build_repos_id_anchor_expr() {
    local prop="$1"; shift
    [ "$#" -eq 0 ] && { printf ''; return 0; }
    local expr="" sep="" dashed
    for r in "$@"; do
        dashed=$(repo_to_dashed_path "$r")
        expr+="${sep}${prop} contains \"repositories-${dashed}-images-\""
        sep=" or "
    done
    printf '%s' "$expr"
}

# ---------------------------------------------------------------------------
# Wrap `az graph query` with retry+backoff and JSON validation. On success
# populates two globals (LAST_QUERY_RESPONSE, LAST_QUERY_RETRIES) so the
# caller can invoke the function directly without command substitution —
# `$(...)` would spawn a subshell and swallow those side effects.
#
# Returns 0 on success, non-zero after 3 failed attempts.
# Failures counted: az exit != 0, OR stdout not parseable as JSON, OR the
# expected `.data` field is missing (indicates a malformed response).
# Backoff: 2s after 1st failure, 5s after 2nd. No sleep after last attempt.
# ---------------------------------------------------------------------------
LAST_QUERY_RESPONSE=""
LAST_QUERY_RETRIES=0
run_graph_query() {
    local query_file="$1"
    local skip_token="${2:-}"
    local delays=(2 5)
    local az_stderr response rc
    LAST_QUERY_RESPONSE=""
    LAST_QUERY_RETRIES=0

    for attempt in 1 2 3; do
        az_stderr=$(mktemp)
        if [ -z "$skip_token" ]; then
            response=$(az graph query -q "$(cat "$query_file")" \
                        --first 1000 --output json 2>"$az_stderr")
        else
            response=$(az graph query -q "$(cat "$query_file")" \
                        --first 1000 --skip-token "$skip_token" \
                        --output json 2>"$az_stderr")
        fi
        rc=$?
        if [ "$rc" -eq 0 ] && printf '%s' "$response" | jq -e '.data' >/dev/null 2>&1; then
            rm -f "$az_stderr"
            LAST_QUERY_RESPONSE="$response"
            return 0
        fi
        local err_preview
        err_preview=$(head -c 300 "$az_stderr" 2>/dev/null)
        rm -f "$az_stderr"
        LAST_QUERY_RETRIES=$attempt
        log_warn "az graph query attempt ${attempt}/3 failed rc=${rc}: ${err_preview:-<empty stderr, invalid JSON?>}"
        if [ "$attempt" -lt 3 ]; then
            local delay="${delays[$((attempt-1))]}"
            log_info "az graph query retry backoff=${delay}s"
            sleep "$delay"
        fi
    done
    return 1
}

# Function to display usage
usage() {
    echo "Usage: $0 --acr-name <ACR_NAME> [--min-score <SCORE>] [--max-score <SCORE>] [--repository <REPOSITORY>] [--dry-run] [--block-images] [--unblock]"
    echo ""
    echo "Arguments:"
    echo "  --acr-name, -a       Name of the Azure Container Registry (Required)"
    echo "  --min-score          Minimum CVSS score to filter (Default: 9)"
    echo "  --max-score          Maximum CVSS score to filter (Default: 10)"
    echo "  --repository, -r     Broad substring filter — single repo, uses 'contains' (Optional)"
    echo "                       e.g. --repository app  matches 'app', 'app-backend', 'myapp'"
    echo "  --repositories       Controlled EXACT list of repositories (comma-separated)"
    echo "                       e.g. --repositories app-backend,payments-api,catalog-svc"
    echo "                       - each entry must exist exactly in the ACR (validated up front)"
    echo "                       - empty (',,') or duplicate entries abort the run"
    echo "                       - deterministic scope: 'app' does NOT capture 'app-backend'"
    echo "                       Mutually exclusive with --repository and --scan-image"
    echo "  --dry-run, -d        Print commands without executing"
    echo "  --block-images       BLOCK vulnerable images (default: report only)"
    echo "  --unblock            UNBLOCK vulnerable images based on CVE query"
    echo "  --unblock-all        UNBLOCK all blocked images in ACR or repository"
    echo "  --image <IMAGE>      Specific image to unblock (format: repo@sha256:digest)"
    echo "  --scan-image <IMAGE> Scan for CVEs (formats: repo, repo:tag, repo@sha256:digest)"
    echo "  --list-blocked       List all blocked images in ACR (or specific repository)"
    echo "  --auto-approve       Skip confirmation prompt (use with caution!)"
    echo "  --debug              Print generated KQL query and run diagnostic ARG preview"
    echo "  --help, -h           Show this help message"
    echo ""
    echo "CVSS Score Classification (automatic):"
    echo "  Critical:  9.0 - 10.0"
    echo "  High:      7.0 - 8.9"
    echo "  Medium:    4.0 - 6.9"
    echo "  Low:       0.1 - 3.9"
    echo "  None:      0.0"
    echo ""
    echo "Examples:"
    echo "  # Report all Critical CVEs (score >= 9.0)"
    echo "  $0 --acr-name myacr --min-score 9"
    echo ""
    echo "  # Report High and Critical CVEs (score >= 7.0)"
    echo "  $0 --acr-name myacr --min-score 7"
    echo ""
    echo "  # Report only High CVEs (score between 7.0 and 8.9)"
    echo "  $0 --acr-name myacr --min-score 7 --max-score 8.9"
    echo ""
    echo "  # Report Medium CVEs (score between 4.0 and 6.9)"
    echo "  $0 --acr-name myacr --min-score 4 --max-score 6.9"
    echo ""
    echo "  # Block all Critical CVEs in a specific repository"
    echo "  $0 --acr-name myacr --min-score 9 --repository myapp --block-images"
    echo ""
    echo "  # Dry-run: simulate blocking without making changes"
    echo "  $0 --acr-name myacr --min-score 9 --repository myapp --block-images --dry-run"
    echo ""
    echo "  # List all blocked images in the ACR"
    echo "  $0 --acr-name myacr --list-blocked"
    echo ""
    echo "  # List blocked images in a specific repository"
    echo "  $0 --acr-name myacr --repository myapp --list-blocked"
    echo ""
    echo "  # Unblock a specific image"
    echo "  $0 --acr-name myacr --image myapp@sha256:abc123..."
    echo ""
    echo "  # Unblock all blocked images in a specific repository"
    echo "  $0 --acr-name myacr --repository myapp --unblock-all"
    echo ""
    echo "  # Unblock all blocked images in the entire ACR"
    echo "  $0 --acr-name myacr --unblock-all"
    echo ""
    echo "  # Dry-run: simulate unblocking all images in a repository"
    echo "  $0 --acr-name myacr --repository myapp --unblock-all --dry-run"
    echo ""
    echo "  # Scan all tags of a repository"
    echo "  $0 --acr-name myacr --scan-image base-images/ubi9-openjdk17 --min-score 9"
    echo ""
    echo "  # Scan a specific tag"
    echo "  $0 --acr-name myacr --scan-image base-images/ubi9-openjdk17:latest --min-score 9"
    echo ""
    echo "  # Scan a specific digest"
    echo "  $0 --acr-name myacr --scan-image base-images/ubi9-openjdk17@sha256:abc123..."
    echo ""
    echo "  # Scan a curated list of repositories (multi-repo report)"
    echo "  $0 --acr-name myacr --min-score 9 --repositories app,payments,catalog"
    echo ""
    echo "By default, this script only generates a CSV report without blocking any images."
    exit 1
}

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --acr-name|-a) ACR_NAME="$2"; shift ;;
        --min-score) MIN_SCORE="$2"; shift ;;
        --max-score) MAX_SCORE="$2"; shift ;;
        --repository|-r) REPOSITORY="$2"; shift ;;
        --repositories) REPOSITORIES="$2"; shift ;;
        --dry-run|-d) DRY_RUN=true ;;
        --block-images) BLOCK_IMAGES=true ;;
        --unblock) UNBLOCK=true ;;
        --unblock-all) UNBLOCK_ALL=true ;;
        --image) IMAGE="$2"; shift ;;
        --scan-image) SCAN_IMAGE="$2"; shift ;;
        --list-blocked) LIST_BLOCKED=true ;;
        --auto-approve) AUTO_APPROVE=true ;;
        --debug) DEBUG=true ;;
        --help|-h) usage ;;
        *) echo "Unknown parameter passed: $1"; usage ;;
        esac
    shift
done

# Validate required arguments
if [ -z "$ACR_NAME" ]; then
    echo "Error: --acr-name is required."
    usage
fi

# Best-effort structured logging. Never gates the scan: if logs/ or the
# file are unusable, init_logging logs a WARN and lets us keep running.
# Compute mode first so the header + start line are meaningful.
if [ "$LIST_BLOCKED" = true ];  then _LOG_MODE="list-blocked"
elif [ -n "$IMAGE" ];            then _LOG_MODE="unblock-single"
elif [ "$UNBLOCK_ALL" = true ];  then _LOG_MODE="unblock-all"
elif [ "$UNBLOCK" = true ];      then _LOG_MODE="unblock"
elif [ "$BLOCK_IMAGES" = true ]; then _LOG_MODE="block"
elif [ -n "$SCAN_IMAGE" ];       then _LOG_MODE="scan-image"
else                                  _LOG_MODE="report-only"
fi
[ "$DRY_RUN" = true ] && _LOG_MODE="${_LOG_MODE}+dry-run"

# shellcheck source=lib/logging.sh
source "$(dirname "$0")/lib/logging.sh"
init_logging "defender.sh" "$_LOG_MODE" \
    --acr-name "$ACR_NAME" \
    --min-score "$MIN_SCORE" --max-score "$MAX_SCORE" \
    ${REPOSITORY:+--repository "$REPOSITORY"} \
    ${REPOSITORIES:+--repositories "$REPOSITORIES"} \
    ${SCAN_IMAGE:+--scan-image "$SCAN_IMAGE"} \
    ${IMAGE:+--image "$IMAGE"}
log_info "start acr=$ACR_NAME mode=$_LOG_MODE score_range=${MIN_SCORE}..${MAX_SCORE}"

# --repository, --repositories and --scan-image define the scan scope in
# incompatible ways. Refuse ambiguous combinations up front instead of letting
# a downstream filter silently ignore one of them.
_scope_flags=0
[ -n "$REPOSITORY" ]   && _scope_flags=$((_scope_flags + 1))
[ -n "$REPOSITORIES" ] && _scope_flags=$((_scope_flags + 1))
[ -n "$SCAN_IMAGE" ]   && _scope_flags=$((_scope_flags + 1))
if [ "$_scope_flags" -gt 1 ]; then
    echo "Error: --repository, --repositories and --scan-image are mutually exclusive." >&2
    echo "       Pick one scoping flag." >&2
    exit 1
fi

# Check prerequisites
if ! command -v az &> /dev/null; then
    echo "Error: Azure CLI ('az') not found. Please install it."
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "Error: jq not found. Please install it."
    exit 1
fi
if ! command -v bc &> /dev/null; then
    echo "Error: bc not found. Please install it."
    exit 1
fi

# Validate ACR exists
echo "Validating Azure Container Registry '$ACR_NAME'..."
if ! az acr show --name "$ACR_NAME" --output none 2>/dev/null; then
    echo "Error: ACR '$ACR_NAME' not found or you don't have access to it."
    echo "Please check the ACR name and your Azure permissions."
    exit 1
fi

# Validate repository exists (if provided)
# Note: We check if any repository contains the filter value, since the query uses 'contains'
if [ -n "$REPOSITORY" ]; then
    echo "Validating repository filter '$REPOSITORY'..."
    ALL_REPOS=$(list_all_repositories "$ACR_NAME")
    # grep returns 1 if no match — swallow so we fall through to the error
    # branch below with a clear message instead of the script just exiting.
    MATCHING_REPOS=$(echo "$ALL_REPOS" | grep -i "$REPOSITORY" | head -5 || true)
    if [ -z "$MATCHING_REPOS" ]; then
        echo "Error: No repositories matching '$REPOSITORY' found in ACR '$ACR_NAME'."
        echo "Use 'az acr repository list --name $ACR_NAME' to see available repositories."
        exit 1
    fi
    echo "Found matching repositories:"
    echo "$MATCHING_REPOS" | sed 's/^/  - /'
    # grep -c also returns 1 on no match — force 0.
    REPO_COUNT=$(echo "$ALL_REPOS" | grep -ic "$REPOSITORY" || true)
    if [ "$REPO_COUNT" -gt 5 ]; then
        echo "  ... and $((REPO_COUNT - 5)) more"
    fi
fi

# Validate --repositories list (if provided). CONTROLLED list semantics:
# each entry must exist EXACTLY in the ACR (no substring match). Empty or
# duplicate entries are caught in parse_repo_list and abort the run before
# we ever touch the query.
if [ -n "$REPOSITORIES" ]; then
    echo "Validating repositories filter '$REPOSITORIES'..."
    if ! _parsed=$(parse_repo_list "$REPOSITORIES"); then
        exit 1  # parse_repo_list already printed the reason to stderr
    fi

    ALL_REPOS=$(list_all_repositories "$ACR_NAME")
    missing=()
    while IFS= read -r _r; do
        # `-Fx` = fixed string, whole line — no regex, no substring, no
        # case folding. `app` will NOT match `myapp` or `app-backend`.
        if printf '%s\n' "$ALL_REPOS" | grep -qFx "$_r"; then
            printf '  - %s (exact match)\n' "$_r"
        else
            missing+=("$_r")
        fi
    done <<< "$_parsed"

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Error: repositories not found in '$ACR_NAME' (exact match): ${missing[*]}" >&2
        echo "       Available repositories can be listed with:" >&2
        echo "         az acr repository list --name $ACR_NAME --top 5000 --output tsv" >&2
        exit 1
    fi
fi

# Handle --scan-image: resolve tag to digest if needed
SCAN_REPOSITORY=""
SCAN_DIGEST=""
if [ -n "$SCAN_IMAGE" ]; then
    echo "Processing scan-image: $SCAN_IMAGE"

    # Check if it's a digest format (repo@sha256:...)
    if [[ "$SCAN_IMAGE" == *"@sha256:"* ]]; then
        SCAN_REPOSITORY="${SCAN_IMAGE%%@*}"
        SCAN_DIGEST="${SCAN_IMAGE#*@}"
        echo "  Repository: $SCAN_REPOSITORY"
        echo "  Digest: $SCAN_DIGEST"
    # Check if it's a tag format (repo:tag)
    elif [[ "$SCAN_IMAGE" == *":"* ]]; then
        SCAN_REPOSITORY="${SCAN_IMAGE%:*}"
        SCAN_TAG="${SCAN_IMAGE##*:}"
        echo "  Repository: $SCAN_REPOSITORY"
        echo "  Tag: $SCAN_TAG"
        echo "  Resolving tag to digest..."

        # Resolve tag → digest via `az acr manifest list-metadata` (the previous
        # `az acr repository show-manifests` was deprecated in Azure CLI 2.36+
        # and removed in later versions). Output shape is compatible: an array
        # of {digest, tags[...]} objects, so the same JMESPath filter applies.
        # tr -d '\r' strips CRLF that appears on Windows/Git Bash shells.
        # `|| true` swallows az failures / non-existent tags — the empty-check
        # below is the authoritative error path.
        SCAN_DIGEST=$(az acr manifest list-metadata \
            --name "$ACR_NAME" \
            --repository "$SCAN_REPOSITORY" \
            --query "[?tags[?@=='$SCAN_TAG']].digest | [0]" \
            --output tsv 2>/dev/null | tr -d '\r' || true)

        if [ -z "$SCAN_DIGEST" ]; then
            echo "Error: Could not find digest for tag '$SCAN_TAG' in repository '$SCAN_REPOSITORY'."
            echo "Please verify the image exists: az acr repository show-tags --name $ACR_NAME --repository $SCAN_REPOSITORY"
            exit 1
        fi
        echo "  Resolved digest: $SCAN_DIGEST"
    # Repository only format (repo/image) - scan all tags
    else
        SCAN_REPOSITORY="$SCAN_IMAGE"
        SCAN_DIGEST=""
        echo "  Repository: $SCAN_REPOSITORY"
        echo "  Mode: All tags (no specific digest filter)"
    fi

    # Validate repository exists
    if ! az acr repository show --name "$ACR_NAME" --repository "$SCAN_REPOSITORY" --output none 2>/dev/null; then
        echo "Error: Repository '$SCAN_REPOSITORY' not found in ACR '$ACR_NAME'."
        exit 1
    fi
    echo ""
fi

# Handle --list-blocked mode
if [ "$LIST_BLOCKED" = true ]; then
    echo ""
    echo "Listing blocked images in ACR '$ACR_NAME'..."
    echo "--------------------------------------------------"

    # Get list of repositories to check
    ALL_REPOS=$(list_all_repositories "$ACR_NAME")
    if [ -n "$REPOSITORY" ]; then
        REPOS_TO_CHECK=$(echo "$ALL_REPOS" | grep -i "$REPOSITORY" || true)
    else
        REPOS_TO_CHECK="$ALL_REPOS"
    fi

    BLOCKED_COUNT=0
    BLOCKED_REPORT="blocked_images_report.csv"
    echo '"repository","digest","createdTime","lastUpdateTime"' > "$BLOCKED_REPORT"

    for REPO in $REPOS_TO_CHECK; do
        # Get manifests with readEnabled=false
        BLOCKED_MANIFESTS=$(az acr manifest list-metadata --name "$ACR_NAME" --repository "$REPO" --query "[?readEnabled==\`false\`]" --output json 2>/dev/null || echo '[]')

        if [ -n "$BLOCKED_MANIFESTS" ] && [ "$BLOCKED_MANIFESTS" != "[]" ]; then
            # Extract fields in one jq pass (tab-separated) to avoid 3× base64 decodes.
            # Process substitution keeps BLOCKED_COUNT in the parent shell.
            while IFS=$'\t' read -r DIGEST CREATED UPDATED; do
                [ -z "$DIGEST" ] && continue
                echo "BLOCKED: ${REPO}@${DIGEST}"
                echo "\"$REPO\",\"$DIGEST\",\"$CREATED\",\"$UPDATED\"" >> "$BLOCKED_REPORT"
                BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
            done < <(echo "$BLOCKED_MANIFESTS" | jq -r '.[] | [.digest, (.createdTime // "N/A"), (.lastUpdateTime // "N/A")] | @tsv')
        fi
    done

    echo "--------------------------------------------------"
    # Use in-memory counter — avoids wc -l inflation when CSV fields contain newlines.
    echo "Total blocked images found: $BLOCKED_COUNT"
    if [ "$BLOCKED_COUNT" -gt 0 ]; then
        echo "Report saved to: $BLOCKED_REPORT"
    else
        rm -f "$BLOCKED_REPORT"
        echo "No blocked images found."
    fi
    exit 0
fi

# Handle --image mode (unblock a specific image)
if [ -n "$IMAGE" ]; then
    echo ""
    echo "Unblocking specific image: $IMAGE"
    echo "--------------------------------------------------"

    # Safety confirmation
    if [ "$DRY_RUN" = false ] && [ "$AUTO_APPROVE" = false ]; then
        YELLOW='\033[1;33m'
        NC='\033[0m'
        echo -e "${YELLOW}WARNING: You are about to UNBLOCK an image.${NC}"
        echo "This will allow clients to pull this image again."
        echo ""
        read -p "Are you sure you want to proceed? (yes/no): " CONFIRMATION
        if [[ ! "$CONFIRMATION" =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Operation cancelled by user."
            exit 0
        fi
        echo ""
    fi

    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Would unblock: $IMAGE"
        echo "Command: az acr repository update --name $ACR_NAME --image $IMAGE --read-enabled true"
    else
        # Under strict mode, chain success/failure directly (SC2181):
        # `if az ...; then ... else ... fi` is safer than checking `$?`.
        if az acr repository update --name "$ACR_NAME" --image "$IMAGE" --read-enabled true; then
            echo "Successfully unblocked: $IMAGE"
        else
            echo "Failed to unblock: $IMAGE"
        fi
    fi
    exit 0
fi

# Handle --unblock-all mode
if [ "$UNBLOCK_ALL" = true ]; then
    echo ""

    # Unblock all blocked images in repository or entire ACR
    if [ -n "$REPOSITORY" ]; then
        echo "Unblocking all blocked images matching '$REPOSITORY' in ACR '$ACR_NAME'..."
    else
        echo "Unblocking ALL blocked images in ACR '$ACR_NAME'..."
    fi
    echo "--------------------------------------------------"

    # Get list of repositories to check
    ALL_REPOS=$(list_all_repositories "$ACR_NAME")
    if [ -n "$REPOSITORY" ]; then
        REPOS_TO_CHECK=$(echo "$ALL_REPOS" | grep -i "$REPOSITORY" || true)
    else
        REPOS_TO_CHECK="$ALL_REPOS"
    fi

    # First, count how many images will be unblocked
    IMAGES_TO_UNBLOCK=()
    for REPO in $REPOS_TO_CHECK; do
        BLOCKED_MANIFESTS=$(az acr manifest list-metadata --name "$ACR_NAME" --repository "$REPO" --query "[?readEnabled==\`false\`].digest" --output tsv 2>/dev/null || true)
        for DIGEST in $BLOCKED_MANIFESTS; do
            IMAGES_TO_UNBLOCK+=("${REPO}@${DIGEST}")
        done
    done

    TOTAL_TO_UNBLOCK=${#IMAGES_TO_UNBLOCK[@]}

    if [ "$TOTAL_TO_UNBLOCK" -eq 0 ]; then
        echo "No blocked images found."
        exit 0
    fi

    echo "Found $TOTAL_TO_UNBLOCK blocked image(s) to unblock."
    echo ""

    # Safety confirmation
    if [ "$DRY_RUN" = false ] && [ "$AUTO_APPROVE" = false ]; then
        YELLOW='\033[1;33m'
        RED='\033[0;31m'
        NC='\033[0m'
        echo -e "${YELLOW}WARNING: You are about to UNBLOCK $TOTAL_TO_UNBLOCK image(s).${NC}"
        echo "This will allow clients to pull these images again."
        echo ""
        read -p "Are you sure you want to proceed? (yes/no): " CONFIRMATION
        if [[ ! "$CONFIRMATION" =~ ^[Yy][Ee][Ss]$ ]]; then
            echo "Operation cancelled by user."
            exit 0
        fi
        echo ""
    fi

    # Unblock each image
    UNBLOCKED_COUNT=0
    for IMAGE_ID in "${IMAGES_TO_UNBLOCK[@]}"; do
        if [ "$DRY_RUN" = true ]; then
            echo "[DRY-RUN] Would unblock: $IMAGE_ID"
        else
            echo "Unblocking: $IMAGE_ID"
            if az acr repository update --name "$ACR_NAME" --image "$IMAGE_ID" --read-enabled true --output none 2>/dev/null; then
                echo "  Successfully unblocked"
                UNBLOCKED_COUNT=$((UNBLOCKED_COUNT + 1))
            else
                echo "  Failed to unblock"
            fi
        fi
    done

    echo "--------------------------------------------------"
    if [ "$DRY_RUN" = true ]; then
        echo "Dry-run complete. $TOTAL_TO_UNBLOCK image(s) would be unblocked."
    else
        echo "Unblock complete. $UNBLOCKED_COUNT of $TOTAL_TO_UNBLOCK image(s) unblocked."
    fi
    exit 0
fi

# Determine action mode
if [ "$UNBLOCK" = true ]; then
    ACTION_MODE="UNBLOCK (enable)"
elif [ "$BLOCK_IMAGES" = true ]; then
    ACTION_MODE="BLOCK (disable)"
else
    ACTION_MODE="REPORT ONLY (no changes)"
fi

echo "Configuration:"
echo "  ACR Name:    $ACR_NAME"
echo "  Score Range: $MIN_SCORE - $MAX_SCORE"
if [ -n "$SCAN_IMAGE" ]; then
    echo "  Scan Image:  $SCAN_IMAGE"
    echo "  Repository:  $SCAN_REPOSITORY"
    if [ -n "$SCAN_DIGEST" ]; then
        echo "  Digest:      $SCAN_DIGEST"
    else
        echo "  Digest:      (all tags)"
    fi
else
    echo "  Repository:  ${REPOSITORY:-All}"
fi
echo "  Action:      $ACTION_MODE"
echo "  Dry Run:     $DRY_RUN"
echo "--------------------------------------------------"

# Initialize CSV report if in report-only mode (default behavior).
# Atomic write: rows are appended to $REPORT_TMP throughout the loop and only
# renamed to $REPORT_FILE on success. If anything fails mid-loop, the trap
# below removes the partial tmp — the previous $REPORT_FILE (if any) stays
# untouched, so downstream tools never see a truncated report.
REPORT_TMP=""
if [ "$BLOCK_IMAGES" = false ] && [ "$UNBLOCK" = false ]; then
    REPORT_TMP="${REPORT_FILE}.tmp.$$"
    echo "Report mode enabled. Generating CSV report: $REPORT_FILE"
    echo '"repository","digest","tag","cvssScore","cveId","severity","packageCategory","packageLanguage","packageName","currentVersion","fixedVersion","patchable","remediation","fixStatus","cveAgeDays","isInExploitKit","hasPublishedExploit","hasVerifiedExploit","lastPushedToRegistryUTC"' > "$REPORT_TMP"
fi

# Safety confirmation if blocking/unblocking images (not in dry-run mode and not auto-approved)
if [ "$DRY_RUN" = false ] && [ "$AUTO_APPROVE" = false ] && ([ "$BLOCK_IMAGES" = true ] || [ "$UNBLOCK" = true ]); then
    # Yellow color for warning
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m' # No Color

    if [ "$UNBLOCK" = true ]; then
        echo -e "${GREEN}INFO: You are about to UNBLOCK images.${NC}"
        echo -e "This will allow clients to pull these images again."
    else
        echo -e "${YELLOW}WARNING: You are about to BLOCK images in production!${NC}"
        echo -e "${RED}This will prevent clients from pulling these images (HTTP 405).${NC}"
    fi
    echo ""
    read -p "Are you sure you want to proceed? (yes/no): " CONFIRMATION

    if [[ ! "$CONFIRMATION" =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Operation cancelled by user."
        exit 0
    fi
    echo ""
fi

# Build the KQL Query using temp file to avoid bash escaping issues
QUERY_FILE=$(mktemp)
# Cleanup: always remove the KQL temp file; also remove the partial CSV tmp
# if we exited before the final rename. When the loop succeeds we unset
# REPORT_TMP so the trap leaves the final report in place.
trap 'rm -f "$QUERY_FILE" ${REPORT_TMP:+"$REPORT_TMP"}' EXIT

# Pre-compute early filter snippets to inject INSIDE each leg before extends/mv-expand.
# This lets ARG push the filters down and avoid scanning the whole subscription.
EARLY_FILTER_A=""
EARLY_FILTER_B=""

if [ -n "$SCAN_REPOSITORY" ]; then
    EARLY_FILTER_A="| where properties.additionalData.artifactDetails.repositoryName == \"$SCAN_REPOSITORY\""
    _REPO_DASHED=$(repo_to_dashed_path "$SCAN_REPOSITORY")
    EARLY_FILTER_B="| where properties.resourceDetails.Id contains \"$_REPO_DASHED\""
    if [ -n "$SCAN_DIGEST" ]; then
        _DIGEST_HEX="${SCAN_DIGEST#sha256:}"
        EARLY_FILTER_B="$EARLY_FILTER_B and properties.resourceDetails.Id contains \"$_DIGEST_HEX\""
    fi
elif [ -n "$REPOSITORY" ]; then
    EARLY_FILTER_A="| where properties.additionalData.artifactDetails.repositoryName contains \"$REPOSITORY\""
    _REPO_DASHED=$(repo_to_dashed_path "$REPOSITORY")
    EARLY_FILTER_B="| where properties.resourceDetails.Id contains \"$_REPO_DASHED\""
elif [ -n "$REPOSITORIES" ]; then
    # CONTROLLED list semantics (task #38): exact match, not substring.
    # Leg A uses KQL `in (...)`. Leg B uses `contains "repositories-<dashed>-images-"`
    # — the `repositories-…-images-` bracketing is the exact-match anchor for
    # the SoftwareUpdate `resourceDetails.Id` format, so `app` never captures
    # `myapp` or `app-backend`.
    mapfile -t _repos_list < <(parse_repo_list "$REPOSITORIES")
    _expr_a=$(build_repos_in_expr \
        "properties.additionalData.artifactDetails.repositoryName" \
        "${_repos_list[@]}")
    EARLY_FILTER_A="| where $_expr_a"
    _expr_b=$(build_repos_id_anchor_expr \
        "properties.resourceDetails.Id" \
        "${_repos_list[@]}")
    EARLY_FILTER_B="| where $_expr_b"
fi

# Union of both assessment shapes to ensure full coverage:
# Leg A: MDVM subassessments (c0b7cfc6-... key) — preferred schema with rich fields.
# Leg B: Grouped SoftwareUpdate assessments — still populated in many ACR environments.
cat > "$QUERY_FILE" << ENDQUERY
securityresources
| where type =~ "microsoft.security/assessments/subassessments"
| where id contains "/assessments/c0b7cfc6-3172-465a-b378-53c7ff2cc0d5/"
$EARLY_FILTER_A
| extend
    cveId = tostring(properties.id),
    cvssScore = coalesce(
        todouble(properties.additionalData.cvssV30Score),
        case(
            properties.additionalData.vulnerabilityDetails.severity =~ "Critical", 9.0,
            properties.additionalData.vulnerabilityDetails.severity =~ "High",     7.0,
            properties.additionalData.vulnerabilityDetails.severity =~ "Medium",   4.0,
            properties.additionalData.vulnerabilityDetails.severity =~ "Low",      0.1,
            0.0
        )
    ),
    digest = tostring(properties.additionalData.artifactDetails.digest),
    repository = tostring(properties.additionalData.artifactDetails.repositoryName),
    lastPushedToRegistryUTC = tostring(properties.additionalData.artifactDetails.lastPushedToRegistryUTC),
    packageCategory = tostring(properties.additionalData.softwareDetails.category),
    packageLanguage = tostring(properties.additionalData.softwareDetails.language),
    packageName = tostring(properties.additionalData.softwareDetails.packageName),
    currentVersion = tostring(properties.additionalData.softwareDetails.version),
    fixedVersion = coalesce(
        tostring(properties.additionalData.softwareDetails.fixedVersion),
        tostring(properties.additionalData.vulnerabilityDetails.fixedVersion)
    ),
    patchable = case(
        tostring(properties.additionalData.softwareDetails.fixStatus) =~ "FixAvailable", "true",
        tostring(properties.additionalData.softwareDetails.fixStatus) in~ ("NoFix", "NoFixAvailable", "WillNotFix"), "false",
        isnotnull(properties.additionalData.patchable), tostring(properties.additionalData.patchable),
        isnotnull(properties.additionalData.vulnerabilityDetails.isPatchable), tostring(properties.additionalData.vulnerabilityDetails.isPatchable),
        ""
    ),
    remediation = tostring(properties.remediation),
    severityRaw = tostring(properties.status.severity),
    fixStatus = tostring(properties.additionalData.softwareDetails.fixStatus),
    cveAgeDays = iff(
        isnotnull(properties.additionalData.vulnerabilityDetails.publishedDate),
        datetime_diff('day', now(), todatetime(properties.additionalData.vulnerabilityDetails.publishedDate)),
        long(-1)
    ),
    isInExploitKit = iff(
        isnotnull(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.isInExploitKit)
            and tobool(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.isInExploitKit),
        "true", "false"
    ),
    hasPublishedExploit = iff(
        isnotnull(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsPublished)
            and tobool(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsPublished),
        "true", "false"
    ),
    hasVerifiedExploit = iff(
        isnotnull(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsVerified)
            and tobool(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsVerified),
        "true", "false"
    )
| where cveId startswith "CVE-" and cvssScore >= $MIN_SCORE and cvssScore <= $MAX_SCORE
| project repository, digest, cvssScore, cveId, severityRaw, packageCategory, packageLanguage, packageName, currentVersion, fixedVersion, patchable, remediation, fixStatus, cveAgeDays, isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC
| union (securityresources
    | where type =~ "microsoft.security/assessments"
    | where properties.metadata.recommendationCategory == "SoftwareUpdate"
    | where properties.resourceDetails.ResourceType == ".containerimage"
    | where properties.resourceDetails.Source == "Azure"
    $EARLY_FILTER_B
    | extend
        _rad = parse_json(tostring(properties.resourceAdditionalData)),
        _dashedPath = extract(@"repositories-(.+)-images-sha256:[a-f0-9]+", 1, tostring(properties.resourceDetails.Id)),
        _resourceName = tostring(properties.resourceDetails.ResourceName),
        _digest = strcat("sha256:", extract(@"sha256:([a-f0-9]+)", 1, tostring(properties.resourceDetails.Id))),
        _cvesJson = parse_json(tostring(properties.additionalData.CvesDetails)),
        _pkgCategory = tostring(properties.additionalData.PackageType),
        _pkgLanguage = tostring(properties.additionalData.Language),
        _pkgName = tostring(properties.additionalData.SoftwareName)
    | mv-expand cve = _cvesJson
    | extend
        cveId = tostring(cve.CveId),
        cvssScore = coalesce(
            todouble(cve.Cvss[0].Value.Base),
            case(
                cve.Severity =~ "Critical", 9.0,
                cve.Severity =~ "High",     7.0,
                cve.Severity =~ "Medium",   4.0,
                cve.Severity =~ "Low",      0.1,
                0.0
            )
        ),
        repository = iff(
            _dashedPath == _resourceName,
            _resourceName,
            strcat(substring(_dashedPath, 0, strlen(_dashedPath) - strlen(_resourceName) - 1), "/", _resourceName)
        ),
        severityRaw = tostring(cve.Severity),
        fixStatus = tostring(cve.FixStatus),
        fixedVersion = tostring(cve.FixedVersion),
        patchable = case(
            tostring(cve.FixStatus) =~ "FixAvailable", "true",
            tostring(cve.FixStatus) in~ ("NoFix", "NoFixAvailable", "WillNotFix"), "false",
            ""
        ),
        remediation = tostring(cve.Description),
        cveAgeDays = iff(
            isnotnull(cve.PublishedDate),
            datetime_diff('day', now(), todatetime(cve.PublishedDate)),
            long(-1)
        ),
        isInExploitKit = iff(
            isnotnull(cve.ExploitabilityDetails.IsInExploitKit)
                and tobool(cve.ExploitabilityDetails.IsInExploitKit),
            "true", "false"
        ),
        hasPublishedExploit = iff(
            isnotnull(cve.ExploitabilityDetails.ExploitStepsPublished)
                and tobool(cve.ExploitabilityDetails.ExploitStepsPublished),
            "true", "false"
        ),
        hasVerifiedExploit = iff(
            isnotnull(cve.ExploitabilityDetails.ExploitStepsVerified)
                and tobool(cve.ExploitabilityDetails.ExploitStepsVerified),
            "true", "false"
        ),
        lastPushedToRegistryUTC = tostring(_rad.LastPushedToRegistryUTC)
    | where cveId startswith "CVE-" and cvssScore >= $MIN_SCORE and cvssScore <= $MAX_SCORE
    | project repository, digest=_digest, cvssScore, cveId, severityRaw, packageCategory=_pkgCategory, packageLanguage=_pkgLanguage, packageName=_pkgName, currentVersion="", fixedVersion, patchable, remediation, fixStatus, cveAgeDays, isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC)
ENDQUERY

# Final projection and ordering
if [ "$BLOCK_IMAGES" = false ] && [ "$UNBLOCK" = false ]; then
    printf '%s' " | project repository, digest, cvssScore, cveId, severityRaw, packageCategory, packageLanguage, packageName, currentVersion, fixedVersion, patchable, remediation, fixStatus, cveAgeDays, isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC | distinct repository, digest, cvssScore, cveId, severityRaw, packageCategory, packageLanguage, packageName, currentVersion, fixedVersion, patchable, remediation, fixStatus, cveAgeDays, isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC | order by cvssScore desc, repository asc" >> "$QUERY_FILE"
else
    printf '%s' " | project repository, digest | distinct repository, digest | order by repository asc" >> "$QUERY_FILE"
fi

# Debug: print query and run diagnostic preview if requested
if [ "$DEBUG" = true ]; then
    echo ""
    echo "=== [DEBUG] KQL Query gerada ==="
    cat "$QUERY_FILE"
    echo ""
    echo "=== [DEBUG] Diagnóstico ARG — repositórios encontrados (sem filtro de score) ==="
    _REPO_FILTER=""
    [ -n "$REPOSITORY" ] && _REPO_FILTER="| where properties.additionalData.artifactDetails.repositoryName contains \"$REPOSITORY\""
    az graph query -q "securityresources | where type =~ 'microsoft.security/assessments/subassessments' | where id contains '/assessments/c0b7cfc6-3172-465a-b378-53c7ff2cc0d5/' $_REPO_FILTER | extend repository = tostring(properties.additionalData.artifactDetails.repositoryName), cvssScore = todouble(properties.additionalData.cvssV30Score) | summarize cve_count=count(), max_cvss=max(cvssScore), min_cvss=min(cvssScore) by repository | order by max_cvss desc" --output table 2>&1 || echo "[DEBUG] az graph query falhou"
    echo ""
fi
echo "Executing Azure Resource Graph query..."

SKIP_TOKEN=""
TOTAL_PROCESSED=0
PAGE_NUM=0

while : ; do
    PAGE_NUM=$((PAGE_NUM + 1))
    _t_page_start=$(_now_realtime)

    # ── phase 1: graph_query ────────────────────────────────────────────
    _t_graph_start=$(_now_realtime)
    # Fail-fast: if the query keeps failing after 3 tries, abort with a clear
    # message so operators don't consume a truncated CSV as authoritative.
    # Call directly (no $(...)) so globals set by the function survive.
    if ! run_graph_query "$QUERY_FILE" "$SKIP_TOKEN"; then
        log_error "az graph query failed on page ${PAGE_NUM} after 3 attempts; aborting (processed=${TOTAL_PROCESSED} pages=$((PAGE_NUM - 1)))"
        exit 2
    fi
    RESPONSE="$LAST_QUERY_RESPONSE"

    # Defensive: `run_graph_query` already validated .data exists, but if jq
    # ever hiccups we treat it as end-of-results rather than crash.
    BATCH_COUNT=$(printf '%s' "$RESPONSE" | jq '.data | length' 2>/dev/null || echo 0)
    _t_graph_ms=$(_elapsed_ms "$_t_graph_start")

    if [ -z "$BATCH_COUNT" ] || [ "$BATCH_COUNT" -eq 0 ]; then
        echo "[Page ${PAGE_NUM}] batch=0 → end of results"
        break
    fi

    echo "[Page ${PAGE_NUM}] batch=${BATCH_COUNT} images, total_before=${TOTAL_PROCESSED}, retries=${LAST_QUERY_RETRIES}"

    # ── phase 2: tag_resolve (per-page tag cache) ────────────────────────
    _t_tags_start=$(_now_realtime)
    _tag_api_calls=0
    # Build tag cache for unique repo+digest pairs in this batch (1 call per unique digest)
    declare -A TAG_CACHE
    while IFS= read -r cache_entry; do
        c_repo=$(echo "$cache_entry" | base64 --decode | jq -r '.repository')
        c_digest=$(echo "$cache_entry" | base64 --decode | jq -r '.digest')
        cache_key="${c_repo}@${c_digest}"
        if [ -z "${TAG_CACHE[$cache_key]+x}" ]; then
            _tag_api_calls=$((_tag_api_calls + 1))
            c_tag=$(az acr repository show-tags \
                --name "$ACR_NAME" \
                --repository "$c_repo" \
                --detail \
                --query "[?digest=='$c_digest'].name | [0]" \
                --output tsv 2>/dev/null | tr -d '\r' || echo "N/A")
            TAG_CACHE[$cache_key]="${c_tag:-N/A}"
        fi
    done < <(echo "$RESPONSE" | jq -r '.data[] | @base64')
    _t_tags_ms=$(_elapsed_ms "$_t_tags_start")

    # ── phase 3: rows (parse + CSV write) ────────────────────────────────
    _t_rows_start=$(_now_realtime)

    # PR-A: one jq invocation per PAGE emits every row as US-separated
    # (0x1F) fields; the shell loop just splits with `IFS=$'\x1f' read`.
    # Prior code did 18 (echo|base64|jq) subprocesses per row — ~340ms/row
    # of pure shell overhead on the client. This shape spawns exactly one
    # jq per page, regardless of row count. Field ORDER below is the CSV
    # contract (matches csv_write_row call site and the CSV header); do
    # not reorder without updating the reader below AND the tests.
    # `clean` collapses \r, \n and 0x1F inside string fields so multi-line
    # remediation text never breaks the delimiter or the row boundary.
    JQ_ROW_EXTRACT='
        def clean(x): (x // "" | tostring | gsub("[\r\n\u001f]"; " "));
        .data[] | [
            clean(.repository),
            clean(.digest),
            clean(.cvssScore // "0"),
            clean(.cveId // "N/A"),
            clean(.severityRaw),
            clean(.packageCategory),
            clean(.packageLanguage),
            clean(.packageName),
            clean(.currentVersion),
            clean(.fixedVersion),
            clean(.patchable),
            clean(.remediation),
            clean(.fixStatus),
            clean(.cveAgeDays),
            clean(.isInExploitKit // "false"),
            clean(.hasPublishedExploit // "false"),
            clean(.hasVerifiedExploit // "false"),
            clean(.lastPushedToRegistryUTC)
        ] | join("\u001f")
    '

    while IFS=$'\x1f' read -r \
        REPO DIGEST CVSS_SCORE CVE_ID SEVERITY_RAW \
        PKG_CATEGORY PKG_LANGUAGE PKG_NAME CURRENT_VERSION FIXED_VERSION \
        PATCHABLE REMEDIATION FIX_STATUS CVE_AGE_DAYS \
        IN_EXPLOIT_KIT PUB_EXPLOIT VER_EXPLOIT LAST_PUSHED; do

        # Filter by specific digest if --scan-image was used
        if [ -n "$SCAN_DIGEST" ] && [ "$DIGEST" != "$SCAN_DIGEST" ]; then
            continue
        fi

        # Severity: Defender raw is authoritative; fall back to CVSS-derived.
        if [ -n "$SEVERITY_RAW" ]; then
            SEVERITY="$SEVERITY_RAW"
        else
            SEVERITY=$(classify_severity "$CVSS_SCORE")
        fi

        IMAGE_ID="${REPO}@${DIGEST}"

        # Retrieve tag from cache (resolved once per unique digest above)
        TAG="${TAG_CACHE[${REPO}@${DIGEST}]:-N/A}"

        # Report-only mode (default): write all columns to CSV
        if [ "$BLOCK_IMAGES" = false ] && [ "$UNBLOCK" = false ]; then
            csv_write_row \
                "$REPO" "$DIGEST" "$TAG" "$CVSS_SCORE" "$CVE_ID" "$SEVERITY" \
                "$PKG_CATEGORY" "$PKG_LANGUAGE" "$PKG_NAME" "$CURRENT_VERSION" "$FIXED_VERSION" \
                "$PATCHABLE" "$REMEDIATION" "$FIX_STATUS" \
                "$CVE_AGE_DAYS" "$IN_EXPLOIT_KIT" "$PUB_EXPLOIT" "$VER_EXPLOIT" \
                "$LAST_PUSHED" >> "$REPORT_TMP"
            TOTAL_PROCESSED=$((TOTAL_PROCESSED + 1))
            continue
        fi

        # Determine action based on UNBLOCK flag
        if [ "$UNBLOCK" = true ]; then
            ACTION="unblock"
            READ_ENABLED="true"
        else
            ACTION="block"
            READ_ENABLED="false"
        fi
        
        if [ "$DRY_RUN" = true ]; then
            echo "[DRY-RUN] Would $ACTION: $IMAGE_ID (in $ACR_NAME)"
            echo "Command: az acr repository update --name $ACR_NAME --image $IMAGE_ID --read-enabled $READ_ENABLED"
        else
            echo "${ACTION^}ing image: $IMAGE_ID"
            if az acr repository update --name "$ACR_NAME" --image "$IMAGE_ID" --read-enabled "$READ_ENABLED"; then
                echo "Successfully ${ACTION}ed $IMAGE_ID"
            else
                echo "Failed to $ACTION $IMAGE_ID"
            fi
        fi
        
        TOTAL_PROCESSED=$((TOTAL_PROCESSED + 1))
    done < <(printf '%s' "$RESPONSE" | jq -r "$JQ_ROW_EXTRACT")
    _t_rows_ms=$(_elapsed_ms "$_t_rows_start")
    _t_total_ms=$(_elapsed_ms "$_t_page_start")

    echo "[Page ${PAGE_NUM}] done, total_after=${TOTAL_PROCESSED}"
    # Structured per-page timing, one line per page. Stable format for
    # dashboards and benchmark parsing — do not reorder without updating
    # scripts/benchmark-defender.sh.
    log_info "page ${PAGE_NUM} batch=${BATCH_COUNT} total=${TOTAL_PROCESSED} retries=${LAST_QUERY_RETRIES} tag_api_calls=${_tag_api_calls} timings_ms=graph_query:${_t_graph_ms} tag_resolve:${_t_tags_ms} rows:${_t_rows_ms} total:${_t_total_ms}"

    # Check for next page
    SKIP_TOKEN=$(printf '%s' "$RESPONSE" | jq -r '.skip_token // empty' 2>/dev/null || true)
    if [ -z "$SKIP_TOKEN" ]; then
        break
    fi
done

# All pages processed successfully — promote the tmp CSV to the final name
# atomically. Unset REPORT_TMP so the EXIT trap doesn't remove it.
if [ -n "$REPORT_TMP" ]; then
    mv -f "$REPORT_TMP" "$REPORT_FILE"
    REPORT_TMP=""
fi

echo "--------------------------------------------------"
echo "Processing complete."
if [ "$BLOCK_IMAGES" = false ] && [ "$UNBLOCK" = false ]; then
    echo "Total images found: $TOTAL_PROCESSED across ${PAGE_NUM} page(s)"
    echo "Report saved to: $REPORT_FILE"
    log_info "end total_processed=${TOTAL_PROCESSED} pages=${PAGE_NUM} report_file=${REPORT_FILE}"
else
    echo "Total images processed: $TOTAL_PROCESSED across ${PAGE_NUM} page(s)"
    log_info "end total_processed=${TOTAL_PROCESSED} pages=${PAGE_NUM} mode=${_LOG_MODE}"
fi