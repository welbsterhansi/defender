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
SKIP_TAGS=false
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
# ---------------------------------------------------------------------------
# Azure Resource Graph query — REST transport (az rest, api 2022-10-01).
#
# Why not `az graph query`? The `resource-graph` CLI extension (2.1.1 as of
# 2026-09) is pinned to api-version 2021-03-01 with no flag to override. On
# that version, JOINs against `microsoft.security/cvedetails` silently return
# enriched=0 rows — so CVSS, exploit signals and publishedDate come back null
# even though the underlying table has 390k+ populated records. See erros.md.
#
# Why NOT pass `managementGroups: [<tenant_id>]` in the body? Empirical:
# with that filter, cvedetails count drops to 0 (the table disappears from
# the scope). Default scope (all accessible subscriptions) is what
# `Search-AzGraph -UseTenantScope` actually uses. See erros.md Erro 5.
#
# Populates globals so callers can use side-effect-only invocation
# (command substitution `$(...)` would spawn a subshell and lose them):
#   LAST_QUERY_RESPONSE   — full JSON response body
#   LAST_QUERY_RETRIES    — how many attempts before success (0..2 on OK, 3 on fail)
#   LAST_QUERY_SKIP_TOKEN — the `$skipToken` from response, empty if last page
#
# Args:
#   $1  KQL query string
#   $2  skip_token (empty for first page)
#
# Returns 0 on success, non-zero after 3 failed attempts.
# Failures counted: az exit != 0, OR stdout not parseable as JSON, OR the
# expected `.data` field is missing (indicates a malformed response).
# Backoff: 2s after 1st failure, 5s after 2nd. No sleep after last attempt.
# ---------------------------------------------------------------------------
ARG_REST_ENDPOINT="https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
LAST_QUERY_RESPONSE=""
LAST_QUERY_RETRIES=0
LAST_QUERY_SKIP_TOKEN=""

run_arg_rest_query() {
    local query="$1"
    local skip_token="${2:-}"
    local delays=(2 5)
    local body az_stderr response rc

    LAST_QUERY_RESPONSE=""
    LAST_QUERY_RETRIES=0
    LAST_QUERY_SKIP_TOKEN=""

    if [ -z "$skip_token" ]; then
        body=$(jq -nc --arg q "$query" '{query: $q, options: {"$top": 1000}}')
    else
        body=$(jq -nc --arg q "$query" --arg t "$skip_token" \
            '{query: $q, options: {"$top": 1000, "$skipToken": $t}}')
    fi

    for attempt in 1 2 3; do
        az_stderr=$(mktemp)
        response=$(az rest --method post --url "$ARG_REST_ENDPOINT" --body "$body" 2>"$az_stderr")
        rc=$?
        if [ "$rc" -eq 0 ] && printf '%s' "$response" | jq -e '.data' >/dev/null 2>&1; then
            rm -f "$az_stderr"
            LAST_QUERY_RESPONSE="$response"
            LAST_QUERY_SKIP_TOKEN=$(printf '%s' "$response" | jq -r '.["$skipToken"] // empty' 2>/dev/null || true)
            return 0
        fi
        local err_preview
        err_preview=$(head -c 300 "$az_stderr" 2>/dev/null)
        rm -f "$az_stderr"
        LAST_QUERY_RETRIES=$attempt
        log_warn "az rest (resource graph) attempt ${attempt}/3 failed rc=${rc}: ${err_preview:-<empty stderr, invalid JSON?>}"
        if [ "$attempt" -lt 3 ]; then
            local delay="${delays[$((attempt-1))]}"
            log_info "az rest (resource graph) retry backoff=${delay}s"
            sleep "$delay"
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# KQL builders — small, testable, single-responsibility.
#
# Split into two queries by design (see erros.md Erro 4): a single JOIN over
# 1.6M+ rows blows up ARG with UnexpectedQueryExecutionError. Instead we
# enumerate (repo, digest) pairs first, then run the enriched JOIN per digest.
# Each per-digest query touches ~500-3000 rows, well within ARG limits.
# ---------------------------------------------------------------------------

# Small query that lists unique (repository, digest) pairs matching the given
# early filter. Used to drive the outer per-digest scan loop.
build_enumerate_digests_query() {
    local filter="${1:-}"
    cat <<KQL
securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == ".containerimage"
| where properties.resourceDetails.Source == "Azure"
$filter
| extend _image = parse_json(tostring(properties.resourceAdditionalData))
| extend
    _repository = tostring(_image.RepositoryDetails.RepositoryName),
    _digest     = tostring(_image.Digest)
| where isnotempty(_digest)
| distinct _repository, _digest
KQL
}

# Full per-digest scan with cvedetails JOIN. Projects exactly the 18 fields
# consumed by JQ_ROW_EXTRACT downstream — do NOT reorder without updating
# the reader in the main scan loop and the CSV header/tests.
#
# Filter by cvssScore >= MIN_SCORE / <= MAX_SCORE is applied at the KQL
# level (same behavior as the previous monolithic query).
build_digest_scan_query() {
    local digest="$1"
    cat <<KQL
securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == ".containerimage"
| where properties.resourceDetails.Source == "Azure"
| extend
    _scanner = parse_json(tostring(properties.additionalData.ScannersDetails)),
    _image   = parse_json(tostring(properties.resourceAdditionalData)),
    _cves    = parse_json(tostring(properties.additionalData.CvesDetails))
| extend _digest = tostring(_image.Digest)
| where _digest == "$digest"
| mv-expand cve = _cves
| extend cveId = coalesce(tostring(cve.CveId), tostring(cve.cveId))
| where isnotempty(cveId)
| join kind=leftouter (
    securityresources
    | where type =~ "microsoft.security/cvedetails"
    | where tostring(properties.status) !~ "Reject"
    | extend _cveIdJoin = coalesce(tostring(properties.cveId), tostring(name))
    | where isnotempty(_cveIdJoin)
    | extend _cvss40 = todouble(properties.cvss["4.0"].base)
    | extend _cvss31 = todouble(properties.cvss["3.1"].base)
    | extend _cvss30 = todouble(properties.cvss["3.0"].base)
    | extend _cvss20 = todouble(properties.cvss["2.0"].base)
    | extend _cvssEnrich = coalesce(_cvss40, _cvss31, _cvss30, _cvss20)
    | extend _publishedDateEnrich = todatetime(properties.publishedDate)
    | extend _severityEnrich = tostring(properties.severity)
    | extend _verifiedExpEnrich = iff(isnull(properties.exploitabilityDetails.IsVerified), false, tobool(properties.exploitabilityDetails.IsVerified))
    | extend _publishedExpEnrich = iff(isnull(properties.exploitabilityDetails.IsPubliclyDisclosed), false, tobool(properties.exploitabilityDetails.IsPubliclyDisclosed))
    | extend _inExploitKitEnrich = iff(isnull(properties.exploitabilityDetails.IsInExploitKit), false, tobool(properties.exploitabilityDetails.IsInExploitKit))
    | summarize
        _cvssEnrich = max(_cvssEnrich),
        _publishedDateEnrich = take_any(_publishedDateEnrich),
        _severityEnrich = take_any(_severityEnrich),
        _verifiedExpEnrich = max(toint(_verifiedExpEnrich)),
        _publishedExpEnrich = max(toint(_publishedExpEnrich)),
        _inExploitKitEnrich = max(toint(_inExploitKitEnrich))
      by cveId = _cveIdJoin
  ) on cveId
| project-away cveId1
| extend
    repository = tostring(_image.RepositoryDetails.RepositoryName),
    digest     = _digest,
    lastPushedToRegistryUTC = tostring(coalesce(
        _image.LastPushedToRegistryUTC,
        _image.RepositoryDetails.LastPushedToRegistryUTC
    )),
    packageName = tostring(coalesce(
        properties.additionalData.SoftwareName,
        properties.additionalData.softwareName
    )),
    currentVersion = case(
        array_length(_scanner.mdvm.DetectedSoftwareVersions) > 0,
            strcat_array(_scanner.mdvm.DetectedSoftwareVersions, ", "),
        array_length(_scanner.agentlessmdvm.DetectedSoftwareVersions) > 0,
            strcat_array(_scanner.agentlessmdvm.DetectedSoftwareVersions, ", "),
        tostring(properties.additionalData.DetectedSoftwareVersions)
    ),
    fixedVersion = tostring(coalesce(
        _scanner.mdvm.FixedVersion,
        _scanner.agentlessmdvm.FixedVersion,
        properties.additionalData.FixedVersion,
        cve.FixedVersion,
        cve.fixedVersion
    )),
    fixStatus = tostring(coalesce(
        cve.FixStatus,
        cve.fixStatus,
        properties.additionalData.FixStatus,
        _scanner.mdvm.FixStatus
    )),
    packageCategory = tostring(coalesce(
        properties.additionalData.PackageType,
        _scanner.mdvm.category,
        _scanner.mdvm.PackageType
    )),
    packageLanguage = tostring(coalesce(
        properties.additionalData.Language,
        _scanner.mdvm.Language
    )),
    remediation = tostring(coalesce(
        cve.Description,
        properties.remediation,
        properties.description
    )),
    severityRaw = tostring(coalesce(_severityEnrich, cve.Severity)),
    cvssScore = coalesce(
        _cvssEnrich,
        todouble(cve.Cvss[0].Value.Base),
        case(
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "Critical", 9.0,
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "High",     7.0,
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "Medium",   4.0,
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "Low",      0.1,
            0.0
        )
    ),
    cveAgeDays = iff(
        isnotnull(_publishedDateEnrich),
        datetime_diff('day', now(), _publishedDateEnrich),
        long(-1)
    ),
    isInExploitKit      = iff(tobool(_inExploitKitEnrich) == true, "true", "false"),
    hasPublishedExploit = iff(tobool(_publishedExpEnrich) == true, "true", "false"),
    hasVerifiedExploit  = iff(tobool(_verifiedExpEnrich)  == true, "true", "false")
| extend patchable = case(
    fixStatus =~ "FixAvailable", "true",
    fixStatus in~ ("NoFix", "NoFixAvailable", "WillNotFix"), "false",
    isnotempty(fixedVersion), "true",
    ""
  )
| where cveId startswith "CVE-" and cvssScore >= $MIN_SCORE and cvssScore <= $MAX_SCORE
| project
    repository, digest, cvssScore, cveId, severityRaw,
    packageCategory, packageLanguage, packageName, currentVersion, fixedVersion,
    patchable, remediation, fixStatus, cveAgeDays,
    isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC
| distinct
    repository, digest, cvssScore, cveId, severityRaw,
    packageCategory, packageLanguage, packageName, currentVersion, fixedVersion,
    patchable, remediation, fixStatus, cveAgeDays,
    isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC
| order by cvssScore desc, repository asc
KQL
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
    echo "  --skip-tags          Skip the tag_resolve phase entirely (Optional)"
    echo "                       - Zero 'az repository show-tags' calls"
    echo "                       - Every row in the CSV has tag=\"N/A\""
    echo "                       - Escape hatch for large scans where CVE data is all that matters"
    echo "                       - Incompatible with --scan-image"
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
        --skip-tags) SKIP_TAGS=true ;;
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
_SKIP_TAGS_ARG=""
[ "$SKIP_TAGS" = true ] && _SKIP_TAGS_ARG="--skip-tags"
init_logging "defender.sh" "$_LOG_MODE" \
    --acr-name "$ACR_NAME" \
    --min-score "$MIN_SCORE" --max-score "$MAX_SCORE" \
    ${REPOSITORY:+--repository "$REPOSITORY"} \
    ${REPOSITORIES:+--repositories "$REPOSITORIES"} \
    ${SCAN_IMAGE:+--scan-image "$SCAN_IMAGE"} \
    ${IMAGE:+--image "$IMAGE"} \
    ${_SKIP_TAGS_ARG:+$_SKIP_TAGS_ARG}
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

# --skip-tags bypasses the whole tag resolution phase. It is contradictory
# with --scan-image, which explicitly resolves tag → digest up front and
# needs the tag machinery. Fail early with exit 2 so operators see the
# mistake instead of a report full of N/As they did not ask for.
if [ "$SKIP_TAGS" = true ] && [ -n "$SCAN_IMAGE" ]; then
    echo "Error: --skip-tags is incompatible with --scan-image." >&2
    echo "       --scan-image resolves tag → digest, so it cannot skip tags." >&2
    exit 2
fi
if [ "$SKIP_TAGS" = true ]; then
    log_info "tag_resolve DISABLED via --skip-tags (all rows will have tag=N/A)"
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

# Cleanup: remove the partial CSV tmp if we exit before the final rename.
# When the scan loop succeeds we unset REPORT_TMP so the trap leaves the
# final report in place. No temp KQL file anymore — queries are built as
# strings by the KQL builder functions above and passed directly to
# `run_arg_rest_query` via jq's `--arg`.
trap 'rm -f ${REPORT_TMP:+"$REPORT_TMP"}' EXIT

# Pre-compute the early filter snippet used by the digest ENUMERATION query.
# ARG pushes this filter down so enumeration doesn't scan the whole tenant.
# The per-digest scan query does NOT need this filter — it uses the exact
# digest string to filter, which is even tighter.
EARLY_FILTER_B=""

if [ -n "$SCAN_REPOSITORY" ]; then
    _REPO_DASHED=$(repo_to_dashed_path "$SCAN_REPOSITORY")
    EARLY_FILTER_B="| where properties.resourceDetails.Id contains \"$_REPO_DASHED\""
    if [ -n "$SCAN_DIGEST" ]; then
        _DIGEST_HEX="${SCAN_DIGEST#sha256:}"
        EARLY_FILTER_B="$EARLY_FILTER_B and properties.resourceDetails.Id contains \"$_DIGEST_HEX\""
    fi
elif [ -n "$REPOSITORY" ]; then
    _REPO_DASHED=$(repo_to_dashed_path "$REPOSITORY")
    EARLY_FILTER_B="| where properties.resourceDetails.Id contains \"$_REPO_DASHED\""
elif [ -n "$REPOSITORIES" ]; then
    # CONTROLLED list semantics: exact match, not substring. Uses
    # `contains "repositories-<dashed>-images-"` — the bracketing is the
    # exact-match anchor for the SoftwareUpdate `resourceDetails.Id` format,
    # so `app` never captures `myapp` or `app-backend`.
    mapfile -t _repos_list < <(parse_repo_list "$REPOSITORIES")
    _expr_b=$(build_repos_id_anchor_expr \
        "properties.resourceDetails.Id" \
        "${_repos_list[@]}")
    EARLY_FILTER_B="| where $_expr_b"
fi

# --- LEGACY KQL DEPRECATED --------------------------------------------------
# The monolithic query below (with `let cvedetails = ...; ... | join ...`) was
# retired in the 2026-09 refactor. See erros.md — it hit two ARG-side issues
# that empty-out the CSV in prod:
#   (a) top-level `let` returns null JOINs silently in ARG (subset of Kusto).
#   (b) even with `let` fixed, JOIN over 1.6M+ rows blows up the ARG engine
#       with `UnexpectedQueryExecutionError`.
# Replacement: enumerate (repo, digest) pairs first, then run the enriched
# JOIN per-digest (small dataset, ARG stable). See build_enumerate_digests_query
# and build_digest_scan_query above.
# ---------------------------------------------------------------------------
: <<'DEPRECATED_KQL'
let cvedetails =
    securityresources
    | where type == "microsoft.security/cvedetails"
    | where tostring(properties.status) !~ "Reject"
    | extend cveIdJoin = toupper(tostring(properties.cveId))
    | extend
        _cvssEnrich = todouble(coalesce(
            properties.cvss["4.0"].base,
            properties.cvss["3.0"].base,
            properties.cvss["2.0"].base
        )),
        _severityEnrich       = tostring(properties.severity),
        _publishedDateEnrich  = todatetime(properties.publishedDate),
        _inExploitKitEnrich   = tobool(properties.exploitabilityDetails.IsInExploitKit),
        _publishedExpEnrich   = tobool(properties.exploitabilityDetails.IsPubliclyDisclosed),
        _verifiedExpEnrich    = tobool(properties.exploitabilityDetails.IsVerified)
    | project cveIdJoin, _cvssEnrich, _severityEnrich, _publishedDateEnrich,
              _inExploitKitEnrich, _publishedExpEnrich, _verifiedExpEnrich;
securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == ".containerimage"
| where properties.resourceDetails.Source == "Azure"
$EARLY_FILTER_B
| extend
    _scanner = parse_json(tostring(properties.additionalData.ScannersDetails)),
    _image   = parse_json(tostring(properties.resourceAdditionalData)),
    _cves    = parse_json(tostring(properties.additionalData.CvesDetails))
| mv-expand cve = _cves
| extend cveId = tostring(cve.CveId)
| where isnotempty(cveId)
| extend cveIdJoin = toupper(cveId)
| join kind=leftouter cvedetails on cveIdJoin
| extend
    repository = tostring(_image.RepositoryDetails.RepositoryName),
    digest     = tostring(_image.Digest),
    lastPushedToRegistryUTC = tostring(coalesce(
        _image.LastPushedToRegistryUTC,
        _image.RepositoryDetails.LastPushedToRegistryUTC
    )),
    packageName    = tostring(properties.additionalData.SoftwareName),
    currentVersion = tostring(_scanner.mdvm.DetectedSoftwareVersions[0]),
    fixedVersion   = tostring(cve.FixedVersion),
    packageCategory = tostring(coalesce(
        properties.additionalData.PackageType,
        _scanner.mdvm.category,
        _scanner.mdvm.PackageType
    )),
    packageLanguage = tostring(coalesce(
        properties.additionalData.Language,
        _scanner.mdvm.Language
    )),
    fixStatus = tostring(coalesce(
        cve.FixStatus,
        properties.additionalData.FixStatus,
        _scanner.mdvm.FixStatus
    )),
    remediation = tostring(coalesce(
        cve.Description,
        properties.remediation,
        properties.description
    )),
    severityRaw = tostring(coalesce(_severityEnrich, cve.Severity)),
    cvssScore = coalesce(
        _cvssEnrich,
        todouble(cve.Cvss[0].Value.Base),
        case(
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "Critical", 9.0,
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "High",     7.0,
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "Medium",   4.0,
            tostring(coalesce(_severityEnrich, cve.Severity)) =~ "Low",      0.1,
            0.0
        )
    ),
    cveAgeDays = iff(
        isnotnull(coalesce(_publishedDateEnrich, todatetime(cve.PublishedDate))),
        datetime_diff('day', now(), coalesce(_publishedDateEnrich, todatetime(cve.PublishedDate))),
        long(-1)
    ),
    isInExploitKit = iff(
        tobool(coalesce(
            _inExploitKitEnrich,
            cve.ExploitabilityDetails.IsInExploitKit
        )) == true,
        "true", "false"
    ),
    hasPublishedExploit = iff(
        tobool(coalesce(
            _publishedExpEnrich,
            cve.ExploitabilityDetails.ExploitStepsPublished,
            cve.ExploitabilityDetails.IsPubliclyDisclosed
        )) == true,
        "true", "false"
    ),
    hasVerifiedExploit = iff(
        tobool(coalesce(
            _verifiedExpEnrich,
            cve.ExploitabilityDetails.ExploitStepsVerified,
            cve.ExploitabilityDetails.IsVerified
        )) == true,
        "true", "false"
    )
| extend patchable = case(
    fixStatus =~ "FixAvailable", "true",
    fixStatus in~ ("NoFix", "NoFixAvailable", "WillNotFix"), "false",
    isnotempty(fixedVersion), "true",
    ""
  )
| where cveId startswith "CVE-" and cvssScore >= $MIN_SCORE and cvssScore <= $MAX_SCORE
| project repository, digest, cvssScore, cveId, severityRaw, packageCategory, packageLanguage, packageName, currentVersion, fixedVersion, patchable, remediation, fixStatus, cveAgeDays, isInExploitKit, hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC
DEPRECATED_KQL

# Debug: print the enumerate + per-digest KQL that will actually run
if [ "$DEBUG" = true ]; then
    echo ""
    echo "=== [DEBUG] Enumerate digests KQL ==="
    build_enumerate_digests_query "$EARLY_FILTER_B"
    echo ""
    echo "=== [DEBUG] Per-digest scan KQL (example, uses <DIGEST> placeholder) ==="
    build_digest_scan_query "<DIGEST>"
    echo ""
fi
echo "Executing Azure Resource Graph query..."

TOTAL_PROCESSED=0
TOTAL_PAGES=0
DIGEST_NUM=0

# Tag cache is execution-global — one az call per unique repo, reused for
# every digest of that repo. REPO_TAGS_TRIED tracks "already attempted"
# (success OR fail) so a failed repo is not retried (blast radius: all
# digests of that repo → TAG=N/A, 1 WARN total).
declare -A TAG_CACHE=()
declare -A REPO_TAGS_TRIED=()

# ═════════════════════════════════════════════════════════════════════════
# PHASE 0 — Enumerate (repository, digest) pairs
#
# Small query listing unique image identities matching the filter. Drives
# the per-digest scan loop below. `--scan-image` with an explicit digest is
# shortcut: we already know the pair, no ARG call needed.
# ═════════════════════════════════════════════════════════════════════════
declare -a DIGEST_PAIRS=()

if [ -n "$SCAN_REPOSITORY" ] && [ -n "$SCAN_DIGEST" ]; then
    DIGEST_PAIRS=("${SCAN_REPOSITORY}|${SCAN_DIGEST}")
    log_info "enumerate: bypass (using --scan-image target directly)"
    echo "Enumerate: 1 pair (from --scan-image)"
else
    _t_enum_start=$(_now_realtime)
    _ENUM_QUERY=$(build_enumerate_digests_query "$EARLY_FILTER_B")
    ENUM_SKIP_TOKEN=""
    _enum_pages=0
    while : ; do
        _enum_pages=$((_enum_pages + 1))
        if ! run_arg_rest_query "$_ENUM_QUERY" "$ENUM_SKIP_TOKEN"; then
            log_error "digest enumeration failed on page ${_enum_pages} after 3 attempts; aborting"
            exit 2
        fi
        mapfile -t _page_pairs < <(printf '%s' "$LAST_QUERY_RESPONSE" \
            | jq -r '.data[] | select(._digest != null and ._digest != "") | "\(._repository)|\(._digest)"')
        if [ "${#_page_pairs[@]}" -gt 0 ]; then
            DIGEST_PAIRS+=("${_page_pairs[@]}")
        fi
        ENUM_SKIP_TOKEN="$LAST_QUERY_SKIP_TOKEN"
        [ -z "$ENUM_SKIP_TOKEN" ] && break
    done
    _t_enum_ms=$(_elapsed_ms "$_t_enum_start")
    log_info "enumerate: found ${#DIGEST_PAIRS[@]} unique pairs in ${_enum_pages} page(s) time_ms=${_t_enum_ms}"
    echo "Enumerate: ${#DIGEST_PAIRS[@]} unique (repo, digest) pair(s)"
fi

TOTAL_DIGESTS=${#DIGEST_PAIRS[@]}

if [ "$TOTAL_DIGESTS" -eq 0 ]; then
    echo "No matching images found."
    if [ -n "$REPORT_TMP" ]; then
        mv -f "$REPORT_TMP" "$REPORT_FILE"
        REPORT_TMP=""
    fi
    log_info "end total_processed=0 digests=0 report_file=${REPORT_FILE:-<none>}"
    exit 0
fi

# ═════════════════════════════════════════════════════════════════════════
# PHASE 1 — Resolve tags upfront (one az call per unique repo)
#
# Extract unique repos from DIGEST_PAIRS and fetch tag listings once each.
# Bypass entirely if --skip-tags. Failure to fetch a repo's tags is logged
# once and its digests fall back to TAG=N/A (never aborts the scan).
# ═════════════════════════════════════════════════════════════════════════
_t_tags_start=$(_now_realtime)
_tag_api_calls=0

if [ "$SKIP_TAGS" = true ]; then
    log_info "tag_resolve: skipped (--skip-tags); all rows get TAG=N/A"
    _t_tags_ms=0
else
    _unique_repo_count=$(printf '%s\n' "${DIGEST_PAIRS[@]}" | awk -F'|' '{print $1}' | sort -u | wc -l)
    log_info "tag_resolve: start unique_repos=${_unique_repo_count}"

    while IFS= read -r repo_name; do
        [ -z "$repo_name" ] && continue
        [ -n "${REPO_TAGS_TRIED[$repo_name]+x}" ] && continue
        REPO_TAGS_TRIED[$repo_name]=1
        _tag_api_calls=$((_tag_api_calls + 1))

        tags_json=$(az acr repository show-tags \
            --name "$ACR_NAME" \
            --repository "$repo_name" \
            --detail \
            --top 5000 \
            --output json 2>/dev/null || true)

        if [ -z "$tags_json" ] || ! printf '%s' "$tags_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
            log_warn "show-tags failed for repository=${repo_name} — digests in this repo will use TAG=N/A"
            continue
        fi

        tag_count=$(printf '%s' "$tags_json" | jq 'length' 2>/dev/null || echo 0)
        if [ "$tag_count" = "5000" ]; then
            log_warn "show-tags returned exactly 5000 entries for repository=${repo_name} — response may be truncated; some digests may fall back to TAG=N/A"
        fi

        # FIRST-tag-wins for digests with multiple tags (matches previous
        # "[0]" JMESPath filter).
        while IFS=$'\x1f' read -r d_digest d_name; do
            [ -z "$d_digest" ] && continue
            key="${repo_name}@${d_digest}"
            if [ -z "${TAG_CACHE[$key]+x}" ]; then
                TAG_CACHE[$key]="$d_name"
            fi
        done < <(printf '%s' "$tags_json" | jq -r '.[] | select(.digest and .name) | [.digest, .name] | join("")')
    done < <(printf '%s\n' "${DIGEST_PAIRS[@]}" | awk -F'|' '{print $1}' | sort -u)

    _t_tags_ms=$(_elapsed_ms "$_t_tags_start")
    log_info "tag_resolve: end api_calls=${_tag_api_calls} cached_pairs=${#TAG_CACHE[@]} time_ms=${_t_tags_ms}"
    echo "Tags:      ${_tag_api_calls} az call(s), ${#TAG_CACHE[@]} tag(s) cached"
fi

# ═════════════════════════════════════════════════════════════════════════
# PHASE 2 — Per-digest scan with inner pagination
#
# For each (repo, digest) pair, run the enriched KQL (JOIN with cvedetails)
# scoped to a single digest. Small dataset per call → ARG stable → no
# UnexpectedQueryExecutionError. Inner while loop drains skip-token pages
# until the digest is fully consumed. Rows stream directly to CSV — no
# in-memory accumulation across pages.
#
# Fail-fast per page after 3 retries in run_arg_rest_query. Aborts the
# whole scan (incomplete CSV is worse than obvious failure — operator can
# re-run).
# ═════════════════════════════════════════════════════════════════════════
JQ_ROW_EXTRACT='
    def clean(x): (x // "" | tostring | gsub("[\r\n]"; " "));
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
    ] | join("")
'

for pair in "${DIGEST_PAIRS[@]}"; do
    DIGEST_NUM=$((DIGEST_NUM + 1))
    _repo="${pair%%|*}"
    _digest="${pair##*|}"
    _t_digest_start=$(_now_realtime)
    _digest_rows_before=$TOTAL_PROCESSED
    _digest_pages=0

    _SCAN_QUERY=$(build_digest_scan_query "$_digest")
    SCAN_SKIP_TOKEN=""

    while : ; do
        _digest_pages=$((_digest_pages + 1))
        if ! run_arg_rest_query "$_SCAN_QUERY" "$SCAN_SKIP_TOKEN"; then
            log_error "scan failed digest_short=${_digest:(-12)} repo=${_repo} page=${_digest_pages} after 3 attempts; aborting (processed=${TOTAL_PROCESSED} digests=$((DIGEST_NUM - 1))/${TOTAL_DIGESTS})"
            exit 2
        fi
        RESPONSE="$LAST_QUERY_RESPONSE"

        BATCH_COUNT=$(printf '%s' "$RESPONSE" | jq '.data | length' 2>/dev/null || echo 0)
        if [ -z "$BATCH_COUNT" ] || [ "$BATCH_COUNT" -eq 0 ]; then
            _digest_pages=$((_digest_pages - 1))
            break
        fi

        # ── row processing (stream: no accumulation) ─────────────────────
        # One jq invocation per PAGE emits every row as US-separated (0x1F)
        # fields; the shell loop splits with `IFS=$'\x1f' read`. Field
        # ORDER is the CSV contract (matches csv_write_row call site and
        # the CSV header) — do not reorder without updating JQ_ROW_EXTRACT
        # AND the tests.
        while IFS=$'\x1f' read -r \
            REPO DIGEST CVSS_SCORE CVE_ID SEVERITY_RAW \
            PKG_CATEGORY PKG_LANGUAGE PKG_NAME CURRENT_VERSION FIXED_VERSION \
            PATCHABLE REMEDIATION FIX_STATUS CVE_AGE_DAYS \
            IN_EXPLOIT_KIT PUB_EXPLOIT VER_EXPLOIT LAST_PUSHED; do

            # Severity: Defender raw is authoritative; fall back to CVSS-derived.
            if [ -n "$SEVERITY_RAW" ]; then
                SEVERITY="$SEVERITY_RAW"
            else
                SEVERITY=$(classify_severity "$CVSS_SCORE")
            fi

            IMAGE_ID="${REPO}@${DIGEST}"
            TAG="${TAG_CACHE[${REPO}@${DIGEST}]:-N/A}"

            # Report-only mode (default): write all columns to CSV.
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

            # Block/unblock modes.
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

        SCAN_SKIP_TOKEN="$LAST_QUERY_SKIP_TOKEN"
        [ -z "$SCAN_SKIP_TOKEN" ] && break
    done

    _digest_rows=$((TOTAL_PROCESSED - _digest_rows_before))
    _t_digest_ms=$(_elapsed_ms "$_t_digest_start")
    TOTAL_PAGES=$((TOTAL_PAGES + _digest_pages))

    echo "[${DIGEST_NUM}/${TOTAL_DIGESTS}] ${_repo} @${_digest:(-12)}: ${_digest_rows} row(s), ${_digest_pages} page(s), ${_t_digest_ms}ms"
    log_info "digest ${DIGEST_NUM}/${TOTAL_DIGESTS} repo=${_repo} digest_short=${_digest:(-12)} pages=${_digest_pages} rows=${_digest_rows} time_ms=${_t_digest_ms}"
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
    echo "Total rows found: ${TOTAL_PROCESSED} across ${TOTAL_DIGESTS} digest(s), ${TOTAL_PAGES} page(s)"
    echo "Report saved to: $REPORT_FILE"
    log_info "end total_processed=${TOTAL_PROCESSED} digests=${TOTAL_DIGESTS} pages=${TOTAL_PAGES} report_file=${REPORT_FILE}"
else
    echo "Total actions taken: ${TOTAL_PROCESSED} across ${TOTAL_DIGESTS} digest(s), ${TOTAL_PAGES} page(s)"
    log_info "end total_processed=${TOTAL_PROCESSED} digests=${TOTAL_DIGESTS} pages=${TOTAL_PAGES} mode=${_LOG_MODE}"
fi