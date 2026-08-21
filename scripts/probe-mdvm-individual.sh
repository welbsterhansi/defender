#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/probe-mdvm-individual.sh — read-only Defender for Cloud ARG probe
#
# Purpose (investigation, 2026-08):
#   Microsoft retired legacy grouped container vulnerability recommendations
#   (sub-assessments) on 2026-07-31 — the exact shape defender.sh's KQL depends
#   on for Leg A (c0b7cfc6-…). This probe runs FIVE read-only Azure Resource
#   Graph queries to gather the raw evidence needed to design the migration
#   safely, WITHOUT modifying defender.sh, its KQL, or any CSV.
#
# What it does NOT do:
#   - No writes to any CSV, no calls to `acr repository show-tags`,
#     no pagination, no image blocking/unblocking, no OpenShift calls,
#     no changes to defender.sh.
#   - Absolutely read-only against Azure Resource Graph.
#
# Output:
#   Writes 5 JSON files to an output directory (default ./probes/probe-<ts>/).
#   probe-1: legacy sub-assessment row count (expected ~0 after retirement)
#   probe-2: recommendation UUIDs currently emitting for ACR — with per-known-UUID
#            breakdown (c0b7cfc6, 33422d8f, c609cf0f from the MS transition doc)
#            plus any unknown-new UUIDs Microsoft added
#   probe-3: 3 raw assessments — CONTAINS CLIENT REPO/DIGEST DATA, do not share
#   probe-4: presence check for every schema path defender.sh currently uses,
#            plus the paths speculated by other analyses (cvssV31, fixState,
#            exploitUrisPublished, vulnerabilityDetails.cvssV3Score, …)
#   probe-5: bag_keys discovery — enumerates ALL keys present under each
#            subtree (additionalData, CvesDetails[], vulnerabilityDetails,
#            softwareDetails, artifactDetails). Catches unknown-unknowns
#            such as new fields for EPSS, KEV listing, exploit maturity.
#
# Usage:
#   scripts/probe-mdvm-individual.sh --acr-name <ACR>
#   scripts/probe-mdvm-individual.sh --acr-name <ACR> --repository <repo>
#   scripts/probe-mdvm-individual.sh --acr-name <ACR> --output-dir ./probes/x
#
# Safety:
#   Refuses to run without --acr-name (same guardrail as `make smoke-real`)
#   so nobody accidentally probes the wrong subscription.
#
# Reference: docs/investigation-mdvm-2026-08.md
# ---------------------------------------------------------------------------
set -euo pipefail

ACR_NAME=""
REPOSITORY=""
OUT_DIR=""

usage() {
    sed -n '3,42p' "$0"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --acr-name)   ACR_NAME="${2:-}";   shift 2 ;;
        --repository) REPOSITORY="${2:-}"; shift 2 ;;
        --output-dir) OUT_DIR="${2:-}";    shift 2 ;;
        -h|--help)    usage 0 ;;
        *)            echo "Unknown flag: $1" >&2; usage 2 ;;
    esac
done

if [ -z "$ACR_NAME" ]; then
    echo "Error: --acr-name is required (safety guardrail — this probe hits real ARG)." >&2
    usage 2
fi

# Prerequisites — bail out early with a clear message instead of a cryptic
# `az` traceback halfway through.
for cmd in az jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: '$cmd' not found on PATH." >&2
        exit 2
    fi
done

if ! az account show >/dev/null 2>&1; then
    echo "Error: not logged in. Run 'az login' first." >&2
    exit 2
fi

# Validate ACR exists — same pattern defender.sh uses (fail before touching ARG).
if ! az acr show --name "$ACR_NAME" >/dev/null 2>&1; then
    echo "Error: ACR '$ACR_NAME' not found in the current subscription." >&2
    exit 2
fi

# Build optional Leg-B-style repo filter. The `repositories-<dashed>-images-`
# anchor is the same convention the legacy SoftwareUpdate leg used in
# resourceDetails.Id — we reuse it here to stay consistent with what
# defender.sh already produces, so results are comparable.
REPO_FILTER=""
if [ -n "$REPOSITORY" ]; then
    _dashed="${REPOSITORY//\//-}"
    REPO_FILTER="| where properties.resourceDetails.Id contains \"repositories-${_dashed}-images-\""
fi

# Default output dir: ./probes/probe-YYYYMMDD-HHMMSS — timestamp keeps
# consecutive runs isolated so nothing overwrites earlier evidence.
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="probes/probe-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUT_DIR"

echo "ACR:        $ACR_NAME" >&2
[ -n "$REPOSITORY" ] && echo "Repository: $REPOSITORY (Leg-B-style filter applied to probes 2–4)" >&2
echo "Output:     $OUT_DIR" >&2
echo >&2

run_probe() {
    local label="$1"
    local out_file="$2"
    local query="$3"

    echo "==> $label" >&2
    if ! az graph query -q "$query" --first 100 --output json > "$OUT_DIR/$out_file" 2> "$OUT_DIR/$out_file.err"; then
        echo "    FAILED — see $OUT_DIR/$out_file.err" >&2
        return 1
    fi
    rm -f "$OUT_DIR/$out_file.err"
    # Quick sanity read — how many rows in the response.
    local count
    count=$(jq -r '(.data | length) // 0' "$OUT_DIR/$out_file" 2>/dev/null || echo "?")
    echo "    ok — $count row(s) → $out_file" >&2
}

# ---------------------------------------------------------------------------
# Probe 1: is the legacy Leg-A sub-assessment for c0b7cfc6-… still emitting?
# Expected after 2026-07-31 retirement: 0 rows. If > 0, the tenant has not
# fully propagated the retirement yet.
# ---------------------------------------------------------------------------
run_probe "[1/4] Legacy sub-assessments count (c0b7cfc6-...)" \
    "probe-1-subassessments-count.json" \
    "securityresources
    | where type =~ 'microsoft.security/assessments/subassessments'
    | where id contains 'c0b7cfc6-3172-465a-b378-53c7ff2cc0d5'
    | summarize legacy_subassessment_rows = count()"

# ---------------------------------------------------------------------------
# Probe 2: which recommendation UUIDs are actually emitting today for
# .containerimage / Source=Azure? Per the MS transition doc, THREE UUIDs
# now cover ACR containers under SoftwareUpdate (was one grouped UUID):
#   - c0b7cfc6-...  Azure registry container images should have vulnerabilities resolved
#   - 33422d8f-...  Container images in Azure registry should have vulnerability findings resolved
#   - c609cf0f-...  Azure running container images should have vulnerabilities resolved
# We list ALL UUIDs (not filtered) plus a per-known-UUID row count, so any
# 4th UUID Microsoft adds later shows up too.
# Ref: https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations
# ---------------------------------------------------------------------------
run_probe "[2/5] Recommendation UUIDs emitting for ACR (all + known-3 breakdown)" \
    "probe-2-assessment-ids.json" \
    "securityresources
    | where type == 'microsoft.security/assessments'
    | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
    | where properties.resourceDetails.ResourceType == '.containerimage'
    | where properties.resourceDetails.Source == 'Azure'
    ${REPO_FILTER}
    | extend assessmentId = extract('/assessments/([^/]+)', 1, tolower(tostring(id)))
    | extend knownUuid = case(
        assessmentId == 'c0b7cfc6-3172-465a-b378-53c7ff2cc0d5', 'c0b7cfc6-acr-registry',
        assessmentId == '33422d8f-ab1e-42be-bc9a-38685bb567b9', '33422d8f-acr-registry-v2',
        assessmentId == 'c609cf0f-71ab-41e9-a3c6-9a1f7fe1b8d5', 'c609cf0f-acr-running',
        'unknown-new-uuid'
      )
    | summarize rows = count() by assessmentId, knownUuid
    | order by rows desc"

# ---------------------------------------------------------------------------
# Probe 3: 3 raw assessments — the ONLY reliable way to see where cveId,
# CVSS, exploitability, fixStatus etc. are now nested in the individual
# model. NOTE: this file contains real repository names and digests from
# the client's registry — treat it as sensitive and do not paste externally
# without redaction.
# ---------------------------------------------------------------------------
run_probe "[3/5] Raw sample (3 assessments — CONTAINS CLIENT DATA)" \
    "probe-3-raw-sample.json" \
    "securityresources
    | where type == 'microsoft.security/assessments'
    | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
    | where properties.resourceDetails.ResourceType == '.containerimage'
    | where properties.resourceDetails.Source == 'Azure'
    ${REPO_FILTER}
    | take 3"

# ---------------------------------------------------------------------------
# Probe 4: presence-of-path check. Each countif returns how many rows
# actually populate that JSON path — including the old paths defender.sh
# uses AND the renamed paths speculated by other analyses. Zero on the
# old path + non-zero on the new path = confirmed rename. No guessing.
# ---------------------------------------------------------------------------
run_probe "[4/5] Schema path presence (old vs speculated new)" \
    "probe-4-field-presence.json" \
    "securityresources
    | where type == 'microsoft.security/assessments'
    | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
    | where properties.resourceDetails.ResourceType == '.containerimage'
    | where properties.resourceDetails.Source == 'Azure'
    ${REPO_FILTER}
    | summarize
        total                            = count(),
        tem_CvesDetails                  = countif(isnotnull(properties.additionalData.CvesDetails)),
        tem_cvssV30Score                 = countif(isnotnull(properties.additionalData.cvssV30Score)),
        tem_cvssV31Score                 = countif(isnotnull(properties.additionalData.cvssV31Score)),
        tem_vulnDetails                  = countif(isnotnull(properties.additionalData.vulnerabilityDetails)),
        tem_vulnDetails_cvssV3Score      = countif(isnotnull(properties.additionalData.vulnerabilityDetails.cvssV3Score)),
        tem_softwareDetails_fixStatus    = countif(isnotnull(properties.additionalData.softwareDetails.fixStatus)),
        tem_vulnDetails_fixState         = countif(isnotnull(properties.additionalData.vulnerabilityDetails.fixState)),
        tem_exploitabilityAssessment     = countif(isnotnull(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment)),
        tem_exploitUrisPublished         = countif(isnotnull(properties.additionalData.vulnerabilityDetails.exploitUrisPublished)),
        tem_artifactDetails              = countif(isnotnull(properties.additionalData.artifactDetails)),
        tem_DetectedSoftwareVersions     = countif(isnotnull(properties.additionalData.DetectedSoftwareVersions)),
        tem_FixedVersion_top             = countif(isnotnull(properties.additionalData.FixedVersion)),
        tem_metadata_severity            = countif(isnotnull(properties.metadata.severity)),
        tem_status_severity              = countif(isnotnull(properties.status.severity))"

# ---------------------------------------------------------------------------
# Probe 5: discovery via bag_keys.
# probe-4 is an ALLOWLIST — it only reports paths we thought to ask about.
# If Microsoft added a brand-new field (e.g. EPSS score, KEV listing,
# exploit maturity, package purl), probe-4 misses it silently.
# This probe enumerates the actual keys present under each subtree and
# aggregates by frequency. Zero writes, aggregations only.
#
# Output shape per row: subtree | key | rows_with_key
#   subtree = one of additionalData / additionalData.CvesDetails[] /
#             vulnerabilityDetails / softwareDetails / artifactDetails
#   key     = a top-level property name found under that subtree
#   rows    = how many assessments populated that key (higher = more
#             widespread, likely to matter for the migration design)
# ---------------------------------------------------------------------------
run_probe "[5/5] Key discovery via bag_keys (finds unknown-unknowns)" \
    "probe-5-bag-keys.json" \
    "securityresources
    | where type == 'microsoft.security/assessments'
    | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
    | where properties.resourceDetails.ResourceType == '.containerimage'
    | where properties.resourceDetails.Source == 'Azure'
    ${REPO_FILTER}
    | extend
        _ad  = properties.additionalData,
        _vd  = properties.additionalData.vulnerabilityDetails,
        _sd  = properties.additionalData.softwareDetails,
        _art = properties.additionalData.artifactDetails,
        _cveArr = parse_json(tostring(properties.additionalData.CvesDetails))
    | mv-expand _cveObj = _cveArr
    | mv-apply k_ad  = bag_keys(_ad)  on (extend subtree='additionalData',                key=tostring(k_ad))
    | union (
        securityresources
        | where type == 'microsoft.security/assessments'
        | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
        | where properties.resourceDetails.ResourceType == '.containerimage'
        | where properties.resourceDetails.Source == 'Azure'
        ${REPO_FILTER}
        | extend _cveArr = parse_json(tostring(properties.additionalData.CvesDetails))
        | mv-expand _cveObj = _cveArr
        | mv-apply k_cve = bag_keys(_cveObj) on (extend subtree='additionalData.CvesDetails[]', key=tostring(k_cve))
      )
    | union (
        securityresources
        | where type == 'microsoft.security/assessments'
        | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
        | where properties.resourceDetails.ResourceType == '.containerimage'
        | where properties.resourceDetails.Source == 'Azure'
        ${REPO_FILTER}
        | extend _vd = properties.additionalData.vulnerabilityDetails
        | where isnotnull(_vd)
        | mv-apply k_vd = bag_keys(_vd) on (extend subtree='additionalData.vulnerabilityDetails', key=tostring(k_vd))
      )
    | union (
        securityresources
        | where type == 'microsoft.security/assessments'
        | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
        | where properties.resourceDetails.ResourceType == '.containerimage'
        | where properties.resourceDetails.Source == 'Azure'
        ${REPO_FILTER}
        | extend _sd = properties.additionalData.softwareDetails
        | where isnotnull(_sd)
        | mv-apply k_sd = bag_keys(_sd) on (extend subtree='additionalData.softwareDetails', key=tostring(k_sd))
      )
    | union (
        securityresources
        | where type == 'microsoft.security/assessments'
        | where properties.metadata.recommendationCategory == 'SoftwareUpdate'
        | where properties.resourceDetails.ResourceType == '.containerimage'
        | where properties.resourceDetails.Source == 'Azure'
        ${REPO_FILTER}
        | extend _art = properties.additionalData.artifactDetails
        | where isnotnull(_art)
        | mv-apply k_art = bag_keys(_art) on (extend subtree='additionalData.artifactDetails', key=tostring(k_art))
      )
    | summarize rows_with_key = count() by subtree, key
    | order by subtree asc, rows_with_key desc"

echo >&2
echo "Done." >&2
echo "Next: share $OUT_DIR/probe-{1,2,4,5}.json here (probes 1, 2, 4, 5 are aggregations — safe)." >&2
echo "      probe-3-raw-sample.json contains client data — inspect locally with jq, share only redacted excerpts." >&2
