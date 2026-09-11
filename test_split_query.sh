#!/usr/bin/env bash
# test_split_query.sh v3 — multi-digest loop + skip-token pagination + retry
#
# Melhorias sobre v2:
#   1. Skip-token pagination: itera todas paginas por digest (nao trunca em 1000).
#   2. Retry/backoff [2, 5]s por page em erros HTTP/rede/UnexpectedQueryExecutionError.
#   3. Validacao de field count == 18 no CSV final (via python3 csv module).
#   4. Resumo tabular por digest (pages, rows, enriched, tempo).
#
# Uso:
#   ./test_split_query.sh <digest1> [digest2] [digest3] ...
#
# Output:
#   test_output_<UTC-timestamp>.csv (18 colunas, formato exato defender.sh:977)
#
# Requisitos: az cli logado, jq, python3 (opcional, so pra validacao final).

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "uso: $0 <digest1> [digest2] [digest3] ..." >&2
    echo "     digest deve ter formato sha256:<64 hex chars>" >&2
    exit 1
fi

if ! az account show >/dev/null 2>&1; then
    echo "erro: nao logado no az cli. rode 'az login' primeiro." >&2
    exit 1
fi

DIGESTS=("$@")
API="https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
OUTPUT_CSV="test_output_$(date -u +%Y%m%dT%H%M%SZ).csv"
EXPECTED_FIELDS=18

CSV_HEADER="repository,digest,cvssScore,cveId,severityRaw,packageCategory,packageLanguage,packageName,currentVersion,fixedVersion,patchable,remediation,fixStatus,cveAgeDays,isInExploitKit,hasPublishedExploit,hasVerifiedExploit,lastPushedToRegistryUTC"
echo "$CSV_HEADER" > "$OUTPUT_CSV"

# ---------- KQL template (interpola $DIGEST no loop) ----------

kql_for_digest() {
    local digest="$1"
    cat <<KQL_END
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
    digest = _digest,
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
    isInExploitKit = iff(tobool(_inExploitKitEnrich) == true, "true", "false"),
    hasPublishedExploit = iff(tobool(_publishedExpEnrich) == true, "true", "false"),
    hasVerifiedExploit = iff(tobool(_verifiedExpEnrich) == true, "true", "false")
| extend patchable = case(
    fixStatus =~ "FixAvailable", "true",
    fixStatus in~ ("NoFix", "NoFixAvailable", "WillNotFix"), "false",
    isnotempty(fixedVersion), "true",
    ""
  )
| where cveId startswith "CVE-"
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
KQL_END
}

# ---------- az rest com retry/backoff [2, 5]s ----------
# Sucesso: seta LAST_RESP e retorna 0. Falha apos 3 tentativas: retorna 1.

az_rest_retry() {
    local body="$1"
    local delays=(2 5)
    local attempt rc err
    for attempt in 1 2 3; do
        if LAST_RESP=$(az rest --method post --url "$API" --body "$body" 2>&1); then
            return 0
        fi
        rc=$?
        err=$(head -c 200 <<<"$LAST_RESP")
        echo "    WARN: tentativa ${attempt}/3 falhou (rc=$rc): ${err}" >&2
        if [[ $attempt -lt 3 ]]; then
            local delay="${delays[$((attempt-1))]}"
            echo "    retry em ${delay}s..." >&2
            sleep "$delay"
        fi
    done
    return 1
}

# ---------- loop principal ----------

TOTAL_ROWS=0
TOTAL_ENRICHED=0
DIGESTS_OK=0
DIGESTS_FAIL=0
declare -a SUMMARY_LINES
SUMMARY_LINES+=("digest	pages	rows	enriched	time")

for DIGEST in "${DIGESTS[@]}"; do
    echo "=== digest: $DIGEST ==="

    KQL=$(kql_for_digest "$DIGEST")
    NEXT_TOKEN=""
    PAGE=0
    DIGEST_ROWS=0
    DIGEST_ENRICHED=0
    DIGEST_START=$(date +%s)
    DIGEST_FAILED=0

    while true; do
        PAGE=$((PAGE + 1))
        if [[ -z "$NEXT_TOKEN" ]]; then
            BODY=$(jq -nc --arg q "$KQL" '{query: $q, options: {"$top": 1000}}')
        else
            BODY=$(jq -nc --arg q "$KQL" --arg t "$NEXT_TOKEN" \
                '{query: $q, options: {"$top": 1000, "$skipToken": $t}}')
        fi

        if ! az_rest_retry "$BODY"; then
            echo "  FALHA definitiva na page $PAGE apos 3 retries — pulando digest" >&2
            DIGEST_FAILED=1
            break
        fi

        COUNT=$(jq '.data | length' <<<"$LAST_RESP")
        ENRICHED=$(jq '[.data[] | select(.cvssScore != null and .cvssScore > 0)] | length' <<<"$LAST_RESP")

        DIGEST_ROWS=$((DIGEST_ROWS + COUNT))
        DIGEST_ENRICHED=$((DIGEST_ENRICHED + ENRICHED))

        # append CSV
        jq -r '.data[] | [
            .repository, .digest, .cvssScore, .cveId, .severityRaw,
            .packageCategory, .packageLanguage, .packageName, .currentVersion, .fixedVersion,
            .patchable, .remediation, .fixStatus, .cveAgeDays,
            .isInExploitKit, .hasPublishedExploit, .hasVerifiedExploit, .lastPushedToRegistryUTC
        ] | @csv' <<<"$LAST_RESP" >> "$OUTPUT_CSV"

        echo "  page $PAGE: ${COUNT} linhas (${ENRICHED} enriched)"

        NEXT_TOKEN=$(jq -r '.["$skipToken"] // empty' <<<"$LAST_RESP")
        if [[ -z "$NEXT_TOKEN" ]]; then
            break
        fi
    done

    DIGEST_ELAPSED=$(( $(date +%s) - DIGEST_START ))

    # digest short pra tabela (ultimos 12 chars do sha)
    DIGEST_SHORT="${DIGEST:(-12)}"

    if [[ $DIGEST_FAILED -eq 1 ]]; then
        DIGESTS_FAIL=$((DIGESTS_FAIL + 1))
        SUMMARY_LINES+=("${DIGEST_SHORT}	${PAGE}	${DIGEST_ROWS}	${DIGEST_ENRICHED}	${DIGEST_ELAPSED}s FAIL")
        continue
    fi

    if [[ $DIGEST_ROWS -eq 0 ]]; then
        DIGESTS_FAIL=$((DIGESTS_FAIL + 1))
        SUMMARY_LINES+=("${DIGEST_SHORT}	0	0	0	${DIGEST_ELAPSED}s 0-rows")
        echo "  0 linhas (digest nao existe no tenant ou sem CVEs)" >&2
        continue
    fi

    DIGESTS_OK=$((DIGESTS_OK + 1))
    TOTAL_ROWS=$((TOTAL_ROWS + DIGEST_ROWS))
    TOTAL_ENRICHED=$((TOTAL_ENRICHED + DIGEST_ENRICHED))
    SUMMARY_LINES+=("${DIGEST_SHORT}	${PAGE}	${DIGEST_ROWS}	${DIGEST_ENRICHED}	${DIGEST_ELAPSED}s")
done

# ---------- validacao de field count (opcional, precisa python3) ----------

BAD_FIELD_LINES="?"
if command -v python3 >/dev/null 2>&1; then
    BAD_FIELD_LINES=$(python3 - "$OUTPUT_CSV" "$EXPECTED_FIELDS" <<'PY'
import csv, sys
path, expected = sys.argv[1], int(sys.argv[2])
bad = 0
with open(path, newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    for i, row in enumerate(reader, 1):
        if len(row) != expected:
            bad += 1
            if bad <= 3:
                print(f"  line {i}: {len(row)} fields (esperado {expected})", file=sys.stderr)
print(bad)
PY
)
fi

# ---------- resumo tabular ----------

echo ""
echo "=== RESUMO POR DIGEST ==="
printf '%s\n' "${SUMMARY_LINES[@]}" | column -t -s $'\t'

echo ""
echo "=== TOTAIS ==="
echo "digests processados: ${#DIGESTS[@]}  (ok=${DIGESTS_OK}, fail=${DIGESTS_FAIL})"
echo "total de linhas:     ${TOTAL_ROWS}"
if [[ $TOTAL_ROWS -gt 0 ]]; then
    RATE=$(( TOTAL_ENRICHED * 100 / TOTAL_ROWS ))
    echo "enriched (CVSS>0):   ${TOTAL_ENRICHED}  (${RATE}%)"
fi
echo "field count validation: ${BAD_FIELD_LINES} linhas com != ${EXPECTED_FIELDS} campos"
echo "CSV gerado:          ${OUTPUT_CSV}"

echo ""
echo "--- preview do CSV (5 primeiras linhas) ---"
head -6 "$OUTPUT_CSV" | cut -c 1-200

# ---------- verdict ----------

echo ""
if [[ $DIGESTS_FAIL -gt 0 ]]; then
    echo "RESULTADO: PARCIAL — ${DIGESTS_FAIL} de ${#DIGESTS[@]} digests falharam ou vieram vazios."
    exit 2
elif [[ $TOTAL_ROWS -eq 0 ]]; then
    echo "RESULTADO: FALHOU — nenhuma linha coletada."
    exit 3
elif [[ "$BAD_FIELD_LINES" != "0" && "$BAD_FIELD_LINES" != "?" ]]; then
    echo "RESULTADO: FALHOU — ${BAD_FIELD_LINES} linhas com field count errado (esperado ${EXPECTED_FIELDS})."
    exit 4
elif [[ $TOTAL_ENRICHED -eq 0 ]]; then
    echo "RESULTADO: FALHOU — 0% enriched (JOIN com cvedetails nao bateu)."
    exit 5
elif [[ $TOTAL_ENRICHED -lt $TOTAL_ROWS ]]; then
    RATE=$(( TOTAL_ENRICHED * 100 / TOTAL_ROWS ))
    echo "RESULTADO: PARCIAL — ${RATE}% enriched. Investigar linhas sem CVSS."
    exit 0
else
    echo "RESULTADO: OK — 100% enriched, todos os campos validados."
    echo "           Proximo passo: comparar ${OUTPUT_CSV} com vulnerable_images_report.csv antigo."
fi
