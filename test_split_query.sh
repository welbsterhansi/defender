#!/usr/bin/env bash
# test_split_query.sh v2 — multi-digest loop, emite CSV no formato exato
# de producao (18 colunas, mesma ordem/nomes de defender.sh:977).
#
# Estrategia:
#   - Loop por digest.
#   - Pra cada digest, chama ARG via az rest (api 2022-10-01, default scope)
#     com KQL Daniel-style (JOIN inline com cvedetails, filtro por 1 digest).
#   - Extends adicionais pra cobrir os 5 campos que Daniel nao traz:
#       packageCategory, packageLanguage, remediation,
#       lastPushedToRegistryUTC, patchable
#     + cveAgeDays (derivado de PublishedDate).
#   - Coalesces identicos aos de defender.sh (mesmos fallbacks).
#   - Emite CSV unico com header + linhas de todos os digests.
#
# Uso:
#   ./test_split_query.sh <digest1> [digest2] [digest3] ...
#
# Exemplo:
#   ./test_split_query.sh \
#     sha256:9fd3febced652e9318e5782ac993cd080ef26a03c65d039c40ecf533d69b9bcf \
#     sha256:aaaa...
#
# Output:
#   test_output_<timestamp>.csv (18 colunas, formato defender.sh)

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

# ---------- CSV header: 18 colunas na ordem exata de defender.sh:977 ----------

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

# ---------- loop principal ----------

TOTAL_ROWS=0
TOTAL_ENRICHED=0
DIGESTS_OK=0
DIGESTS_FAIL=0

for DIGEST in "${DIGESTS[@]}"; do
    echo "=== digest: $DIGEST ==="

    KQL=$(kql_for_digest "$DIGEST")
    BODY=$(jq -nc --arg q "$KQL" '{query: $q, options: {"$top": 1000}}')

    START=$(date +%s)
    if ! RESP=$(az rest --method post --url "$API" --body "$BODY" 2>&1); then
        echo "  FALHA: $(head -c 200 <<<"$RESP")" >&2
        DIGESTS_FAIL=$((DIGESTS_FAIL + 1))
        continue
    fi
    ELAPSED=$(( $(date +%s) - START ))

    COUNT=$(jq '.data | length' <<<"$RESP")
    if [[ "$COUNT" -eq 0 ]]; then
        echo "  0 linhas (digest nao existe no tenant ou sem CVEs)" >&2
        DIGESTS_FAIL=$((DIGESTS_FAIL + 1))
        continue
    fi

    ENRICHED=$(jq '[.data[] | select(.cvssScore != null and .cvssScore > 0)] | length' <<<"$RESP")
    echo "  linhas: $COUNT | enriched (CVSS>0): $ENRICHED | tempo: ${ELAPSED}s"

    if [[ "$COUNT" -eq 1000 ]]; then
        echo "  AVISO: bateu no limite de 1000 linhas — pode ter truncado." >&2
        echo "         Producao vai precisar de paginacao via skip-token." >&2
    fi

    # append CSV: jq @csv escapa aspas/virgulas automaticamente
    jq -r '.data[] | [
        .repository, .digest, .cvssScore, .cveId, .severityRaw,
        .packageCategory, .packageLanguage, .packageName, .currentVersion, .fixedVersion,
        .patchable, .remediation, .fixStatus, .cveAgeDays,
        .isInExploitKit, .hasPublishedExploit, .hasVerifiedExploit, .lastPushedToRegistryUTC
    ] | @csv' <<<"$RESP" >> "$OUTPUT_CSV"

    TOTAL_ROWS=$((TOTAL_ROWS + COUNT))
    TOTAL_ENRICHED=$((TOTAL_ENRICHED + ENRICHED))
    DIGESTS_OK=$((DIGESTS_OK + 1))
done

# ---------- resumo ----------

echo ""
echo "=== RESUMO ==="
echo "digests processados: ${#DIGESTS[@]}  (ok=$DIGESTS_OK, fail=$DIGESTS_FAIL)"
echo "total de linhas:    $TOTAL_ROWS"
if [[ "$TOTAL_ROWS" -gt 0 ]]; then
    RATE=$(( TOTAL_ENRICHED * 100 / TOTAL_ROWS ))
    echo "enriched (CVSS>0):  $TOTAL_ENRICHED  (${RATE}%)"
fi
echo "CSV gerado:         $OUTPUT_CSV"

echo ""
echo "--- preview do CSV (5 primeiras linhas apos header) ---"
head -6 "$OUTPUT_CSV" | column -t -s ','

echo ""
if [[ "$DIGESTS_FAIL" -gt 0 ]]; then
    echo "RESULTADO: PARCIAL — $DIGESTS_FAIL de ${#DIGESTS[@]} digests falharam."
    exit 2
elif [[ "$TOTAL_ENRICHED" -eq 0 ]]; then
    echo "RESULTADO: FALHOU — 0% enriched."
    exit 3
elif [[ "$TOTAL_ENRICHED" -lt "$TOTAL_ROWS" ]]; then
    echo "RESULTADO: PARCIAL — enriched < total. Investigar linhas sem CVSS."
else
    echo "RESULTADO: OK — 100% enriched, todos os 18 campos populados."
    echo "           Compare $OUTPUT_CSV com um CSV antigo de vulnerable_images_report.csv."
    echo "           Se bater linha/coluna, podemos refatorar defender.sh."
fi
