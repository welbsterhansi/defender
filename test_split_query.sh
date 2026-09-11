#!/usr/bin/env bash
# test_split_query.sh — reproduz em bash + az rest a query do Daniel
# (proven working no Portal via PowerShell Search-AzGraph -UseTenantScope).
#
# Objetivo: validar que a mesma query, com os mesmos filtros por 1 digest,
# funciona via CLI usando:
#   - az rest (nao az graph query)
#   - api-version 2022-10-01
#   - tenant scope (managementGroups: [<tenant_id>])
#
# Se funcionar, prova que o pipeline inteiro (transport + api-version + scope
# + KQL com JOIN) esta correto quando o dataset e pequeno (1 digest).
# Aí o refactor do defender.sh passa a ser: iterar digests do ACR e chamar
# essa mesma query por digest, agregando o CSV.
#
# Uso:
#   ./test_split_query.sh <digest>
#
# Exemplo:
#   ./test_split_query.sh sha256:9fd3febced652e9318e5782ac993cd080ef26a03c65d039c40ecf533d69b9bcf
#
# Requisitos: az cli logado no tenant certo, jq instalado.

set -euo pipefail

DIGEST="${1:?uso: $0 <sha256:...>}"

if [[ ! "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "erro: digest deve ter formato sha256:<64 hex chars>" >&2
    exit 1
fi

API="https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"

if ! az account show >/dev/null 2>&1; then
    echo "erro: nao logado no az cli. rode 'az login' primeiro." >&2
    exit 1
fi
echo "digest: $DIGEST"
echo ""

# ---------- KQL: reproducao fiel da query do Daniel ----------
# Ordem preservada. Unica mudanca: $Digest interpolado como literal string.

KQL=$(cat <<KQL_END
securityresources
| extend Scanner=parse_json(tostring(properties.additionalData.ScannersDetails))
| extend ImageData=parse_json(tostring(properties.resourceAdditionalData))
| extend Cves=parse_json(tostring(properties.additionalData.CvesDetails))
| extend Repository=tostring(ImageData.RepositoryDetails.RepositoryName)
| extend RegistryHost=tostring(ImageData.RepositoryDetails.RegistryHost)
| extend Digest=tostring(ImageData.Digest)
| extend ImageUri=tostring(ImageData.ImageUri)
| where Digest == "$DIGEST"
| mv-expand Cve=Cves
| extend CveId=coalesce(tostring(Cve.CveId), tostring(Cve.cveId))
| where isnotempty(CveId)
| join kind=leftouter (
    securityresources
    | where type =~ "microsoft.security/cvedetails"
    | extend CveId=coalesce(tostring(properties.cveId), tostring(name))
    | where isnotempty(CveId)
    | extend Cvss40=todouble(properties.cvss["4.0"].base)
    | extend Cvss31=todouble(properties.cvss["3.1"].base)
    | extend Cvss30=todouble(properties.cvss["3.0"].base)
    | extend Cvss20=todouble(properties.cvss["2.0"].base)
    | extend CvssScore=coalesce(Cvss40,Cvss31,Cvss30,Cvss20)
    | extend CvssVersion=case(
        isnotnull(Cvss40),"4.0",
        isnotnull(Cvss31),"3.1",
        isnotnull(Cvss30),"3.0",
        isnotnull(Cvss20),"2.0",
        ""
    )
    | extend PublishedDate=todatetime(properties.publishedDate)
    | extend ExploitVerified=iff(isnull(properties.exploitabilityDetails.IsVerified),false,tobool(properties.exploitabilityDetails.IsVerified))
    | extend IsPubliclyDisclosed=iff(isnull(properties.exploitabilityDetails.IsPubliclyDisclosed),false,tobool(properties.exploitabilityDetails.IsPubliclyDisclosed))
    | extend IsInExploitKit=iff(isnull(properties.exploitabilityDetails.IsInExploitKit),false,tobool(properties.exploitabilityDetails.IsInExploitKit))
    | extend ExploitTypes=tostring(properties.exploitabilityDetails.Types)
    | summarize
        CvssScore=max(CvssScore),
        CvssVersion=take_any(CvssVersion),
        PublishedDate=take_any(PublishedDate),
        ExploitVerified=max(toint(ExploitVerified)),
        IsPubliclyDisclosed=max(toint(IsPubliclyDisclosed)),
        IsInExploitKit=max(toint(IsInExploitKit)),
        ExploitTypes=take_any(ExploitTypes)
    by CveId
) on CveId
| project-away CveId1
| extend ExploitVerified=tobool(ExploitVerified)
| extend IsPubliclyDisclosed=tobool(IsPubliclyDisclosed)
| extend IsInExploitKit=tobool(IsInExploitKit)
| extend Recommendation=tostring(properties.displayName)
| extend PackageName=coalesce(tostring(properties.additionalData.SoftwareName), tostring(properties.additionalData.softwareName))
| extend Vendor=coalesce(tostring(properties.additionalData.SoftwareVendor), tostring(properties.additionalData.softwareVendor))
| extend MdvmDetectedVersions=Scanner.mdvm.DetectedSoftwareVersions
| extend AgentlessMdvmDetectedVersions=Scanner.agentlessmdvm.DetectedSoftwareVersions
| extend CurrentVersion=case(
    array_length(MdvmDetectedVersions)>0, strcat_array(MdvmDetectedVersions,", "),
    array_length(AgentlessMdvmDetectedVersions)>0, strcat_array(AgentlessMdvmDetectedVersions,", "),
    isnotempty(tostring(properties.additionalData.DetectedSoftwareVersions)), tostring(properties.additionalData.DetectedSoftwareVersions),
    isnotempty(tostring(properties.additionalData.SoftwareVersion)), tostring(properties.additionalData.SoftwareVersion),
    isnotempty(tostring(properties.additionalData.DetectedVersion)), tostring(properties.additionalData.DetectedVersion),
    ""
)
| extend FixedVersion=coalesce(
    tostring(Scanner.mdvm.FixedVersion),
    tostring(Scanner.agentlessmdvm.FixedVersion),
    tostring(properties.additionalData.FixedVersion),
    tostring(properties.additionalData.RecommendedVersion),
    tostring(Cve.FixedVersion),
    tostring(Cve.fixedVersion)
)
| extend FixStatus=coalesce(
    tostring(Cve.FixStatus),
    tostring(Cve.fixStatus),
    iff(isnotempty(FixedVersion),"Fix available","")
)
| extend Severity=case(
    CvssScore >= 9.0,"Critical",
    CvssScore >= 7.0,"High",
    CvssScore >= 4.0,"Medium",
    CvssScore > 0.0,"Low",
    tostring(properties.metadata.severity)
)
| project
    CveId, Severity, CvssScore, CvssVersion,
    Repository, RegistryHost, Digest,
    PackageName, Vendor, CurrentVersion, FixedVersion, FixStatus,
    PublishedDate, ExploitVerified, IsPubliclyDisclosed, IsInExploitKit, ExploitTypes
| order by IsInExploitKit desc, ExploitVerified desc, IsPubliclyDisclosed desc, CvssScore desc, PackageName asc
KQL_END
)

# ---------- monta o body: default scope (todas subs acessiveis) ----------
# NAO usar managementGroups: [tenant_id] — isso ESCONDE cvedetails.
# Empirico: com esse filtro, cvedetails count = 0; sem ele = 390k+.
# Search-AzGraph -UseTenantScope no PowerShell nao mapeia pra managementGroups.

BODY=$(jq -nc \
    --arg q "$KQL" \
    '{
        query: $q,
        options: {"$top": 1000}
    }')

echo "=== chamando ARG (az rest, api 2022-10-01, default scope) ==="
if ! RESP=$(az rest --method post --url "$API" --body "$BODY" 2>&1); then
    echo "FALHA:" >&2
    echo "$RESP" >&2
    exit 1
fi

COUNT=$(jq '.data | length' <<<"$RESP")
echo "linhas retornadas: $COUNT"

if [[ "$COUNT" -eq 0 ]]; then
    echo ""
    echo "AVISO: 0 linhas. Digest existe no tenant? Assessments/CvesDetails populado?" >&2
    echo "       Verifique no Portal Defender for Cloud se essa imagem foi escaneada." >&2
    exit 2
fi

ENRICHED=$(jq '[.data[] | select(.CvssScore != null and .CvssScore > 0)] | length' <<<"$RESP")
echo "linhas com CvssScore > 0: $ENRICHED de $COUNT"

echo ""
echo "--- amostra (10 primeiras linhas) ---"
jq -r '
    .data[0:10][] |
    [.CveId, (.CvssScore // 0), (.Severity // "?"), (.PackageName // "?"),
     (if .IsInExploitKit then "K" else "-" end),
     (if .ExploitVerified then "V" else "-" end),
     (if .IsPubliclyDisclosed then "P" else "-" end)] |
    @tsv
' <<<"$RESP" | column -t -s $'\t'

echo ""
if [[ "$ENRICHED" -eq 0 ]]; then
    echo "RESULTADO: FALHOU — CvssScore zero em todas as linhas."
    echo "           JOIN nao esta batendo. Investigue amostra bruta:"
    echo "           jq '.data[0]' <<< resposta"
    exit 3
elif [[ "$ENRICHED" -lt "$COUNT" ]]; then
    RATE=$(( ENRICHED * 100 / COUNT ))
    echo "RESULTADO: PARCIAL — ${RATE}% enriched. Aceitavel se >=90%."
else
    echo "RESULTADO: OK — 100% enriched. Padrao funciona."
    echo "           Refactor viavel: iterar digests do ACR e chamar essa query por digest."
fi
