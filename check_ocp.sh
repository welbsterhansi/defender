#!/usr/bin/env bash
# Target runtime: Linux / WSL on the client (bash 4+ guaranteed).
# `env bash` keeps this portable in case a dev runs it elsewhere.
#
# Strict mode: catch typos, silent failures, and half-written pipelines.
# `pipefail` matters because our pipelines often terminate in `head -1`,
# which returns 0 even when the upstream command failed.
set -euo pipefail

# Verifica se o argumento do arquivo de entrada foi passado
if [ "$#" -lt 1 ]; then
    echo "Uso: $0 <arquivo_vulnerabilidades.csv> [arquivo_saida.csv]"
    echo "Exemplo: $0 vulnerable_images_report.csv resultado_final.csv"
    exit 1
fi

LIST_FILE="$1"
OUTPUT_FILE="${2:-resultado_cruzamento.csv}"

if [ ! -f "$LIST_FILE" ]; then
    echo "Erro: O arquivo '$LIST_FILE' não foi encontrado!"
    exit 1
fi

# Best-effort structured logging. Never gates the cross-reference: if
# logs/ or the file are unusable, init_logging logs a WARN and the run
# continues (terminal output stays as-is).
# shellcheck source=lib/logging.sh
source "$(dirname "$0")/lib/logging.sh"
init_logging "check_ocp.sh" "cross-reference" "$LIST_FILE" "$OUTPUT_FILE"
log_info "start list_file=$LIST_FILE output_file=$OUTPUT_FILE"

echo "A carregar lista de vulnerabilidades de: $LIST_FILE ..."
# Pré-parseia LIST_FILE em memória:
#   CSV_BY_DIGEST[<digest>] = "linha1\x1elinha2\x1e..."
# Um digest pode aparecer em várias linhas (uma por CVE). \x1e (RS, record
# separator) une essas linhas sem colidir com conteúdo normal.
# Antes: dois grep por pod → O(pods × linhas_csv). Agora: 1 parse + O(1)
# lookup por pod.
# Explicit `=()` initializer — under `set -u`, some bash versions treat a
# `declare -A` that never had an element inserted as unbound when queried
# with `${#arr[@]}`. Assigning `()` up-front pins it to a defined empty state.
declare -A CSV_BY_DIGEST=()
while IFS= read -r line; do
    # `grep` returns 1 when the CSV header or a malformed row has no sha256.
    # Wrap in `|| true` so strict mode doesn't abort the load on those rows.
    digest=$(printf '%s' "$line" | grep -oE 'sha256:[a-f0-9]{64}' | head -1 || true)
    [ -z "$digest" ] && continue
    if [ -z "${CSV_BY_DIGEST[$digest]:-}" ]; then
        CSV_BY_DIGEST[$digest]="$line"
    else
        CSV_BY_DIGEST[$digest]+=$'\x1e'"$line"
    fi
done < "$LIST_FILE"
VULN_COUNT=${#CSV_BY_DIGEST[@]}
echo "Carregados $VULN_COUNT digests únicos para verificar."

echo "A consultar projetos visíveis..."
# We list ALL visible namespaces first to distinguish "excluded by design"
# from "invisible / no permission". `oc get projects` returns only what the
# caller can see, so this baseline is what we compare against.
if ! ALL_NS_RAW=$(oc get projects -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null); then
    echo "Erro: 'oc get projects' falhou. Sessão expirada ou sem cluster?" >&2
    exit 1
fi
ALL_VISIBLE=$(printf '%s' "$ALL_NS_RAW" | grep -c . || true)

# Platform filter — kept explicit so we can count what we skipped.
PLATFORM_FILTER='^(openshift-|kube-|default$|logging|monitoring)'
PROJECTS=$(printf '%s\n' "$ALL_NS_RAW" | grep -vE "$PLATFORM_FILTER" || true)
NS_IGNORED=$(printf '%s\n' "$ALL_NS_RAW" | grep -cE "$PLATFORM_FILTER" || true)

if [ -z "$PROJECTS" ]; then
    echo "Nenhum projeto (não-plataforma) para analisar." >&2
    echo "  Namespaces visíveis: $ALL_VISIBLE"
    echo "  Ignorados (plataforma): $NS_IGNORED"
    exit 1
fi

echo "A verificar workloads e cruzar dados..."

# Arquivo temporário para os dados brutos (flat)
RAW_OUTPUT="/tmp/raw_findings_flat.csv"
trap 'rm -f "$RAW_OUTPUT"' EXIT
echo "NAMESPACE,PARENT_TYPE,PARENT_NAME,repository,digest,tag,cvssScore,cveId,severity,packageCategory,packageLanguage,packageName,currentVersion,fixedVersion,patchable,remediation,fixStatus,cveAgeDays,isInExploitKit,hasPublishedExploit,hasVerifiedExploit,lastPushedToRegistryUTC" > "$RAW_OUTPUT"

# ── Per-namespace state counters ────────────────────────────────────────────
# Every visible namespace ends up in exactly one bucket. The final coverage
# summary sums these so the operator knows whether the report is complete.
NS_SUCCESS_WITH_PODS=0    # analyzed OK, at least one pod
NS_NO_PODS=0              # analyzed OK, zero pods (normal for idle ns)
NS_RBAC_ERR=0             # oc returned "forbidden" (missing RBAC on ns)
NS_OC_ERR=0               # oc returned any other non-zero
NS_PARSE_ERR=0            # oc succeeded but jq couldn't parse the JSON
POD_COUNT=0
MATCH_COUNT=0
RBAC_NAMESPACES=()
FAILED_NAMESPACES=()

# jq expression is a here-doc constant so we don't re-quote in the loop.
JQ_POD_EXTRACT='
    .items[] |
    [
        .metadata.namespace,
        .metadata.name,
        (.metadata.ownerReferences[0].kind // ""),
        (.metadata.ownerReferences[0].name // ""),
        ([((.status.containerStatuses // [])[].imageID),
          ((.status.initContainerStatuses // [])[].imageID)]
         | join(" "))
    ] | join("")
'

for project in $PROJECTS; do
    oc_stderr=$(mktemp)
    if ! oc_json=$(oc get pods -n "$project" -o json 2>"$oc_stderr"); then
        # Any non-zero from oc. Sniff stderr to distinguish RBAC (common) from
        # other errors (connection, unknown resource, etc.) so the operator
        # gets an actionable hint instead of raw text that may leak internals.
        if grep -qiE 'forbidden|cannot (get|list)' "$oc_stderr"; then
            NS_RBAC_ERR=$((NS_RBAC_ERR + 1))
            RBAC_NAMESPACES+=("$project")
            echo "  [WARN] $project: RBAC error — grant get/list pods in namespace '$project' or exclude it from the platform filter" >&2
            log_warn "namespace=$project RBAC_ERR"
        else
            NS_OC_ERR=$((NS_OC_ERR + 1))
            FAILED_NAMESPACES+=("$project")
            err_preview=$(head -c 200 "$oc_stderr" | tr '\n' ' ' || true)
            echo "  [WARN] $project: oc failed — ${err_preview:-no stderr}" >&2
            log_warn "namespace=$project OC_ERR: ${err_preview:-no stderr}"
        fi
        rm -f "$oc_stderr"
        continue
    fi
    rm -f "$oc_stderr"

    # oc succeeded → try to extract the pod tuples with jq.
    if ! project_pods=$(printf '%s' "$oc_json" | jq -r "$JQ_POD_EXTRACT" 2>/dev/null); then
        NS_PARSE_ERR=$((NS_PARSE_ERR + 1))
        FAILED_NAMESPACES+=("$project")
        echo "  [WARN] $project: parse error — jq could not extract pods from oc JSON" >&2
        log_warn "namespace=$project PARSE_ERR"
        continue
    fi

    if [ -z "$project_pods" ]; then
        NS_NO_PODS=$((NS_NO_PODS + 1))
        continue
    fi

    NS_SUCCESS_WITH_PODS=$((NS_SUCCESS_WITH_PODS + 1))

    while IFS=$'\x1f' read -r namespace podname owner_kind owner_name image_ids; do
        [ -z "$namespace" ] && continue
        POD_COUNT=$((POD_COUNT + 1))

        # 1. Normalização do Owner
        if [ -z "$owner_kind" ]; then
            parent_kind="Pod"
            parent_name="$podname"
        else
            parent_kind="$owner_kind"
            parent_name="$owner_name"
        fi

        # 2. Resolução do Pai (ReplicaSet → Deployment, RC-N → DeploymentConfig)
        if [[ "$parent_kind" == "ReplicationController" ]]; then
            cleaned_name=$(echo "$parent_name" | sed -E 's/-[0-9]+$//')
            if [ "$cleaned_name" != "$parent_name" ]; then
                parent_kind="DeploymentConfig"
                parent_name="$cleaned_name"
            fi
        elif [[ "$parent_kind" == "ReplicaSet" ]]; then
            cleaned_name=$(echo "$parent_name" | sed -E 's/-[a-z0-9]+$//')
            if [ "$cleaned_name" != "$parent_name" ]; then
                parent_kind="Deployment"
                parent_name="$cleaned_name"
            fi
        fi

        # 3. Verificação de Imagens
        for image_id in $image_ids; do
            running_digest=$(echo "$image_id" | grep -oE 'sha256:[a-f0-9]{64}' || true)
            if [ -n "$running_digest" ] && [ -n "${CSV_BY_DIGEST[$running_digest]:-}" ]; then
                MATCH_COUNT=$((MATCH_COUNT + 1))
                while IFS= read -r csv_line; do
                    [ -z "$csv_line" ] && continue
                    echo "\"$namespace\",\"$parent_kind\",\"$parent_name\",$csv_line" >> "$RAW_OUTPUT"
                done <<< "${CSV_BY_DIGEST[$running_digest]//$'\x1e'/$'\n'}"
            fi
        done
    done <<< "$project_pods"
done

# ── Coverage summary — printed BEFORE the aggregation so it stays visible
# even if group_findings.py fails. Numbers here are the operator's ground
# truth: partial coverage means the CSV is NOT authoritative.
NS_FAILED_TOTAL=$((NS_RBAC_ERR + NS_OC_ERR + NS_PARSE_ERR))

echo ""
echo "=== Coverage summary ==="
echo "  Namespaces visible:        $ALL_VISIBLE"
echo "  Ignored (platform filter): $NS_IGNORED"
echo "  Analyzed (OK, with pods):  $NS_SUCCESS_WITH_PODS"
echo "  Analyzed (OK, no pods):    $NS_NO_PODS"
echo "  RBAC errors:               $NS_RBAC_ERR"
echo "  Other oc errors:           $NS_OC_ERR"
echo "  Parse errors:              $NS_PARSE_ERR"
echo "  Pods processed:            $POD_COUNT"
echo "  Digest matches:            $MATCH_COUNT"

if [ "$NS_FAILED_TOTAL" -gt 0 ]; then
    echo "  COVERAGE: PARTIAL — $NS_FAILED_TOTAL namespace(s) failed"
    if [ "${#RBAC_NAMESPACES[@]}" -gt 0 ]; then
        echo "    RBAC-blocked: ${RBAC_NAMESPACES[*]}"
    fi
    if [ "${#FAILED_NAMESPACES[@]}" -gt 0 ]; then
        echo "    Failed:       ${FAILED_NAMESPACES[*]}"
    fi
    COVERAGE_EXIT=3
    log_warn "COVERAGE PARTIAL failed=${NS_FAILED_TOTAL} rbac=${NS_RBAC_ERR} oc=${NS_OC_ERR} parse=${NS_PARSE_ERR} pods=${POD_COUNT} matches=${MATCH_COUNT}"
else
    echo "  COVERAGE: COMPLETE"
    COVERAGE_EXIT=0
    log_info "COVERAGE COMPLETE analyzed=${NS_SUCCESS_WITH_PODS} no_pods=${NS_NO_PODS} pods=${POD_COUNT} matches=${MATCH_COUNT}"
fi
echo ""

# Verifica se encontrou algo antes de rodar o Python
if [ ! -s "$RAW_OUTPUT" ] || [ "$(wc -l < "$RAW_OUTPUT")" -le 1 ]; then
    echo "Nenhuma vulnerabilidade encontrada nos workloads."
    echo "NAMESPACE,PARENT_TYPE,PARENT_NAME,REPOSITORY,DIGEST,TAG,CVE_COUNT,CRITICALITY,CVSS_SCORE,CVE_LIST,CVE_SEVERITY_MAP,PACKAGE_CATEGORY,PACKAGE_LANGUAGE,PACKAGE_NAME,CURRENT_VERSION,FIXED_VERSION,PATCHABLE,REMEDIATION,FIX_STATUS,CVE_AGE_DAYS,IS_IN_EXPLOIT_KIT,HAS_PUBLISHED_EXPLOIT,HAS_VERIFIED_EXPLOIT,LAST_PUSHED_TO_REGISTRY_UTC" > "$OUTPUT_FILE"
    log_info "end output_file=$OUTPUT_FILE coverage_exit=${COVERAGE_EXIT} findings=0"
    exit "$COVERAGE_EXIT"
fi

echo "Processando e agrupando resultados..."

# Delegates the aggregation to group_findings.py — same behavior as the
# previous inline `python3 -c '...'`, but the logic is now unit-tested
# (see tests/test_group_findings_unit.py) and lives in a module.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ! python3 "$SCRIPT_DIR/group_findings.py" "$RAW_OUTPUT" "$OUTPUT_FILE"; then
    echo "Erro: falha ao agrupar resultados." >&2
    log_error "group_findings.py failed"
    exit 1
fi

echo "Processamento concluído."
log_info "end output_file=$OUTPUT_FILE coverage_exit=${COVERAGE_EXIT}"
exit "$COVERAGE_EXIT"
