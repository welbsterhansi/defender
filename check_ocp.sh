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

echo "A carregar lista de vulnerabilidades de: $LIST_FILE ..."
# Pré-parseia LIST_FILE em memória:
#   CSV_BY_DIGEST[<digest>] = "linha1\x1elinha2\x1e..."
# Um digest pode aparecer em várias linhas (uma por CVE). \x1e (RS, record
# separator) une essas linhas sem colidir com conteúdo normal.
# Antes: dois grep por pod → O(pods × linhas_csv). Agora: 1 parse + O(1)
# lookup por pod.
declare -A CSV_BY_DIGEST
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

echo "A consultar projetos visíveis (filtrando infraestrutura)..."
# `grep -v` returns 1 if every line matches the exclusion pattern (all pods
# in platform namespaces). Guard so the empty-result branch below can handle it.
PROJECTS=$(oc get projects -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
           | grep -vE '^(openshift-|kube-|default$|logging|monitoring)' || true)

if [ -z "$PROJECTS" ]; then
    echo "Nenhum projeto encontrado ou sem permissão."
    exit 1
fi

echo "A verificar workloads e cruzar dados..."

# Arquivo temporário para os dados brutos (flat)
RAW_OUTPUT="/tmp/raw_findings_flat.csv"
# Cabeçalho para o CSV intermediário — espelha o schema do defender.sh (19 colunas de vuln)
echo "NAMESPACE,PARENT_TYPE,PARENT_NAME,repository,digest,tag,cvssScore,cveId,severity,packageCategory,packageLanguage,packageName,currentVersion,fixedVersion,patchable,remediation,fixStatus,cveAgeDays,isInExploitKit,hasPublishedExploit,hasVerifiedExploit,lastPushedToRegistryUTC" > "$RAW_OUTPUT"

for project in $PROJECTS; do
    # Obtém dados dos pods via JSON + jq. Substituto do jsonpath original,
    # que concatenava containerStatuses e initContainerStatuses com espaço
    # e quebrava em edge cases (imageID com espaço, campos ausentes).
    # Separador: US (\x1f, ASCII 31). Não é whitespace, então bash `read`
    # preserva campos vazios entre delimitadores (comportamento diferente
    # de \t, que é colapsado quando IFS contém só whitespace).
    project_pods=$(oc get pods -n "$project" -o json 2>/dev/null | jq -r '
        .items[] |
        [
            .metadata.namespace,
            .metadata.name,
            (.metadata.ownerReferences[0].kind // ""),
            (.metadata.ownerReferences[0].name // ""),
            ([((.status.containerStatuses // [])[].imageID),
              ((.status.initContainerStatuses // [])[].imageID)]
             | join(" "))
        ] | join("\u001f")
    ' 2>/dev/null)

    if [ -z "$project_pods" ]; then continue; fi

    while IFS=$'\x1f' read -r namespace podname owner_kind owner_name image_ids; do
        if [ -z "$namespace" ]; then continue; fi

        # 1. Normalização do Owner
        if [ -z "$owner_kind" ]; then
            parent_kind="Pod"
            parent_name="$podname"
        else
            parent_kind="$owner_kind"
            parent_name="$owner_name"
        fi

        # 2. Resolução do Pai (Parent Resolution)
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
            # Pods without a resolved digest (e.g., pending pull) have no
            # sha256 in imageID; grep exits 1 → swallow it under strict mode.
            running_digest=$(echo "$image_id" | grep -oE 'sha256:[a-f0-9]{64}' || true)

            if [ -n "$running_digest" ] && [ -n "${CSV_BY_DIGEST[$running_digest]:-}" ]; then
                # O(1) lookup via associative array pré-populado; sem grep no
                # loop. Múltiplas linhas por digest são separadas por \x1e (RS).
                while IFS= read -r csv_line; do
                    [ -z "$csv_line" ] && continue
                    echo "\"$namespace\",\"$parent_kind\",\"$parent_name\",$csv_line" >> "$RAW_OUTPUT"
                done <<< "${CSV_BY_DIGEST[$running_digest]//$'\x1e'/$'\n'}"
            fi
        done
    done <<< "$project_pods"
done

# Verifica se encontrou algo antes de rodar o Python
if [ ! -s "$RAW_OUTPUT" ] || [ "$(wc -l < "$RAW_OUTPUT")" -le 1 ]; then
    echo "Nenhuma vulnerabilidade encontrada nos workloads."
    rm -f "$RAW_OUTPUT"
    echo "NAMESPACE,PARENT_TYPE,PARENT_NAME,REPOSITORY,DIGEST,TAG,CVE_COUNT,CRITICALITY,CVSS_SCORE,CVE_LIST,CVE_SEVERITY_MAP,PACKAGE_CATEGORY,PACKAGE_LANGUAGE,PACKAGE_NAME,CURRENT_VERSION,FIXED_VERSION,PATCHABLE,REMEDIATION,FIX_STATUS,CVE_AGE_DAYS,IS_IN_EXPLOIT_KIT,HAS_PUBLISHED_EXPLOIT,HAS_VERIFIED_EXPLOIT,LAST_PUSHED_TO_REGISTRY_UTC" > "$OUTPUT_FILE"
    exit 0
fi

echo "Processando e agrupando resultados..."

# Delegates the aggregation to group_findings.py — same behavior as the
# previous inline `python3 -c '...'`, but the logic is now unit-tested
# (see tests/test_group_findings_unit.py) and lives in a module.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ! python3 "$SCRIPT_DIR/group_findings.py" "$RAW_OUTPUT" "$OUTPUT_FILE"; then
    echo "Erro: falha ao agrupar resultados." >&2
    rm -f "$RAW_OUTPUT"
    exit 1
fi

# Limpeza
rm -f "$RAW_OUTPUT"

echo "Processamento concluído."