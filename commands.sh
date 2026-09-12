#!/usr/bin/env bash
# Teste controlado bash vs python — P0.5 scan compat check.
#
# Roda os dois back-to-back com --skip-tags (elimina tag como
# variavel) e imprime 4 numeros que respondem se ha divergencia.
#
# Uso:
#     git pull origin fix/mdvm-migration-remove-leg-a
#     bash commands.sh
#
# Assume: cwd tem defender.sh + venv ativo com defender_pipeline.

set +e

# ── 1. Rodar bash e python back-to-back (menos de 30s de intervalo) ──────
echo ">> rodando defender.sh (bash) com --skip-tags ..."
./defender.sh --acr-name bdsoregistry \
              --repository redhat-sso-7/rhsso75 \
              --min-score 7 --skip-tags > bash_run.log 2>&1
mv -f vulnerable_images_report.csv scan_shell.csv

echo ">> rodando python -m defender_pipeline scan com --skip-tags ..."
python -m defender_pipeline scan --acr-name bdsoregistry \
    --repository redhat-sso-7/rhsso75 \
    --min-score 7 --skip-tags --output scan.csv > python_run.log 2>&1

# ── 2. Diagnostico compacto ─────────────────────────────────────────────
echo ""
echo "=== 1. Linhas ==="
printf "bash:   %s\npython: %s\n" \
    "$(wc -l < scan_shell.csv)" "$(wc -l < scan.csv)"

echo ""
echo "=== 2. Digests unicos ==="
printf "bash:   %s\npython: %s\ncomum:  %s\n" \
    "$(tail -n +2 scan_shell.csv | awk -F',' '{print $2}' | sort -u | wc -l)" \
    "$(tail -n +2 scan.csv       | awk -F',' '{print $2}' | sort -u | wc -l)" \
    "$(comm -12 \
        <(tail -n +2 scan_shell.csv | awk -F',' '{print $2}' | sort -u) \
        <(tail -n +2 scan.csv       | awk -F',' '{print $2}' | sort -u) \
        | wc -l)"

echo ""
echo "=== 3. Tag == N/A ratio ==="
printf "bash:   %s de %s\npython: %s de %s\n" \
    "$(tail -n +2 scan_shell.csv | awk -F',' '$3=="\"N/A\""' | wc -l)" \
    "$(tail -n +2 scan_shell.csv | wc -l)" \
    "$(tail -n +2 scan.csv       | awk -F',' '$3=="\"N/A\""' | wc -l)" \
    "$(tail -n +2 scan.csv       | wc -l)"

echo ""
echo "=== 4. Diff apos NEUTRALIZAR tag (col 3 -> N/A nos dois) ==="
awk -F',' 'BEGIN{OFS=","} {$3="\"N/A\""; print}' scan_shell.csv \
    | tail -n +2 | sort -u > /tmp/_sh_notag.csv
awk -F',' 'BEGIN{OFS=","} {$3="\"N/A\""; print}' scan.csv \
    | tail -n +2 | sort -u > /tmp/_py_notag.csv
printf "bash unique:   %s\npython unique: %s\nso no bash:    %s\nso no python:  %s\n" \
    "$(wc -l < /tmp/_sh_notag.csv)" \
    "$(wc -l < /tmp/_py_notag.csv)" \
    "$(comm -23 /tmp/_sh_notag.csv /tmp/_py_notag.csv | wc -l)" \
    "$(comm -13 /tmp/_sh_notag.csv /tmp/_py_notag.csv | wc -l)"

echo ""
echo "=== 5. Padrao cvssScore nas rows unicas ==="
_sh_diff=$(comm -23 /tmp/_sh_notag.csv /tmp/_py_notag.csv)
_py_diff=$(comm -13 /tmp/_sh_notag.csv /tmp/_py_notag.csv)
_sh_total=$(printf '%s\n' "$_sh_diff" | grep -c . || echo 0)
_py_total=$(printf '%s\n' "$_py_diff" | grep -c . || echo 0)
_sh_seven=$(printf '%s\n' "$_sh_diff" | awk -F',' '$4=="\"7\""' | wc -l)
_py_seven=$(printf '%s\n' "$_py_diff" | awk -F',' '$4=="\"7\""' | wc -l)
printf "so no bash:    %s de %s tem cvss=7 (fallback)\n" "$_sh_seven" "$_sh_total"
printf "so no python:  %s de %s tem cvss=7 (fallback)\n" "$_py_seven" "$_py_total"

# Salva output completo em arquivo pra debug (caso foto falhe)
{
    echo "--- so no bash (distribuicao cvssScore) ---"
    printf '%s\n' "$_sh_diff" | awk -F',' '{print $4}' | sort | uniq -c | sort -rn
    echo ""
    echo "--- so no python (distribuicao cvssScore) ---"
    printf '%s\n' "$_py_diff" | awk -F',' '{print $4}' | sort | uniq -c | sort -rn
} > diff_details.txt

echo ""
echo "(detalhes completos em: diff_details.txt — use 'cat diff_details.txt')"

rm -f /tmp/_sh_notag.csv /tmp/_py_notag.csv

# ── 6. Contadores por fase (isolamento da causa) ────────────────────────
# Extrai numeros dos logs de cada lado. Se ainda nao suficiente, olhar
# bash_run.log e python_run.log inteiros. Tambem tenta ler logs/run-*.log
# se as fases nao vazarem por stderr.

_grep_num() {
    # $1 = pattern; $2 = key= to extract number after
    grep -oE "$1[^$]*" "$3" 2>/dev/null | tail -1 | grep -oE "$2[0-9]+" | grep -oE "[0-9]+"
}

# Logs de cada lado — combina o stderr capturado + qualquer run-*.log gerado
_bash_all_logs="bash_run.log $(ls -t logs/run-*.log 2>/dev/null | head -1)"
_py_all_logs="python_run.log $(ls -t logs/run-*.log 2>/dev/null | head -2 | tail -1)"

_extract() {
    # $1 = key regex; $2..N = arquivos de log
    local key="$1"; shift
    for f in "$@"; do
        [ -f "$f" ] || continue
        local val
        val=$(grep -oE "$key" "$f" 2>/dev/null | tail -1 | grep -oE "[0-9]+$")
        if [ -n "$val" ]; then
            echo "$val"
            return
        fi
    done
    echo "-"
}

_b_enum=$(_extract "enumerate: found [0-9]+" $_bash_all_logs)
_p_enum=$(_extract "enumerate: found [0-9]+" $_py_all_logs)

_b_asrows=$(_extract "phase2a[^$]*rows=[0-9]+" $_bash_all_logs)
_p_asrows=$(_extract "phase2a[^$]*rows=[0-9]+" $_py_all_logs)

_b_cves=$(_extract "phase2b[^$]*unique_cves=[0-9]+" $_bash_all_logs)
_p_cves=$(_extract "phase2b[^$]*unique_cves=[0-9]+" $_py_all_logs)

_b_cvrows=$(_extract "phase2c[^$]*rows=[0-9]+" $_bash_all_logs)
_p_cvrows=$(_extract "phase2c[^$]*rows=[0-9]+" $_py_all_logs)

_b_read=$(_extract "rows_read=[0-9]+" $_bash_all_logs)
_p_read=$(_extract "rows_read=[0-9]+" $_py_all_logs)

_b_enr=$(_extract "rows_enriched=[0-9]+" $_bash_all_logs)
_p_enr=$(_extract "rows_enriched=[0-9]+" $_py_all_logs)

_b_emit=$(_extract "rows_emitted=[0-9]+" $_bash_all_logs)
_p_emit=$(_extract "rows_emitted=[0-9]+" $_py_all_logs)

echo ""
echo "=== 6. Contadores por fase ==="
printf "%-24s %10s %10s\n" "" "BASH" "PYTHON"
printf "%-24s %10s %10s\n" "enumerate pairs"   "$_b_enum"   "$_p_enum"
printf "%-24s %10s %10s\n" "assessments rows"  "$_b_asrows" "$_p_asrows"
printf "%-24s %10s %10s\n" "unique CVEs"       "$_b_cves"   "$_p_cves"
printf "%-24s %10s %10s\n" "cvedetails rows"   "$_b_cvrows" "$_p_cvrows"
printf "%-24s %10s %10s\n" "merge rows_read"   "$_b_read"   "$_p_read"
printf "%-24s %10s %10s\n" "merge rows_enriched" "$_b_enr"  "$_p_enr"
printf "%-24s %10s %10s\n" "merge rows_emitted"  "$_b_emit" "$_p_emit"
echo ""
echo "(logs completos em: bash_run.log, python_run.log, logs/run-*.log)"

# ── 7. Tuplas (digest,cveId,packageName,currentVersion,fixedVersion) ────
# Usa Python csv (nao awk) para nao quebrar em campos com virgulas.
# Chave estendida para desambiguar mesma package em versoes diferentes.
#
# Se tuplas batem nos dois lados → divergencia e VALOR de campo
# (cvss / enrichment volatilidade / formatacao). NAO e bug de codigo.
# Se tuplas divergem → filter/dedup produz conjuntos diferentes: bug.
echo ""
echo "=== 7. Tuplas (digest,cveId,pkgName,curVer,fixVer) unicas ==="
python3 <<'PY'
import csv

FIELDS = ("digest", "cveId", "packageName", "currentVersion", "fixedVersion")

def keyset(path: str) -> set:
    keys = set()
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            keys.add(tuple(row.get(k, "") for k in FIELDS))
    return keys

bash = keyset("scan_shell.csv")
py   = keyset("scan.csv")
print(f"bash:                  {len(bash)}")
print(f"python:                {len(py)}")
print(f"so no bash (tuplas):   {len(bash - py)}")
print(f"so no python (tuplas): {len(py - bash)}")
print(f"comum (tuplas):        {len(bash & py)}")
PY

# ── 8. Comparacao lado a lado de 3 tuplas divergentes ────────────────────
# Para cada tupla so-no-python, procura no bash pela chave curta
# (digest, cveId, packageName) e mostra o que difere em (currentVersion,
# fixedVersion). Isso mostra se o problema e versao de pacote, valor
# de campo, ou tupla totalmente ausente.
echo ""
echo "=== 8. Amostra tuplas divergentes (3 de cada lado) ==="
python3 <<'PY'
import csv

FULL = ("digest","cveId","packageName","currentVersion","fixedVersion")
SHORT = ("digest","cveId","packageName")

def load(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        rows.extend(list(csv.DictReader(f)))
    return rows

def full_keys(rows):
    return {tuple(r.get(k,"") for k in FULL): r for r in rows}

def short_index(rows):
    idx = {}
    for r in rows:
        idx.setdefault(tuple(r.get(k,"") for k in SHORT), []).append(r)
    return idx

sh_rows = load("scan_shell.csv"); py_rows = load("scan.csv")
sh_full = full_keys(sh_rows); py_full = full_keys(py_rows)
sh_idx = short_index(sh_rows); py_idx = short_index(py_rows)

def show(label, keys_only_here, this_full, other_idx, other_label):
    print(f"-- 3 tuplas so no {label} --")
    for k in list(keys_only_here)[:3]:
        row = this_full[k]
        short = tuple(row.get(x,"") for x in SHORT)
        print(f"  {row.get('cveId')} / {row.get('packageName')}")
        print(f"    {label}: curVer={row.get('currentVersion')!r} fixVer={row.get('fixedVersion')!r}")
        matches = other_idx.get(short, [])
        if matches:
            for m in matches[:2]:
                print(f"    {other_label} (mesma chave curta): curVer={m.get('currentVersion')!r} fixVer={m.get('fixedVersion')!r}")
        else:
            print(f"    {other_label}: (nenhuma row com essa chave curta)")

show("python", set(py_full) - set(sh_full), py_full, sh_idx, "bash  ")
print()
show("bash  ", set(sh_full) - set(py_full), sh_full, py_idx, "python")
PY

# ── 9. Ambos mergers no MESMO input (veredicto merger vs pipeline) ──────
echo ""
echo "=== 9. decision_dump — mesmo input alimentando os 2 mergers ==="
python3 decision_dump.py bdsoregistry redhat-sso-7/rhsso75 7 10 2>&1 | tail -20
