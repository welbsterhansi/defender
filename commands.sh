#!/usr/bin/env bash
# P0.6 cluster validation — bash check_ocp.sh vs python defender_pipeline cluster.
#
# Uso:
#     git pull origin fix/mdvm-migration-remove-leg-a
#     bash commands.sh
#
# Assume: cwd tem a branch fix/mdvm-migration-remove-leg-a, venv ativo com
# defender_pipeline instalado (pip install -e '.[pipeline]'), oc login OK.
#
# Se scan_broad.csv nao existir, gera com scan de score 9-10 full ACR
# (varias imagens em varios repos → chance real de bater workloads no
# cluster que nao sejam platform-filtered).

set +e

# ── 0. Garantir CVE CSV com escopo largo ────────────────────────────────
if [ ! -f scan_broad.csv ]; then
    echo ">> gerando scan_broad.csv (defender.sh full ACR score 9-10 --skip-tags) ..."
    ./defender.sh --acr-name bdsoregistry --min-score 9 --max-score 10 --skip-tags > scan_broad_gen.log 2>&1
    if [ ! -f vulnerable_images_report.csv ]; then
        echo "erro: defender.sh nao produziu CSV. Ver scan_broad_gen.log"
        exit 1
    fi
    mv vulnerable_images_report.csv scan_broad.csv
fi
_cve_rows=$(($(wc -l < scan_broad.csv) - 1))
echo "input CVE CSV: scan_broad.csv ($_cve_rows CVE rows)"

# ── 1. Rodar os dois back-to-back ────────────────────────────────────────
echo ">> rodando check_ocp.sh ..."
./check_ocp.sh scan_broad.csv bash_cluster.csv > bash_cluster.log 2>&1
_bash_exit=$?

echo ">> rodando python -m defender_pipeline cluster ..."
python -m defender_pipeline cluster \
    --vulnerabilities scan_broad.csv \
    --output python_cluster.csv > python_cluster.log 2>&1
_py_exit=$?

# ── 2. Veredictos ────────────────────────────────────────────────────────
_bash_lines=$(($(wc -l < bash_cluster.csv 2>/dev/null || echo 1) - 1))
_py_lines=$(($(wc -l < python_cluster.csv 2>/dev/null || echo 1) - 1))

echo ""
echo "=== execucao ==="
printf "%-15s exit=%s  rows=%s\n" "bash:"   "$_bash_exit" "$_bash_lines"
printf "%-15s exit=%s  rows=%s\n" "python:" "$_py_exit"   "$_py_lines"

# Header
if [ -f bash_cluster.csv ] && [ -f python_cluster.csv ]; then
    _hdr_match="false"
    [ "$(head -1 bash_cluster.csv)" = "$(head -1 python_cluster.csv)" ] && _hdr_match="true"
else
    _hdr_match="false (arquivo ausente)"
fi

# Exit code
_exit_match="false"
[ "$_bash_exit" = "$_py_exit" ] && _exit_match="true"

# Coverage
_bash_cov=$(grep -oE "COVERAGE: (COMPLETE|PARTIAL)" bash_cluster.log 2>/dev/null | tail -1)
_py_cov_raw=$(grep -oE "overall=(COMPLETE|PARTIAL)" python_cluster.log 2>/dev/null | tail -1 | cut -d= -f2)
_py_cov="COVERAGE: ${_py_cov_raw}"
_cov_match="false"
[ "$_bash_cov" = "$_py_cov" ] && _cov_match="true"

echo ""
echo "=== veredictos ==="
printf "%-24s %s\n" "header_match:"    "$_hdr_match"
printf "%-24s %s\n" "exit_code_match:" "$_exit_match  (bash=$_bash_exit python=$_py_exit)"
printf "%-24s %s\n" "coverage_match:"  "$_cov_match  (bash=$_bash_cov python=$_py_cov)"

# ── 3. Sobreposicao de tuplas — python csv (respeita quoting) ────────────
python3 - <<'PY'
import csv, sys

KEY = ("NAMESPACE", "PARENT_TYPE", "PARENT_NAME", "REPOSITORY", "DIGEST")

def keyset(path):
    keys = set()
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                keys.add(tuple(row.get(k, "") for k in KEY))
    except FileNotFoundError:
        return None
    return keys

bash = keyset("bash_cluster.csv")
py   = keyset("python_cluster.csv")

if bash is None or py is None:
    print("tuplas: nao pode calcular (arquivo ausente)")
    sys.exit(0)

overlap = bash & py
only_bash = bash - py
only_py = py - bash
union = len(bash | py)
ratio = (len(overlap) / max(union, 1)) * 100

print()
print("=== tuplas (NS,PARENT_TYPE,PARENT_NAME,REPO,DIGEST) ===")
print(f"bash unique:   {len(bash)}")
print(f"python unique: {len(py)}")
print(f"comum:         {len(overlap)}")
print(f"so no bash:    {len(only_bash)}")
print(f"so no python:  {len(only_py)}")
print(f"overlap_ratio: {ratio:.1f}%")
print()
print(f"verdict tuple_sets_match_strong: {'true' if len(only_bash) <= 10 and len(only_py) <= 10 else 'false'}   (thresh: <=10 divergent each side)")
PY
