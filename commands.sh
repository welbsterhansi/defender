#!/usr/bin/env bash
# P0.6 cluster validation — bash check_ocp.sh vs python defender_pipeline cluster.
#
# Uso:
#     git pull origin fix/mdvm-migration-remove-leg-a
#     bash commands.sh
#
# Assume: cwd tem a branch fix/mdvm-migration-remove-leg-a, venv ativo com
# defender_pipeline instalado (pip install -e '.[pipeline]'), oc login OK,
# e um CVE CSV chamado scan.csv OU scan_shell.csv na cwd (do P0.5).

set +e

# Escolhe o input CVE CSV (mesmo pra ambos os lados)
if [ -f scan.csv ]; then
    INPUT_CSV="scan.csv"
elif [ -f scan_shell.csv ]; then
    INPUT_CSV="scan_shell.csv"
elif [ -f vulnerable_images_report.csv ]; then
    INPUT_CSV="vulnerable_images_report.csv"
else
    echo "erro: nenhum CVE CSV encontrado (scan.csv / scan_shell.csv / vulnerable_images_report.csv)"
    exit 1
fi
echo "input CVE CSV: $INPUT_CSV"

# ── Roda os dois back-to-back ────────────────────────────────────────────
echo ">> rodando check_ocp.sh ..."
./check_ocp.sh "$INPUT_CSV" bash_cluster.csv > bash_cluster.log 2>&1
_bash_exit=$?

echo ">> rodando python -m defender_pipeline cluster ..."
python -m defender_pipeline cluster \
    --vulnerabilities "$INPUT_CSV" \
    --output python_cluster.csv > python_cluster.log 2>&1
_py_exit=$?

# ── Veredictos ────────────────────────────────────────────────────────────
_bash_lines=$(wc -l < bash_cluster.csv 2>/dev/null || echo 0)
_py_lines=$(wc -l < python_cluster.csv 2>/dev/null || echo 0)

echo ""
echo "=== execucao ==="
printf "%-15s exit=%s  rows=%s\n" "bash:"   "$_bash_exit" "$_bash_lines"
printf "%-15s exit=%s  rows=%s\n" "python:" "$_py_exit"   "$_py_lines"

# Header identico?
if [ -f bash_cluster.csv ] && [ -f python_cluster.csv ]; then
    _bash_hdr=$(head -1 bash_cluster.csv)
    _py_hdr=$(head -1 python_cluster.csv)
    if [ "$_bash_hdr" = "$_py_hdr" ]; then
        _hdr_match="true"
    else
        _hdr_match="false"
    fi
else
    _hdr_match="false (arquivo ausente)"
fi

# Exit code igual?
if [ "$_bash_exit" = "$_py_exit" ]; then
    _exit_match="true"
else
    _exit_match="false"
fi

# Coverage line dos dois logs
_bash_cov=$(grep -oE "COVERAGE: (COMPLETE|PARTIAL)" bash_cluster.log 2>/dev/null | tail -1)
_py_cov=$(grep -oE "overall=(COMPLETE|PARTIAL)" python_cluster.log 2>/dev/null | tail -1 | tr '=' ' ' | awk '{print $2}')
_py_cov="COVERAGE: ${_py_cov}"
if [ "$_bash_cov" = "$_py_cov" ]; then
    _cov_match="true"
else
    _cov_match="false"
fi

echo ""
echo "=== veredictos ==="
printf "%-24s %s\n" "header_match:"    "$_hdr_match"
printf "%-24s %s\n" "exit_code_match:" "$_exit_match  (bash=$_bash_exit python=$_py_exit)"
printf "%-24s %s\n" "coverage_match:"  "$_cov_match  (bash=$_bash_cov python=$_py_cov)"

# ── Sobreposicao de tuplas — python csv (respeita quoting) ───────────────
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
ratio = (len(overlap) / max(len(bash | py), 1)) * 100

print()
print("=== tuplas (NS,PARENT_TYPE,PARENT_NAME,REPO,DIGEST) ===")
print(f"bash unique:   {len(bash)}")
print(f"python unique: {len(py)}")
print(f"comum:         {len(overlap)}")
print(f"so no bash:    {len(only_bash)}")
print(f"so no python:  {len(only_py)}")
print(f"overlap_ratio: {ratio:.1f}%")

# Verdict final
strong = (len(only_bash) <= 10 and len(only_py) <= 10)
print()
print(f"verdict tuple_sets_match_strong: {str(strong).lower()}   (thresh: <=10 divergent each side)")
PY
