#!/usr/bin/env bash
# client-probe.sh — teste de paridade bash vs python (roda no cliente).
#
# Cobre os 3 estagios da pipeline (scan, cluster, expand) e imprime 4
# linhas sinteticas: 3 comparacoes + 1 veredicto final.
#
# Uso:
#     git pull origin main
#     bash client-probe.sh
#
# Pre-req: az login (para scan) + oc login (para cluster) + venv com
# defender_pipeline instalado (pip install -e .).
#
# Overrides via env:
#     ACR=<name>           default bdsoregistry
#     REPO=<substring>     default redhat-sso-7/rhsso75  (scope pequeno)
#     MINSCORE=<float>     default 7

set +e

ACR="${ACR:-bdsoregistry}"
REPO="${REPO:-redhat-sso-7/rhsso75}"
MINSCORE="${MINSCORE:-7}"

WORK=$(mktemp -d) || { echo "erro: mktemp"; exit 1; }
trap 'rm -rf "$WORK"' EXIT

# ── 1. SCAN — bash x python ──────────────────────────────────────────────
./defender.sh --acr-name "$ACR" --repository "$REPO" \
              --min-score "$MINSCORE" --skip-tags >/dev/null 2>&1
mv -f vulnerable_images_report.csv "$WORK/scan_bash.csv" 2>/dev/null

python3 -m defender_pipeline scan --acr-name "$ACR" --repository "$REPO" \
    --min-score "$MINSCORE" --skip-tags \
    --output "$WORK/scan_py.csv" >/dev/null 2>&1

SCAN_BASH=$(wc -l < "$WORK/scan_bash.csv" 2>/dev/null | tr -d ' ')
SCAN_PY=$(wc -l < "$WORK/scan_py.csv" 2>/dev/null | tr -d ' ')
SCAN_EQ="false"; cmp -s "$WORK/scan_bash.csv" "$WORK/scan_py.csv" && SCAN_EQ="true"

# ── 2. CLUSTER — bash x python (mesmo input: scan_bash.csv) ──────────────
cp "$WORK/scan_bash.csv" vulnerable_images_report.csv
./check_ocp.sh >/dev/null 2>&1
mv -f resultado_cruzamento.csv "$WORK/cluster_bash.csv" 2>/dev/null

python3 -m defender_pipeline cluster \
    --vulnerabilities "$WORK/scan_bash.csv" \
    --output "$WORK/cluster_py.csv" >/dev/null 2>&1

CL_BASH=$(wc -l < "$WORK/cluster_bash.csv" 2>/dev/null | tr -d ' ')
CL_PY=$(wc -l < "$WORK/cluster_py.csv" 2>/dev/null | tr -d ' ')
CL_EQ="false"; cmp -s "$WORK/cluster_bash.csv" "$WORK/cluster_py.csv" && CL_EQ="true"

# ── 3. EXPAND — bash x python (mesmos inputs) ────────────────────────────
python3 expandcsv.py \
    --cruzamento "$WORK/cluster_bash.csv" \
    --vulnerabilities "$WORK/scan_bash.csv" \
    --output "$WORK/expand_bash.csv" >/dev/null 2>&1

python3 -m defender_pipeline expand \
    --cruzamento "$WORK/cluster_bash.csv" \
    --vulnerabilities "$WORK/scan_bash.csv" \
    --output "$WORK/expand_py.csv" >/dev/null 2>&1

EX_BASH=$(wc -l < "$WORK/expand_bash.csv" 2>/dev/null | tr -d ' ')
EX_PY=$(wc -l < "$WORK/expand_py.csv" 2>/dev/null | tr -d ' ')
EX_EQ="false"; cmp -s "$WORK/expand_bash.csv" "$WORK/expand_py.csv" && EX_EQ="true"

# ── 4. Veredicto ─────────────────────────────────────────────────────────
MATCH=0
[[ "$SCAN_EQ" == "true" ]] && MATCH=$((MATCH+1))
[[ "$CL_EQ"   == "true" ]] && MATCH=$((MATCH+1))
[[ "$EX_EQ"   == "true" ]] && MATCH=$((MATCH+1))

printf "SCAN     bash=%-6s py=%-6s equal=%s\n"    "$SCAN_BASH" "$SCAN_PY" "$SCAN_EQ"
printf "CLUSTER  bash=%-6s py=%-6s equal=%s\n"    "$CL_BASH"   "$CL_PY"   "$CL_EQ"
printf "EXPAND   bash=%-6s py=%-6s equal=%s\n"    "$EX_BASH"   "$EX_PY"   "$EX_EQ"
printf "RESULT   %d/3 stages match\n"             "$MATCH"

[[ "$MATCH" -eq 3 ]]
