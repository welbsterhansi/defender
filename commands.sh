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
              --min-score 7 --skip-tags > /dev/null 2>&1
mv -f vulnerable_images_report.csv scan_shell.csv

echo ">> rodando python -m defender_pipeline scan com --skip-tags ..."
python -m defender_pipeline scan --acr-name bdsoregistry \
    --repository redhat-sso-7/rhsso75 \
    --min-score 7 --skip-tags --output scan.csv > /dev/null 2>&1

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
rm -f /tmp/_sh_notag.csv /tmp/_py_notag.csv
