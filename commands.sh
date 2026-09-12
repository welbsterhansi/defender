#!/usr/bin/env bash
# Diagnóstico da divergência bash vs python no scan (P0.5).
#
# Uso no cliente:
#     git pull origin fix/mdvm-migration-remove-leg-a
#     bash commands.sh > output.txt 2>&1
#
# Depois cola o output.txt no chat.
#
# Assume que scan_shell.csv (do defender.sh) e scan.csv (do
# defender_pipeline scan) já estão na pasta atual, gerados com as
# mesmas flags (--repository redhat-sso-7/rhsso75 --min-score 7).

set +e   # não aborta na primeira falha — quero ver todos os diagnósticos

echo "==========================================================="
echo "  0. Sanity — arquivos existem?"
echo "==========================================================="
ls -la scan_shell.csv scan.csv 2>&1
echo ""

echo "==========================================================="
echo "  1. Headers idênticos?"
echo "==========================================================="
echo "--- scan_shell.csv (bash) ---"
head -1 scan_shell.csv
echo "--- scan.csv (python) ---"
head -1 scan.csv
echo ""
if diff <(head -1 scan_shell.csv) <(head -1 scan.csv) > /dev/null; then
    echo "OK — headers idênticos"
else
    echo "DIVERGENTE — headers diferem"
fi
echo ""

echo "==========================================================="
echo "  2. Contagem de linhas totais"
echo "==========================================================="
wc -l scan_shell.csv scan.csv 2>&1
echo ""

echo "==========================================================="
echo "  3. Gerar CSVs ordenados (dedup) para comparação"
echo "==========================================================="
tail -n +2 scan_shell.csv | sort -u > scan_shell_sorted.csv
tail -n +2 scan.csv       | sort -u > scan_sorted.csv
echo "bash unique:   $(wc -l < scan_shell_sorted.csv)"
echo "python unique: $(wc -l < scan_sorted.csv)"
echo ""

echo "==========================================================="
echo "  4. Distribuição de cvssScore nas rows SÓ NO BASH"
echo "     (se maioria for '7', hipótese fallback→severity confirmada)"
echo "==========================================================="
comm -23 scan_shell_sorted.csv scan_sorted.csv | awk -F',' '{print $4}' | sort | uniq -c | sort -rn
echo ""

echo "==========================================================="
echo "  5. Distribuição de cvssScore nas rows SÓ NO PYTHON"
echo "     (esperado: vazio ou pouco — se muito, é bug bidirecional)"
echo "==========================================================="
comm -13 scan_shell_sorted.csv scan_sorted.csv | awk -F',' '{print $4}' | sort | uniq -c | sort -rn
echo ""

echo "==========================================================="
echo "  6. Grep de 3 CVEs específicas nos dois CSVs"
echo "     (compara cvssScore direto para cada CVE)"
echo "==========================================================="
for cve in "CVE-2022-1384" "CVE-2022-25308" "CVE-2024-6655"; do
    echo "--- $cve ---"
    echo "bash:"
    grep -h ",\"$cve\"," scan_shell.csv | head -3
    echo "python:"
    grep -h ",\"$cve\"," scan.csv | head -3
    echo ""
done

echo "==========================================================="
echo "  7. Contagem de CVEs únicos em cada CSV"
echo "     (se diferente, Python está PERDENDO CVEs, não apenas rows)"
echo "==========================================================="
echo "bash CVEs únicos:   $(tail -n +2 scan_shell.csv | awk -F',' '{print $5}' | sort -u | wc -l)"
echo "python CVEs únicos: $(tail -n +2 scan.csv | awk -F',' '{print $5}' | sort -u | wc -l)"
echo ""

echo "==========================================================="
echo "  8. Amostra de 5 rows SÓ NO BASH (com cvssScore + cveId)"
echo "     — pra ter mais material se precisar"
echo "==========================================================="
comm -23 scan_shell_sorted.csv scan_sorted.csv | awk -F',' '{print $4, $5, $9, $6}' | head -5
echo ""

echo "==========================================================="
echo "  FIM"
echo "==========================================================="
