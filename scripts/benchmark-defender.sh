#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/benchmark-defender.sh — local performance harness for defender.sh
#
# Plants a fake `az` on PATH that simulates:
#   - az acr show / acr repository list / acr manifest list-metadata
#   - az graph query returning configurable pages of configurable rows,
#     cycling through N unique repositories
#   - az acr repository show-tags returning a synthetic tag per digest
#   - artificial per-call latency to model network round-trip cost
#
# Then runs defender.sh against the fake and prints a summary parsed from
# the structured `timings_ms=` log lines that defender.sh emits per page.
#
# Purpose (task #42, PR-0): baseline measurement BEFORE any optimization
# (PR-A jq refactor, PR-B tag cache per repo). Not a CI test — do not
# assert on absolute times.
#
# Usage:
#   scripts/benchmark-defender.sh
#   scripts/benchmark-defender.sh --pages 5 --rows-per-page 1000 \
#                                 --repos 20 --latency-ms 20
# ---------------------------------------------------------------------------
set -euo pipefail

PAGES=3
ROWS_PER_PAGE=500
REPOS=10
LATENCY_MS=20

usage() {
    sed -n '3,25p' "$0"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --pages)         PAGES="$2";         shift 2 ;;
        --rows-per-page) ROWS_PER_PAGE="$2"; shift 2 ;;
        --repos)         REPOS="$2";         shift 2 ;;
        --latency-ms)    LATENCY_MS="$2";    shift 2 ;;
        -h|--help)       usage 0 ;;
        *) echo "unknown arg: $1" >&2; usage 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── fake az ────────────────────────────────────────────────────────────
mkdir -p "$WORK/bin"
cat > "$WORK/bin/az" <<AZEOF
#!/usr/bin/env bash
# Log every invocation for post-run analysis.
echo "\$*" >> "$WORK/az_calls.log"

# Artificial latency to model network cost.
if [ "$LATENCY_MS" -gt 0 ]; then
    sleep "\$(awk "BEGIN {print $LATENCY_MS/1000}")"
fi

case "\$1 \$2" in
    "acr show")   exit 0 ;;
    "graph query")
        counter_file="$WORK/page_counter"
        prev=\$(cat "\$counter_file" 2>/dev/null || echo 0)
        curr=\$(( prev + 1 ))
        echo "\$curr" > "\$counter_file"

        if [ "\$curr" -gt "$PAGES" ]; then
            echo '{"data":[],"skip_token":""}'
            exit 0
        fi

        # Emit a deterministic page of \$ROWS_PER_PAGE rows, cycling repos.
        python3 - "$ROWS_PER_PAGE" "$REPOS" "$PAGES" "\$curr" <<'PYEOF'
import json, sys
rows_per_page = int(sys.argv[1])
n_repos       = int(sys.argv[2])
n_pages       = int(sys.argv[3])
current_page  = int(sys.argv[4])

data = []
base = (current_page - 1) * rows_per_page
for i in range(rows_per_page):
    idx = base + i
    repo_num = (idx % n_repos) + 1
    data.append({
        "repository": f"repo-{repo_num}",
        "digest": f"sha256:{idx:064x}",
        "cvssScore": 9.5,
        "cveId": f"CVE-9999-{idx:05d}",
        "severityRaw": "Critical",
        "packageCategory": "os",
        "packageLanguage": "c",
        "packageName": f"pkg-{idx}",
        "currentVersion": "1.0",
        "fixedVersion": "2.0",
        "patchable": "true",
        "remediation": "upgrade",
        "fixStatus": "FixAvailable",
        "cveAgeDays": 30,
        "isInExploitKit": "false",
        "hasPublishedExploit": "false",
        "hasVerifiedExploit": "false",
        "lastPushedToRegistryUTC": ""
    })

skip = "cursor-next" if current_page < n_pages else ""
print(json.dumps({"data": data, "skip_token": skip}))
PYEOF
        exit 0 ;;
esac

case "\$1 \$2 \$3" in
    "acr repository list")
        for i in \$(seq 1 $REPOS); do printf 'repo-%d\n' "\$i"; done
        exit 0 ;;
    "acr manifest list-metadata")
        echo '[]'
        exit 0 ;;
    "acr repository show-tags")
        # Benchmark cares about call count and latency, not tag identity.
        echo "v1.0"
        exit 0 ;;
esac
exit 0
AZEOF
chmod +x "$WORK/bin/az"

# ── run defender.sh under the fake ─────────────────────────────────────
export PATH="$WORK/bin:$PATH"
cd "$WORK"

echo "=== defender.sh benchmark ==="
echo "  pages:            $PAGES"
echo "  rows per page:    $ROWS_PER_PAGE"
echo "  unique repos:     $REPOS"
echo "  latency per call: ${LATENCY_MS}ms"
echo ""

wall_start="${EPOCHREALTIME:-0}"

set +e
"$REPO_ROOT/defender.sh" --acr-name benchmark --min-score 0 --max-score 10 \
    > run.stdout 2> run.stderr
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "defender.sh failed with exit $rc" >&2
    echo "--- last stderr lines ---" >&2
    tail -30 run.stderr >&2
    exit "$rc"
fi

wall_end="${EPOCHREALTIME:-0}"
wall_ms=$(awk -v s="$wall_start" -v e="$wall_end" 'BEGIN {
    if (s == "0" || e == "0") { print "n/a"; exit }
    printf "%d", (e - s) * 1000
}')

# ── summary ─────────────────────────────────────────────────────────────
echo "=== Per-page timings (from log) ==="
if ls logs/run-*.log >/dev/null 2>&1; then
    grep 'timings_ms=' logs/run-*.log | sed 's/^.*INFO  //'
else
    echo "  (no log file produced)"
fi
echo ""

show_tags_count=$(grep -c 'acr repository show-tags' "$WORK/az_calls.log" 2>/dev/null || echo 0)
graph_query_count=$(grep -c 'graph query' "$WORK/az_calls.log" 2>/dev/null || echo 0)
total_az_calls=$(wc -l < "$WORK/az_calls.log" 2>/dev/null | tr -d ' ' || echo 0)

echo "=== API call counts (from fake az) ==="
printf '  %-26s %s\n' "total az calls:"          "$total_az_calls"
printf '  %-26s %s\n' "az graph query:"          "$graph_query_count"
printf '  %-26s %s\n' "az repository show-tags:" "$show_tags_count"
echo ""

echo "=== Aggregate (sum across pages) ==="
if ls logs/run-*.log >/dev/null 2>&1; then
    # POSIX awk: extract fields with gsub + split (avoids gawk's 3-arg match).
    awk '
        /timings_ms=/ {
            for (i = 1; i <= NF; i++) {
                # The first field is `timings_ms=graph_query:N` (fused);
                # subsequent are bare `key:N`. Match anywhere, split on `:`.
                if ($i ~ /graph_query:[0-9]+/)   { split($i, x, ":"); gq += x[2] }
                else if ($i ~ /tag_resolve:[0-9]+/) { split($i, x, ":"); tr += x[2] }
                else if ($i ~ /rows:[0-9]+/)        { split($i, x, ":"); rw += x[2] }
                else if ($i ~ /total:[0-9]+/)       { split($i, x, ":"); tt += x[2] }
            }
        }
        END {
            printf "  graph_query total:  %d ms\n", gq
            printf "  tag_resolve total:  %d ms\n", tr
            printf "  rows total:         %d ms\n", rw
            printf "  page-time total:    %d ms  (sum of per-page totals)\n", tt
        }
    ' logs/run-*.log
fi
printf '  %-26s %s ms\n' "wall clock:" "$wall_ms"
