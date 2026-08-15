# defender-local-actions

Local pipeline that scans an **Azure Container Registry (ACR)** for image vulnerabilities via **Microsoft Defender for Cloud**, cross-references the results against **workloads running in OpenShift**, and produces an executive HTML report ranked by CVSS score and exploit availability.

> Deep technical reference for AI assistants and IDEs: see [AGENTS.md](./AGENTS.md).

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| `az` | ≥ 2.60 | Azure CLI, logged in with reader access to the target ACR |
| `oc` | any | OpenShift CLI, logged in with `get pods` on target projects |
| `jq` | ≥ 1.6 | JSON processing in shell scripts |
| `bc` | any | CVSS score arithmetic in `defender.sh` |
| Python | ≥ 3.11 | `expandcsv.py` and `report.py` |

Install on macOS: `brew install azure-cli openshift-cli jq bc python@3.11`

## Quickstart — full pipeline

```bash
# 1. Scan ACR for CVEs (report-only by default)
./defender.sh --acr-name <ACR_NAME> --min-score 9 --max-score 10
#    → vulnerable_images_report.csv

# 2. Cross-reference with running OpenShift workloads
./check_ocp.sh vulnerable_images_report.csv resultado_cruzamento.csv
#    → resultado_cruzamento.csv (one row per workload+image, CVEs aggregated)

# 3. Expand grouped rows into one row per CVE
python3 expandcsv.py \
    --cruzamento resultado_cruzamento.csv \
    --vulnerabilities vulnerable_images_report.csv \
    --output expanded.csv

# 4. Render the HTML report
python3 report.py
#    → vulnerability_report.html
```

Open `vulnerability_report.html` in a browser to view the executive summary.

## Development

Local test/lint tooling is wired through `make`:

```bash
make help    # list all targets
make test    # pytest (offline; no Azure/OpenShift calls)
make lint    # ruff + pyright + bash -n + shellcheck
make check   # test + lint
make report  # regenerate HTML from existing CSVs
make clean   # remove generated CSVs, HTML, caches
```

Tests run entirely offline against synthetic CSV fixtures generated in `tests/conftest.py` — no live Azure or OpenShift calls. See `tests/test_e2e.py` for the full-pipeline integration test.

## Manual smoke test (real Azure/OpenShift)

Use this to sanity-check a real environment. **Always report-only.** Never pass `--block-images` or `--unblock*` without explicit team approval.

```bash
# 1. Confirm you are on the right Azure subscription
az account show --query '{name:name, id:id}' -o table

# 2. Run defender.sh with the tightest score band (critical only)
./defender.sh --acr-name <ACR_NAME> --min-score 9.8 --max-score 10
# Expect: `[Page N] batch=X ...` progress logs
# Expect: `vulnerable_images_report.csv` written atomically at the end
# On failure, the old CSV (if any) stays untouched; nothing partial gets consumed
```

Verify the CSV:

```bash
wc -l vulnerable_images_report.csv      # header + N rows
head -3 vulnerable_images_report.csv    # sanity check schema
```

Then continue the pipeline (still no side effects on ACR/OCP — read-only):

```bash
./check_ocp.sh vulnerable_images_report.csv
python3 expandcsv.py
python3 report.py
```

### What NEVER to run in a smoke test

| Command | Why |
|---------|-----|
| `./defender.sh ... --block-images` | Blocks manifest pulls; production impact |
| `./defender.sh ... --unblock` | Reverts prior blocks silently |
| `./defender.sh ... --unblock-all` | Bulk revert across the whole ACR |
| `./defender.sh ... --image <ref>` | Unblocks a specific image without ACR-wide confirmation |
| Anything without `--acr-name` on the intended registry | Wrong-target risk |

If you actually need to block/unblock, do it via a change ticket, not via smoke.

## Repository layout

```
defender-local-actions/
├── defender.sh            # ACR scan via Azure Resource Graph (KQL)
├── check_ocp.sh           # OpenShift cross-reference (delegates aggregation to group_findings.py)
├── group_findings.py      # Aggregate flat rows → one per (workload, image)
├── expandcsv.py           # Expand grouped rows into per-CVE rows
├── report.py              # Render HTML report
├── tests/                 # pytest fixtures + unit + E2E
├── Makefile               # test / lint / check / report / clean
├── pyproject.toml         # pytest, ruff, pyright config
├── AGENTS.md              # Technical reference for AI assistants
└── README.md              # This file
```

## Safety rules

- The KQL query in `defender.sh` is tuned for the specific Defender for Cloud subscription in production. **Do not modify** without a full smoke test in a staging subscription first.
- `check_ocp.sh` filters out platform namespaces (`openshift-*`, `kube-*`, `default`, `logging`, `monitoring`) to avoid noise.
- All destructive `defender.sh` modes (block/unblock) require interactive confirmation unless `--auto-approve` is passed. Do not automate `--auto-approve`.
