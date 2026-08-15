# defender-local-actions

Local pipeline that scans an **Azure Container Registry (ACR)** for image vulnerabilities via **Microsoft Defender for Cloud**, cross-references the results against **workloads running in OpenShift**, and produces an executive HTML report ranked by CVSS score and exploit availability.

> **AI assistants:**
> - GitHub Copilot reads [`.github/copilot-instructions.md`](./.github/copilot-instructions.md) automatically.
> - Claude Code / Cursor / Aider read [`AGENTS.md`](./AGENTS.md).
>
> Both files carry the same rules (make check as merge gate, don't touch the KQL, no client names in source, etc.). Update both if a rule changes.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| `az` | ≥ 2.60 | Azure CLI, logged in with reader access to the target ACR |
| `oc` | any | OpenShift CLI, logged in with `get pods` on target projects |
| `jq` | ≥ 1.6 | JSON processing in shell scripts |
| `bc` | any | CVSS score arithmetic in `defender.sh` |
| Python | ≥ 3.11 | `expandcsv.py` and `report.py` |

Target runtime is Linux / WSL (bash 4+). macOS works for local dev if you install a newer bash (`brew install bash`).

## Quickstart — full pipeline

```bash
# 1. Scan ACR for CVEs (report-only by default)
./defender.sh --acr-name <ACR_NAME> --min-score 9 --max-score 10
#    → vulnerable_images_report.csv

# Broad scope by substring (single repo):
./defender.sh --acr-name <ACR_NAME> --min-score 9 --repository app
#    → matches 'app', 'app-backend', 'myapp'  (contains semantics)

# Controlled scope by exact repo names (curated list):
./defender.sh --acr-name <ACR_NAME> --min-score 9 --repositories app-backend,payments-api,catalog-svc
#    → matches ONLY those three exact repos
#    → 'app' would NOT capture 'app-backend'
#    → each entry validated against the ACR before the query runs
#    → empty entries (',,') or duplicates abort the run

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

### Reading `check_ocp.sh` coverage output

Each run prints a `=== Coverage summary ===` block. **Trust the report only when it says `COVERAGE: COMPLETE`.**

```
=== Coverage summary ===
  Namespaces visible:        42
  Ignored (platform filter): 8
  Analyzed (OK, with pods):  30
  Analyzed (OK, no pods):    3
  RBAC errors:               1     ← namespace we could not query
  Other oc errors:           0
  Parse errors:              0
  Pods processed:            487
  Digest matches:            15
  COVERAGE: PARTIAL — 1 namespace(s) failed
    RBAC-blocked: prd-restricted
```

| Bucket | Meaning | What to do |
|--------|---------|------------|
| `Analyzed (OK, ...)` | oc + jq succeeded | nothing |
| `Ignored (platform filter)` | namespace excluded by design (`openshift-*`, `kube-*`, `default`, `logging`, `monitoring`) | nothing |
| `RBAC errors` | our user has no `get pods` on that namespace | grant RBAC or exclude it explicitly |
| `Other oc errors` | connection, token expired, unknown resource | investigate stderr in previous WARN line |
| `Parse errors` | oc succeeded but returned malformed JSON | usually an oc/kubectl version mismatch |

Exit code semantics:
- `0` → COVERAGE: COMPLETE, safe to distribute the report
- `3` → COVERAGE: PARTIAL, at least one namespace failed. **Do not treat as authoritative.**

### Rollout no cliente (first run)

Before running against the real cluster, walk through this checklist:

1. `bash --version` → must be ≥ 4.0 (Linux/WSL default is fine).
2. `make check` → 92 tests must pass, ruff/pyright/shellcheck clean.
3. `az account show` → confirm you're pointed at the right subscription.
4. `oc whoami && oc project` → confirm cluster identity.
5. `make smoke-real ACR_NAME=<acr>` → smallest safe scope (critical CVEs only, report-only).
6. Inspect `vulnerable_images_report.csv` for sanity (row count, sample rows).
7. `./check_ocp.sh vulnerable_images_report.csv` → check the coverage summary.
8. Only if `COVERAGE: COMPLETE`, continue with `make pipeline-local`.
9. Open `vulnerability_report.html` and share with the team.

Never combine steps 5 with block/unblock flags on the first run.

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
