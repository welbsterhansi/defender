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

# Fast mode — skip the tag_resolve phase (CI/CD, large scans, CVE counts only):
./defender.sh --acr-name <ACR_NAME> --min-score 9 --skip-tags
#    → zero 'az repository show-tags' calls
#    → every CSV row has tag="N/A"
#    → phase-2 latency drops to 0ms; downstream (report.py, expandcsv.py) is unchanged
#    → incompatible with --scan-image (which resolves tag → digest up front)

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

The HTML report is organized as two tabs — **Images** (Azure Container
Registry data: one row per `repo:tag@digest`) and **Cluster** (OpenShift
runtime data: one row per namespace/workload). Each CVE row shows three
independent exploit signals (**V**erified / **P**ublished / **In-K**it)
as colored chips, explained in a legend above the tabs; the Exploit
filter can isolate any one of the three. Two columns previously loaded
but hidden — **Fix Status** (`FixAvailable` / `NoFix` / …) and
**Age (days)** — are now surfaced per CVE, and a per-severity KPI row
under the main totals shows the Critical/High/Medium/Low breakdown at
a glance.

Container image references (`repo:tag@digest`) render via a single
shared component (`_image_ref`) in both tabs — same font, weight, and
size regardless of surrounding container. Layout is two lines: `repo:tag`
on the primary line and `@sha256:…` (truncated) on the secondary line,
with the full digest available on hover. Images without a recorded tag
show `:(no tag)` in a muted style in both tabs (previously the OpenShift
tab silently omitted the marker).

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

## Data source (post-2026-07-31)

Microsoft retired the legacy grouped `microsoft.security/assessments/subassessments` type on **2026-07-31**. `defender.sh` was migrated to the individual-recommendations model in August 2026:

- **Single leg** against `microsoft.security/assessments` filtered by `recommendationCategory == "SoftwareUpdate"` + `resourceDetails.ResourceType == ".containerimage"` + `Source == "Azure"`.
- All CVE fields (severity, CVSS, exploit signals, published date, description, fix status) are read inline from `properties.additionalData.CvesDetails[]`.
- Image identity comes from `properties.resourceAdditionalData.RepositoryDetails.*` and `.Digest`.
- Package version comes from `properties.additionalData.ScannersDetails.mdvm.*`.
- CSV column order is unchanged — downstream (`expandcsv.py`, `group_findings.py`, `report.py`) is untouched.

Details, path map, and rationale: [`docs/mdvm-individual-migration.md`](./docs/mdvm-individual-migration.md).

### Known limitation — repo-level data quality on the Microsoft side

Some repositories (observed with base OS images and similar system-level layers) return CVEs with `Severity == "Unknown"` and no `Cvss[0].Value.Base` populated. In those cases the row falls to `cvssScore = 0.0` and is filtered out by `--min-score`. This is a Microsoft-side data-population gap in the individual model (see [Azure/Microsoft-Defender-for-Cloud#1056](https://github.com/Azure/Microsoft-Defender-for-Cloud/issues/1056)) — no code change on our side can invent severity values that Defender didn't emit. Run `--debug` to see the diagnostic aggregate; if entire repos show `sev_unknown` = 100%, that's the symptom.

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

### Timing telemetry

Each page of the ARG pagination loop in `defender.sh` emits a structured line to the log (task #42):

```
[2026-08-16T10:23:45Z] INFO  page 3 batch=1000 total=3000 retries=0 tag_api_calls=340 timings_ms=graph_query:1240 tag_resolve:32100 rows:15400 total:48800
```

Fields:
- `page` — 1-based page number
- `batch` — rows returned by ARG on this page (≤ 1000, server-side max)
- `total` — cumulative rows written so far
- `retries` — retries used by `run_graph_query` on this specific page
- `tag_api_calls` — `az repository show-tags` calls made on THIS page (0 when every repo was already cached from an earlier page, or when `--skip-tags` is set)
- `timings_ms` — per-phase wall-clock in milliseconds:
  - `graph_query` — Azure Resource Graph round-trip (network + server compute)
  - `tag_resolve` — tag cache build (1 call per unique repo per execution; `0` when `--skip-tags` is set)
  - `rows` — CSV parsing + write for the whole batch
  - `total` — sum of the phases (small delta = overhead)

Format is stable — do not reorder without updating `scripts/benchmark-defender.sh` and the format tests in `tests/test_defender_timing_log_format.py`.

**Local benchmark** (no real Azure needed):

```bash
scripts/benchmark-defender.sh --pages 3 --rows-per-page 1000 --repos 20 --latency-ms 20
```

Simulates configurable page size, repo diversity, and per-call latency. Prints per-page timings, aggregate breakdown, and API call counts. Useful for measuring the impact of upcoming optimizations (PR-A jq refactor, PR-B tag cache per repo) without waiting for a real ACR scan.

### Logs

Every run of `defender.sh` and `check_ocp.sh` records **critical events only** — start, retry, error, coverage, generated file paths — to a timestamped file in `logs/`. The terminal output is untouched; the log is a compact operational trail for auditing and troubleshooting.

```
logs/
├── run-20260815-115734-48146.log   # defender.sh
└── run-20260815-120214-48892.log   # check_ocp.sh
```

- **Name**: `run-YYYYMMDD-HHMMSS-<pid>.log` (UTC + PID = collision-safe under parallel CI).
- **Header**: 8 lines with timestamp, script, mode, args, log path, pid.
- **Events**: `[YYYY-MM-DDTHH:MM:SSZ] LEVEL  message` — one per critical event. Not a stdout mirror.
- **Best-effort**: if `logs/` can't be created or the file becomes unwritable at runtime, a WARN surfaces on stderr and the script keeps running normally. **Logging never gates the scan.**
- **Secrets**: values of flags whose name matches `--token` / `--password` / `--secret` / `--*key` become `<redacted>` in the header. Do not pass secrets as CLI args regardless.

Collecting from CI:

```yaml
- name: Upload defender logs
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: defender-logs
    path: logs/run-*.log
```

Local cleanup: `make clean` removes `logs/` along with the other generated artifacts.

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
