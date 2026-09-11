# AGENTS.md

Context for AI coding assistants (Claude Code, Cursor, Aider, etc.) working on this repository.

> **GitHub Copilot uses [`.github/copilot-instructions.md`](./.github/copilot-instructions.md)** — that file carries the same rules in Copilot's native location. Keep the two files aligned if a rule changes.

## Purpose

Pipeline that scans an **Azure Container Registry (ACR)** for image vulnerabilities via **Microsoft Defender for Cloud**, cross-references the results against **workloads running in OpenShift**, and produces an executive HTML report ranked by CVSS score and exploit availability.

Primary consumers: platform SRE team (report), developers (remediation actions), security officers (governance).

## Architecture

```
┌────────────────────────────┐      ┌──────────────────────────┐
│ defender.sh                │─────▶│ vulnerable_images_report │
│  Phase 0: enumerate        │      │        .csv (19 cols)    │
│  Phase 1: tag_resolve      │      └────────────┬─────────────┘
│  Phase 2a: batched assess. │                   │
│  Phase 2b: unique CVE IDs  │                   │
│  Phase 2c: batched cvedet. │                   │
│  Phase 2d: enrich (python) │                   │
└────────────────────────────┘                   │
        │                                        │
        └── invokes ──▶ enrich_cvedetails.py     │
                       (Python 3.9+, stdlib only)│
                                                 │
┌────────────┐                                   ▼
│check_ocp.sh│──── oc get pods ──▶ ┌───────────────────────────┐
│  (OCP xref)│                     │ resultado_cruzamento.csv  │
└────────────┘                     │        (24 cols)          │
                                   └────────────┬──────────────┘
                                                │
                                     ┌──────────▼──────────┐
                                     │  expandcsv.py       │
                                     │  1 row per CVE      │
                                     └──────────┬──────────┘
                                                ▼
                                     ┌─────────────────────┐
                                     │  expanded.csv       │
                                     │      (22 cols)      │
                                     └──────────┬──────────┘
                                                ▼
                                     ┌─────────────────────┐
                                     │  report.py          │
                                     │  vulnerability_     │
                                     │  report.html        │
                                     └─────────────────────┘
```

**P2 architecture (2026-09):** `defender.sh` uses a two-phase batched
scan in **report-only** mode (Phase 2a/b/c/d above). **Block/unblock**
modes stay on the legacy per-digest path — same query per digest as
before, with cvedetails JOIN inline. Details in
`docs/mdvm-two-phase-benchmark.md`.

**Python dependency:** `defender.sh` now invokes `enrich_cvedetails.py`
in Phase 2d for the local merge. The file must be co-located with
`defender.sh` (`$(dirname "$0")/enrich_cvedetails.py`); missing helper
aborts the scan with a clear error. Stdlib only — no pip installs.

## Files

| File                  | Language | Role |
|-----------------------|----------|------|
| `defender.sh`         | Bash     | Queries Azure Resource Graph (KQL) via `az rest` for CVEs on ACR images. Report-only mode uses two-phase batched (Phase 2a/2c) + local merge via `enrich_cvedetails.py`; block/unblock modes use legacy per-digest path. Supports block/unblock/list/scan modes. |
| `enrich_cvedetails.py`| Python   | Local merge helper invoked by `defender.sh` in Phase 2d (report-only). Reads `assessments.jsonl` + `cvedetails.jsonl` produced by batched ARG queries, merges by `toupper(cveId)`, applies min/max score filter, and writes the final 19-column CSV. Must be co-located with `defender.sh`. Python 3.9+, stdlib only. |
| `check_ocp.sh`        | Bash     | For each OpenShift project, list running pods and cross-reference their image digests with the CVE CSV. Emits a flat (workload × image × CVE) CSV. Classifies each namespace into one of five states (`SUCCESS_WITH_PODS`, `NO_PODS`, `RBAC_ERR`, `OC_ERR`, `PARSE_ERR`) and prints a coverage summary; exit `0` = complete, exit `3` = partial coverage. |
| `group_findings.py`   | Python   | Called by `check_ocp.sh` to aggregate the flat CSV into one row per unique `(namespace, workload, image)` — CVE list, severity map, max CVSS, carried package/exploit fields. Was previously inline `python3 -c '...'`. |
| `expandcsv.py`        | Python   | Explodes the grouped CSV into one row per unique `(namespace, workload, repository, digest, cveId)`. Uses a 3-level lookup (full → repo+cve → digest-prefix) to tolerate multi-arch manifests. |
| `report.py`           | Python   | Generates a self-contained HTML report organized as two tabs — **Images** (ACR: one row per `repo:tag@digest`) and **Cluster** (OpenShift: one row per namespace/workload). Each CVE row shows three independent exploit signals (Verified / Published / In-Kit) as colored chips with a legend above the tabs; the Exploit filter can isolate any one of the three. `Fix Status` and `Age (days)` columns surface previously-loaded-but-hidden CSV fields, and a per-severity KPI row (Critical/High/Medium/Low) sits below the totals strip. Image references (`repo:tag@digest`) render via one shared helper `_image_ref` — same visual weight in both tabs — with `width:fit-content` so a longer name never stretches its host card. Collapse toggles are `<div role="button" tabindex="0">` (not `<button>`) so the interactive copy button inside the header row is not a nested-button HTML violation. |
| `tests/`              | Python   | pytest suite with synthetic CSV fixtures. |
| `pyproject.toml`      | -        | pytest, ruff, and pyright configuration. |
| `lib/logging.sh`      | Bash     | Sourced by both shells. `init_logging <script> <mode> [args...]` opens `logs/run-YYYYMMDD-HHMMSS-<pid>.log` for structured critical events. `log_info`/`log_warn`/`log_error` write to stderr always and append to the file best-effort. **Never fails the caller**: any file-write error surfaces as a WARN and the script keeps running. Scrubs values of `--token`/`--password`/`--secret`/`--*key` flags in the header. |
| `scripts/benchmark-defender.sh` | Bash | Local perf harness. Plants a fake `az` on `PATH` (configurable pages, rows/page, repos, latency-per-call) and runs `defender.sh` against it. Parses the `timings_ms=` log lines emitted per page and prints an aggregate breakdown. Not a CI test — used to measure the impact of optimizations without waiting for a real ACR scan. |

## Running the pipeline

Prerequisites: `az` CLI (logged in with **Security Reader at tenant scope** so `microsoft.security/cvedetails` enrichment is visible), `oc` CLI (logged in), `jq`, `bc`, `python3` ≥ 3.9 (used by `defender.sh` for the Phase 2d merge helper — stdlib only, no pip installs required).

```bash
# 1. Scan ACR for CVEs (report-only by default; --block-images to enforce)
./defender.sh --acr-name <ACR_NAME> --min-score 9 --max-score 10

# 2. Cross-reference CVEs with OpenShift workloads
./check_ocp.sh vulnerable_images_report.csv resultado_cruzamento.csv

# 3. Expand grouped rows into per-CVE rows
python3 expandcsv.py \
    --cruzamento resultado_cruzamento.csv \
    --vulnerabilities vulnerable_images_report.csv \
    --output expanded.csv

# 4. Generate HTML report
python3 report.py
```

## defender.sh modes

| Flag                  | Effect |
|-----------------------|--------|
| (default)             | Report-only CSV, no side effects |
| `--block-images`      | Sets `readEnabled=false` on matching ACR manifests (HTTP 405 on pull) |
| `--unblock`           | Reverses `--block-images` for the same query |
| `--unblock-all`       | Unblocks every blocked manifest in the ACR (or repository) |
| `--image <ref>`       | Unblock a single `repo@sha256:...` |
| `--list-blocked`      | Enumerates currently blocked manifests |
| `--scan-image <ref>`  | Scan a specific repo, tag, or digest |
| `--repository <r>`    | **Broad** substring filter (uses `contains`) — single repo. `app` will match `app-backend` and `myapp`. |
| `--repositories <l>`  | **Controlled** exact list (comma-separated). Each entry must exist exactly in the ACR; empty entries or duplicates abort. `app` does NOT capture `app-backend`. Mutually exclusive with `--repository` and `--scan-image`. |
| `--skip-tags`         | Bypass the tag_resolve phase entirely. Zero `show-tags` calls, every CSV row has `tag="N/A"`. Escape hatch for large scans where CVE data is all that matters. Incompatible with `--scan-image`. |
| `--dry-run`           | Print commands without executing |
| `--auto-approve`      | Skip interactive confirmation |
| `--debug`             | Print the generated KQL and run a diagnostic ARG query |

## Constraints

- **KQL in `defender.sh` was rewritten 2026-08 for the MDVM individual-recommendations migration + cvedetails enrichment fix.** Microsoft retired the legacy grouped `microsoft.security/assessments/subassessments` type (with the `c0b7cfc6-...` assessment key) on 2026-07-31, then in 2026-08 moved CVE metadata (cvss / severity / exploitability / publishedDate) to `microsoft.security/cvedetails` at **management-group scope**. The current query reads image + package + per-CVE linkage from `microsoft.security/assessments` (`recommendationCategory == "SoftwareUpdate"` + `.containerimage` + `Source == "Azure"`) and LEFT OUTER JOINs with `microsoft.security/cvedetails` for enrichment. `cvedetails.properties.cvss` is dict-keyed by version string (`"4.0"` / `"3.0"` / `"2.0"` — **there is no `"3.1"` key**; a coalesce that references `'3.1'` silently drops every CVSS 3.x-only CVE). Rejected CVEs (`properties.status == "Reject"`) are filtered out. Rows are preserved via LEFT OUTER JOIN when the caller's `az login` context can't reach the MG (enrichment fields fall back to the inline shape from assessments). See `docs/mdvm-cvedetails-schema-2026-08.md` for the full schema sample and `docs/mdvm-individual-migration.md` for the earlier migration rationale. Any change to the KQL must keep the 39 TDD invariants in `tests/test_defender_query_migration.py` green.
- Preserve the existing CSV column order — downstream stages depend on positional and named lookups.
- HTML output is single-file (embedded CSS, no external assets beyond Google Fonts) so it can be emailed or dropped into a wiki.

## Testing

Local tooling used:

```bash
pytest -q                        # unit tests + smoke
ruff check .                     # lint
pyright                          # type check
bash -n defender.sh check_ocp.sh # syntax check
shellcheck defender.sh check_ocp.sh
```

Tests live in `tests/` with fixtures generated programmatically in `tests/conftest.py` (no committed CSV samples).

Shell-script changes need runtime coverage, not just syntax/lint:

- Any new executable shell entry point must be added to `make lint` (`bash -n` and `shellcheck --severity=warning`).
- Any new executable shell entry point must have a tiny happy-path smoke test or Make target that runs it locally with fake inputs, exits `0`, and produces no unexpected stderr.
- Benchmark/diagnostic scripts must be tested for stable output shape and counters, but tests must not assert absolute timing values.
- Heredocs that generate shell scripts are runtime-risky under `set -u`: if the generated body contains inner-script variables such as `$KQL`, `$1`, `$PATH`, command substitutions, or backticks, use a quoted heredoc (`<<'EOF'`) when possible. If outer interpolation is required, escape every inner-script expansion (`\$VAR`, `\$(...)`) and run the generated script path in a smoke test.
- Do not treat `bash -n` or `shellcheck` as sufficient for generated scripts; they can miss heredoc expansion errors that only appear when the parent script runs.

## CSV schemas

### `vulnerable_images_report.csv` (defender.sh)

```
repository, digest, tag, cvssScore, cveId, severity,
packageCategory, packageLanguage, packageName,
currentVersion, fixedVersion, patchable, remediation,
fixStatus, cveAgeDays, isInExploitKit,
hasPublishedExploit, hasVerifiedExploit, lastPushedToRegistryUTC
```

### `resultado_cruzamento.csv` (check_ocp.sh, grouped)

```
NAMESPACE, PARENT_TYPE, PARENT_NAME, REPOSITORY, DIGEST, TAG,
CVE_COUNT, CRITICALITY, CVSS_SCORE, CVE_LIST, CVE_SEVERITY_MAP,
PACKAGE_CATEGORY, PACKAGE_LANGUAGE, PACKAGE_NAME,
CURRENT_VERSION, FIXED_VERSION, PATCHABLE,
REMEDIATION, FIX_STATUS, CVE_AGE_DAYS,
IS_IN_EXPLOIT_KIT, HAS_PUBLISHED_EXPLOIT, HAS_VERIFIED_EXPLOIT,
LAST_PUSHED_TO_REGISTRY_UTC
```

### `expanded.csv` (expandcsv.py)

```
NAMESPACE, PARENT_TYPE, PARENT_NAME, REPOSITORY, DIGEST, TAG, CVE_ID,
CVSS_SCORE, SEVERITY, PACKAGE_CATEGORY, PACKAGE_LANGUAGE, PACKAGE_NAME,
CURRENT_VERSION, FIXED_VERSION, PATCHABLE, REMEDIATION, FIX_STATUS,
CVE_AGE_DAYS, IS_IN_EXPLOIT_KIT, HAS_PUBLISHED_EXPLOIT,
HAS_VERIFIED_EXPLOIT, LAST_PUSHED_TO_REGISTRY_UTC
```

## Coding conventions

- Bash: strict mode (`set -euo pipefail`), `while ... < <(...)` over pipe-to-while for parent-scope counters, quote all variable expansions, prefer `az` `--query` filters over jq post-processing when the shape allows.
- Python: type hints required, prefer stdlib over third-party, `pathlib.Path` over `os.path`, `csv.DictReader` for typed access, `argparse` for CLI entry points.
- Comments: explain **why**, not what. Domain-specific behavior (e.g., multi-arch digest fallback) merits a comment; obvious code does not.

## Safety

- Never run `defender.sh --block-images` or `--unblock*` against production ACR without human approval.
- Never run `oc apply/delete` from any script in this repo — read-only OCP access is sufficient.
- `check_ocp.sh` filters out `openshift-*`, `kube-*`, `default`, `logging`, `monitoring` namespaces to avoid noise from platform-managed workloads.
- **Trust the report only when `check_ocp.sh` prints `COVERAGE: COMPLETE`.** Exit code `3` means at least one namespace failed (typically RBAC) and the report is missing workloads. Distributing a partial report as authoritative is the failure mode this classification exists to prevent.
- `make smoke-real ACR_NAME=<acr>` is the only Make target that touches real infrastructure; it runs in the tightest safe band (CVSS 9.8–10, report-only). No target ever runs block/unblock.

## Python API-first migration (planned, in backlog)

Tasks **P0.1–P0.8** track the migration of the pipeline to a new Python
package `defender_pipeline/` that uses **Azure SDKs and Kubernetes
Python client directly** — no `az`/`az rest`/`az acr`/`oc`/`subprocess`
in the main path. Rationale: performance, testability, modularity,
robustness of retry/backoff, observability, and reduced dependency on
the local CLI toolchain.

### Guardrails for AI assistants working on the migration

- **Do NOT rewrite the new Python path as a `subprocess.run(["az", ...])`
  wrapper.** Use `azure-identity`, `azure-mgmt-resourcegraph`,
  `azure-containerregistry`, `kubernetes` (Python client) instead.
  `subprocess` is only acceptable as a **temporary, explicitly-justified
  fallback** — never as the architecture.
- **Do NOT alter `defender.sh` during the migration.** It stays as the
  stable production baseline. The Python path lives in a separate
  package (`defender_pipeline/`) and is validated in parallel.
- **CSV contracts are frozen.** `vulnerable_images_report.csv` (19 cols),
  `resultado_cruzamento.csv` (24 cols), `expanded.csv` (22 cols) and
  `vulnerability_report.html` must remain byte-identical / semantically
  equivalent until an approved deprecation plan (task P0.8) says
  otherwise. The Python path must diff clean against the bash outputs
  before any cutover.
- **Order of work is enforced by task blocking**: P0.1 (docs) → P0.2
  (contract freeze + contract tests) → P0.3 (architecture design)
  → P0.4 (skeleton) → P0.5 (scan API-first) → P0.6 (OpenShift API-first)
  → P0.7 (expand + report CLI) → P0.8 (cleanup plan). Do not skip ahead.
