# AGENTS.md

Context for AI coding assistants (Claude Code, Cursor, Aider, etc.) working on this repository.

> **GitHub Copilot uses [`.github/copilot-instructions.md`](./.github/copilot-instructions.md)** — that file carries the same rules in Copilot's native location. Keep the two files aligned if a rule changes.

## Purpose

Pipeline that scans an **Azure Container Registry (ACR)** for image vulnerabilities via **Microsoft Defender for Cloud**, cross-references the results against **workloads running in OpenShift**, and produces an executive HTML report ranked by CVSS score and exploit availability.

Primary consumers: platform SRE team (report), developers (remediation actions), security officers (governance).

## Architecture

```
┌────────────┐      ┌──────────────────────────┐
│ defender.sh│─────▶│ vulnerable_images_report │
│  (ACR/KQL) │      │        .csv (19 cols)    │
└────────────┘      └────────────┬─────────────┘
                                 │
┌────────────┐                   ▼
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

## Files

| File                  | Language | Role |
|-----------------------|----------|------|
| `defender.sh`         | Bash     | Queries Azure Resource Graph (KQL) for CVEs on ACR images. Supports block/unblock/list/scan modes. |
| `check_ocp.sh`        | Bash     | For each OpenShift project, list running pods and cross-reference their image digests with the CVE CSV. Emits a flat (workload × image × CVE) CSV. Classifies each namespace into one of five states (`SUCCESS_WITH_PODS`, `NO_PODS`, `RBAC_ERR`, `OC_ERR`, `PARSE_ERR`) and prints a coverage summary; exit `0` = complete, exit `3` = partial coverage. |
| `group_findings.py`   | Python   | Called by `check_ocp.sh` to aggregate the flat CSV into one row per unique `(namespace, workload, image)` — CVE list, severity map, max CVSS, carried package/exploit fields. Was previously inline `python3 -c '...'`. |
| `expandcsv.py`        | Python   | Explodes the grouped CSV into one row per unique `(namespace, workload, repository, digest, cveId)`. Uses a 3-level lookup (full → repo+cve → digest-prefix) to tolerate multi-arch manifests. |
| `report.py`           | Python   | Generates a self-contained HTML report with cluster health score, top CVEs, per-namespace breakdown, and executive analysis. |
| `lib/logging.sh`      | Bash     | Sourced by both shells. `init_logging <script> <mode> [args...]` creates `logs/run-YYYYMMDD-HHMMSS.log` (UTC) and tees all stdout+stderr into it, preserving realtime terminal output. Scrubs values of `--token`/`--password`/`--secret`/`--key` flags in the header. |
| `tests/`              | Python   | pytest suite with synthetic CSV fixtures. |
| `pyproject.toml`      | -        | pytest, ruff, and pyright configuration. |

## Running the pipeline

Prerequisites: `az` CLI (logged in), `oc` CLI (logged in), `jq`, `bc`, Python 3.11+.

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
| `--dry-run`           | Print commands without executing |
| `--auto-approve`      | Skip interactive confirmation |
| `--debug`             | Print the generated KQL and run a diagnostic ARG query |

## Constraints

- **Do not modify the KQL query in `defender.sh`.** It is tuned for a specific Defender for Cloud subscription shape and covers both MDVM (`c0b7cfc6-...`) and legacy `SoftwareUpdate` assessments. Adjust the surrounding shell logic (parsing, resilience, output) freely.
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
