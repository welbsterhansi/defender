# GitHub Copilot — Instructions

Repository purpose: a local pipeline that scans an **Azure Container Registry (ACR)**
for image vulnerabilities via **Microsoft Defender for Cloud**, cross-references
findings against **OpenShift workloads**, and produces a self-contained HTML report
ranked by CVSS score and exploit availability.

These instructions describe the workflow Copilot must follow when suggesting changes.

---

## The merge gate

Every proposed change must leave the repository with `make check` green.
That single command is the contract; if it fails, the change is not ready.

```bash
make check
```

`make check` runs:

- `pytest -q` — unit + integration + E2E tests, all offline
- `ruff check .` — Python lint
- `pyright` — Python type check (if installed)
- `bash -n defender.sh check_ocp.sh` — shell syntax check
- `shellcheck --severity=warning` — shell lint (if installed)

**Rules:**

- If a test fails, fix the cause. Do not weaken assertions. Do not comment tests out.
- Do not use `--no-verify` on `git commit` or `git push` to bypass hooks.
- Do not push directly to `main`. Open a pull request even for small changes.
- If a check tool is missing on the environment, install it or report the gap —
  do not silently skip it.

## Testing discipline

The test suite (`tests/`) has three layers. When you change code, extend the
matching layer:

| Change type                          | Where the test goes                                       |
|--------------------------------------|-----------------------------------------------------------|
| New pure Python function             | `tests/test_<module>_unit.py`                             |
| New HTML section or user-facing field | assert in `tests/test_e2e.py::test_e2e_full_pipeline`     |
| New CSV column (any stage)           | update fixtures in `tests/_data.py` + assert everywhere it flows |
| New shell helper (pure function)     | `tests/test_defender_helpers.py` pattern (`_bash_call`)   |
| Change to embedded jq / Python       | `tests/test_shell_jq_runtime.py` pattern (mock JSON, real jq) |
| Change to `check_ocp.sh` namespace flow | `tests/test_check_ocp_integration.py` (mock `oc` via PATH) |

**When fixing a bug:** first write a test that reproduces the bug (it must fail
against the current code), then apply the fix and confirm the test now passes.

**When adding a feature:** add an assertion to the E2E test that would fail on
the current tree. This is how we ensure the feature stays working.

## Never do these

- **Do not modify the KQL query in `defender.sh`** (the `securityresources | ...`
  block). It is tuned for the current Defender for Cloud subscription. Changing
  it without a staging smoke test can silently miss CVEs or return duplicates.
  Adjust surrounding shell (parsing, retry, logging, exit codes) freely.

- **Do not run `defender.sh --block-images`, `--unblock*`, or `--auto-approve`
  from any script, workflow, or test.** These mutate ACR and require explicit
  human approval via change control.

- **Do not turn off `set -euo pipefail`** in the shell scripts. If a command
  legitimately returns non-zero (e.g. `grep` with no match, `az` with a soft
  failure), wrap it with `|| true` and add a comment explaining why.

- **Do not add live Azure or OpenShift calls in the automated test suite.**
  Mocks are planted on `PATH` (see `tests/test_check_ocp_integration.py` and
  `tests/test_defender_helpers.py` for the pattern). Real infrastructure runs
  only via the operator with `make smoke-real`.

- **Do not reorder CSV columns.** `vulnerable_images_report.csv`,
  `resultado_cruzamento.csv`, and `expanded.csv` are consumed by positional and
  named lookups downstream. Append new columns at the end; never insert or
  reorder. If you do add a column, update every stage that reads/writes the CSV.

- **Do not add a new Python dependency without a clear justification.** The
  pipeline is deliberately stdlib-heavy so it works in restricted client
  environments without a package mirror.

## Development flow

Safe targets (offline, no side effects):

| Command                            | Purpose                                                       |
|------------------------------------|---------------------------------------------------------------|
| `make test`                        | pytest only                                                   |
| `make lint`                        | ruff + pyright + bash -n + shellcheck                         |
| `make check`                       | test + lint (the merge gate)                                  |
| `make report`                      | regenerate `vulnerability_report.html` from existing CSVs     |
| `make pipeline-local`              | `expandcsv.py` + `report.py` against existing CSVs            |
| `make clean`                       | remove generated CSVs, HTML, and Python caches                |

Manual smoke — human operator only, touches real Azure:

| Command                                   | Purpose                                             |
|-------------------------------------------|-----------------------------------------------------|
| `make smoke-real ACR_NAME=<acr>`          | `defender.sh` in report-only mode, CVSS 9.8–10 band |

No `make` target ever invokes block/unblock operations.

## Repository structure

```
├── defender.sh            # ACR scan via Azure Resource Graph (KQL — do not modify)
├── check_ocp.sh           # OpenShift cross-reference; classifies each namespace and
│                            reports COVERAGE: COMPLETE / PARTIAL (exit 0 / 3)
├── group_findings.py      # Aggregate flat CSV → one row per (workload, image)
├── expandcsv.py           # Expand grouped CSV → one row per CVE, 3-level fallback lookup
├── report.py              # Render the single-file HTML report
├── tests/                 # pytest — unit, integration, E2E (all offline)
├── Makefile               # test / lint / check / report / pipeline-local / smoke-real / clean
├── pyproject.toml         # pytest, ruff, pyright config
├── AGENTS.md              # Same rules for Claude Code / Cursor / Aider
└── README.md              # Operator quickstart + rollout checklist
```

## Coverage semantics for `check_ocp.sh`

`check_ocp.sh` exits with a status that reflects data completeness:

- **Exit `0` — `COVERAGE: COMPLETE`.** Every visible non-platform namespace was
  analyzed successfully. Report is authoritative.
- **Exit `3` — `COVERAGE: PARTIAL`.** At least one namespace failed (RBAC
  denied, `oc` error, or JSON parse error). The `WARN` lines above the summary
  list which namespaces and why. **The report is missing workloads** — do not
  distribute it as authoritative and do not treat exit 3 as success in CI.

If you're adding automation on top of this pipeline (a scheduled job, a CI
check, a notification), branch on the exit code and surface partial coverage
explicitly.

## Shell script conventions

- Shebang: `#!/usr/bin/env bash`. Target runtime is Linux / WSL (bash 4+).
- Strict mode is mandatory: `set -euo pipefail` at the top.
- Quote all variable expansions.
- Prefer `while ... < <(cmd)` over `cmd | while ...` when the loop needs to
  mutate variables in the parent shell.
- Use `${arr[$key]:-}` when reading from an associative array; declare with
  explicit `declare -A NAME=()` so `${#NAME[@]}` never trips strict mode.
- **`bash -n` alone is not enough.** It catches shell syntax but not bugs
  inside embedded jq / Python / sed. Add a runtime test that executes the
  embedded tool with mock input.

## Python conventions

- Follow PEP 8. Type hints on new or modified function signatures.
- Prefer `pathlib.Path` over `os.path` for new code.
- Use `argparse` for any script with more than one flag.
- Prefer `csv.DictReader` over positional indexing.
- Keep large logic in module-level functions (testable), not inside `main()`.
- Explicit types on `defaultdict` when values are heterogeneous
  (see `_new_cve_agg` in `report.py`).
