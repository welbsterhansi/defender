# GitHub Copilot — Instructions

Repository purpose: a local pipeline that scans an **Azure Container Registry (ACR)**
for image vulnerabilities via **Microsoft Defender for Cloud**, cross-references
findings against **OpenShift workloads**, and produces a self-contained HTML report
ranked by CVSS score and exploit availability.

These are the rules Copilot must follow when suggesting or making changes.

---

## 1. Safe workflow

- Never work directly on `main`.
- Create a branch for every change.
- Run `make check` before every commit and before opening a PR.
- Do not merge if tests or lints are failing.
- If a test fails, fix the cause. Do not weaken an assertion without a clear
  written justification.
- Do not use `--no-verify` on `git commit` or `git push` to bypass hooks.

## 2. Tests

- A bugfix must include a test that reproduces the bug (it must fail against
  the current code, then pass after the fix).
- A new feature must include a new test or extend an existing one.
- A change to the pipeline must update the end-to-end test in
  `tests/test_e2e.py`.
- A change to the HTML report must validate the generated HTML (assert the new
  field or section is present in the output).
- A change to a shell script must pass `bash -n` and, when applicable, must
  validate the embedded tool at runtime — `jq` expressions with mock JSON,
  `az` / `oc` interactions via `PATH`-mocked binaries.

## 3. Pipeline

- Preserve the order and names of CSV fields.
- If you add a column, update every stage that touches the CSV:
  `defender.sh` → `check_ocp.sh` → `group_findings.py` → `expandcsv.py` →
  `report.py` → tests.
- `check_ocp.sh` exit `3` means partial coverage — at least one namespace
  failed (RBAC, `oc` error, or JSON parse). Do not treat exit `3` as success
  in CI or downstream automation.
- A report with `COVERAGE: PARTIAL` must not be distributed as a source of
  truth. Fix the underlying error (grant RBAC, restore access, correct the
  cluster state) and re-run.

## 4. Operational safety

- `defender.sh` is report-only by default.
- Never use `--block-images`, `--unblock`, `--unblock-all`, or `--auto-approve`
  without explicit approval from the responsible team.
- `make smoke-real ACR_NAME=<acr>` is the only `make` target that touches
  real Azure. Every other target is offline.
- Do not create automated tests that call real Azure or OpenShift. Mocks live
  on `PATH` (see `tests/test_check_ocp_integration.py` and
  `tests/test_defender_helpers.py` for the pattern).

## 5. KQL

- Do not change the KQL query in `defender.sh` without a clear technical
  justification (a new Defender for Cloud schema field, a documented behavior
  change, an on-call incident that traces to the query).
- Any KQL change requires a smoke test in a controlled staging environment
  before merging.
- The surrounding shell (parsing, retry, logging, error handling) can be
  modified freely — those changes still need to pass `make check`.

## 6. Dependencies

- Prefer the Python standard library.
- A new Python dependency needs a clear justification (what problem it solves
  that stdlib does not, why we cannot inline it).
- Do not add an external tool if the repository already solves the problem
  with `bash`, Python stdlib, `jq`, `az`, or `oc`.
- If a dependency is added, document its purpose in the PR description and
  add it to `pyproject.toml`.

## 7. Documentation

- Update `README.md` and `AGENTS.md` whenever you change the operator flow,
  make targets, CSV schema, or operational behavior.
- Error messages must state the cause and the corrective action. Example:
  `"grant get/list pods in namespace '<X>' or exclude it from the platform filter"`
  — not just `"forbidden"`.
- New features that surface in the HTML must be documented in the "Reading
  coverage output" style: what the field means, when it appears, what to do
  with it.

---

## Merge gate

```bash
make check
```

Runs the whole local gate: `pytest -q`, `ruff check .`, `pyright`,
`bash -n` on both shells, `shellcheck --severity=warning`. This is the
contract — if it is not green, the change is not ready.

## Repository structure

```
├── defender.sh            # ACR scan via Azure Resource Graph (KQL — see §5)
├── check_ocp.sh           # OpenShift cross-reference; exits 3 on partial coverage (§3)
├── group_findings.py      # Aggregate flat CSV → one row per (workload, image)
├── expandcsv.py           # Expand grouped CSV → one row per CVE
├── report.py              # Render the single-file HTML report
├── tests/                 # pytest — unit, integration, E2E (all offline)
├── Makefile               # test / lint / check / report / pipeline-local / smoke-real / clean
├── pyproject.toml         # pytest, ruff, pyright config
├── AGENTS.md              # Same rules for Claude Code / Cursor / Aider
└── README.md              # Operator quickstart
```
