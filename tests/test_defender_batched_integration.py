"""Integration tests for defender.sh — P2 batched architecture.

Replaces the retired test_defender_timing_log_format.py (which was tightly
coupled to the per-page timing instrumentation of the pre-P2 design).

Strategy: spin up a fake `az` CLI on PATH, run defender.sh in a subprocess,
and assert on the CSV output, log lines, and az call counts. The fake `az`
inspects the JSON body of `az rest` calls to decide which mocked payload
to return (enumerate / assessments / cvedetails).

What this suite guards:

  * CSV contract — 19 columns, exact header, all values quoted.
  * --skip-tags bypasses Phase 1 entirely (zero `show-tags` calls).
  * Tag cache — one `show-tags` per unique repo, cached across digests.
  * Show-tags failure → digests of that repo → TAG=N/A, 1 WARN, scan continues.
  * Per-phase log format (enumerate / phase2a / phase2c / phase2d) so
    dashboards/log parsers can consume it.
  * enrich_cvedetails.py errors propagate → defender.sh exit non-zero.
"""
from __future__ import annotations

import csv as csv_module
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = REPO_ROOT / "defender.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None
    or shutil.which("jq") is None
    or shutil.which("python3") is None,
    reason="bash, jq or python3 missing",
)

# ═══════════════════════════════════════════════════════════════════════════
# Fake `az` CLI — inspects az rest body to route to enumerate / assessments /
# cvedetails mock payloads; handles az acr subcommands too.
# ═══════════════════════════════════════════════════════════════════════════


def _write_fake_az(
    bin_dir: Path,
    *,
    enumerate_pairs: list[tuple[str, str]] | None = None,
    assessments_rows: list[dict] | None = None,
    cvedetails_rows: list[dict] | None = None,
    repo_tags: dict[str, list[dict]] | None = None,
    failing_repos: set[str] | None = None,
    fail_enrich_with_status: int = 0,
) -> Path:
    """Create a fake `az` on `bin_dir` that:

    - Returns `enumerate_pairs` (as `_repository`/`_digest`) for enumerate query.
    - Returns `assessments_rows` for the assessments batched query.
    - Returns `cvedetails_rows` for the cvedetails batched query.
    - Returns `repo_tags[repo]` for `az acr repository show-tags`.
    - Exits 1 for repos in `failing_repos` (show-tags failure path).
    - Logs every call to `<bin_dir>/../az_calls.log` for counting assertions.

    Returns the workspace root (parent of bin_dir).
    """
    workspace = bin_dir.parent
    bin_dir.mkdir(parents=True, exist_ok=True)
    payloads = workspace / "payloads"
    payloads.mkdir(exist_ok=True)
    tags_dir = workspace / "tags"
    tags_dir.mkdir(exist_ok=True)

    enum_payload = {"data": [
        {"_repository": r, "_digest": d} for r, d in (enumerate_pairs or [])
    ]}
    (payloads / "enumerate.json").write_text(
        json.dumps(enum_payload), encoding="utf-8",
    )

    assessments_payload = {"data": list(assessments_rows or [])}
    (payloads / "assessments.json").write_text(
        json.dumps(assessments_payload), encoding="utf-8",
    )

    cvedetails_payload = {"data": list(cvedetails_rows or [])}
    (payloads / "cvedetails.json").write_text(
        json.dumps(cvedetails_payload), encoding="utf-8",
    )

    for repo, tags in (repo_tags or {}).items():
        safe = repo.replace("/", "__")
        (tags_dir / f"{safe}.json").write_text(json.dumps(tags), encoding="utf-8")

    for repo in failing_repos or set():
        safe = repo.replace("/", "__")
        (tags_dir / f"{safe}.fail").touch()

    known_repos = "\n".join(sorted((repo_tags or {}).keys()))

    az_body = f"""#!/usr/bin/env bash
# Every invocation logged for count assertions.
echo "$*" >> "{workspace}/az_calls.log"

case "$1 $2" in
    "account show")
        echo '{{"user":{{"name":"test@test"}},"tenantId":"tid"}}'
        exit 0
        ;;
    "acr show")
        exit 0
        ;;
esac

case "$1 $2 $3" in
    "acr repository list")
        cat <<'REPOS_EOF'
{known_repos}
REPOS_EOF
        exit 0
        ;;
    "acr repository show-tags")
        repo=""
        shift 3
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --repository) repo="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        safe="${{repo//\\//__}}"
        if [ -f "{tags_dir}/${{safe}}.fail" ]; then exit 1; fi
        if [ -f "{tags_dir}/${{safe}}.json" ]; then
            cat "{tags_dir}/${{safe}}.json"; exit 0
        fi
        echo '[]'
        exit 0
        ;;
esac

if [ "$1" = "rest" ]; then
    body=""
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "--body" ]; then body="$2"; break; fi
        shift
    done
    # Route by KQL marker string in the query body.
    if echo "$body" | grep -q 'distinct _repository, _digest'; then
        cat "{payloads}/enumerate.json"
        exit 0
    fi
    if echo "$body" | grep -q 'inlineSeverity'; then
        cat "{payloads}/assessments.json"
        exit 0
    fi
    if echo "$body" | grep -q 'cvssEnrich'; then
        cat "{payloads}/cvedetails.json"
        exit 0
    fi
    echo '{{"data":[]}}'
    exit 0
fi

exit 0
"""
    az_path = bin_dir / "az"
    az_path.write_text(az_body, encoding="utf-8")
    az_path.chmod(0o755)

    if fail_enrich_with_status:
        # Replace enrich_cvedetails.py with a stub that exits non-zero.
        # Used by TestExitCodeOnEnrichFailure.
        (workspace / "enrich_cvedetails.py").write_text(
            f"#!/usr/bin/env python3\nimport sys\nsys.exit({fail_enrich_with_status})\n",
            encoding="utf-8",
        )

    return workspace


# ═══════════════════════════════════════════════════════════════════════════
# Helpers for building test payload rows in the shape defender.sh expects.
# ═══════════════════════════════════════════════════════════════════════════


def _assessment_row(
    repo: str = "myrepo",
    digest_hex: str = "a" * 64,
    cve: str = "CVE-2024-1",
    **overrides,
) -> dict:
    """Shape matches Query A projection in defender.sh."""
    row = {
        "repository": repo,
        "digest": f"sha256:{digest_hex}",
        "cveId": cve,
        "packageName": "openssl",
        "currentVersion": "1.0",
        "fixedVersion": "2.0",
        "fixStatus": "FixAvailable",
        "packageCategory": "OS",
        "packageLanguage": "",
        "remediation": "upgrade",
        "lastPushedToRegistryUTC": "2024-01-01",
        "inlineSeverity": "",
        "inlineCvssBase": 0,
        "inlinePublishedDate": "",
        "inlineInExploitKit": "",
        "inlinePubliclyDisclosed": "",
        "inlineVerified": "",
    }
    row.update(overrides)
    return row


def _cvedetails_row(
    cve: str = "CVE-2024-1",
    cvss: float = 9.8,
    severity: str = "Critical",
    **overrides,
) -> dict:
    """Shape matches Query B projection."""
    row = {
        "cveIdJoin": cve.upper(),
        "cvssEnrich": cvss,
        "publishedDateEnrich": "2024-05-01T00:00:00Z",
        "severityEnrich": severity,
        "verifiedExpEnrich": 1,
        "publishedExpEnrich": 1,
        "inExploitKitEnrich": 1,
    }
    row.update(overrides)
    return row


def _run_defender(
    tmp_path: Path,
    *,
    enumerate_pairs: list[tuple[str, str]] | None = None,
    assessments_rows: list[dict] | None = None,
    cvedetails_rows: list[dict] | None = None,
    repo_tags: dict[str, list[dict]] | None = None,
    failing_repos: set[str] | None = None,
    extra_args: list[str] | None = None,
    fail_enrich_with_status: int = 0,
) -> subprocess.CompletedProcess:
    """Run defender.sh in `tmp_path` with a fake `az` on PATH."""
    workspace = _write_fake_az(
        tmp_path / "bin",
        enumerate_pairs=enumerate_pairs,
        assessments_rows=assessments_rows,
        cvedetails_rows=cvedetails_rows,
        repo_tags=repo_tags,
        failing_repos=failing_repos,
        fail_enrich_with_status=fail_enrich_with_status,
    )
    # defender.sh looks for enrich_cvedetails.py relative to its own dir.
    # We invoke it from tmp_path (cwd) but with the real path; the helper
    # must be at `dirname(defender.sh)/enrich_cvedetails.py`, which is the
    # repo root. Copy it into a `lib/` alongside the fake defender.sh IF
    # we're stubbing it (fail_enrich_with_status), otherwise the real one
    # is at REPO_ROOT and already discoverable via dirname of DEFENDER.
    env = os.environ.copy()
    env["PATH"] = f"{workspace / 'bin'}:{env['PATH']}"

    # If we're stubbing enrich_cvedetails.py to force failure, we need
    # defender.sh's `dirname($0)` to resolve to the stubbed path. Easiest
    # way: copy defender.sh into `workspace` too and run that copy.
    if fail_enrich_with_status:
        script = workspace / "defender.sh"
        shutil.copy(DEFENDER, script)
    else:
        script = DEFENDER

    argv = [str(script), "--acr-name", "mock-acr",
            "--min-score", "0", "--max-score", "10"]
    if extra_args:
        argv.extend(extra_args)
    return subprocess.run(
        argv, cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )


def _find_log(tmp_path: Path) -> str:
    """Read the run log file produced under tmp_path/logs/."""
    logs = list((tmp_path / "logs").glob("run-*.log"))
    assert logs, "no log file produced"
    return logs[-1].read_text(encoding="utf-8")


def _count_az_calls(tmp_path: Path, marker: str) -> int:
    log_path = tmp_path / "az_calls.log"
    if not log_path.exists():
        return 0
    return sum(1 for line in log_path.read_text(encoding="utf-8").splitlines()
               if marker in line)


def _read_csv(tmp_path: Path) -> list[list[str]]:
    with (tmp_path / "vulnerable_images_report.csv").open("r", encoding="utf-8") as f:
        return list(csv_module.reader(f))


# ═══════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestCsvContract:
    """CSV format is a downstream contract (expandcsv.py, report.py). This
    is the safety net for every PR — regressions here break the pipeline."""

    def test_header_exact_19_columns(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1.0", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr

        rows = _read_csv(tmp_path)
        assert len(rows) >= 1, "CSV missing header"
        assert rows[0] == [
            "repository", "digest", "tag", "cvssScore", "cveId", "severity",
            "packageCategory", "packageLanguage", "packageName",
            "currentVersion", "fixedVersion", "patchable", "remediation",
            "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
            "hasVerifiedExploit", "lastPushedToRegistryUTC",
        ]

    def test_every_data_row_has_19_quoted_fields(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1.0", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr

        raw_lines = (tmp_path / "vulnerable_images_report.csv").read_text(
            encoding="utf-8",
        ).splitlines()
        for line in raw_lines[1:]:  # skip header
            assert line.count('"') == 38, (
                f"expected 38 quotes (19 fields × 2), got {line.count(chr(34))}: {line}"
            )

    def test_cvss_from_enrichment_wins_over_inline(self, tmp_path: Path) -> None:
        # Assessments has inline High/8.1; enrichment has Critical/9.8.
        # Enrichment must win.
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row(
                inlineSeverity="High", inlineCvssBase=8.1,
            )],
            cvedetails_rows=[_cvedetails_row(cvss=9.8, severity="Critical")],
            repo_tags={"myrepo": [{"name": "v1.0", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr

        rows = _read_csv(tmp_path)
        assert rows[1][3] == "9.8", rows[1]        # cvssScore
        assert rows[1][5] == "Critical", rows[1]   # severity

    def test_inline_fallback_when_no_enrichment(self, tmp_path: Path) -> None:
        # Assessments has inline High/8.1; cvedetails returns empty.
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row(
                cveId="CVE-9999-NOENRICH",
                inlineSeverity="High", inlineCvssBase=8.1,
            )],
            cvedetails_rows=[],
            repo_tags={"myrepo": [{"name": "v1.0", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr

        rows = _read_csv(tmp_path)
        assert rows[1][3] == "8.1", rows[1]     # inline wins
        assert rows[1][5] == "High", rows[1]


class TestSkipTagsFlag:
    """--skip-tags bypasses Phase 1 entirely: zero show-tags calls, all
    rows get TAG=N/A. The flag also appears in the log header line for
    audit trail."""

    def test_zero_show_tags_calls_and_all_na(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "SHOULD-NOT-APPEAR",
                                   "digest": "sha256:" + "a" * 64}]},
            extra_args=["--skip-tags"],
        )
        assert r.returncode == 0, r.stderr

        assert _count_az_calls(tmp_path, "show-tags") == 0

        rows = _read_csv(tmp_path)
        assert rows[1][2] == "N/A", rows[1]

    def test_log_shows_skip_tags_disabled_message(
        self, tmp_path: Path,
    ) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[],
            extra_args=["--skip-tags"],
        )
        assert r.returncode == 0, r.stderr
        log = _find_log(tmp_path)
        assert "tag_resolve DISABLED via --skip-tags" in log

    def test_skip_tags_appears_in_args_header(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[],
            extra_args=["--skip-tags"],
        )
        assert r.returncode == 0, r.stderr
        log = _find_log(tmp_path)
        header = "\n".join(log.splitlines()[:15])
        assert "--skip-tags" in header, header

    def test_default_run_resolves_tags(self, tmp_path: Path) -> None:
        # Regression guard — without --skip-tags, show-tags IS called.
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1.0",
                                   "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr
        assert _count_az_calls(tmp_path, "show-tags") >= 1

        rows = _read_csv(tmp_path)
        assert rows[1][2] == "v1.0", rows[1]


class TestTagCacheUpfront:
    """P2 architecture: tag cache is built ONCE upfront (Phase 1), before
    the batched scan runs. Same guarantees as pre-P2 apply: one call per
    unique repo, failures don't abort, missing digests fall back to N/A."""

    def test_one_show_tags_per_unique_repo(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[
                ("repo-a", "sha256:" + "1" * 64),
                ("repo-a", "sha256:" + "2" * 64),
                ("repo-a", "sha256:" + "3" * 64),
                ("repo-b", "sha256:" + "4" * 64),
            ],
            assessments_rows=[
                _assessment_row(repo="repo-a", digest_hex="1" * 64),
                _assessment_row(repo="repo-a", digest_hex="2" * 64,
                                cve="CVE-2024-2"),
                _assessment_row(repo="repo-a", digest_hex="3" * 64,
                                cve="CVE-2024-3"),
                _assessment_row(repo="repo-b", digest_hex="4" * 64,
                                cve="CVE-2024-4"),
            ],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={
                "repo-a": [
                    {"name": "a-1", "digest": "sha256:" + "1" * 64},
                    {"name": "a-2", "digest": "sha256:" + "2" * 64},
                    {"name": "a-3", "digest": "sha256:" + "3" * 64},
                ],
                "repo-b": [{"name": "b-1", "digest": "sha256:" + "4" * 64}],
            },
        )
        assert r.returncode == 0, r.stderr
        # 2 unique repos → 2 show-tags calls (not 4 for the 4 digests).
        assert _count_az_calls(tmp_path, "show-tags") == 2

    def test_show_tags_failure_yields_na_and_warns_once(
        self, tmp_path: Path,
    ) -> None:
        # repo-fail returns error; repo-ok returns tags. Scan continues.
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[
                ("repo-fail", "sha256:" + "1" * 64),
                ("repo-ok", "sha256:" + "2" * 64),
            ],
            assessments_rows=[
                _assessment_row(repo="repo-fail", digest_hex="1" * 64),
                _assessment_row(repo="repo-ok", digest_hex="2" * 64,
                                cve="CVE-2024-2"),
            ],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={
                "repo-ok": [{"name": "ok-1", "digest": "sha256:" + "2" * 64}],
                "repo-fail": [],
            },
            failing_repos={"repo-fail"},
        )
        assert r.returncode == 0, r.stderr

        # Scan reaches CSV emit.
        rows = _read_csv(tmp_path)
        by_repo = {r[0]: r for r in rows[1:]}
        assert by_repo["repo-fail"][2] == "N/A"
        assert by_repo["repo-ok"][2] == "ok-1"

        # WARN about the failed repo appears exactly once.
        log = _find_log(tmp_path)
        warn_count = sum(
            1 for line in log.splitlines()
            if "WARN" in line and "show-tags failed" in line
            and "repo-fail" in line
        )
        assert warn_count == 1


class TestBatchedPhaseLogs:
    """Log format for dashboards/parsers. Each phase must emit a start/end
    line with stable structure. Order enforced too — enumerate before
    phase2a, phase2c before phase2d."""

    def test_enumerate_log_line_present(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr
        log = _find_log(tmp_path)
        assert re.search(
            r"enumerate:\s+found\s+\d+\s+unique\s+pairs\s+in\s+\d+\s+page\(s\)"
            r"\s+time_ms=\d+", log,
        )

    def test_phase2a_and_2c_log_lines_present(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr
        log = _find_log(tmp_path)
        assert re.search(
            r"phase2a\s+assessments_batched:\s+end\s+batches=\d+\s+rows=\d+"
            r"\s+time_ms=\d+", log,
        )
        assert re.search(
            r"phase2c\s+cvedetails_batched:\s+end\s+batches=\d+\s+rows=\d+"
            r"\s+time_ms=\d+", log,
        )

    def test_phase2d_merge_summary_present(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr
        log = _find_log(tmp_path)
        assert re.search(
            r"phase2d\s+merge:\s+enrich_cvedetails\s+rows_read=\d+"
            r"\s+rows_emitted=\d+\s+rows_enriched=\d+", log,
        )

    def test_end_log_line_has_final_counts(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr
        log = _find_log(tmp_path)
        assert re.search(
            r"end\s+total_processed=\d+\s+digests=\d+\s+pages=\d+", log,
        )


class TestEmptyResults:
    """When enumerate returns 0 pairs, the run exits cleanly with a header-
    only CSV — no crash, no confusing errors."""

    def test_empty_enumerate_produces_header_only_csv(
        self, tmp_path: Path,
    ) -> None:
        r = _run_defender(tmp_path, enumerate_pairs=[])
        assert r.returncode == 0, r.stderr

        csv_path = tmp_path / "vulnerable_images_report.csv"
        if csv_path.exists():
            rows = _read_csv(tmp_path)
            assert len(rows) == 1, "expected header-only CSV, got data rows"

    def test_no_matching_images_logged(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, enumerate_pairs=[])
        assert r.returncode == 0, r.stderr
        # Stdout OR log OR both may carry the "No matching images" line.
        combined = r.stdout + r.stderr
        try:
            combined += _find_log(tmp_path)
        except AssertionError:
            pass
        assert "No matching images" in combined or "digests=0" in combined


class TestRemediationSafety:
    """Multi-line remediation must NOT break the CSV row count or column
    positions. csv_field in the Python helper collapses newlines to space."""

    def test_multiline_remediation_stays_on_one_row(
        self, tmp_path: Path,
    ) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row(
                remediation="line one\nline two\r\nline three",
            )],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr

        raw = (tmp_path / "vulnerable_images_report.csv").read_text(
            encoding="utf-8",
        )
        lines = raw.splitlines()
        assert len(lines) == 2, (
            f"embedded newlines split the row into {len(lines) - 1} data lines"
        )

    def test_comma_in_remediation_survives_via_quoting(
        self, tmp_path: Path,
    ) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row(
                remediation="Update, please, urgently",
            )],
            cvedetails_rows=[_cvedetails_row()],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
        )
        assert r.returncode == 0, r.stderr

        with (tmp_path / "vulnerable_images_report.csv").open() as f:
            rows = list(csv_module.reader(f))
        assert len(rows[1]) == 19, "commas in remediation shifted columns"
        assert rows[1][12] == "Update, please, urgently"


class TestExitCodeOnEnrichFailure:
    """If enrich_cvedetails.py fails, defender.sh must propagate non-zero
    exit and log an error. No silent CSV emission with missing rows."""

    def test_exit_2_when_python_helper_fails(self, tmp_path: Path) -> None:
        r = _run_defender(
            tmp_path,
            enumerate_pairs=[("myrepo", "sha256:" + "a" * 64)],
            assessments_rows=[_assessment_row()],
            cvedetails_rows=[],
            repo_tags={"myrepo": [{"name": "v1", "digest": "sha256:" + "a" * 64}]},
            fail_enrich_with_status=1,
        )
        assert r.returncode != 0, (
            f"expected non-zero exit; got {r.returncode}\n{r.stdout}\n{r.stderr}"
        )
