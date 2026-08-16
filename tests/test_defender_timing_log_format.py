"""
Behavior tests for the per-page timing instrumentation added in PR-0 (#42).

These are NOT performance tests. They only verify:
  - The `timings_ms=` log line appears once per non-empty page.
  - The line has the stable field layout dashboards/benchmarks will parse.
  - Timing values are non-negative integers (no unit suffix, no `n/a`).
  - The `tag_api_calls` counter appears and matches the number of unique
    digests in the page (baseline behavior — will change in PR-B).
  - Empty batches do NOT emit a timing line (only the "batch=0" note).

Uses PATH-mocked `az` — no live Azure calls.
"""
from __future__ import annotations

import csv as csv_module
import io
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
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="bash or jq missing",
)


def _make_fake_az_returning(
    bin_dir: Path,
    graph_pages: list[dict],
    *,
    repo_tags: dict[str, list[dict]] | None = None,
    failing_repos: set[str] | None = None,
) -> Path:
    """
    Fake `az` that returns `graph_pages[i]` on the (i+1)-th `graph query`
    invocation, then empty {"data":[]} on subsequent calls. Logs every
    invocation to `<bin_dir>/../az_calls.log` for count assertions.

    show-tags behavior (PR-B):
      - Returns a JSON array of {name, digest} objects matching the shape
        of `az acr repository show-tags --detail --output json`.
      - `repo_tags` overrides the response per repository. If omitted, one
        synthetic tag (tag-1, tag-2, ...) is auto-generated per unique
        digest seen in `graph_pages` for that repository — enough for
        default tests where we only care about counts.
      - `failing_repos` — set of repos for which `az` will exit 1 (used
        by the failure-handling tests).
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    payloads_dir = bin_dir.parent / "payloads"
    tags_dir = bin_dir.parent / "tags"
    payloads_dir.mkdir(exist_ok=True)
    tags_dir.mkdir(exist_ok=True)
    for i, page in enumerate(graph_pages, start=1):
        (payloads_dir / f"page{i}.json").write_text(json.dumps(page), encoding="utf-8")

    if repo_tags is None:
        repo_tags = {}
        for page in graph_pages:
            for row in page.get("data", []):
                r = row["repository"]
                d = row["digest"]
                bucket = repo_tags.setdefault(r, [])
                if not any(t["digest"] == d for t in bucket):
                    bucket.append({"name": f"tag-{len(bucket) + 1}", "digest": d})
    for repo, tags in repo_tags.items():
        safe = repo.replace("/", "__")
        (tags_dir / f"{safe}.json").write_text(json.dumps(tags), encoding="utf-8")

    for repo in failing_repos or set():
        safe = repo.replace("/", "__")
        (tags_dir / f"{safe}.fail").write_text("", encoding="utf-8")

    body = f"""#!/usr/bin/env bash
echo "$*" >> "{bin_dir.parent}/az_calls.log"
if [ "$1 $2" = "acr show" ]; then exit 0; fi
if [ "$1 $2 $3" = "acr repository list" ]; then exit 0; fi
if [ "$1 $2 $3" = "acr repository show-tags" ]; then
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
    echo '[]'; exit 0
fi
if [ "$1 $2" = "graph query" ]; then
    ctr="{bin_dir.parent}/page_counter"
    prev=$(cat "$ctr" 2>/dev/null || echo 0)
    curr=$(( prev + 1 ))
    echo "$curr" > "$ctr"
    payload="{payloads_dir}/page${{curr}}.json"
    if [ -f "$payload" ]; then
        cat "$payload"
    else
        echo '{{"data":[],"skip_token":""}}'
    fi
    exit 0
fi
exit 0
"""
    az_path = bin_dir / "az"
    az_path.write_text(body, encoding="utf-8")
    az_path.chmod(0o755)
    return bin_dir.parent


def _row(digest_hex: str, cve: str = "CVE-1", repo: str = "myapp") -> dict:
    return {
        "repository": repo,
        "digest": f"sha256:{digest_hex}",
        "cvssScore": 9.5,
        "cveId": cve,
        "severityRaw": "Critical",
        "packageCategory": "os", "packageLanguage": "c",
        "packageName": "pkg", "currentVersion": "1.0", "fixedVersion": "2.0",
        "patchable": "true", "remediation": "upgrade", "fixStatus": "FixAvailable",
        "cveAgeDays": 30, "isInExploitKit": "false",
        "hasPublishedExploit": "false", "hasVerifiedExploit": "false",
        "lastPushedToRegistryUTC": "",
    }


def _run_defender(
    tmp_path: Path,
    graph_pages: list[dict],
    *,
    repo_tags: dict[str, list[dict]] | None = None,
    failing_repos: set[str] | None = None,
) -> subprocess.CompletedProcess:
    fake_root = _make_fake_az_returning(
        tmp_path / "bin", graph_pages,
        repo_tags=repo_tags, failing_repos=failing_repos,
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_root / 'bin'}:{env['PATH']}"
    return subprocess.run(
        [str(DEFENDER), "--acr-name", "benchmark", "--min-score", "0", "--max-score", "10"],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )


def _first_timing_match(log_text: str) -> re.Match[str] | None:
    for line in log_text.splitlines():
        m = TIMING_LINE_RE.search(line)
        if m:
            return m
    return None


TIMING_LINE_RE = re.compile(
    r"page (?P<page>\d+) "
    r"batch=(?P<batch>\d+) "
    r"total=(?P<total>\d+) "
    r"retries=(?P<retries>\d+) "
    r"tag_api_calls=(?P<tag_calls>\d+) "
    r"timings_ms=graph_query:(?P<graph>\d+) "
    r"tag_resolve:(?P<tags>\d+) "
    r"rows:(?P<rows>\d+) "
    r"total:(?P<page_total>\d+)"
)


class TestTimingLogFormat:
    def test_single_page_emits_one_timing_line(self, tmp_path: Path) -> None:
        pages = [{"data": [_row("aaa" * 21 + "a")], "skip_token": ""}]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr

        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        matches = [m for m in (TIMING_LINE_RE.search(line) for line in log.splitlines()) if m]
        assert len(matches) == 1, f"expected 1 timing line, got {len(matches)}: {log}"

        m = matches[0]
        assert m["page"] == "1"
        assert m["batch"] == "1"
        assert m["tag_calls"] == "1"  # one unique digest in this page
        # All timing values are non-negative integers (may be 0 on very fast runs).
        for key in ("graph", "tags", "rows", "page_total"):
            assert int(m[key]) >= 0, f"{key} negative: {m[key]}"

    def test_multi_page_emits_one_line_per_non_empty_page(self, tmp_path: Path) -> None:
        pages = [
            {"data": [_row("aaa" * 21 + "a"), _row("bbb" * 21 + "b")],
             "skip_token": "cursor-1"},
            {"data": [_row("ccc" * 21 + "c")],
             "skip_token": ""},
        ]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr

        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        matches = [m for line in log.splitlines()
                   for m in [TIMING_LINE_RE.search(line)] if m]
        assert len(matches) == 2
        assert matches[0]["page"] == "1" and matches[0]["batch"] == "2"
        assert matches[1]["page"] == "2" and matches[1]["batch"] == "1"

    def test_empty_batch_does_not_emit_timing_line(self, tmp_path: Path) -> None:
        # Only "batch=0 → end of results" — no timings_ms line.
        pages: list[dict] = []
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr

        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert not any(TIMING_LINE_RE.search(line) for line in log.splitlines()), \
            "empty batch must not produce a timings_ms line"
        assert "batch=0" in log or "batch=0" in r.stdout


def _count_show_tags(tmp_path: Path) -> int:
    log = (tmp_path / "az_calls.log").read_text(encoding="utf-8")
    return sum(1 for line in log.splitlines() if "acr repository show-tags" in line)


class TestTagApiCallsCounter:
    """PR-B semantics: `tag_api_calls` on the per-page timing line counts
    actual `az show-tags` invocations made on that page. Cache is
    execution-global, so a repo already resolved on an earlier page does
    NOT increment the counter on later pages."""

    def test_counter_matches_show_tags_invocations(self, tmp_path: Path) -> None:
        # 3 rows, 3 distinct digests, all in the SAME repo → 1 call.
        pages = [{"data": [
            _row("a" * 64, repo="repo-alpha"),
            _row("b" * 64, repo="repo-alpha"),
            _row("c" * 64, repo="repo-alpha"),
        ], "skip_token": ""}]
        _run_defender(tmp_path, pages)

        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        m = _first_timing_match(log)
        assert m is not None
        assert int(m["tag_calls"]) == _count_show_tags(tmp_path) == 1

    def test_counter_matches_unique_repos_not_digests(self, tmp_path: Path) -> None:
        # 3 rows across 2 repos → 2 calls (one per repo).
        pages = [{"data": [
            _row("a" * 64, repo="repo-alpha"),
            _row("b" * 64, repo="repo-alpha"),
            _row("c" * 64, repo="repo-beta"),
        ], "skip_token": ""}]
        _run_defender(tmp_path, pages)
        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        m = _first_timing_match(log)
        assert m is not None
        assert int(m["tag_calls"]) == _count_show_tags(tmp_path) == 2


class TestCsvOutputUnchanged:
    """Instrumentation must NOT change the CSV. Header and column order are
    a downstream contract (expandcsv.py, report.py depend on positional
    lookups). This test is the safety-net for every PR in the perf series."""

    def test_header_and_row_shape_preserved(self, tmp_path: Path) -> None:
        pages = [{"data": [_row("a" * 64, "CVE-100", "myrepo")], "skip_token": ""}]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr

        csv_path = tmp_path / "vulnerable_images_report.csv"
        assert csv_path.exists()
        lines = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2  # header + 1 row

        expected_header = (
            '"repository","digest","tag","cvssScore","cveId","severity",'
            '"packageCategory","packageLanguage","packageName","currentVersion",'
            '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
            '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit",'
            '"lastPushedToRegistryUTC"'
        )
        assert lines[0] == expected_header, "CSV header drifted from expected"

        # Row starts with the fake repo/digest we passed in.
        assert lines[1].startswith('"myrepo","sha256:'), lines[1]
        # Every value quoted (csv_write_row invariant).
        assert lines[1].count('"') == 38  # 19 fields × 2 quotes


class TestPrbTagCachePerRepo:
    """PR-B: `az show-tags --detail` returns ALL tags of a repo in one call.
    The cache is now keyed per repository (not per digest), and lives for
    the whole execution (not per page). These tests lock the acceptance
    criteria the reviewer set on PR-B:

      - N digests in one repo → 1 call to show-tags
      - N repos → N calls
      - Same repo across pages → 1 call total (execution-global cache)
      - show-tags failure → digests of that repo → TAG=N/A, 1 WARN per
        repo (no retry on later pages), scan continues (exit 0)
      - CSV preserves TAG when the show-tags response includes the digest
      - First-tag-wins for digests that carry multiple tags (matches the
        prior `[?digest=='X'].name | [0]` semantics)
      - Truncation guard: response with exactly 5000 entries logs a WARN
    """

    def _read_csv_by_digest(self, tmp_path: Path) -> dict[str, dict[str, str]]:
        csv = (tmp_path / "vulnerable_images_report.csv").read_text(encoding="utf-8")
        rows = list(csv_module.reader(io.StringIO(csv)))
        header, data_rows = rows[0], rows[1:]
        return {
            dict(zip(header, r, strict=True))["digest"]:
                dict(zip(header, r, strict=True))
            for r in data_rows
        }

    def test_multiple_digests_same_repo_makes_one_call(
        self, tmp_path: Path
    ) -> None:
        pages = [{"data": [
            _row("a" * 64, repo="repo-alpha"),
            _row("b" * 64, repo="repo-alpha"),
        ], "skip_token": ""}]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr
        assert _count_show_tags(tmp_path) == 1

    def test_multiple_repos_make_one_call_each(self, tmp_path: Path) -> None:
        pages = [{"data": [
            _row("a" * 64, repo="repo-alpha"),
            _row("b" * 64, repo="repo-beta"),
            _row("c" * 64, repo="repo-gamma"),
        ], "skip_token": ""}]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr
        assert _count_show_tags(tmp_path) == 3

    def test_same_repo_across_pages_makes_one_call(self, tmp_path: Path) -> None:
        pages = [
            {"data": [_row("a" * 64, repo="repo-alpha")],
             "skip_token": "cursor-1"},
            {"data": [_row("b" * 64, repo="repo-alpha")],
             "skip_token": ""},
        ]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr
        # execution-global cache: second page reuses page-1 tag data.
        assert _count_show_tags(tmp_path) == 1

        # Per-page counter reports 0 on the second page (no new az calls).
        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        matches = [TIMING_LINE_RE.search(line) for line in log.splitlines()]
        matches = [m for m in matches if m is not None]
        assert len(matches) == 2, matches
        assert int(matches[0]["tag_calls"]) == 1
        assert int(matches[1]["tag_calls"]) == 0

    def test_show_tags_failure_yields_na_and_warns_once(
        self, tmp_path: Path
    ) -> None:
        # 2 pages, same failing repo — WARN must fire exactly once, both
        # digests fall back to TAG=N/A, exit 0.
        pages = [
            {"data": [_row("a" * 64, repo="repo-broken")],
             "skip_token": "cursor-1"},
            {"data": [_row("b" * 64, repo="repo-broken")],
             "skip_token": ""},
        ]
        r = _run_defender(tmp_path, pages, failing_repos={"repo-broken"})
        assert r.returncode == 0, r.stderr

        by_digest = self._read_csv_by_digest(tmp_path)
        assert by_digest["sha256:" + "a" * 64]["tag"] == "N/A"
        assert by_digest["sha256:" + "b" * 64]["tag"] == "N/A"

        # az was called once for the failing repo — not retried on page 2.
        assert _count_show_tags(tmp_path) == 1

        # WARN appears exactly once for that repo.
        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        warns = [
            line for line in log.splitlines()
            if "show-tags failed" in line and "repo-broken" in line
        ]
        assert len(warns) == 1, warns

    def test_csv_preserves_tag_when_found(self, tmp_path: Path) -> None:
        pages = [{"data": [
            _row("a" * 64, repo="repo-alpha"),
            _row("b" * 64, repo="repo-alpha"),
        ], "skip_token": ""}]
        repo_tags = {"repo-alpha": [
            {"name": "release-1.0", "digest": "sha256:" + "a" * 64},
            {"name": "release-2.0", "digest": "sha256:" + "b" * 64},
        ]}
        r = _run_defender(tmp_path, pages, repo_tags=repo_tags)
        assert r.returncode == 0, r.stderr

        by_digest = self._read_csv_by_digest(tmp_path)
        assert by_digest["sha256:" + "a" * 64]["tag"] == "release-1.0"
        assert by_digest["sha256:" + "b" * 64]["tag"] == "release-2.0"

    def test_first_tag_wins_for_duplicate_digest(self, tmp_path: Path) -> None:
        # Two tags point at the same digest. Prior code used
        # `[?digest=='X'].name | [0]` → array-order-first. The per-repo
        # map must preserve that: first tag in the show-tags response wins.
        digest = "sha256:" + "a" * 64
        pages = [{"data": [_row("a" * 64, repo="repo-alpha")], "skip_token": ""}]
        repo_tags = {"repo-alpha": [
            {"name": "v1.0",           "digest": digest},
            {"name": "v1.0-hotfix",    "digest": digest},
        ]}
        r = _run_defender(tmp_path, pages, repo_tags=repo_tags)
        assert r.returncode == 0, r.stderr

        by_digest = self._read_csv_by_digest(tmp_path)
        assert by_digest[digest]["tag"] == "v1.0", (
            "expected first-tag-wins semantics; got last-tag-wins"
        )

    def test_show_tags_truncation_warns_at_5000(self, tmp_path: Path) -> None:
        # Craft exactly 5000 tag entries; only one digest overlaps with the
        # scanned row so we can also confirm the found digest still resolves.
        digest = "sha256:" + "a" * 64
        tags = [{"name": f"tag-{i}", "digest": f"sha256:{i:064x}"}
                for i in range(4999)]
        tags.append({"name": "match", "digest": digest})
        assert len(tags) == 5000
        pages = [{"data": [_row("a" * 64, repo="repo-huge")], "skip_token": ""}]
        r = _run_defender(tmp_path, pages, repo_tags={"repo-huge": tags})
        assert r.returncode == 0, r.stderr

        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        warns = [
            line for line in log.splitlines()
            if "returned exactly 5000" in line and "repo-huge" in line
        ]
        assert len(warns) == 1, warns

        by_digest = self._read_csv_by_digest(tmp_path)
        assert by_digest[digest]["tag"] == "match"


class TestJqCleanBehavior:
    """PR-A moved per-row parsing from 18× (base64+jq) into one jq per page
    that emits US-separated fields. The jq `clean` helper strips characters
    that would corrupt the pipeline: CR/LF (would create phantom CSV rows)
    and 0x1F itself (would shift downstream columns because bash `read`
    splits on it). These tests lock that behavior.
    """

    def test_multi_line_remediation_collapsed_to_single_line(
        self, tmp_path: Path
    ) -> None:
        row = _row("f" * 64, "CVE-ML", "myrepo")
        row["remediation"] = "line one\nline two\r\nline three"
        pages = [{"data": [row], "skip_token": ""}]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr

        csv = (tmp_path / "vulnerable_images_report.csv").read_text(encoding="utf-8")
        lines = csv.splitlines()
        # Exactly one data line (no extra rows from embedded newlines).
        assert len(lines) == 2, f"embedded newlines broke row count: {lines!r}"
        # And the remediation values are joined with spaces (the `clean`
        # helper in the jq expression). Any of the substrings should appear
        # somewhere in the row, but NOT split across lines.
        data_row = lines[1]
        assert "line one" in data_row
        assert "line two" in data_row
        assert "line three" in data_row

    def test_us_char_inside_field_does_not_shift_downstream_columns(
        self, tmp_path: Path
    ) -> None:
        # A field containing the US (0x1F) delimiter itself must be
        # neutralised at the source (in jq's clean), otherwise bash `read`
        # would split on it and shift every subsequent column left by one.
        # We verify semantic column integrity: the CVE age we set (77) must
        # end up in the cveAgeDays column, and lastPushedToRegistryUTC must
        # hold the timestamp — not values shifted in from remediation.
        row = _row("d" * 64, "CVE-US", "myrepo")
        row["remediation"] = "before\x1fafter"
        row["cveAgeDays"] = 77
        row["lastPushedToRegistryUTC"] = "2026-01-15T10:00:00Z"
        pages = [{"data": [row], "skip_token": ""}]
        r = _run_defender(tmp_path, pages)
        assert r.returncode == 0, r.stderr

        csv = (tmp_path / "vulnerable_images_report.csv").read_text(encoding="utf-8")
        rows = list(csv_module.reader(io.StringIO(csv)))
        assert len(rows) == 2, rows
        header, data = rows
        by_name = dict(zip(header, data, strict=True))
        # Downstream columns landed where they belong.
        assert by_name["cveAgeDays"] == "77", by_name
        assert by_name["lastPushedToRegistryUTC"] == "2026-01-15T10:00:00Z", by_name
        # And the remediation value survives as a single field, with the
        # 0x1F collapsed to a space by clean().
        assert "before" in by_name["remediation"]
        assert "after" in by_name["remediation"]
        assert "\x1f" not in by_name["remediation"]
