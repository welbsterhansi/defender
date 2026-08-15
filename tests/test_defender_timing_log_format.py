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


def _make_fake_az_returning(bin_dir: Path, graph_pages: list[dict]) -> Path:
    """
    Fake `az` that returns `graph_pages[i]` on the (i+1)-th `graph query`
    invocation, then empty {"data":[]} on subsequent calls. Logs every
    invocation to `<bin_dir>/../az_calls.log` for count assertions.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    payloads_dir = bin_dir.parent / "payloads"
    payloads_dir.mkdir(exist_ok=True)
    for i, page in enumerate(graph_pages, start=1):
        (payloads_dir / f"page{i}.json").write_text(json.dumps(page), encoding="utf-8")

    body = f"""#!/usr/bin/env bash
echo "$*" >> "{bin_dir.parent}/az_calls.log"
if [ "$1 $2" = "acr show" ]; then exit 0; fi
if [ "$1 $2 $3" = "acr repository list" ]; then exit 0; fi
if [ "$1 $2 $3" = "acr repository show-tags" ]; then echo "v1.0"; exit 0; fi
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


def _run_defender(tmp_path: Path, graph_pages: list[dict]) -> subprocess.CompletedProcess:
    fake_root = _make_fake_az_returning(tmp_path / "bin", graph_pages)
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


class TestTagApiCallsCounter:
    """Baseline behavior: 1 call per unique (repo, digest) tuple in the page.
    PR-B will change this to 1 call per repo — the test will be updated then."""

    def test_counter_matches_unique_digests(self, tmp_path: Path) -> None:
        # 3 rows, 3 distinct digests → 3 show-tags calls expected.
        pages = [{"data": [
            _row("a" * 64), _row("b" * 64), _row("c" * 64),
        ], "skip_token": ""}]
        _run_defender(tmp_path, pages)
        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        m = _first_timing_match(log)
        assert m is not None
        assert m["tag_calls"] == "3"

    def test_counter_matches_az_calls(self, tmp_path: Path) -> None:
        """The counter defender.sh reports must match the number of
        `show-tags` invocations the fake az actually observed."""
        pages = [{"data": [_row("a" * 64), _row("b" * 64)], "skip_token": ""}]
        _run_defender(tmp_path, pages)

        az_calls = (tmp_path / "az_calls.log").read_text(encoding="utf-8")
        actual_show_tags = sum(
            1 for line in az_calls.splitlines() if "acr repository show-tags" in line
        )
        log = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        m = _first_timing_match(log)
        assert m is not None
        assert int(m["tag_calls"]) == actual_show_tags


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
