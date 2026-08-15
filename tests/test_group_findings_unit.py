"""
Unit tests for group_findings.py — the stage that turns the flat CSV from
check_ocp.sh into the grouped CSV consumed downstream.

Behaviors covered:
  - one output row per unique (ns, kind, name, repo, digest)
  - CVE list, severity list, cve_severity_map deterministic (sorted)
  - max CVSS across all matching rows
  - tag preferred over "N/A"
  - carried fields: last non-empty wins
  - remediation: shortest non-empty wins
  - malformed cvssScore does not crash
  - end-to-end file round-trip via group_file()
"""
from __future__ import annotations

import csv
from pathlib import Path

import group_findings


def _row(**kwargs) -> dict[str, str]:
    """Build a flat-row dict with all expected keys populated (defaults empty)."""
    base = {
        "NAMESPACE": "ns", "PARENT_TYPE": "Deployment", "PARENT_NAME": "app",
        "repository": "myapp", "digest": "sha256:aaa", "tag": "v1",
        "cvssScore": "9.0", "cveId": "CVE-A", "severity": "Critical",
        "packageCategory": "", "packageLanguage": "", "packageName": "",
        "currentVersion": "", "fixedVersion": "", "patchable": "",
        "remediation": "", "fixStatus": "", "cveAgeDays": "",
        "isInExploitKit": "false", "hasPublishedExploit": "false",
        "hasVerifiedExploit": "false", "lastPushedToRegistryUTC": "",
    }
    base.update({k: str(v) for k, v in kwargs.items()})
    return base


class TestGroupRows:
    def test_single_row_produces_one_group(self) -> None:
        out = group_findings.group_rows([_row()])
        assert len(out) == 1
        # Column count matches header
        assert len(out[0]) == len(group_findings.OUTPUT_HEADER)

    def test_two_cves_same_workload_collapse(self) -> None:
        out = group_findings.group_rows([
            _row(cveId="CVE-1", severity="Critical", cvssScore="9.8"),
            _row(cveId="CVE-2", severity="High",     cvssScore="7.5"),
        ])
        assert len(out) == 1
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["CVE_COUNT"] == 2
        assert row["CVE_LIST"] == "CVE-1, CVE-2"
        assert row["CVSS_SCORE"] == 9.8  # max
        # sev_list is sorted (deterministic output)
        assert row["CRITICALITY"] == "Critical, High"
        assert row["CVE_SEVERITY_MAP"] == "CVE-1:Critical;CVE-2:High"

    def test_different_digests_are_separate_groups(self) -> None:
        out = group_findings.group_rows([
            _row(digest="sha256:aaa"),
            _row(digest="sha256:bbb"),
        ])
        assert len(out) == 2

    def test_tag_na_replaced_when_real_tag_arrives(self) -> None:
        out = group_findings.group_rows([
            _row(tag="N/A", cveId="CVE-1"),
            _row(tag="v2.0", cveId="CVE-2"),
        ])
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["TAG"] == "v2.0"

    def test_tag_stays_na_if_all_rows_are_na(self) -> None:
        out = group_findings.group_rows([_row(tag="N/A"), _row(tag="")])
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["TAG"] == "N/A"

    def test_carried_field_last_non_empty_wins(self) -> None:
        out = group_findings.group_rows([
            _row(cveId="CVE-1", packageName="", fixedVersion=""),
            _row(cveId="CVE-2", packageName="django", fixedVersion="4.2.11"),
            _row(cveId="CVE-3", packageName="", fixedVersion="4.2.12"),  # overwrites
        ])
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["PACKAGE_NAME"] == "django"
        assert row["FIXED_VERSION"] == "4.2.12"

    def test_remediation_shortest_non_empty_wins(self) -> None:
        out = group_findings.group_rows([
            _row(cveId="CVE-1", remediation="Upgrade to the latest patched version A B C D"),
            _row(cveId="CVE-2", remediation="Upgrade django"),  # shorter
            _row(cveId="CVE-3", remediation=""),
        ])
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["REMEDIATION"] == "Upgrade django"

    def test_malformed_cvss_does_not_crash(self) -> None:
        """cvssScore like 'N/A' or empty must not raise; group still produced."""
        out = group_findings.group_rows([
            _row(cveId="CVE-1", cvssScore="oops"),
            _row(cveId="CVE-2", cvssScore=""),
            _row(cveId="CVE-3", cvssScore="9.1"),
        ])
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["CVSS_SCORE"] == 9.1
        assert row["CVE_COUNT"] == 3

    def test_exploit_flags_carried_over_when_true(self) -> None:
        out = group_findings.group_rows([
            _row(cveId="CVE-1"),  # all false
            _row(cveId="CVE-2", hasVerifiedExploit="true"),
        ])
        row = dict(zip(group_findings.OUTPUT_HEADER, out[0], strict=True))
        assert row["HAS_VERIFIED_EXPLOIT"] == "true"

    def test_empty_input_yields_empty_output(self) -> None:
        assert group_findings.group_rows([]) == []


class TestGroupFile:
    def test_round_trip_matches_direct_call(self, tmp_path: Path) -> None:
        # Write a flat CSV, run group_file, re-read and confirm shape.
        flat = tmp_path / "flat.csv"
        with flat.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(_row().keys()))
            w.writeheader()
            w.writerow(_row(cveId="CVE-1", cvssScore="9.8"))
            w.writerow(_row(cveId="CVE-2", cvssScore="9.9"))
            w.writerow(_row(digest="sha256:bbb", cveId="CVE-3", cvssScore="7.0"))

        grouped = tmp_path / "grouped.csv"
        n = group_findings.group_file(flat, grouped)
        assert n == 2  # 2 unique (workload, image) tuples

        with grouped.open(encoding="utf-8", newline="") as f:
            header = next(csv.reader(f))
            rows = list(csv.DictReader(f, fieldnames=header))
        assert header == group_findings.OUTPUT_HEADER
        assert len(rows) == 2
        # First group has 2 CVEs, second has 1
        by_digest = {r["DIGEST"]: r for r in rows}
        assert by_digest["sha256:aaa"]["CVE_COUNT"] == "2"
        assert by_digest["sha256:bbb"]["CVE_COUNT"] == "1"


class TestMainCli:
    def test_missing_input_returns_1(self, tmp_path: Path, capsys) -> None:
        import sys as _sys
        argv = _sys.argv
        _sys.argv = ["group_findings.py", str(tmp_path / "nope.csv"), str(tmp_path / "out.csv")]
        try:
            rc = group_findings.main()
        finally:
            _sys.argv = argv
        assert rc == 1
        err = capsys.readouterr().err
        assert "não encontrado" in err
