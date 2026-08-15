"""
Unit tests for expandcsv.py — the CVE expansion stage.

Complements the E2E test with focused coverage of the trickier branches:
  - `_lookup` 3-level fallback (multi-arch and prefix cases)
  - `split_cves` edge cases (whitespace, dupes, empty)
  - `get_field` legacy/new schema fallback
  - `load_vulnerability_data` error paths
  - `expand_cves` sev_map fallback + dedup
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

import expandcsv
from tests._data import CRUZAMENTO_HEADER, DEFENDER_HEADER
from tests._data import write_csv as _write_csv

# ---------------------------------------------------------------------------
# get_field
# ---------------------------------------------------------------------------

class TestGetField:
    def test_returns_first_non_empty(self) -> None:
        row = {"NAMESPACE": "", "namespace": "prd-fad"}
        assert expandcsv.get_field(row, "NAMESPACE", "namespace") == "prd-fad"

    def test_prefers_first_name(self) -> None:
        row = {"NAMESPACE": "up", "namespace": "low"}
        assert expandcsv.get_field(row, "NAMESPACE", "namespace") == "up"

    def test_default_when_all_missing(self) -> None:
        assert expandcsv.get_field({}, "a", "b", default="fallback") == "fallback"

    def test_treats_none_as_missing(self) -> None:
        row = {"a": None, "b": "value"}
        assert expandcsv.get_field(row, "a", "b") == "value"


# ---------------------------------------------------------------------------
# split_cves
# ---------------------------------------------------------------------------

class TestSplitCves:
    def test_empty_input(self) -> None:
        assert expandcsv.split_cves("") == []
        assert expandcsv.split_cves(None) == []  # type: ignore[arg-type]

    def test_dedup_preserves_order(self) -> None:
        assert expandcsv.split_cves("CVE-A, CVE-B, CVE-A, CVE-C") == [
            "CVE-A", "CVE-B", "CVE-C"
        ]

    def test_strips_whitespace(self) -> None:
        assert expandcsv.split_cves("  CVE-A ,\tCVE-B\n") == ["CVE-A", "CVE-B"]

    def test_ignores_empty_entries(self) -> None:
        assert expandcsv.split_cves("CVE-A,,CVE-B,,") == ["CVE-A", "CVE-B"]


# ---------------------------------------------------------------------------
# _lookup — 3-level fallback
# ---------------------------------------------------------------------------

class TestLookup:
    def _idx(self, entries):
        """Build the 3 indexes for a small in-memory dataset."""
        idx_full, idx_digest, idx_prefix = {}, {}, {}
        for repo, digest, cve, detail in entries:
            idx_full[(repo, digest, cve)] = detail
            idx_digest.setdefault((repo, cve), detail)
            prefix = digest.replace("sha256:", "")[:16]
            idx_prefix.setdefault((repo, prefix, cve), detail)
        return idx_full, idx_digest, idx_prefix

    def test_level_1_exact_match(self) -> None:
        want = {"CVSS_SCORE": "9.8"}
        idxs = self._idx([("repo", "sha256:aaa", "CVE-1", want)])
        got = expandcsv._lookup(*idxs, "repo", "sha256:aaa", "CVE-1")
        assert got == want

    def test_level_2_multiarch_falls_back_to_repo_plus_cve(self) -> None:
        """cruzamento carries manifest-list digest, Defender has child digest."""
        child_digest = "sha256:child1111111111111111111111111111111111111111111111111111111111"
        parent_digest = "sha256:parent222222222222222222222222222222222222222222222222222222222"
        want = {"CVSS_SCORE": "9.8"}
        idxs = self._idx([("repo", child_digest, "CVE-1", want)])
        got = expandcsv._lookup(*idxs, "repo", parent_digest, "CVE-1")
        assert got == want, "should have fallen back to (repo, cve) index"

    def test_level_3_prefix_fallback(self) -> None:
        """Digest slightly truncated in one source vs the other."""
        full_digest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        # Different suffix, same first 16 chars post-prefix
        variant = "sha256:abcdef1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        want = {"CVSS_SCORE": "9.0"}
        idxs = self._idx([("repo", full_digest, "CVE-1", want)])
        # Wipe the (repo, cve) fallback so we force the prefix path
        idxs[1].clear()
        got = expandcsv._lookup(*idxs, "repo", variant, "CVE-1")
        assert got == want

    def test_all_levels_miss_returns_empty(self) -> None:
        idxs = self._idx([("repo", "sha256:aaa", "CVE-1", {"x": "y"})])
        assert expandcsv._lookup(*idxs, "other-repo", "sha256:zzz", "CVE-9") == {}


# ---------------------------------------------------------------------------
# load_vulnerability_data
# ---------------------------------------------------------------------------

class TestLoadVulnerabilityData:
    def test_normal_populates_all_indexes(self, defender_csv_normal: Path) -> None:
        idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
            str(defender_csv_normal)
        )
        assert len(idx_full) == 3
        # Every (repo, cve) also appears in the digest fallback
        for (repo, _digest, cve) in idx_full:
            assert (repo, cve) in idx_digest

    def test_missing_column_raises_with_helpful_message(
        self, defender_csv_missing_columns: Path
    ) -> None:
        with pytest.raises(ValueError, match="missing required defender.sh columns"):
            expandcsv.load_vulnerability_data(str(defender_csv_missing_columns))

    def test_empty_file_ok(self, defender_csv_empty: Path) -> None:
        idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
            str(defender_csv_empty)
        )
        assert idx_full == {} and idx_digest == {} and idx_prefix == {}

    def test_rows_without_required_fields_are_skipped(self, tmp_path: Path) -> None:
        """Empty repository/digest/cveId rows must be silently dropped, not raise."""
        rows = [
            ["good/repo", "sha256:aaa", "v1", "9.0", "CVE-1", "Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],
            ["", "sha256:bbb", "v1", "9.0", "CVE-2", "Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],  # empty repo
            ["good/repo", "", "v1", "9.0", "CVE-3", "Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],  # empty digest
        ]
        path = _write_csv(tmp_path / "partial.csv", DEFENDER_HEADER, rows)
        idx_full, _, _ = expandcsv.load_vulnerability_data(str(path))
        assert len(idx_full) == 1
        assert ("good/repo", "sha256:aaa", "CVE-1") in idx_full


# ---------------------------------------------------------------------------
# expand_cves
# ---------------------------------------------------------------------------

class TestExpandCves:
    def test_new_schema_uppercase(
        self, defender_csv_normal: Path, cruzamento_csv_new: Path
    ) -> None:
        idxs = expandcsv.load_vulnerability_data(str(defender_csv_normal))
        rows = expandcsv.expand_cves(str(cruzamento_csv_new), *idxs)
        assert len(rows) == 3

    def test_legacy_lowercase_schema(
        self, defender_csv_normal: Path, cruzamento_csv_legacy: Path
    ) -> None:
        """The legacy CSV uses lowercase headers — must still parse."""
        idxs = expandcsv.load_vulnerability_data(str(defender_csv_normal))
        rows = expandcsv.expand_cves(str(cruzamento_csv_legacy), *idxs)
        assert len(rows) == 1
        assert rows[0]["CVE_ID"] == "CVE-2024-0001"
        assert rows[0]["NAMESPACE"] == "prd-fad"

    def test_dedup_same_cve_in_same_workload(
        self, defender_csv_normal: Path, tmp_path: Path
    ) -> None:
        """If CVE_LIST accidentally contains dupes, we emit only one row."""
        rows = [[
            "prd", "Deployment", "app", "myapp/backend",
            "sha256:aaa111", "v1.2",
            "1", "Critical", "9.8",
            "CVE-2024-0001, CVE-2024-0001",   # duplicate
            "CVE-2024-0001:Critical",
            "", "", "", "", "", "", "", "", "", "", "", "", "",
        ]]
        cruz = _write_csv(tmp_path / "cruz.csv", CRUZAMENTO_HEADER, rows)
        idxs = expandcsv.load_vulnerability_data(str(defender_csv_normal))
        out = expandcsv.expand_cves(str(cruz), *idxs)
        assert len(out) == 1

    def test_severity_fallback_from_sev_map(self, tmp_path: Path) -> None:
        """If defender lookup misses severity, sev_map from cruzamento fills it."""
        # Defender CSV without matching digest → lookup returns {}
        empty_def = _write_csv(tmp_path / "def.csv", DEFENDER_HEADER, [])
        # Cruzamento carries the severity in CVE_SEVERITY_MAP
        cruz_rows = [[
            "ns", "Deployment", "app", "unknown/repo", "sha256:zzz", "v1",
            "1", "Critical", "9.8",
            "CVE-X",
            "CVE-X:High",   # sev_map fallback
            "", "", "", "", "", "", "", "", "", "", "", "", "",
        ]]
        cruz = _write_csv(tmp_path / "cruz.csv", CRUZAMENTO_HEADER, cruz_rows)
        idxs = expandcsv.load_vulnerability_data(str(empty_def))
        out = expandcsv.expand_cves(str(cruz), *idxs)
        assert len(out) == 1
        assert out[0]["SEVERITY"] == "High", "should fall back to sev_map value"

    def test_rows_without_repo_or_digest_are_skipped(
        self, defender_csv_normal: Path, tmp_path: Path
    ) -> None:
        rows = [
            ["ns", "Deployment", "app", "", "sha256:aaa", "v1",
             "1", "Critical", "9.8", "CVE-A", "CVE-A:Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],
            ["ns", "Deployment", "app", "myapp/backend", "", "v1",
             "1", "Critical", "9.8", "CVE-A", "CVE-A:Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],
        ]
        cruz = _write_csv(tmp_path / "cruz.csv", CRUZAMENTO_HEADER, rows)
        idxs = expandcsv.load_vulnerability_data(str(defender_csv_normal))
        assert expandcsv.expand_cves(str(cruz), *idxs) == []


# ---------------------------------------------------------------------------
# write_output — column contract
# ---------------------------------------------------------------------------

class TestWriteOutput:
    def test_header_order_matches_output_fields(self, tmp_path: Path) -> None:
        rows = [{f: f"val_{i}" for i, f in enumerate(expandcsv.OUTPUT_FIELDS)}]
        out = tmp_path / "expanded.csv"
        expandcsv.write_output(rows, str(out))
        with out.open(encoding="utf-8", newline="") as f:
            header = next(csv.reader(f))
        assert header == expandcsv.OUTPUT_FIELDS

    def test_all_fields_quoted(self, tmp_path: Path) -> None:
        rows = [{f: "" for f in expandcsv.OUTPUT_FIELDS}]
        rows[0]["CVE_ID"] = "CVE-1"
        out = tmp_path / "expanded.csv"
        expandcsv.write_output(rows, str(out))
        content = out.read_text(encoding="utf-8")
        # QUOTE_ALL: every column value wrapped in double quotes
        assert '"CVE-1"' in content
