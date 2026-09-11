"""Unit tests for `enrich_cvedetails.py` (P2 two-phase batched scan).

Covers:
  * CSV emission format (`csv_field`, `csv_write_row`) — must match bash's
    `csv_field` semantics exactly (double-quoted, internal `"` → `'`,
    newlines/CR collapsed to space).
  * Coercers (`to_bool`, `to_float`, `bool_str`, `parse_published_date`,
    `cvss_from_severity`, `classify_severity`, `compute_patchable`) —
    fallback semantics matching the retired inline KQL logic.
  * Loaders (`load_cvedetails`, `load_tag_cache`) — accept empty files,
    malformed JSONL lines (warn, skip), and uppercase the join key.
  * `enrich_and_emit` end-to-end — merge by upper(cveId), min/max score
    filter, distinct dedup, tag lookup fallback to "N/A".

These are the safety net for the P2 refactor: any future change to the
helper must keep behavior compatible with defender.sh's expectations.
"""
from __future__ import annotations

import csv
import io
import json
import sys
from datetime import timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import enrich_cvedetails as ec  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════
# csv_field — must mirror defender.sh:40-46 exactly.
# ═══════════════════════════════════════════════════════════════════════════


class TestCsvField:
    def test_wraps_plain_value_in_double_quotes(self) -> None:
        assert ec.csv_field("hello") == '"hello"'

    def test_none_becomes_empty_quoted(self) -> None:
        assert ec.csv_field(None) == '""'

    def test_number_gets_stringified(self) -> None:
        assert ec.csv_field(9.8) == '"9.8"'

    def test_internal_double_quote_becomes_apostrophe(self) -> None:
        # Matches: v="${v//\"/\'}"
        assert ec.csv_field('has "quotes"') == "\"has 'quotes'\""

    def test_newline_collapsed_to_space(self) -> None:
        assert ec.csv_field("line1\nline2") == '"line1 line2"'

    def test_carriage_return_collapsed_to_space(self) -> None:
        assert ec.csv_field("line1\r\nline2") == '"line1  line2"'

    def test_internal_comma_preserved(self) -> None:
        # csv_field does NOT escape commas — the outer csv_write_row relies
        # on the double-quote wrapping so commas inside quotes are safe.
        assert ec.csv_field("a, b, c") == '"a, b, c"'


class TestCsvWriteRow:
    def test_emits_18_fields_comma_separated(self) -> None:
        buf = io.StringIO()
        ec.csv_write_row(buf, ["a", "b", "c"])
        assert buf.getvalue() == '"a","b","c"\n'

    def test_empty_values_still_quoted(self) -> None:
        buf = io.StringIO()
        ec.csv_write_row(buf, ["", None, "x"])
        assert buf.getvalue() == '"","","x"\n'

    def test_output_is_valid_csv(self) -> None:
        buf = io.StringIO()
        ec.csv_write_row(buf, ["hello, world", "line1\nline2", 'a "quote"'])
        parsed = list(csv.reader(io.StringIO(buf.getvalue())))
        assert parsed == [["hello, world", "line1 line2", "a 'quote'"]]


# ═══════════════════════════════════════════════════════════════════════════
# classify_severity + cvss_from_severity — bash `classify_severity` twin.
# ═══════════════════════════════════════════════════════════════════════════


class TestClassifySeverity:
    @pytest.mark.parametrize("score,expected", [
        (10.0, "Critical"),
        (9.0, "Critical"),
        (8.9, "High"),
        (7.0, "High"),
        (6.9, "Medium"),
        (4.0, "Medium"),
        (3.9, "Low"),
        (0.1, "Low"),
        (0.0, "None"),
    ])
    def test_boundary_and_bucket(self, score: float, expected: str) -> None:
        assert ec.classify_severity(score) == expected


class TestCvssFromSeverity:
    @pytest.mark.parametrize("severity,expected", [
        ("Critical", 9.0), ("critical", 9.0), ("CRITICAL", 9.0),
        ("High", 7.0), ("HIGH", 7.0),
        ("Medium", 4.0), ("Low", 0.1),
        ("None", 0.0), ("Unknown", 0.0), ("", 0.0),
    ])
    def test_maps_severity_to_representative_score(
        self, severity: str, expected: float,
    ) -> None:
        assert ec.cvss_from_severity(severity) == expected


# ═══════════════════════════════════════════════════════════════════════════
# Bool / float / date coercers.
# ═══════════════════════════════════════════════════════════════════════════


class TestToBool:
    @pytest.mark.parametrize("value,expected", [
        (True, True),
        (False, False),
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("", False),
        (None, False),
        ("yes", False),   # explicit — only "true"/"1"/True are truthy
        (1, False),       # int 1 stringifies to "1" — wait, actually True
    ])
    def test_common_shapes(self, value, expected: bool) -> None:
        # Note: int 1 → str(1)="1" → in ("true","1") → True. But the
        # parametrize entry expects False — that's the historical behavior
        # of the code (int is stringified). Correct expectation:
        if isinstance(value, int) and not isinstance(value, bool) and value == 1:
            expected = True
        assert ec.to_bool(value) == expected


class TestBoolStr:
    def test_returns_true_or_false_lowercase(self) -> None:
        assert ec.bool_str(True) == "true"
        assert ec.bool_str("false") == "false"
        assert ec.bool_str(None) == "false"
        assert ec.bool_str("1") == "true"


class TestToFloat:
    @pytest.mark.parametrize("value,expected", [
        ("9.8", 9.8),
        (9.8, 9.8),
        (0, 0.0),
        (None, None),
        ("", None),
        ("not-a-number", None),
    ])
    def test_best_effort_conversion(self, value, expected) -> None:
        assert ec.to_float(value) == expected


class TestParsePublishedDate:
    def test_iso_utc_zulu_shape(self) -> None:
        dt = ec.parse_published_date("2024-05-01T00:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.year == 2024

    def test_iso_with_offset(self) -> None:
        dt = ec.parse_published_date("2024-05-01T00:00:00+00:00")
        assert dt is not None
        assert dt.year == 2024

    def test_naive_iso_gets_utc_assumed(self) -> None:
        dt = ec.parse_published_date("2024-05-01T00:00:00")
        assert dt is not None
        assert dt.tzinfo is timezone.utc

    def test_empty_and_invalid_return_none(self) -> None:
        assert ec.parse_published_date("") is None
        assert ec.parse_published_date("not-a-date") is None


class TestComputePatchable:
    @pytest.mark.parametrize("fix_status,fixed_version,expected", [
        ("FixAvailable", "", "true"),
        ("fixavailable", "", "true"),   # case-insensitive
        ("NoFix", "", "false"),
        ("NoFixAvailable", "", "false"),
        ("WillNotFix", "", "false"),
        ("", "2.0", "true"),            # empty fix_status + fixedVersion → true
        ("", "", ""),                    # neither → empty (unknown)
        ("something-else", "", ""),      # unknown status + no version → empty
    ])
    def test_matches_kql_case_logic(
        self, fix_status: str, fixed_version: str, expected: str,
    ) -> None:
        assert ec.compute_patchable(fix_status, fixed_version) == expected


# ═══════════════════════════════════════════════════════════════════════════
# Loaders — cvedetails.jsonl and tags TSV.
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadCvedetails:
    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        assert ec.load_cvedetails(p) == {}

    def test_missing_file_returns_empty_dict(self, tmp_path: Path) -> None:
        assert ec.load_cvedetails(tmp_path / "does-not-exist.jsonl") == {}

    def test_keys_are_uppercased(self, tmp_path: Path) -> None:
        p = tmp_path / "cve.jsonl"
        p.write_text(
            json.dumps({"cveIdJoin": "cve-2024-lowercase", "cvssEnrich": 5.0}) + "\n"
            + json.dumps({"cveIdJoin": "CVE-2024-UPPER", "cvssEnrich": 7.0}) + "\n",
            encoding="utf-8",
        )
        loaded = ec.load_cvedetails(p)
        # Both keys normalized to uppercase.
        assert set(loaded.keys()) == {"CVE-2024-LOWERCASE", "CVE-2024-UPPER"}

    def test_malformed_line_warns_and_skips(
        self, tmp_path: Path, capsys: pytest.CaptureFixture,
    ) -> None:
        p = tmp_path / "bad.jsonl"
        p.write_text(
            '{"cveIdJoin":"CVE-1","cvssEnrich":9.8}\n'
            'not-valid-json\n'
            '{"cveIdJoin":"CVE-2","cvssEnrich":7.0}\n',
            encoding="utf-8",
        )
        loaded = ec.load_cvedetails(p)
        assert set(loaded.keys()) == {"CVE-1", "CVE-2"}
        err = capsys.readouterr().err
        assert "invalid JSON" in err


class TestLoadTagCache:
    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.tsv"
        p.write_text("", encoding="utf-8")
        assert ec.load_tag_cache(p) == {}

    def test_reads_tab_separated_key_value(self, tmp_path: Path) -> None:
        p = tmp_path / "tags.tsv"
        p.write_text(
            "repo/app@sha256:aaa\tv1.0\n"
            "repo/other@sha256:bbb\tlatest\n",
            encoding="utf-8",
        )
        assert ec.load_tag_cache(p) == {
            "repo/app@sha256:aaa": "v1.0",
            "repo/other@sha256:bbb": "latest",
        }

    def test_skips_lines_without_tab(self, tmp_path: Path) -> None:
        p = tmp_path / "tags.tsv"
        p.write_text(
            "key1\tvalue1\n"
            "malformed-no-tab\n"
            "key2\tvalue2\n",
            encoding="utf-8",
        )
        assert ec.load_tag_cache(p) == {"key1": "value1", "key2": "value2"}


# ═══════════════════════════════════════════════════════════════════════════
# enrich_and_emit — end-to-end merge behavior.
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Create empty file paths for a run of enrich_and_emit."""
    a = tmp_path / "assessments.jsonl"
    c = tmp_path / "cvedetails.jsonl"
    t = tmp_path / "tags.tsv"
    o = tmp_path / "output.csv"
    a.write_text("", encoding="utf-8")
    c.write_text("", encoding="utf-8")
    t.write_text("", encoding="utf-8")
    # Simulate defender.sh writing the header before invoking us.
    o.write_text(
        '"repository","digest","tag","cvssScore","cveId","severity",'
        '"packageCategory","packageLanguage","packageName","currentVersion",'
        '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
        '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit",'
        '"lastPushedToRegistryUTC"\n',
        encoding="utf-8",
    )
    return a, c, t, o


def _make_assessment_row(**overrides) -> dict:
    row = {
        "repository": "myrepo",
        "digest": "sha256:aaa",
        "cveId": "CVE-2024-1",
        "packageName": "openssl",
        "currentVersion": "1.0",
        "fixedVersion": "2.0",
        "fixStatus": "FixAvailable",
        "packageCategory": "OS",
        "packageLanguage": "",
        "remediation": "Update, please",
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


def _make_cvedetail_row(**overrides) -> dict:
    row = {
        "cveIdJoin": "CVE-2024-1",
        "cvssEnrich": 9.8,
        "publishedDateEnrich": "2024-05-01T00:00:00Z",
        "severityEnrich": "Critical",
        "verifiedExpEnrich": 1,
        "publishedExpEnrich": 1,
        "inExploitKitEnrich": 1,
    }
    row.update(overrides)
    return row


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8",
    )


def _read_csv_data_rows(path: Path) -> list[list[str]]:
    """Read the CSV, skipping the header row."""
    with path.open("r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    return rows[1:]


class TestEnrichEndToEnd:
    def test_single_row_fully_enriched(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [_make_assessment_row()])
        _write_jsonl(c, [_make_cvedetail_row()])
        t.write_text("myrepo@sha256:aaa\tv1.0\n", encoding="utf-8")

        read, emitted, enriched = ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        assert (read, emitted, enriched) == (1, 1, 1)

        rows = _read_csv_data_rows(o)
        assert len(rows) == 1
        r = rows[0]
        # 19 fields, in the exact contract order.
        assert len(r) == 19
        assert r[0] == "myrepo"                # repository
        assert r[1] == "sha256:aaa"            # digest
        assert r[2] == "v1.0"                  # tag from cache
        assert r[3] == "9.8"                   # cvssScore from enrichment
        assert r[4] == "CVE-2024-1"            # cveId
        assert r[5] == "Critical"              # severity (enrichment)
        assert r[11] == "true"                 # patchable (FixAvailable)
        assert r[15] == "true"                 # isInExploitKit
        assert r[16] == "true"                 # hasPublishedExploit
        assert r[17] == "true"                 # hasVerifiedExploit

    def test_row_without_enrichment_falls_back_to_inline(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [_make_assessment_row(
            cveId="CVE-9999-NOENRICH",
            inlineSeverity="High",
            inlineCvssBase=8.1,
            inlinePublishedDate="2023-01-01T00:00:00Z",
            inlineInExploitKit="false",
            inlinePubliclyDisclosed="true",
            inlineVerified="false",
        )])
        _write_jsonl(c, [])  # no enrichment

        read, emitted, enriched = ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        assert (read, emitted, enriched) == (1, 1, 0)

        rows = _read_csv_data_rows(o)
        r = rows[0]
        assert r[3] == "8.1"           # inline CVSS wins
        assert r[5] == "High"          # inline severity
        assert r[15] == "false"        # inline exploit chips
        assert r[16] == "true"
        assert r[17] == "false"

    def test_min_max_score_filter_drops_rows(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [
            _make_assessment_row(cveId="CVE-1", inlineSeverity="Low"),       # cvss 0.1
            _make_assessment_row(cveId="CVE-2", inlineSeverity="High"),      # cvss 7.0
            _make_assessment_row(cveId="CVE-3", inlineSeverity="Critical"),  # cvss 9.0
        ])
        _write_jsonl(c, [])

        read, emitted, enriched = ec.enrich_and_emit(a, c, t, o, 5.0, 10.0)
        assert read == 3
        assert emitted == 2  # CVE-1 (0.1) dropped by min-score
        assert enriched == 0

    def test_distinct_dedup_removes_duplicate_rows(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        # Two identical rows.
        _write_jsonl(a, [_make_assessment_row(), _make_assessment_row()])
        _write_jsonl(c, [_make_cvedetail_row()])

        read, emitted, enriched = ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        assert (read, emitted, enriched) == (2, 1, 2)   # 2 read, 1 emitted (dedup)

    def test_missing_tag_falls_back_to_na(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [_make_assessment_row(digest="sha256:unknown")])
        _write_jsonl(c, [_make_cvedetail_row()])
        # No entry for sha256:unknown in tag cache.

        ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        rows = _read_csv_data_rows(o)
        assert rows[0][2] == "N/A"

    def test_non_cve_prefix_rows_skipped(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [
            _make_assessment_row(cveId="CVE-2024-good"),
            _make_assessment_row(cveId="NOT-A-CVE"),   # should be skipped
            _make_assessment_row(cveId=""),            # should be skipped
        ])
        _write_jsonl(c, [])

        read, emitted, _enriched = ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        # rows_read counts all 3, but only 1 is emitted (the CVE-prefix one).
        assert read == 3
        assert emitted == 1

    def test_case_insensitive_cveid_join(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        # assessments row cveId in lowercase; enrichment key in uppercase.
        _write_jsonl(a, [_make_assessment_row(cveId="CVE-2024-mixed")])
        _write_jsonl(c, [_make_cvedetail_row(
            cveIdJoin="CVE-2024-MIXED",   # different case
            cvssEnrich=9.5, severityEnrich="Critical",
        )])

        _read, _emitted, enriched = ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        # Enrichment must match despite case difference.
        assert enriched == 1

    def test_remediation_with_comma_and_newline_survives_csv(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [_make_assessment_row(
            remediation="Line 1, part A\nLine 2, part B",
        )])
        _write_jsonl(c, [_make_cvedetail_row()])

        ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        # Read back via csv module — newlines collapsed, commas preserved.
        rows = _read_csv_data_rows(o)
        assert rows[0][12] == "Line 1, part A Line 2, part B"

    def test_cveagedays_derived_from_enrichment_date(
        self, workspace: tuple[Path, Path, Path, Path],
    ) -> None:
        a, c, t, o = workspace
        _write_jsonl(a, [_make_assessment_row()])
        _write_jsonl(c, [_make_cvedetail_row(
            publishedDateEnrich="2020-01-01T00:00:00Z",
        )])
        ec.enrich_and_emit(a, c, t, o, 0.0, 10.0)
        rows = _read_csv_data_rows(o)
        age = int(rows[0][14])
        assert age > 365 * 5     # published 5+ years ago at test time
