"""Smoke test: pytest runs, fixtures load, source modules import."""
from __future__ import annotations

import csv
from pathlib import Path


def test_fixtures_defender_normal(defender_csv_normal: Path) -> None:
    with defender_csv_normal.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 3
    assert rows[0]["cveId"] == "CVE-2024-0001"
    assert rows[1]["cvssScore"] == "10.0"


def test_fixtures_defender_multiarch(defender_csv_multiarch: Path) -> None:
    with defender_csv_multiarch.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len({r["digest"] for r in rows}) == 2
    assert len({r["cveId"] for r in rows}) == 1


def test_fixtures_cruzamento_new(cruzamento_csv_new: Path) -> None:
    with cruzamento_csv_new.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["NAMESPACE"] == "ns-app"
    assert "CVE-2024-0001" in rows[0]["CVE_LIST"]


def test_fixtures_cruzamento_legacy_headers(cruzamento_csv_legacy: Path) -> None:
    with cruzamento_csv_legacy.open(encoding="utf-8") as f:
        header = next(csv.reader(f))
    assert "namespace" in header
    assert "NAMESPACE" not in header


def test_source_modules_import() -> None:
    """expandcsv and report modules must import and expose their public entrypoints."""
    import expandcsv
    import report

    assert callable(expandcsv.main)
    assert callable(expandcsv.load_vulnerability_data)
    assert callable(report.load_data)
    assert callable(report.build_html)
