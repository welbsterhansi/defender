"""
Unit tests for report.py — the HTML render stage.

Complements the E2E test with focused coverage of the pure helpers and
edge cases in the aggregation logic:
  - `_is_weaponized`   — flag OR semantics + case handling
  - `_exploit_icon`    — precedence verified > published > kit > none
  - `_version_cell`    — escapes HTML in package/version to prevent injection
  - `_cve_row`         — data-* attributes populated for the filter JS
  - `build_image_view` — dedup, sort, weaponized_count with N workloads
  - `sev_class`        — CVSS score → badge class boundaries
"""
from __future__ import annotations

from pathlib import Path

import pytest

import report
from tests._data import CRUZAMENTO_HEADER, write_csv

# ---------------------------------------------------------------------------
# _is_weaponized
# ---------------------------------------------------------------------------

class TestIsWeaponized:
    @pytest.mark.parametrize("flags", [
        {"hasVerifiedExploit": "true"},
        {"hasPublishedExploit": "true"},
        {"isInExploitKit": "true"},
        {"hasVerifiedExploit": "True"},   # mixed case
        {"hasPublishedExploit": "TRUE"},
    ])
    def test_true_when_any_flag_set(self, flags: dict) -> None:
        assert report._is_weaponized(flags) is True

    def test_false_when_all_flags_absent_or_false(self) -> None:
        assert report._is_weaponized({}) is False
        assert report._is_weaponized({
            "hasVerifiedExploit": "false",
            "hasPublishedExploit": "false",
            "isInExploitKit": "false",
        }) is False

    def test_ignores_unrelated_keys(self) -> None:
        assert report._is_weaponized({"randomField": "true"}) is False


# ---------------------------------------------------------------------------
# _exploit_icon — precedence
# ---------------------------------------------------------------------------

class TestExploitIcon:
    def test_verified_beats_published(self) -> None:
        assert report._exploit_icon({
            "hasVerifiedExploit": "true",
            "hasPublishedExploit": "true",
            "isInExploitKit": "true",
        }) == "🔴"

    def test_published_beats_kit(self) -> None:
        assert report._exploit_icon({
            "hasPublishedExploit": "true",
            "isInExploitKit": "true",
        }) == "🟠"

    def test_kit_only(self) -> None:
        assert report._exploit_icon({"isInExploitKit": "true"}) == "🟡"

    def test_none_returns_dash(self) -> None:
        assert report._exploit_icon({}) == "—"


# ---------------------------------------------------------------------------
# _version_cell — HTML escaping
# ---------------------------------------------------------------------------

class TestVersionCell:
    def test_normal_values_render(self) -> None:
        cell = report._version_cell({
            "packageName": "django",
            "currentVersion": "4.1.0",
            "fixedVersion": "4.2.11",
        })
        assert "4.1.0 → 4.2.11" in cell
        assert 'data-copy="django 4.1.0 → 4.2.11"' in cell

    def test_missing_versions_show_dash(self) -> None:
        cell = report._version_cell({"packageName": "pkg"})
        assert "— → —" in cell
        # Payload still has the package name so devs know what to look up
        assert 'data-copy="pkg — → —"' in cell

    def test_html_special_chars_escaped_in_attribute(self) -> None:
        """Package with `<` or `"` must not break the data-copy attribute."""
        cell = report._version_cell({
            "packageName": '<script>&"',
            "currentVersion": "1",
            "fixedVersion": "2",
        })
        # Payload attribute uses entity-encoded quotes
        assert '<script>' not in cell.split('data-copy="')[1].split('"')[0]
        assert "&lt;script&gt;" in cell


# ---------------------------------------------------------------------------
# _cve_row — data-* attributes for the JS filter
# ---------------------------------------------------------------------------

class TestCveRow:
    def _row(self, **kwargs) -> str:
        base = {
            "id": "CVE-1", "severity": "High", "score": 8.5,
            "packageName": "pkg", "currentVersion": "1.0", "fixedVersion": "2.0",
            "patchable": "true",
        }
        base.update(kwargs)
        return report._cve_row(base)

    def test_data_sev_matches_severity(self) -> None:
        assert 'data-sev="High"' in self._row(severity="High")
        assert 'data-sev="Critical"' in self._row(severity="Critical")

    def test_data_patch_lowercased(self) -> None:
        assert 'data-patch="true"' in self._row(patchable="TRUE")
        assert 'data-patch="false"' in self._row(patchable="False")

    def test_data_expl_1_when_weaponized(self) -> None:
        assert 'data-expl="1"' in self._row(hasVerifiedExploit="true")

    def test_data_expl_0_when_no_exploit(self) -> None:
        assert 'data-expl="0"' in self._row()

    def test_patch_icon_matches_state(self) -> None:
        assert "✅" in self._row(patchable="true")
        assert "❌" in self._row(patchable="false")
        assert "—" in self._row(patchable="")


# ---------------------------------------------------------------------------
# sev_class — score boundaries
# ---------------------------------------------------------------------------

class TestSevClass:
    @pytest.mark.parametrize("score,expected", [
        (10.0, "s-max"),
        (9.9,  "s-crit"),
        (9.5,  "s-crit"),
        (9.4,  "s-high"),
        (9.0,  "s-high"),
        (8.9,  "s-med"),
        (4.0,  "s-med"),
        (0.0,  "s-med"),
    ])
    def test_boundaries(self, score: float, expected: str) -> None:
        assert report.sev_class(score) == expected


# ---------------------------------------------------------------------------
# build_image_view — the main aggregation
# ---------------------------------------------------------------------------

class TestBuildImageView:
    def _ns(self, workloads):
        """Build a `namespaces` dict compatible with build_image_view."""
        out: dict = {}
        for ns, wtype, wname, repo, digest, tag, cves in workloads:
            out.setdefault(ns, {})[(wtype, wname)] = {
                "type": wtype, "name": wname,
                "repo": repo, "digest": digest, "tag": tag,
                "cve_count": len(cves), "max_score": max(c["score"] for c in cves) if cves else 0.0,
                "cves": cves,
            }
        return out

    def test_same_image_two_workloads_dedups_cves(self) -> None:
        cves = [{"id": "CVE-1", "score": 9.8, "severity": "Critical"}]
        ns = self._ns([
            ("prd-a", "Deployment", "app", "repo", "sha256:aaa", "v1", cves),
            ("prd-b", "Deployment", "app", "repo", "sha256:aaa", "v1", cves),
        ])
        images = report.build_image_view(ns)
        assert len(images) == 1
        assert len(images[0]["cves"]) == 1
        assert len(images[0]["workloads"]) == 2

    def test_different_digests_are_separate_images(self) -> None:
        cves_a = [{"id": "CVE-1", "score": 9.0, "severity": "High"}]
        cves_b = [{"id": "CVE-2", "score": 7.0, "severity": "High"}]
        ns = self._ns([
            ("ns", "Deployment", "a", "repo", "sha256:aaa", "v1", cves_a),
            ("ns", "Deployment", "b", "repo", "sha256:bbb", "v2", cves_b),
        ])
        assert len(report.build_image_view(ns)) == 2

    def test_sorted_by_max_score_desc(self) -> None:
        ns = self._ns([
            ("ns", "Deployment", "low", "r", "sha256:1", "v1",
             [{"id": "CVE-1", "score": 5.0, "severity": "Medium"}]),
            ("ns", "Deployment", "hi",  "r", "sha256:2", "v2",
             [{"id": "CVE-2", "score": 9.9, "severity": "Critical"}]),
        ])
        imgs = report.build_image_view(ns)
        assert imgs[0]["max_score"] == 9.9
        assert imgs[1]["max_score"] == 5.0

    def test_weaponized_count_only_counts_flagged_cves(self) -> None:
        ns = self._ns([("ns", "Deployment", "app", "r", "sha256:a", "v1", [
            {"id": "CVE-1", "score": 9.0, "severity": "Critical",
             "hasVerifiedExploit": "true"},
            {"id": "CVE-2", "score": 8.0, "severity": "High",
             "hasVerifiedExploit": "false"},
            {"id": "CVE-3", "score": 7.0, "severity": "High",
             "isInExploitKit": "true"},
        ])])
        assert report.build_image_view(ns)[0]["weaponized_count"] == 2


# ---------------------------------------------------------------------------
# build_html — resilient to edge cases
# ---------------------------------------------------------------------------

class TestBuildHtmlEdgeCases:
    def _minimal_csvs(self, tmp_path: Path, sum_rows, exp_rows):
        sum_path = write_csv(tmp_path / "s.csv", CRUZAMENTO_HEADER, sum_rows)
        exp_path = write_csv(
            tmp_path / "e.csv",
            ["NAMESPACE", "PARENT_TYPE", "PARENT_NAME", "REPOSITORY", "DIGEST",
             "TAG", "CVE_ID", "CVSS_SCORE", "SEVERITY", "PACKAGE_CATEGORY",
             "PACKAGE_LANGUAGE", "PACKAGE_NAME", "CURRENT_VERSION", "FIXED_VERSION",
             "PATCHABLE", "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
             "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
             "LAST_PUSHED_TO_REGISTRY_UTC"],
            exp_rows,
        )
        return sum_path, exp_path

    def test_html_generated_with_single_workload(self, tmp_path: Path) -> None:
        sum_p, exp_p = self._minimal_csvs(
            tmp_path,
            [["ns", "Deployment", "app", "r/a", "sha256:1", "v1", "1", "Critical",
              "9.8", "CVE-1", "CVE-1:Critical",
              "", "", "", "", "", "", "", "", "", "", "", "", ""]],
            [["ns", "Deployment", "app", "r/a", "sha256:1", "v1", "CVE-1", "9.8",
              "Critical", "", "", "", "", "", "", "", "", "", "", "", "", ""]],
        )
        ns = report.load_data(str(sum_p), str(exp_p))
        html = report.build_html(ns)
        assert "CVE-1" in html
        assert "Vulnerable Images" in html

    def test_no_crash_on_all_100_score(self, tmp_path: Path) -> None:
        """Every workload at CVSS 10.0 exercises the critical-alert path."""
        sum_rows = [
            ["ns", "Deployment", f"app{i}", f"r/a{i}", f"sha256:{i:04x}", "v1",
             "1", "Critical", "10.0", f"CVE-{i}", f"CVE-{i}:Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""]
            for i in range(5)
        ]
        exp_rows = [
            ["ns", "Deployment", f"app{i}", f"r/a{i}", f"sha256:{i:04x}", "v1",
             f"CVE-{i}", "10.0", "Critical", "", "", "", "", "", "", "", "", "",
             "", "", "", ""]
            for i in range(5)
        ]
        sum_p, exp_p = self._minimal_csvs(tmp_path, sum_rows, exp_rows)
        ns = report.load_data(str(sum_p), str(exp_p))
        html = report.build_html(ns)
        # After the redesign (task #35), the critical-alert copy lives in the
        # sticky alert bar at the top with the phrase "Immediate action".
        assert "Immediate action" in html
        assert "CVSS 10.0" in html
        # Score 10.0 KPI should render with the `critical` red variant.
        assert 'class="kpi-num critical"' in html
