"""
Unit tests for report.py — the HTML render stage.

Complements the E2E test with focused coverage of the pure helpers and
edge cases in the aggregation logic:
  - `_is_weaponized`   — flag OR semantics + case handling
  - `_exploit_cell`    — 3 independent V/P/K signal chips
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
# _exploit_cell — 3 independent chips (V/P/K)
# ---------------------------------------------------------------------------

class TestExploitCell:
    def test_all_three_signals_render_independently(self) -> None:
        cell = report._exploit_cell({
            "hasVerifiedExploit": "true",
            "hasPublishedExploit": "true",
            "isInExploitKit": "true",
        })
        assert 'class="expl-chip on-v"' in cell
        assert 'class="expl-chip on-p"' in cell
        assert 'class="expl-chip on-k"' in cell

    def test_no_signals_all_off(self) -> None:
        cell = report._exploit_cell({})
        assert cell.count('class="expl-chip off"') == 3

    def test_single_signal_others_off(self) -> None:
        cell = report._exploit_cell({"isInExploitKit": "true"})
        assert 'class="expl-chip on-k"' in cell
        assert cell.count('class="expl-chip off"') == 2

    def test_titles_are_human_readable(self) -> None:
        cell = report._exploit_cell({"hasVerifiedExploit": "true"})
        assert 'title="Verified exploit exists"' in cell


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

    def test_data_expl_attribute_removed(self) -> None:
        assert 'data-expl=' not in self._row(hasVerifiedExploit="true")

    def test_patch_icon_matches_state(self) -> None:
        assert "✅" in self._row(patchable="true")
        assert "❌" in self._row(patchable="false")
        assert "—" in self._row(patchable="")

    def test_data_v_p_k_reflect_individual_flags(self) -> None:
        row = self._row(hasVerifiedExploit="true", isInExploitKit="true")
        assert 'data-v="1"' in row
        assert 'data-p="0"' in row
        assert 'data-k="1"' in row

    def test_fix_status_and_age_included_in_row(self) -> None:
        row = self._row(fixStatus="NoFix", cveAgeDays="120")
        assert "NoFix" in row
        assert ">120<" in row

    def test_patch_cell_has_aria_label(self) -> None:
        assert 'aria-label="Patchable"' in self._row(patchable="true")
        assert 'aria-label="Not patchable"' in self._row(patchable="false")
        assert 'aria-label="Patch status unknown"' in self._row(patchable="")


# ---------------------------------------------------------------------------
# _fix_status_cell — Fix Status column (PR-UX-3 Task 4)
# ---------------------------------------------------------------------------

class TestFixStatusCell:
    def test_renders_value(self) -> None:
        assert "FixAvailable" in report._fix_status_cell({"fixStatus": "FixAvailable"})

    def test_missing_value_shows_dash(self) -> None:
        assert ">—<" in report._fix_status_cell({})

    def test_html_escaped(self) -> None:
        cell = report._fix_status_cell({"fixStatus": "<b>x</b>"})
        assert "<b>" not in cell
        assert "&lt;b&gt;" in cell


# ---------------------------------------------------------------------------
# _age_cell — CVE age (days) column (PR-UX-3 Task 4)
# ---------------------------------------------------------------------------

class TestAgeCell:
    def test_renders_value(self) -> None:
        assert ">45<" in report._age_cell({"cveAgeDays": "45"})

    def test_missing_value_shows_dash(self) -> None:
        assert ">—<" in report._age_cell({"cveAgeDays": ""})

    def test_zero_is_not_treated_as_missing(self) -> None:
        # `cveAgeDays="0"` is a real value (today), not missing — only
        # whitespace/empty counts as missing.
        assert ">0<" in report._age_cell({"cveAgeDays": "0"})


# ---------------------------------------------------------------------------
# _cve_table_head — deduped <thead> for both image and workload cards
# ---------------------------------------------------------------------------

class TestCveTableHead:
    def test_columns_include_fix_status_and_age(self) -> None:
        head = report._cve_table_head()
        assert "<th>Fix Status</th>" in head
        assert "<th>Age (days)</th>" in head
        assert "<th>Exploit</th>" in head


# ---------------------------------------------------------------------------
# _severity_counts — per-severity KPI breakdown (PR-UX-3 Task 5)
# ---------------------------------------------------------------------------

class TestSeverityCounts:
    def test_counts_by_severity(self) -> None:
        cves = [
            {"severity": "Critical"}, {"severity": "Critical"},
            {"severity": "High"}, {"severity": "Low"},
        ]
        counts = report._severity_counts(cves)
        assert counts == {"Critical": 2, "High": 1, "Low": 1}

    def test_empty_list(self) -> None:
        assert report._severity_counts([]) == {}

    def test_missing_severity_bucketed_as_unknown(self) -> None:
        assert report._severity_counts([{"severity": ""}]) == {"Unknown": 1}


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

    def test_full_digest_available_via_title(self, tmp_path: Path) -> None:
        # PR-UX-3 Task 6: the truncated `@digest_short` shown in image and
        # workload cards must expose the FULL sha256 via a `title=` tooltip
        # so devs can copy/inspect it without regenerating the report.
        digest = "sha256:" + "a" * 64
        sum_p, exp_p = self._minimal_csvs(
            tmp_path,
            [["ns", "Deployment", "app", "r/a", digest, "v1", "1", "Critical",
              "9.8", "CVE-1", "CVE-1:Critical",
              "", "", "", "", "", "", "", "", "", "", "", "", ""]],
            [["ns", "Deployment", "app", "r/a", digest, "v1", "CVE-1", "9.8",
              "Critical", "", "", "", "", "", "", "", "", "", "", "", "", ""]],
        )
        ns = report.load_data(str(sum_p), str(exp_p))
        html = report.build_html(ns)
        assert f'title="{digest}"' in html

    def test_visible_counter_format(self, tmp_path: Path) -> None:
        # PR-UX-3 Task 6: `applyFilters()` must now count `.card`s scoped to
        # the ACTIVE `.tab-panel` so the "N of M visible" text reflects
        # what the user is currently looking at, not the sum of both tabs.
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
        assert "activePanel" in html
        assert "totalCards" in html

    def test_exploit_legend_visible_by_default(self, tmp_path: Path) -> None:
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
        assert 'class="expl-legend"' in html
        assert "Verified exploit exists" in html
        assert "Published exploit exists" in html
        assert "Included in an exploit kit" in html
        # tabs from PR-UX-1 must still be intact
        assert 'role="tablist"' in html

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

    def test_tabs_present_with_source_labels(self, tmp_path: Path) -> None:
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
        assert 'role="tablist"' in html
        assert 'id="tab-images"' in html
        assert 'id="tab-cluster"' in html
        assert "Azure Container Registry" in html
        assert "OpenShift Cluster" in html
        assert "function switchTab(" in html

    def test_existing_filters_still_present(self, tmp_path: Path) -> None:
        """Regression guard: tabs must not remove the severity/patch/exploit/
        search filter bar or its onchange wiring."""
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
        assert 'id="fSev"' in html
        assert 'id="fPatch"' in html
        assert 'id="fExpl"' in html
        assert 'id="fSearch"' in html
        assert "function applyFilters(" in html
        assert "function cpy(" in html  # copy-to-clipboard buttons unaffected

    def test_exploit_filter_has_granular_options(self, tmp_path: Path) -> None:
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
        assert '<option value="v">Verified only</option>' in html
        assert '<option value="p">Published only</option>' in html
        assert '<option value="k">In kit only</option>' in html
