"""
TDD invariants for the MDVM individual-recommendations migration.

Microsoft retired the legacy `microsoft.security/assessments/subassessments`
type on 2026-07-31 (see docs/investigation-mdvm-2026-08.md). The new
individual-recommendations model for ACR containers has a schema that
Microsoft never documented publicly for containers — the actual paths
below were determined empirically by running a probe query at the client's
tenant, then confirmed with a working end-to-end query from the client team.

Key schema facts (from the client-validated probe):

* CVE-level data is **split across two resource types**:
  - `microsoft.security/assessments` (this leg) → carries `CvesDetails[]`,
    which is now essentially just an array of `{CveId}`.
  - `microsoft.security/cvedetails` (JOIN target) → carries `severity`,
    `cvss[<version>].base`, `publishedDate`, `exploitabilityDetails.*`,
    `description`, `remediation`. Joined on `CveId`.

* Package version comes from `additionalData.ScannersDetails.mdvm.*` —
  neither top-level `additionalData` nor inside `CvesDetails[]`.

* Image identity (repo, digest, registry) comes from
  `resourceAdditionalData.RepositoryDetails.*` and
  `resourceAdditionalData.Digest` — clean structured fields, no URL regex
  needed anymore.

* CVSS supports 4.0/3.1/3.0/2.0 with string keys: `cvss["4.0"].base`.

* Exploit signals were renamed under `cvedetails.exploitabilityDetails.*`:
  - `IsInExploitKit` (unchanged)
  - `IsPubliclyDisclosed` (was `ExploitStepsPublished`)
  - `IsVerified` (was `ExploitStepsVerified`)

These tests inspect the KQL heredoc embedded in `defender.sh` (they do NOT
run `az`) and enforce the invariants above so any regression is caught in CI.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFENDER_SH = REPO_ROOT / "defender.sh"


@pytest.fixture(scope="module")
def defender_source() -> str:
    return DEFENDER_SH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def kql(defender_source: str) -> str:
    """Extract the KQL heredoc that defender.sh writes to $QUERY_FILE."""
    match = re.search(
        r'cat\s*>\s*"?\$QUERY_FILE"?\s*<<-?\s*(\w+)\s*\n(.*?)\n\s*\1\b',
        defender_source,
        re.DOTALL,
    )
    assert match, "could not find $QUERY_FILE heredoc in defender.sh"
    return match.group(2)


def _coalesce_blocks(kql: str) -> list[str]:
    """Yield the body of every `coalesce(...)` call in `kql`, using a
    paren-balanced walker so nested `tostring(...)` etc. don't confuse
    the extraction."""
    bodies: list[str] = []
    lower = kql.lower()
    marker = "coalesce("
    for start in range(len(lower)):
        if not lower.startswith(marker, start):
            continue
        depth = 0
        body_start = start + len(marker)
        i = body_start - 1
        while i < len(kql):
            if kql[i] == "(":
                depth += 1
            elif kql[i] == ")":
                depth -= 1
                if depth == 0:
                    bodies.append(kql[body_start:i])
                    break
            i += 1
    return bodies


def _coalesce_contains_all(kql: str, *substrings: str) -> bool:
    """Some coalesce(...) block contains all the given substrings."""
    return any(all(s in body for s in substrings) for body in _coalesce_blocks(kql))


# ---------------------------------------------------------------------------
# 1. Leg A (retired) must be completely gone
# ---------------------------------------------------------------------------


class TestSubassessmentsGone:
    def test_kql_has_no_subassessments_type(self, kql: str) -> None:
        assert "subassessments" not in kql.lower(), (
            "Leg A (microsoft.security/assessments/subassessments) is retired — "
            "must be removed from the main KQL"
        )

    def test_kql_has_no_legacy_c0b7cfc6_filter(self, kql: str) -> None:
        assert "c0b7cfc6-3172-465a-b378-53c7ff2cc0d5" not in kql

    def test_debug_block_does_not_query_subassessments(
        self, defender_source: str,
    ) -> None:
        for match in re.finditer(r"az\s+graph\s+query[^\n]*", defender_source):
            assert "subassessments" not in match.group(0).lower(), (
                f"an `az graph query` still targets subassessments:\n  {match.group(0)}"
            )


# ---------------------------------------------------------------------------
# 2. Individual-model entry point (four required where-clauses)
# ---------------------------------------------------------------------------


class TestIndividualModelEntryPoint:
    def test_type_is_assessments_not_subassessments(self, kql: str) -> None:
        assert re.search(
            r"type\s*[=~]+\s*['\"]microsoft\.security/assessments['\"]",
            kql,
        )

    def test_category_softwareupdate(self, kql: str) -> None:
        assert re.search(
            r"recommendationCategory\s*==\s*['\"]SoftwareUpdate['\"]",
            kql,
        )

    def test_resource_type_containerimage(self, kql: str) -> None:
        assert re.search(
            r"ResourceType\s*==\s*['\"]\.containerimage['\"]",
            kql,
        )

    def test_source_azure(self, kql: str) -> None:
        assert re.search(r"Source\s*==\s*['\"]Azure['\"]", kql)


# ---------------------------------------------------------------------------
# 3. Two-resource JOIN structure — CVE data lives in microsoft.security/cvedetails
# ---------------------------------------------------------------------------


class TestCveDetailsJoin:
    def test_joins_cvedetails_resource_type(self, kql: str) -> None:
        assert re.search(
            r"microsoft\.security/cvedetails",
            kql,
        ), "must join microsoft.security/cvedetails to get severity/CVSS/exploit"

    def test_join_is_leftouter(self, kql: str) -> None:
        # leftouter preserves rows where cvedetails is missing (edge case:
        # very new CVEs not yet in the catalog).
        assert re.search(r"join\s+kind\s*=\s*leftouter", kql, re.IGNORECASE)

    def test_join_key_is_cveid(self, kql: str) -> None:
        # `... ) on cveId` (case-insensitive)
        assert re.search(r"\)\s*on\s+cveId", kql, re.IGNORECASE)


# ---------------------------------------------------------------------------
# 4. Field-source paths validated against the client's tenant
# ---------------------------------------------------------------------------


class TestFieldSources:
    def test_parses_scanners_details(self, kql: str) -> None:
        # additionalData.ScannersDetails is a JSON string that must be parsed
        # to reach the mdvm sub-object (where DetectedSoftwareVersions and
        # FixedVersion live).
        assert re.search(
            r"parse_json\s*\(\s*tostring\s*\(\s*properties\.additionalData\.ScannersDetails",
            kql,
        )

    def test_parses_resource_additional_data(self, kql: str) -> None:
        assert re.search(
            r"parse_json\s*\(\s*tostring\s*\(\s*properties\.resourceAdditionalData",
            kql,
        )

    def test_parses_cves_details(self, kql: str) -> None:
        assert re.search(
            r"parse_json\s*\(\s*tostring\s*\(\s*properties\.additionalData\.CvesDetails",
            kql,
        )

    def test_current_version_from_scanner_mdvm(self, kql: str) -> None:
        # Scanner.mdvm.DetectedSoftwareVersions[0] — array, first element.
        assert re.search(
            r"mdvm\.DetectedSoftwareVersions\s*\[\s*0\s*\]",
            kql,
        )

    def test_fixed_version_from_scanner_mdvm(self, kql: str) -> None:
        assert re.search(r"mdvm\.FixedVersion", kql)

    def test_repository_from_repository_details(self, kql: str) -> None:
        assert re.search(r"RepositoryDetails\.RepositoryName", kql)

    def test_digest_from_image_data(self, kql: str) -> None:
        # ImageData is the parsed resourceAdditionalData; .Digest is at the top.
        # No more URL regex extraction — the structured field is authoritative.
        assert re.search(r"\.Digest\b", kql)

    def test_no_url_regex_for_digest(self, kql: str) -> None:
        # Regression guard against re-introducing the old
        # `strcat("sha256:", extract(@"sha256:...", 1, resourceId))` hack.
        assert not re.search(r'extract\s*\(\s*@?"sha256:', kql), (
            "digest must come from parsed resourceAdditionalData.Digest, "
            "not regex extraction from the URL"
        )


# ---------------------------------------------------------------------------
# 5. CVSS 4.0/3.1/3.0/2.0 support (new in individual model)
# ---------------------------------------------------------------------------


class TestCvssMultiVersion:
    def test_cvss_40_read(self, kql: str) -> None:
        assert re.search(r'cvss\s*\[\s*"4\.0"\s*\]\.base', kql)

    def test_cvss_31_read(self, kql: str) -> None:
        assert re.search(r'cvss\s*\[\s*"3\.1"\s*\]\.base', kql)

    def test_cvss_30_read(self, kql: str) -> None:
        assert re.search(r'cvss\s*\[\s*"3\.0"\s*\]\.base', kql)

    def test_cvss_20_read(self, kql: str) -> None:
        assert re.search(r'cvss\s*\[\s*"2\.0"\s*\]\.base', kql)

    def test_cvss_versions_coalesced(self, kql: str) -> None:
        # All four versions must be inside one coalesce (prefer newest).
        assert _coalesce_contains_all(kql, '"4.0"', '"3.1"', '"3.0"', '"2.0"')


# ---------------------------------------------------------------------------
# 6. Exploit signals — renamed fields from cvedetails.exploitabilityDetails
# ---------------------------------------------------------------------------


class TestExploitSignalRenames:
    def test_uses_is_in_exploit_kit(self, kql: str) -> None:
        assert re.search(r"exploitabilityDetails\.IsInExploitKit", kql)

    def test_uses_is_publicly_disclosed_not_exploit_steps_published(
        self, kql: str,
    ) -> None:
        # NEW: IsPubliclyDisclosed (was ExploitStepsPublished in Leg A)
        assert re.search(r"exploitabilityDetails\.IsPubliclyDisclosed", kql)
        # Regression guard against re-adding the old name.
        assert "ExploitStepsPublished" not in kql, (
            "field renamed to IsPubliclyDisclosed in the individual model"
        )

    def test_uses_is_verified_not_exploit_steps_verified(self, kql: str) -> None:
        # NEW: IsVerified (was ExploitStepsVerified in Leg A)
        assert re.search(r"exploitabilityDetails\.IsVerified\b", kql)
        assert "ExploitStepsVerified" not in kql, (
            "field renamed to IsVerified in the individual model"
        )


# ---------------------------------------------------------------------------
# 7. Coalesce order for the 3 fields with multiple candidate paths
# ---------------------------------------------------------------------------


class TestFieldCoalesceOrder:
    def test_package_category_coalesce_paths(self, kql: str) -> None:
        # All 3 candidate paths that came back populated in the probe:
        #   additionalData.PackageType, Scanner.mdvm.category, Scanner.mdvm.PackageType
        assert _coalesce_contains_all(
            kql, "additionalData.PackageType", "mdvm.category",
        ) or _coalesce_contains_all(
            kql, "additionalData.PackageType", "mdvm.PackageType",
        ), "packageCategory must coalesce additionalData.PackageType with an mdvm.* fallback"

    def test_package_language_coalesce_paths(self, kql: str) -> None:
        assert _coalesce_contains_all(
            kql, "additionalData.Language", "mdvm.Language",
        )

    def test_fix_status_coalesce_paths(self, kql: str) -> None:
        # At least two of the 3 candidate paths must be in one coalesce.
        assert (
            _coalesce_contains_all(kql, "additionalData.FixStatus", "mdvm.FixStatus")
            or _coalesce_contains_all(kql, "additionalData.FixStatus", "Cve.FixStatus")
            or _coalesce_contains_all(kql, "Cve.FixStatus", "mdvm.FixStatus")
        )

    def test_last_pushed_coalesce_paths(self, kql: str) -> None:
        # Top-level LastPushedToRegistryUTC OR nested under RepositoryDetails.
        assert _coalesce_contains_all(
            kql,
            "LastPushedToRegistryUTC",
            "RepositoryDetails.LastPushedToRegistryUTC",
        ) or (
            "LastPushedToRegistryUTC" in kql
        )


# ---------------------------------------------------------------------------
# 8. Downstream contracts — CSV column order + single leg
# ---------------------------------------------------------------------------


class TestCsvColumnOrderPreserved:
    """CSV column order is a downstream contract — `expandcsv.py`,
    `group_findings.py` and `report.py` all key off the KQL `| project`
    column list. Post-migration must preserve the exact same list."""

    EXPECTED_PROJECT_COLUMNS: ClassVar[list[str]] = [
        "repository", "digest", "cvssScore", "cveId", "severityRaw",
        "packageCategory", "packageLanguage", "packageName",
        "currentVersion", "fixedVersion", "patchable", "remediation",
        "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
        "hasVerifiedExploit", "lastPushedToRegistryUTC",
    ]

    def test_project_column_list_matches(self, kql: str) -> None:
        # Only count top-level projects — the cvedetails JOIN subquery
        # also has a `| project`, which is scoped and doesn't count.
        # Heuristic: any `| project` that appears OUTSIDE a `join kind=leftouter (...)`
        # block. Simpler: split on `join kind=leftouter (` and count in the
        # part AFTER the closing `)` — the final projection.
        # For a query with one JOIN, the last `| project` is the top-level one.
        projects = re.findall(r"\|\s*project\s+([^\n|]+)", kql)
        assert projects, "no `| project` clause found"
        top_level = [
            p for p in projects
            if "repository" in p and "cveId" in p and "severityRaw" in p
        ]
        assert len(top_level) == 1, (
            f"expected exactly 1 top-level `| project` (18-column CSV), "
            f"got {len(top_level)}"
        )
        cols = [c.strip() for c in top_level[0].split(",")]
        assert cols == self.EXPECTED_PROJECT_COLUMNS, (
            f"CSV column order is a downstream contract.\n"
            f"expected: {self.EXPECTED_PROJECT_COLUMNS}\n"
            f"     got: {cols}"
        )


class TestSingleLegNotUnion:
    def test_kql_has_no_union(self, kql: str) -> None:
        # Post-migration: single leg + one JOIN, never a union.
        assert not re.search(r"\|\s*union\s*\(", kql), (
            "post-migration KQL should be a single leg + JOIN, not `| union`"
        )
