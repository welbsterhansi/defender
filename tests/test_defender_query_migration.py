"""
TDD invariants for the MDVM individual-recommendations migration.

Microsoft retired the legacy `microsoft.security/assessments/subassessments`
type on 2026-07-31 (see docs/investigation-mdvm-2026-08.md). The individual
model for ACR containers stores CVE-level data INLINE inside
`properties.additionalData.CvesDetails[]` — the same structure the
pre-migration Leg B already used. There is NO cross-resource JOIN needed
in this tenant (an earlier attempt to JOIN with `microsoft.security/cvedetails`
returned zero matches because that resource type is not populated here).

Empirically validated `cve.*` bag keys (from a probe run at the client):

    ["CveId", "AdditionalIdentifiers", "Description", "ExtendedDescription",
     "Cvss", "CvssSource", "Severity", "PublishedDate", "LastModifiedDate",
     "Weaknesses", "FixStatus", "FixedVersion", "ExploitabilityDetails",
     "References", "Tags"]

CVSS is an array of Key/Value objects, e.g.
    [{"Key": "3", "Value": {"Base": 7.1, "CvssVectorString": "..."}}]
so numeric extraction is `todouble(cve.Cvss[0].Value.Base)`.

Image identity comes from `properties.resourceAdditionalData.RepositoryDetails.*`
(clean structured fields — no URL regex extraction).

Package version comes from `properties.additionalData.ScannersDetails.mdvm.*`.

These tests inspect the KQL heredoc embedded in `defender.sh` (they do NOT
run `az`) and enforce the invariants so any regression is caught in CI.
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
            "Leg A (microsoft.security/assessments/subassessments) is retired"
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
# 3. No JOIN with cvedetails — the resource type is empty in target tenants
# ---------------------------------------------------------------------------


class TestNoCvedetailsJoin:
    """Prior attempt to JOIN with `microsoft.security/cvedetails` returned
    zero matches at the client (cvedetails is not populated in this tenant,
    across all accessible subscriptions). All CVE data lives inside
    `properties.additionalData.CvesDetails[]` on the assessments side and
    must be read directly from `cve.*`."""

    def test_kql_has_no_cvedetails_join(self, kql: str) -> None:
        assert "microsoft.security/cvedetails" not in kql, (
            "cvedetails is empty in target tenants; JOIN must be removed"
        )

    def test_kql_has_no_leftouter_join(self, kql: str) -> None:
        assert not re.search(r"join\s+kind\s*=\s*leftouter", kql, re.IGNORECASE), (
            "no JOIN needed — everything reads from cve.* directly"
        )


# ---------------------------------------------------------------------------
# 4. CVE-level fields read from `cve.*` inside CvesDetails[]
# ---------------------------------------------------------------------------


class TestCveFieldsInline:
    """Confirmed by bag_keys probe on the client tenant: every field we need
    is present under `cve.*` in the mv-expanded CvesDetails[] array."""

    def test_severity_from_cve(self, kql: str) -> None:
        assert re.search(r"\bcve\.Severity\b", kql), (
            "severity must come from cve.Severity (inline in CvesDetails[])"
        )

    def test_cvss_base_from_cve_array(self, kql: str) -> None:
        # cve.Cvss is an array of {Key, Value: {Base, CvssVectorString}}.
        # First entry is the operative CVSS score in every sample seen.
        assert re.search(r"cve\.Cvss\[\s*0\s*\]\.Value\.Base", kql), (
            "cvss numeric must be read as cve.Cvss[0].Value.Base"
        )

    def test_fixstatus_from_cve(self, kql: str) -> None:
        assert re.search(r"\bcve\.FixStatus\b", kql)

    def test_fixed_version_from_cve(self, kql: str) -> None:
        assert re.search(r"\bcve\.FixedVersion\b", kql)

    def test_published_date_from_cve(self, kql: str) -> None:
        assert re.search(r"\bcve\.PublishedDate\b", kql)

    def test_description_from_cve(self, kql: str) -> None:
        assert re.search(r"\bcve\.Description\b", kql)

    def test_exploit_kit_from_cve_exploitability_details(self, kql: str) -> None:
        assert re.search(
            r"cve\.ExploitabilityDetails\.IsInExploitKit", kql,
        )

    def test_published_exploit_signal_from_cve(self, kql: str) -> None:
        # Defensive: accept either legacy `ExploitStepsPublished` or the
        # newer `IsPubliclyDisclosed` — both may appear in different tenants.
        assert re.search(
            r"cve\.ExploitabilityDetails\.(ExploitStepsPublished|IsPubliclyDisclosed)",
            kql,
        ), "hasPublishedExploit must read from cve.ExploitabilityDetails"

    def test_verified_exploit_signal_from_cve(self, kql: str) -> None:
        assert re.search(
            r"cve\.ExploitabilityDetails\.(ExploitStepsVerified|IsVerified)",
            kql,
        ), "hasVerifiedExploit must read from cve.ExploitabilityDetails"


# ---------------------------------------------------------------------------
# 5. Image identity + package version — validated structured paths
# ---------------------------------------------------------------------------


class TestFieldSources:
    def test_parses_scanners_details(self, kql: str) -> None:
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
        assert re.search(
            r"mdvm\.DetectedSoftwareVersions\s*\[\s*0\s*\]",
            kql,
        )

    def test_repository_from_repository_details(self, kql: str) -> None:
        assert re.search(r"RepositoryDetails\.RepositoryName", kql)

    def test_digest_from_image_data(self, kql: str) -> None:
        assert re.search(r"\.Digest\b", kql)

    def test_no_url_regex_for_digest(self, kql: str) -> None:
        assert not re.search(r'extract\s*\(\s*@?"sha256:', kql), (
            "digest must come from parsed resourceAdditionalData.Digest, "
            "not regex extraction from the URL"
        )


# ---------------------------------------------------------------------------
# 6. Coalesce order for fields with multiple candidate paths
# ---------------------------------------------------------------------------


class TestFieldCoalesceOrder:
    def test_package_category_coalesce_paths(self, kql: str) -> None:
        assert _coalesce_contains_all(
            kql, "additionalData.PackageType", "mdvm.category",
        ) or _coalesce_contains_all(
            kql, "additionalData.PackageType", "mdvm.PackageType",
        )

    def test_package_language_coalesce_paths(self, kql: str) -> None:
        assert _coalesce_contains_all(
            kql, "additionalData.Language", "mdvm.Language",
        )

    def test_fix_status_coalesce_paths(self, kql: str) -> None:
        # Multiple candidates; require at least cve.FixStatus AND one alternate.
        assert (
            _coalesce_contains_all(kql, "cve.FixStatus", "mdvm.FixStatus")
            or _coalesce_contains_all(kql, "cve.FixStatus", "additionalData.FixStatus")
        )

    def test_cvss_falls_back_to_severity_case(self, kql: str) -> None:
        """When cve.Cvss[0].Value.Base is missing, cvssScore must fall back
        to a case-on-severity mapping so `Unknown` rows deterministically
        land at 0.0 (and are filtered out by min-score) instead of null."""
        # Presence-based check (paren-aware regex would be brittle):
        # we need `case(...)`, a Severity reference, and the Critical→9.0
        # mapping literally somewhere in the KQL.
        assert "case(" in kql
        assert re.search(r"\b[Ss]everity\b", kql)
        assert '"Critical", 9.0' in kql, (
            "cvssScore fallback must map Critical severity to 9.0"
        )


# ---------------------------------------------------------------------------
# 7. Downstream contracts — CSV column order + single leg
# ---------------------------------------------------------------------------


class TestCsvColumnOrderPreserved:
    EXPECTED_PROJECT_COLUMNS: ClassVar[list[str]] = [
        "repository", "digest", "cvssScore", "cveId", "severityRaw",
        "packageCategory", "packageLanguage", "packageName",
        "currentVersion", "fixedVersion", "patchable", "remediation",
        "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
        "hasVerifiedExploit", "lastPushedToRegistryUTC",
    ]

    def test_project_column_list_matches(self, kql: str) -> None:
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
        assert not re.search(r"\|\s*union\s*\(", kql)
