"""
TDD invariants for the MDVM individual-recommendations migration
+ 2026-08 cvedetails enrichment fix.

Microsoft retired the legacy `microsoft.security/assessments/subassessments`
type on 2026-07-31. In the current model:

  * Image + package + per-CVE linkage lives in
    `microsoft.security/assessments` (individual-recommendations), inside
    `properties.additionalData.CvesDetails[]` (mv-expanded to one row per CVE).
  * CVE metadata (CVSS score, severity, exploitability, publishedDate) is
    now published at management-group scope in
    `microsoft.security/cvedetails`. See
    `docs/mdvm-cvedetails-schema-2026-08.md` for the full sample.

The KQL performs a LEFT OUTER JOIN between the two so:
  * Rows are NEVER lost when cvedetails is unreachable (fallback to inline).
  * When cvedetails IS reachable, it overrides the (empty/stale) inline data.

Client-tenant traps encoded here as guardrail invariants:

  * `properties.cvss` is a DICT keyed by string version. Keys are exactly
    `"4.0"`, `"3.0"`, `"2.0"` — there is NO `"3.1"` key. A coalesce that
    references `'3.1'` silently drops every CVSS 3.x-only CVE.
  * Version buckets have lowercase `base` (`.cvss["3.0"].base`), not the
    old inline `.Cvss[0].Value.Base` PascalCase shape.
  * Rejected CVEs (`properties.status == "Reject"`) have all cvss buckets
    null and must be filtered out of the enrichment side.

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
    """Extract the KQL heredoc emitted by build_digest_scan_query().

    Post-refactor (2026-09) the KQL is no longer a single monolithic heredoc
    written to $QUERY_FILE — it is built dynamically per digest by the
    `build_digest_scan_query()` bash function. The heredoc lives inside that
    function's body; we grab it so the guardrail assertions below still work.
    """
    func_start = re.search(
        r'build_digest_scan_query\s*\(\s*\)\s*\{', defender_source,
    )
    assert func_start, (
        "build_digest_scan_query() function not found in defender.sh"
    )
    tail = defender_source[func_start.end():]
    heredoc = re.search(
        r'cat\s*<<-?\s*(\w+)\s*\n(.*?)\n\s*\1\b', tail, re.DOTALL,
    )
    assert heredoc, "no cat<<HEREDOC found inside build_digest_scan_query()"
    return heredoc.group(2)


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

    def test_no_query_targets_subassessments(
        self, defender_source: str,
    ) -> None:
        """Neither the retired `az graph query` (kept via git blame in case of
        rollback) nor the current `az rest` transport may target the retired
        subassessments type."""
        for pattern in (r"az\s+graph\s+query[^\n]*", r"az\s+rest[^\n]*"):
            for match in re.finditer(pattern, defender_source):
                assert "subassessments" not in match.group(0).lower(), (
                    f"az call still targets subassessments:\n  {match.group(0)}"
                )
        # Also guard against subassessments references in the KQL builders.
        assert "subassessments" not in defender_source.lower(), (
            "Leg A (subassessments) is retired — remove all references"
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
# 3. cvedetails JOIN present with the correct schema
# ---------------------------------------------------------------------------


class TestCvedetailsJoinPresent:
    """CVE enrichment (cvss / severity / exploitability / publishedDate)
    now lives in `microsoft.security/cvedetails` (management-group scope).
    The KQL must LEFT OUTER JOIN with it so those fields are populated
    when the caller's `az login` context reaches the MG, and gracefully
    degrade (via inline fallback) when it doesn't."""

    def test_kql_references_cvedetails_type(self, kql: str) -> None:
        assert "microsoft.security/cvedetails" in kql, (
            "enrichment side must query microsoft.security/cvedetails"
        )

    def test_kql_uses_leftouter_join(self, kql: str) -> None:
        assert re.search(r"join\s+kind\s*=\s*leftouter", kql, re.IGNORECASE), (
            "must LEFT OUTER JOIN so rows are not lost when cvedetails is "
            "unreachable (e.g. az login not scoped to the MG)"
        )

    def test_join_key_is_normalized_cveid(self, kql: str) -> None:
        # CVE ids differ in casing between assessments (uppercase, CVE-XXXX)
        # and cvedetails.name (lowercase, cve-xxxx). Join must upper() both
        # sides to avoid silently missing every enrichment match.
        # Accept either the "toupper wraps the outer coalesce" shape or the
        # "toupper wraps just the property read" shape — both normalize case.
        cvedetails_side = re.search(
            r"toupper\s*\([^)]*properties\.cveId", kql,
        )
        assert cvedetails_side, (
            "cvedetails-side join key must upper() properties.cveId "
            "(directly or via a coalesce)"
        )
        assessments_side = re.search(r"toupper\s*\(\s*cveId\s*\)", kql)
        assert assessments_side, (
            "assessments-side join key must upper() cveId"
        )


# ---------------------------------------------------------------------------
# 3b. cvedetails schema guardrails (the "3.1" bug and friends)
# ---------------------------------------------------------------------------


class TestCvedetailsSchemaGuardrails:
    """Regression guards against the exact bugs the client debug surfaced
    in 2026-08. Each of these silently returns null / unknown / 0.0 if
    violated — no runtime error, just bad data in the CSV."""

    def test_no_cvss_31_key(self, kql: str) -> None:
        # properties.cvss has "4.0", "3.0", "2.0" — NEVER "3.1".
        # Match the literal key form (quoted "3.1") but tolerate the
        # CVSS 3.1 vector string that appears under the "3.0" bucket.
        for pattern in (r'cvss\[\s*"3\.1"\s*\]', r"cvss\[\s*'3\.1'\s*\]",
                        r'\bcvss\.\s*"3\.1"', r"properties\.cvss\.\['3\.1'\]"):
            assert not re.search(pattern, kql), (
                f"forbidden CVSS key '3.1' matched pattern {pattern!r} — "
                "the enrichment schema has NO 3.1 key"
            )

    def test_cvss_coalesce_uses_correct_keys(self, kql: str) -> None:
        # The coalesce must reference all three real keys.
        for key in ('"4.0"', '"3.0"', '"2.0"'):
            assert re.search(
                rf"cvss\[\s*{re.escape(key)}\s*\]\.base", kql,
            ), f"cvss key {key} missing from enrichment coalesce"

    def test_cvss_coalesce_orders_4_before_3_before_2(self, kql: str) -> None:
        # 4.0 must win when present (newest scoring model), then 3.0, then 2.0.
        i40 = kql.find('cvss["4.0"].base')
        i30 = kql.find('cvss["3.0"].base')
        i20 = kql.find('cvss["2.0"].base')
        assert i40 != -1 and i30 != -1 and i20 != -1, (
            "all three cvss key reads must be present"
        )
        assert i40 < i30 < i20, (
            "cvss coalesce must be 4.0 → 3.0 → 2.0 (found "
            f"positions 4.0={i40} 3.0={i30} 2.0={i20})"
        )

    def test_rejected_cves_filtered_out(self, kql: str) -> None:
        # cvedetails rows with status="Reject" have all cvss null and
        # should not participate in the enrichment side. Accept an
        # optional tostring(...) wrapper around properties.status.
        assert re.search(
            r"properties\.status[^!\n]*\)?\s*!~\s*['\"]Reject['\"]", kql,
        ), "enrichment side must filter out status='Reject' CVEs"

    def test_severity_read_from_cvedetails_properties(self, kql: str) -> None:
        assert re.search(r"\bproperties\.severity\b", kql), (
            "severity must be read from cvedetails.properties.severity"
        )

    def test_exploit_flags_read_from_cvedetails_properties(
        self, kql: str,
    ) -> None:
        # camelCase container, PascalCase leaves — exactly as the client
        # sample shows. If Microsoft ever ships PascalCase container
        # (`ExploitabilityDetails`) we'll notice via this test.
        for leaf in ("IsInExploitKit", "IsPubliclyDisclosed", "IsVerified"):
            assert re.search(
                rf"properties\.exploitabilityDetails\.{leaf}\b", kql,
            ), f"missing enrichment read: properties.exploitabilityDetails.{leaf}"

    def test_published_date_read_from_cvedetails_properties(
        self, kql: str,
    ) -> None:
        assert re.search(r"\bproperties\.publishedDate\b", kql), (
            "cveAgeDays must be derived from cvedetails.properties.publishedDate"
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
        # currentVersion must come from _scanner.mdvm.DetectedSoftwareVersions.
        # Accept either the single-value shape (`[0]`) or the multi-value
        # shape (`array_length(...)` + `strcat_array(...)` joining all
        # detected versions with a separator).
        assert re.search(
            r"mdvm\.DetectedSoftwareVersions", kql,
        ), "currentVersion must read _scanner.mdvm.DetectedSoftwareVersions"

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
        # `| project` may span multiple lines. Capture everything from
        # `| project` up to the next pipe (which starts the next clause,
        # e.g. `| distinct` or `| order by`).
        projects = re.findall(
            r"\|\s*project\s+(.+?)(?=\n\s*\||\Z)", kql, re.DOTALL,
        )
        assert projects, "no `| project` clause found"
        top_level = [
            p for p in projects
            if "repository" in p and "cveId" in p and "severityRaw" in p
        ]
        assert len(top_level) == 1, (
            f"expected exactly 1 top-level `| project` (18-column CSV), "
            f"got {len(top_level)}"
        )
        # Normalize whitespace/newlines and split into ordered column list.
        collapsed = " ".join(top_level[0].split())
        cols = [c.strip() for c in collapsed.split(",")]
        assert cols == self.EXPECTED_PROJECT_COLUMNS, (
            f"CSV column order is a downstream contract.\n"
            f"expected: {self.EXPECTED_PROJECT_COLUMNS}\n"
            f"     got: {cols}"
        )


class TestSingleLegNotUnion:
    def test_kql_has_no_union(self, kql: str) -> None:
        assert not re.search(r"\|\s*union\s*\(", kql)
