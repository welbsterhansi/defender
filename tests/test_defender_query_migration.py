"""
TDD invariants for the MDVM individual-recommendations migration.

Microsoft retired the legacy `microsoft.security/assessments/subassessments`
type on 2026-07-31 (see docs/investigation-mdvm-2026-08.md). The `defender.sh`
KQL was built on top of that type in Leg A and needs to be rewritten to the
individual-recommendations model that lives under
`microsoft.security/assessments` + `properties.metadata.recommendationCategory
== "SoftwareUpdate"`.

These tests inspect the KQL heredoc embedded in `defender.sh` (they do NOT
run `az`) and enforce the following invariants after migration:

* Leg A (subassessments + c0b7cfc6 UUID) is gone — retired upstream.
* The individual-model entry-point where-clauses are all present.
* Every `additionalData.*` and `cve.*` read that matters is protected by
  `coalesce(PascalCase, camelCase)` because Microsoft emits both casings
  across rows during the transition (pattern validated in the community
  SQL VA migration — Azure/Microsoft-Defender-for-Cloud#1047).
* Severity has a `coalesce(metadata.severity, status.severity)` fallback.
* The CSV column order is preserved — downstream (`expandcsv.py`,
  `group_findings.py`, `report.py`) treats it as a contract.
* The `[DEBUG] MDVM findings` sanity block no longer queries subassessments
  (would silently show 0 rows forever).
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


class TestSubassessmentsGone:
    """Leg A (grouped subassessments) is dead upstream — MS retired the
    type on 2026-07-31. Any query targeting it returns zero rows."""

    def test_kql_has_no_subassessments_type(self, kql: str) -> None:
        assert "subassessments" not in kql.lower(), (
            "Leg A (microsoft.security/assessments/subassessments) is retired — "
            "must be removed from the main KQL"
        )

    def test_kql_has_no_legacy_c0b7cfc6_filter(self, kql: str) -> None:
        """The c0b7cfc6 UUID was Leg A's assessment key filter. Not needed
        in the individual model (we filter by SoftwareUpdate category)."""
        assert "c0b7cfc6-3172-465a-b378-53c7ff2cc0d5" not in kql, (
            "hardcoded c0b7cfc6 filter is a Leg-A artefact — remove"
        )


class TestIndividualModelEntryPoint:
    """The four `where` clauses Microsoft documents as the entry point
    to the individual-recommendations model for ACR containers."""

    def test_type_is_assessments_not_subassessments(self, kql: str) -> None:
        assert re.search(
            r"type\s*[=~]+\s*['\"]microsoft\.security/assessments['\"]",
            kql,
        ), "must query type == 'microsoft.security/assessments'"

    def test_category_softwareupdate(self, kql: str) -> None:
        assert re.search(
            r"recommendationCategory\s*==\s*['\"]SoftwareUpdate['\"]",
            kql,
        ), "must filter by recommendationCategory == 'SoftwareUpdate'"

    def test_resource_type_containerimage(self, kql: str) -> None:
        assert re.search(
            r"ResourceType\s*==\s*['\"]\.containerimage['\"]",
            kql,
        ), "must filter by ResourceType == '.containerimage'"

    def test_source_azure(self, kql: str) -> None:
        assert re.search(
            r"Source\s*==\s*['\"]Azure['\"]",
            kql,
        ), "must filter by resourceDetails.Source == 'Azure'"


def _coalesce_blocks(kql: str) -> list[str]:
    """Yield the body of every top-level `coalesce(...)` call in `kql`,
    using a paren-balanced walker so nested `tostring(...)` etc. don't
    confuse the extraction."""
    bodies: list[str] = []
    lower = kql.lower()
    marker = "coalesce("
    for start in range(len(lower)):
        if not lower.startswith(marker, start):
            continue
        depth = 0
        body_start = start + len(marker)
        i = body_start - 1  # points at '(' of coalesce(
        while i < len(kql):
            ch = kql[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    bodies.append(kql[body_start:i])
                    break
            i += 1
    return bodies


def _has_coalesce_around(kql: str, name_a: str, name_b: str) -> bool:
    """`name_a` and `name_b` both appear inside some coalesce(...) body."""
    return any(name_a in body and name_b in body for body in _coalesce_blocks(kql))


class TestCoalesceGuards:
    """Community-validated migration pattern (Azure/Microsoft-Defender-for-Cloud
    PR #1047, merged 2026-07-02, real-tenant validation): Microsoft emits some
    additionalData fields as PascalCase and some as camelCase across rows in
    the individual model. Every read of a field that varies must be
    `coalesce(PascalCase, camelCase)` to avoid silent nulls."""

    def _has_coalesce_around(self, kql: str, name_a: str, name_b: str) -> bool:
        return _has_coalesce_around(kql, name_a, name_b)

    def test_cvesdetails_coalesced(self, kql: str) -> None:
        assert self._has_coalesce_around(kql, "CvesDetails", "cvesDetails"), (
            "additionalData.CvesDetails must coalesce with camelCase"
        )

    def test_cveid_coalesced(self, kql: str) -> None:
        assert self._has_coalesce_around(kql, "CveId", "cveId"), (
            "cve.CveId must coalesce with cve.cveId"
        )

    def test_cve_severity_coalesced(self, kql: str) -> None:
        assert self._has_coalesce_around(kql, "Severity", "severity"), (
            "cve.Severity must coalesce with cve.severity"
        )

    def test_fixstatus_coalesced(self, kql: str) -> None:
        assert self._has_coalesce_around(kql, "FixStatus", "fixStatus"), (
            "cve.FixStatus must coalesce with cve.fixStatus"
        )

    def test_fixedversion_coalesced(self, kql: str) -> None:
        assert self._has_coalesce_around(kql, "FixedVersion", "fixedVersion"), (
            "cve.FixedVersion must coalesce with cve.fixedVersion"
        )


class TestSeverityFallback:
    """The individual model moved severity from `properties.status.severity`
    (Leg A) to `properties.metadata.severity`. During the transition window
    both may appear — must coalesce to avoid a row losing severity."""

    def test_top_level_severity_has_metadata_status_fallback(self, kql: str) -> None:
        assert _has_coalesce_around(kql, "metadata.severity", "status.severity"), (
            "top-level severity must coalesce metadata.severity + status.severity"
        )


class TestResourceIdDefense:
    """PR #1047 pattern: resource identifiers must coalesce PascalCase +
    camelCase and be normalized via tolower + isnotempty guard, otherwise
    per-casing row splits happen."""

    def test_resource_id_coalesced_pascalcase_camelcase(self, kql: str) -> None:
        assert _has_coalesce_around(
            kql, "resourceDetails.Id", "resourceDetails.id",
        ), "resourceDetails.Id must coalesce with resourceDetails.id"

    def test_has_isnotempty_guard(self, kql: str) -> None:
        assert "isnotempty" in kql, (
            "must guard with | where isnotempty(...) to drop unattributable rows"
        )


class TestCsvColumnOrderPreserved:
    """CSV column order is a downstream contract — `expandcsv.py`,
    `group_findings.py` and `report.py` all key off the KQL `| project`
    column list. The migration MUST preserve the exact same list."""

    EXPECTED_PROJECT_COLUMNS: ClassVar[list[str]] = [
        "repository", "digest", "cvssScore", "cveId", "severityRaw",
        "packageCategory", "packageLanguage", "packageName",
        "currentVersion", "fixedVersion", "patchable", "remediation",
        "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
        "hasVerifiedExploit", "lastPushedToRegistryUTC",
    ]

    def test_project_column_list_matches(self, kql: str) -> None:
        # There should be exactly one `| project ...` clause at the top level
        # (Leg A previously had one, plus Leg B had another). Post-migration:
        # single query, single project.
        projects = re.findall(r"\|\s*project\s+([^\n|]+)", kql)
        assert len(projects) == 1, (
            f"expected exactly 1 `| project` clause post-migration, got {len(projects)}"
        )
        cols = [c.strip() for c in projects[0].split(",")]
        assert cols == self.EXPECTED_PROJECT_COLUMNS, (
            f"CSV column order is a downstream contract.\n"
            f"expected: {self.EXPECTED_PROJECT_COLUMNS}\n"
            f"     got: {cols}"
        )


class TestSingleLegNotUnion:
    """After Leg A removal, the KQL must be a single stream — no union with
    a dead securityresources leg."""

    def test_kql_has_no_union(self, kql: str) -> None:
        # Post-migration: single leg, no union needed. If a future author
        # brings back a union, that's suspicious — force them to reconsider.
        assert not re.search(r"\|\s*union\s*\(", kql), (
            "post-migration KQL should be a single leg — no `| union (...)`"
        )


class TestDebugSanityBlockUpdated:
    """The `[DEBUG] MDVM findings` sanity block (added for troubleshooting)
    also targeted subassessments — would silently return 0 rows forever."""

    def test_debug_block_does_not_query_subassessments(
        self, defender_source: str,
    ) -> None:
        # Find any `az graph query` invocations in the source, ensure
        # none of them still target subassessments.
        for match in re.finditer(r"az\s+graph\s+query[^\n]*", defender_source):
            snippet = match.group(0)
            assert "subassessments" not in snippet.lower(), (
                f"an `az graph query` still targets subassessments — will "
                f"return zero rows always:\n  {snippet}"
            )
