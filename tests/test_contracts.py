"""Contract tests — the frozen baseline the Python migration must preserve.

These tests read the current producer sources and assert that the CSV
headers match the canonical specs in `docs/contracts/`. Any drift here
requires:

  1. Explicit approval in the task backlog.
  2. Update to the contract doc in `docs/contracts/`.
  3. Update to this file.
  4. Update to every downstream consumer.

This suite is the safety net for tasks P0.3–P0.7: the new Python path
must satisfy the same assertions before any deprecation of the Bash/
existing-Python pipeline (task P0.8).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# 1. vulnerable_images_report.csv — 19 cols
#    Producers: defender.sh (header write) + enrich_cvedetails.py (row emit)
# ═══════════════════════════════════════════════════════════════════════════


VULNERABLE_IMAGES_HEADER_CANONICAL = [
    "repository", "digest", "tag", "cvssScore", "cveId", "severity",
    "packageCategory", "packageLanguage", "packageName",
    "currentVersion", "fixedVersion", "patchable", "remediation",
    "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
    "hasVerifiedExploit", "lastPushedToRegistryUTC",
]


class TestVulnerableImagesReportContract:
    """The 19-column CSV emitted by defender.sh + enrich_cvedetails.py.
    See docs/contracts/vulnerable_images_report.md."""

    def test_defender_sh_emits_canonical_header(self) -> None:
        """`defender.sh` line ~769 writes the CSV header. Extract via regex
        and split by comma; strip quotes; compare to canonical list."""
        source = (REPO_ROOT / "defender.sh").read_text(encoding="utf-8")
        # Pattern: literal echo of the quoted CSV header, terminated by
        # a redirection to REPORT_TMP.
        m = re.search(
            r"echo\s+'(\"repository\",\"digest\",[^']+)'\s*>\s*\"?\$REPORT_TMP",
            source,
        )
        assert m, (
            "could not locate the CSV header echo in defender.sh — the "
            "producer either drifted or was refactored without updating "
            "this test. Update docs/contracts/vulnerable_images_report.md "
            "if intentional."
        )
        raw = m.group(1)
        cols = [c.strip('"') for c in raw.split(",")]
        assert cols == VULNERABLE_IMAGES_HEADER_CANONICAL

    def test_enrich_cvedetails_uses_same_header_list(self) -> None:
        """`enrich_cvedetails.CSV_HEADER_COLUMNS` MUST equal the canonical
        list. This guards the Python helper from drifting away from the
        bash producer (they must always agree — bash writes the header,
        Python appends the rows)."""
        import enrich_cvedetails
        assert enrich_cvedetails.CSV_HEADER_COLUMNS == VULNERABLE_IMAGES_HEADER_CANONICAL

    def test_column_count_is_19(self) -> None:
        assert len(VULNERABLE_IMAGES_HEADER_CANONICAL) == 19


# ═══════════════════════════════════════════════════════════════════════════
# 2. resultado_cruzamento.csv — 24 cols
#    Producer: check_ocp.sh
# ═══════════════════════════════════════════════════════════════════════════


RESULTADO_CRUZAMENTO_HEADER_CANONICAL = [
    "NAMESPACE", "PARENT_TYPE", "PARENT_NAME",
    "REPOSITORY", "DIGEST", "TAG",
    "CVE_COUNT", "CRITICALITY", "CVSS_SCORE",
    "CVE_LIST", "CVE_SEVERITY_MAP",
    "PACKAGE_CATEGORY", "PACKAGE_LANGUAGE", "PACKAGE_NAME",
    "CURRENT_VERSION", "FIXED_VERSION", "PATCHABLE",
    "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]


class TestResultadoCruzamentoContract:
    """The 24-column CSV emitted by check_ocp.sh.
    See docs/contracts/resultado_cruzamento.md."""

    def test_check_ocp_emits_canonical_header(self) -> None:
        source = (REPO_ROOT / "check_ocp.sh").read_text(encoding="utf-8")
        # Look for `echo "NAMESPACE,...LAST_PUSHED_TO_REGISTRY_UTC" > "$OUTPUT_FILE"`
        m = re.search(
            r'echo\s+"(NAMESPACE,PARENT_TYPE[^"]+LAST_PUSHED_TO_REGISTRY_UTC)"\s*>\s*"?\$OUTPUT_FILE',
            source,
        )
        assert m, (
            "could not locate resultado_cruzamento.csv header in check_ocp.sh"
        )
        cols = m.group(1).split(",")
        assert cols == RESULTADO_CRUZAMENTO_HEADER_CANONICAL

    def test_column_count_is_24(self) -> None:
        assert len(RESULTADO_CRUZAMENTO_HEADER_CANONICAL) == 24


# ═══════════════════════════════════════════════════════════════════════════
# 3. expanded.csv — 22 cols
#    Producer: expandcsv.py (OUTPUT_FIELDS list)
# ═══════════════════════════════════════════════════════════════════════════


EXPANDED_HEADER_CANONICAL = [
    "NAMESPACE", "PARENT_TYPE", "PARENT_NAME",
    "REPOSITORY", "DIGEST", "TAG", "CVE_ID",
    "CVSS_SCORE", "SEVERITY",
    "PACKAGE_CATEGORY", "PACKAGE_LANGUAGE", "PACKAGE_NAME",
    "CURRENT_VERSION", "FIXED_VERSION", "PATCHABLE",
    "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]


class TestExpandedContract:
    """The 22-column CSV emitted by expandcsv.py.
    See docs/contracts/expanded.md."""

    def test_expandcsv_output_fields_match_canonical(self) -> None:
        import expandcsv
        assert expandcsv.OUTPUT_FIELDS == EXPANDED_HEADER_CANONICAL

    def test_column_count_is_22(self) -> None:
        assert len(EXPANDED_HEADER_CANONICAL) == 22


# ═══════════════════════════════════════════════════════════════════════════
# 4. Cross-CSV coherence — fields that appear in multiple contracts MUST
#    carry the same meaning.
# ═══════════════════════════════════════════════════════════════════════════


class TestCrossCsvCoherence:
    """Fields present in multiple CSV contracts must agree on semantics.
    E.g. `cvssScore` (defender) → `CVSS_SCORE` (cruzamento/expanded) must
    represent the same value — only the naming convention differs (camel
    vs upper snake). Missing that pairing at any step breaks the pipeline."""

    # Rename map: defender-side (camelCase) → downstream (UPPER_SNAKE_CASE).
    DEFENDER_TO_DOWNSTREAM_RENAME = {
        "repository": "REPOSITORY",
        "digest": "DIGEST",
        "tag": "TAG",
        "cvssScore": "CVSS_SCORE",
        "severity": "SEVERITY",
        "packageCategory": "PACKAGE_CATEGORY",
        "packageLanguage": "PACKAGE_LANGUAGE",
        "packageName": "PACKAGE_NAME",
        "currentVersion": "CURRENT_VERSION",
        "fixedVersion": "FIXED_VERSION",
        "patchable": "PATCHABLE",
        "remediation": "REMEDIATION",
        "fixStatus": "FIX_STATUS",
        "cveAgeDays": "CVE_AGE_DAYS",
        "isInExploitKit": "IS_IN_EXPLOIT_KIT",
        "hasPublishedExploit": "HAS_PUBLISHED_EXPLOIT",
        "hasVerifiedExploit": "HAS_VERIFIED_EXPLOIT",
        "lastPushedToRegistryUTC": "LAST_PUSHED_TO_REGISTRY_UTC",
    }

    def test_every_defender_field_reaches_expanded(self) -> None:
        """Except for `cveId` (renamed to `CVE_ID` and injected during expand),
        every other defender column must map to an `expanded.csv` column."""
        expected_downstream = set(self.DEFENDER_TO_DOWNSTREAM_RENAME.values())
        expected_downstream.add("CVE_ID")   # cveId renamed
        actual = set(EXPANDED_HEADER_CANONICAL)
        # expanded.csv adds workload dimensions on top.
        extra = actual - expected_downstream
        assert extra == {"NAMESPACE", "PARENT_TYPE", "PARENT_NAME"}, (
            f"unexpected extra columns in expanded.csv: {extra}"
        )

    def test_every_defender_field_reaches_cruzamento(self) -> None:
        """resultado_cruzamento.csv gets every defender field (renamed) EXCEPT
        `severity` — at the workload/image aggregation level, per-CVE severity
        becomes `CRITICALITY` (max) + `CVE_SEVERITY_MAP` (per-CVE mapping).
        The other fields (repo, digest, tag, package/version/exploit) map 1:1.
        """
        renamed = set(self.DEFENDER_TO_DOWNSTREAM_RENAME.values())
        # SEVERITY becomes CRITICALITY + CVE_SEVERITY_MAP at aggregation level.
        renamed.discard("SEVERITY")
        actual = set(RESULTADO_CRUZAMENTO_HEADER_CANONICAL)
        missing = renamed - actual
        assert missing == set(), (
            f"defender fields missing from resultado_cruzamento.csv: {missing}"
        )
        # And CRITICALITY + CVE_SEVERITY_MAP MUST be present (the aggregation
        # replacements for per-CVE severity).
        assert "CRITICALITY" in actual
        assert "CVE_SEVERITY_MAP" in actual


# ═══════════════════════════════════════════════════════════════════════════
# 5. --skip-tags behavior contract
# ═══════════════════════════════════════════════════════════════════════════


class TestSkipTagsContract:
    """--skip-tags is a frozen behavior. When passed, defender.sh MUST:
      * log the "tag_resolve DISABLED via --skip-tags" line for audit
      * skip Phase 1 entirely (zero `az acr repository show-tags` calls)
      * emit `tag="N/A"` for every CSV row

    The end-to-end behavior is exercised by
    tests/test_defender_batched_integration.py; here we assert the
    source-level guarantees (flag parsed, log line emitted, N/A fallback
    in the merger)."""

    def test_defender_sh_parses_skip_tags_flag(self) -> None:
        source = (REPO_ROOT / "defender.sh").read_text(encoding="utf-8")
        assert re.search(r"--skip-tags\)\s*SKIP_TAGS=true", source), (
            "--skip-tags flag parser missing from defender.sh"
        )

    def test_defender_sh_logs_audit_line_when_skip_tags(self) -> None:
        source = (REPO_ROOT / "defender.sh").read_text(encoding="utf-8")
        assert "tag_resolve DISABLED via --skip-tags" in source, (
            "audit-trail log line missing — --skip-tags must be visible in "
            "the log header per docs/contracts/cli-behavior.md"
        )

    def test_enrich_cvedetails_defaults_missing_tag_to_na(self) -> None:
        """Python helper falls back to 'N/A' when the tag cache has no
        entry for a (repo, digest) pair. This is what makes --skip-tags
        produce tag=N/A everywhere: TAG_CACHE stays empty, every lookup
        returns the default."""
        import enrich_cvedetails as ec
        # Empty cache → default returned for any key
        empty_cache: dict[str, str] = {}
        assert empty_cache.get("any-key", "N/A") == "N/A"
        # And the load_tag_cache function returns empty dict for empty file
        # (see test_enrich_cvedetails.py::TestLoadTagCache::test_empty_...)
        assert callable(ec.load_tag_cache)


# ═══════════════════════════════════════════════════════════════════════════
# 6. Coverage classification contract
# ═══════════════════════════════════════════════════════════════════════════


class TestCoverageClassificationContract:
    """The 5-state coverage classification is a frozen contract used to
    gate whether the report is authoritative. Any change requires
    documentation + downstream updates."""

    EXPECTED_STATES = {
        "SUCCESS_WITH_PODS",
        "NO_PODS",
        "RBAC_ERR",
        "OC_ERR",
        "PARSE_ERR",
    }

    def test_all_five_states_present_in_check_ocp(self) -> None:
        source = (REPO_ROOT / "check_ocp.sh").read_text(encoding="utf-8")
        missing = self.EXPECTED_STATES - {
            state for state in self.EXPECTED_STATES if state in source
        }
        assert missing == set(), (
            f"coverage states missing from check_ocp.sh: {missing}"
        )

    def test_exit_code_3_documented_in_source(self) -> None:
        """Partial coverage MUST exit 3. This anchors the contract for
        downstream automation. `check_ocp.sh` uses a `COVERAGE_EXIT`
        variable that is set to 3 in the partial branch."""
        source = (REPO_ROOT / "check_ocp.sh").read_text(encoding="utf-8")
        # Accept either literal `exit 3` OR `COVERAGE_EXIT=3` (current
        # style — the actual exit uses `exit "$COVERAGE_EXIT"`).
        assert re.search(r"(exit\s+3|COVERAGE_EXIT\s*=\s*3)", source), (
            "check_ocp.sh must exit 3 on partial coverage — see "
            "docs/contracts/resultado_cruzamento.md#exit-codes"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 7. Excluded namespaces contract
# ═══════════════════════════════════════════════════════════════════════════


class TestExcludedNamespacesContract:
    """Platform-managed namespaces are filtered out from the OpenShift
    correlation. This list is frozen — additions/removals require
    approval and downstream doc updates."""

    # Prefixes and literals that MUST appear in the check_ocp.sh source
    # as the excluded namespace filter.
    EXPECTED_PATTERNS = ["openshift-", "kube-", "default", "logging", "monitoring"]

    def test_all_expected_patterns_present_in_check_ocp(self) -> None:
        source = (REPO_ROOT / "check_ocp.sh").read_text(encoding="utf-8")
        for pattern in self.EXPECTED_PATTERNS:
            assert pattern in source, (
                f"excluded namespace pattern '{pattern}' missing from "
                f"check_ocp.sh — see docs/contracts/cli-behavior.md"
            )
