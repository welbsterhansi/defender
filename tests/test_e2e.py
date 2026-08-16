"""
End-to-end pipeline test — offline, no Azure or OpenShift calls.

Exercises the full local flow that operators run after
`defender.sh` and `check_ocp.sh` produce their CSVs:

  defender.csv  +  cruzamento.csv
    → expandcsv.load_vulnerability_data
    → expandcsv.expand_cves
    → expandcsv.write_output
    → report.load_data
    → report.build_html

Guards the invariants operators care about most:
  - expanded.csv has one row per unique (workload, CVE)
  - HTML surfaces the fields dev teams need to remediate
  - No mojibake ever reaches the rendered HTML
  - Missing required columns fail loudly and early
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

import expandcsv
import report

# ---------------------------------------------------------------------------
# Full pipeline — happy path
# ---------------------------------------------------------------------------

def test_e2e_full_pipeline(
    defender_csv_normal: Path,
    cruzamento_csv_new: Path,
    tmp_path: Path,
) -> None:
    # ---- Stage 1: load defender data (3 indexes) ---------------------------
    idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
        str(defender_csv_normal)
    )
    assert idx_full, "defender fixture should have populated the full index"
    # 3 rows in the fixture → 3 keys in idx_full
    assert len(idx_full) == 3
    # Sanity: the same rows show up in the fallback indexes
    assert idx_digest, "digest fallback index should not be empty"

    # ---- Stage 2: expand grouped rows into per-CVE rows --------------------
    rows = expandcsv.expand_cves(
        str(cruzamento_csv_new), idx_full, idx_digest, idx_prefix
    )
    # cruzamento fixture has:
    #   backend workload: CVE-2024-0001 + CVE-2024-0002 = 2 rows
    #   database workload: CVE-2024-0003 = 1 row
    assert len(rows) == 3
    assert {r["CVE_ID"] for r in rows} == {
        "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"
    }
    # Every row is a fully populated dict — no stragglers
    for r in rows:
        assert set(r.keys()) == set(expandcsv.OUTPUT_FIELDS)
        assert r["CVE_ID"].startswith("CVE-")
        assert r["NAMESPACE"]
        assert r["REPOSITORY"]
        assert r["DIGEST"].startswith("sha256:")

    # ---- Stage 3: write to disk and re-parse -------------------------------
    expanded_path = tmp_path / "expanded.csv"
    expandcsv.write_output(rows, str(expanded_path))
    assert expanded_path.exists()

    with expanded_path.open(encoding="utf-8", newline="") as f:
        reloaded = list(csv.DictReader(f))
    assert len(reloaded) == 3
    # Column order matches spec
    with expanded_path.open(encoding="utf-8", newline="") as f:
        header = next(csv.reader(f))
    assert header == expandcsv.OUTPUT_FIELDS

    # ---- Stage 4: render HTML ---------------------------------------------
    ns = report.load_data(str(cruzamento_csv_new), str(expanded_path))
    html = report.build_html(ns)

    # Structural checks — dev-facing fields present
    must_contain = {
        "repository":       "myapp/backend",
        "tag":              "v1.2",
        "digest (prefix)":  "sha256:aaa111",
        "CVE id":           "CVE-2024-0001",
        "package name":     "django",
        "current version":  "4.1.0",
        "fixed version":    "4.2.11",
    }
    for label, needle in must_contain.items():
        assert needle in html, f"HTML missing {label}: expected {needle!r}"

    # Icons — the fixture exercises all three exploit states + patch states
    #   CVE-2024-0002: hasVerifiedExploit=true → lit "V" chip
    #   CVE-2024-0001: patchable=true          → ✅
    #   CVE-2024-0003: patchable=false         → ❌
    assert 'class="expl-chip on-v"' in html, "verified exploit chip missing"
    assert "✅" in html, "patchable check missing"
    assert "❌" in html, "not-patchable cross missing"

    # ---- Task #15: Vulnerable Images section ------------------------------
    # The dev-friendly view groups by (repo, tag, digest) and lists workloads
    # that consume each image. Contract:
    assert "Vulnerable Images" in html, "new dev-facing section title missing"
    assert "Runs in:" in html, "workload attribution row missing"

    # ---- Task #35: no client branding leaks into the HTML -----------------
    # Client name must never appear in the generated report — it belongs to
    # gitignored local docs only. Regex-catch common casings.
    import re as _re
    assert not _re.search(r"novo\s*banco", html, _re.IGNORECASE), \
        "client name leaked into HTML output"

    # ---- Task #34: full image reference `repo:tag@digest` + copy button ---
    # Devs remediate by tag, so the header must expose the full pinnable
    # reference and let the operator copy it in one click.
    repo, tag, digest = "myapp/backend", "v1.2", "sha256:aaa111"
    full_ref = f"{repo}:{tag}@{digest}"
    assert repo in html, "repository missing from header"
    assert f":{tag}" in html, "tag missing from header (should be visually prominent)"
    assert digest in html, "digest missing from header"
    assert full_ref in html, (
        f"full reference '{full_ref}' should appear as one copyable string"
    )
    # Copy button for the reference must exist with the payload as data-copy.
    assert 'class="copy-btn copy-btn-ref"' in html, "image reference copy button missing"
    assert f'data-copy="{full_ref}"' in html, "copy button payload must be repo:tag@digest"
    # PR-UX-4: the tag no longer renders as a separate `.img-tag` chip;
    # it now lives inline with the repo inside the unified `.img-ref-primary`
    # line (bold, full-size), so the same visual-prominence intent is
    # preserved without a per-tab chip class. The reference itself is
    # canonicalised via `.img-ref` (used by both Images and OpenShift tabs).
    assert 'class="img-ref"' in html, "unified image-reference class missing"
    assert 'class="img-ref-primary"' in html, "image-reference primary line missing"

    # ---- Task #16: Weaponized KPI -----------------------------------------
    # KPI counts CVE entries that have any exploit signal.
    # Fixture: CVE-2024-0001 has hasVerifiedExploit=true → weaponized ≥ 1
    assert "Weaponized" in html, "Weaponized KPI label missing"

    # ---- Task #17: copy button on current → fixed -------------------------
    # Each version cell must expose a `data-copy` attribute (dev clipboard)
    # and the JS handler `cpy(` must be present exactly once.
    assert 'class="copy-btn"' in html, "copy button class missing"
    assert 'data-copy=' in html, "copy button payload attribute missing"
    assert 'function cpy(' in html, "cpy JS handler missing"
    # Payload includes the package name so devs paste ready-to-use snippets.
    assert 'data-copy="django 4.1.0 → 4.2.11"' in html, \
        "copy payload should be `<pkg> <current> → <fixed>`"

    # ---- Task #18: client-side filters ------------------------------------
    # Filter bar controls
    assert 'id="fSev"' in html, "severity filter select missing"
    assert 'id="fPatch"' in html, "patchable filter missing"
    assert 'id="fExpl"' in html, "exploit filter missing"
    assert 'id="fSearch"' in html, "text search input missing"
    assert 'function applyFilters(' in html, "applyFilters JS missing"
    # Data attributes on rows (so JS can filter)
    assert 'data-sev="Critical"' in html, "row data-sev missing"
    assert 'data-patch="true"' in html, "row data-patch missing"
    # PR-UX-2 Task 3: single `data-expl` collapsed into 3 independent
    # attributes so the exploit filter can isolate Verified / Published /
    # In-kit individually. All three must be emitted so the JS filter
    # (`applyFilters()`) has values to test against.
    assert 'data-v="' in html, "row data-v missing (Verified exploit signal)"
    assert 'data-p="' in html, "row data-p missing (Published exploit signal)"
    assert 'data-k="' in html, "row data-k missing (In-Kit exploit signal)"
    # Cards must carry lowercased data-search for the free-text filter
    assert 'data-search="' in html, "card data-search missing"

    # ---- Task #19: no hard-coded namespaces/CVEs in Analysis block --------
    # Assert on strings that CANNOT come from the fixture — only from the
    # previously hard-coded copy in the analysis block. The fixture uses
    # `prd-fad` and `prd-shared` as legitimate namespace names, so we can't
    # ban those; but these composites/names never appear in fixture data:
    for stale in (
        "prd-fad/financebatch", "prd-fad/realtime", "rhsso-prd/rhsso-prd",
        "prd-airflow", "prd-env0", "prd-simul-internal",
        "CVE-2024-52533", "CVE-2022-23990", "CVE-2025-6965",
    ):
        assert stale not in html, f"hard-coded {stale!r} leaked into HTML output"


def test_e2e_build_image_view_groups_by_image_and_dedups(
    defender_csv_normal: Path,
    cruzamento_csv_new: Path,
    tmp_path: Path,
) -> None:
    """build_image_view collapses per-workload rows into per-image entries."""
    idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
        str(defender_csv_normal)
    )
    rows = expandcsv.expand_cves(
        str(cruzamento_csv_new), idx_full, idx_digest, idx_prefix
    )
    expanded_path = tmp_path / "expanded.csv"
    expandcsv.write_output(rows, str(expanded_path))
    ns = report.load_data(str(cruzamento_csv_new), str(expanded_path))

    images = report.build_image_view(ns)
    # Fixture: 2 distinct images (myapp/backend + shared/base)
    assert len(images) == 2

    keys = {(img["repo"], img["tag"], img["digest"]) for img in images}
    assert ("myapp/backend", "v1.2", "sha256:aaa111") in keys
    assert ("shared/base", "latest", "sha256:bbb222") in keys

    # Ordered by max CVSS desc — backend has CVE 10.0, shared has 9.1
    assert images[0]["repo"] == "myapp/backend"
    assert images[0]["max_score"] == 10.0
    assert images[1]["max_score"] == 9.1

    # Weaponized counting — backend CVE-2024-0002 has hasVerifiedExploit=true
    backend = images[0]
    assert backend["weaponized_count"] >= 1
    # And CVEs are deduped per image (same CVE across 2 workloads = 1 entry)
    assert len({c["id"] for c in backend["cves"]}) == len(backend["cves"])


# ---------------------------------------------------------------------------
# No mojibake escapes to the final HTML
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mojibake_signature", [
    "â€",      # em/en dash, ellipsis mojibake
    "ðŸ",      # broken emoji leading bytes
    "âŒ",      # broken cross mark
    "âœ…",     # broken check mark
    "Ã³",      # broken ó
    "â‰¥",     # broken ≥
])
def test_e2e_html_has_no_mojibake(
    mojibake_signature: str,
    defender_csv_normal: Path,
    cruzamento_csv_new: Path,
    tmp_path: Path,
) -> None:
    idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
        str(defender_csv_normal)
    )
    rows = expandcsv.expand_cves(
        str(cruzamento_csv_new), idx_full, idx_digest, idx_prefix
    )
    expanded_path = tmp_path / "expanded.csv"
    expandcsv.write_output(rows, str(expanded_path))
    ns = report.load_data(str(cruzamento_csv_new), str(expanded_path))
    html = report.build_html(ns)

    assert mojibake_signature not in html, (
        f"mojibake {mojibake_signature!r} leaked into HTML — "
        f"check source files for UTF-8 corruption"
    )
    # Also confirm the string is valid UTF-8
    html.encode("utf-8", errors="strict")


# ---------------------------------------------------------------------------
# Error handling: missing required column fails loudly
# ---------------------------------------------------------------------------

def test_e2e_missing_required_column_raises(
    defender_csv_missing_columns: Path,
) -> None:
    with pytest.raises(ValueError) as exc_info:
        expandcsv.load_vulnerability_data(str(defender_csv_missing_columns))

    msg = str(exc_info.value)
    # Message must name at least one missing column so the operator can fix
    # the upstream CSV without guessing.
    assert "missing" in msg.lower()
    assert any(col in msg for col in ("cveId", "digest", "repository"))


# ---------------------------------------------------------------------------
# No accidental network / subprocess calls in the offline pipeline
# ---------------------------------------------------------------------------

def test_exploit_flags_survive_full_pipeline(
    defender_csv_normal: Path,
    cruzamento_csv_new: Path,
    tmp_path: Path,
) -> None:
    """
    Regression guard for task #37: adding --repositories to defender.sh must
    NOT change how exploit flags are interpreted downstream.

    Fixture: `defender_csv_normal` has CVE-2024-0002 flagged as
    hasVerifiedExploit=true on `myapp/backend@sha256:aaa111`, which is used by
    `prd-fad/Deployment/backend` in `cruzamento_csv_new`.

    Contract: that flag must survive every stage — the defender index, the
    expand step, the on-disk expanded.csv, and the final rendered HTML (as a
    red-circle icon).
    """
    # Stage 1: defender data loaded — flag reachable in the index
    idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
        str(defender_csv_normal)
    )
    verified_key = ("myapp/backend", "sha256:aaa111", "CVE-2024-0002")
    assert verified_key in idx_full, "defender fixture must have the CVE"
    assert idx_full[verified_key]["HAS_VERIFIED_EXPLOIT"] == "true", (
        "verified-exploit flag lost on load_vulnerability_data"
    )

    # Stage 2: expand_cves preserves the flag per (workload, CVE)
    rows = expandcsv.expand_cves(
        str(cruzamento_csv_new), idx_full, idx_digest, idx_prefix
    )
    verified_rows = [r for r in rows if r["CVE_ID"] == "CVE-2024-0002"]
    assert verified_rows, "expand_cves dropped the CVE"
    for r in verified_rows:
        assert r["HAS_VERIFIED_EXPLOIT"] == "true", (
            f"verified-exploit flag lost on expand_cves: {r!r}"
        )

    # Stage 3: expanded.csv on disk keeps the column populated
    expanded_path = tmp_path / "expanded.csv"
    expandcsv.write_output(rows, str(expanded_path))
    with expanded_path.open(encoding="utf-8", newline="") as f:
        disk_rows = list(csv.DictReader(f))
    disk_verified = [r for r in disk_rows if r["CVE_ID"] == "CVE-2024-0002"]
    assert disk_verified
    for r in disk_verified:
        assert r["HAS_VERIFIED_EXPLOIT"] == "true", (
            "verified-exploit flag lost on write_output"
        )

    # Stage 4: report picks it up and renders the lit "V" chip for verified exploit
    ns = report.load_data(str(cruzamento_csv_new), str(expanded_path))
    html = report.build_html(ns)
    assert 'class="expl-chip on-v"' in html, (
        "verified-exploit CVE did not render the lit V chip in HTML"
    )
    # And the weaponized KPI counts it (>= 1 entry weaponized)
    assert 'class="kpi-num critical"' in html, (
        "Weaponized KPI should be red when >=1 exploit is present"
    )


def test_e2e_no_subprocess_calls(
    monkeypatch: pytest.MonkeyPatch,
    defender_csv_normal: Path,
    cruzamento_csv_new: Path,
    tmp_path: Path,
) -> None:
    """Guard against future regressions that shell out to `az` or `oc`."""
    import subprocess

    def _boom(*args, **kwargs):
        raise AssertionError(
            f"E2E pipeline invoked subprocess: args={args} kwargs={kwargs}"
        )

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "check_output", _boom)
    monkeypatch.setattr(subprocess, "check_call", _boom)

    idx_full, idx_digest, idx_prefix = expandcsv.load_vulnerability_data(
        str(defender_csv_normal)
    )
    rows = expandcsv.expand_cves(
        str(cruzamento_csv_new), idx_full, idx_digest, idx_prefix
    )
    expanded_path = tmp_path / "expanded.csv"
    expandcsv.write_output(rows, str(expanded_path))
    ns = report.load_data(str(cruzamento_csv_new), str(expanded_path))
    _ = report.build_html(ns)
