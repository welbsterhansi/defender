#!/usr/bin/env python3
"""Local enrichment merger — two-phase batched Defender scan (P2, 2026-09).

Reads two JSONL files produced by `defender.sh`:
  * assessments.jsonl — one row per (repo, digest, CVE) from Query A
    (no join). Includes 6 `inline*` fallback fields for when cvedetails
    has no matching row.
  * cvedetails.jsonl — one row per unique CVE ID from Query B. `cveIdJoin`
    is already upper-cased by the KQL.

Merges by upper(cveId), applies min/max cvssScore filter, and appends the
final 19-column CSV in the exact same format as defender.sh's `csv_field` /
`csv_write_row` (double-quoted, internal `"` → `'`, newlines collapsed).

Called from defender.sh after both Query A and Query B have completed.

Usage:
    python3 enrich_cvedetails.py \\
        --assessments <path> \\
        --cvedetails <path> \\
        --tag-cache <path> \\
        --output <path> \\
        --min-score 0.0 --max-score 10.0

`--tag-cache` is a TSV `key\\tvalue` file where key = "repo@digest" and
value = the resolved tag (or absent → "N/A" default at emit time).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


CSV_HEADER_COLUMNS = [
    "repository", "digest", "tag", "cvssScore", "cveId", "severity",
    "packageCategory", "packageLanguage", "packageName",
    "currentVersion", "fixedVersion", "patchable", "remediation",
    "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
    "hasVerifiedExploit", "lastPushedToRegistryUTC",
]


def csv_field(value: Any) -> str:
    """Match defender.sh:40-46 `csv_field` exactly.

    Wraps in double quotes, replaces internal `"` with `'`, collapses
    newlines and carriage returns to a single space so a multi-line
    remediation string never breaks the row.
    """
    s = "" if value is None else str(value)
    s = s.replace('"', "'").replace("\n", " ").replace("\r", " ")
    return f'"{s}"'


def csv_write_row(fout: TextIO, values: list[Any]) -> None:
    """Match defender.sh:48-55 `csv_write_row` exactly."""
    fout.write(",".join(csv_field(v) for v in values) + "\n")


def classify_severity(score: float) -> str:
    """Match defender.sh:57-70 `classify_severity` exactly."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def cvss_from_severity(severity: str) -> float:
    """Fallback matching the case-on-severity block in the old KQL."""
    s = (severity or "").strip().lower()
    if s == "critical":
        return 9.0
    if s == "high":
        return 7.0
    if s == "medium":
        return 4.0
    if s == "low":
        return 0.1
    return 0.0


def to_bool(value: Any) -> bool:
    """Robust bool coercion — handles JSON true/false, "true"/"True",
    "1"/"0", and null-ish (empty, None) → False."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in ("true", "1")


def bool_str(value: Any) -> str:
    """Emit as 'true'/'false' string — matches defender.sh iff(...) output."""
    return "true" if to_bool(value) else "false"


def to_float(value: Any) -> float | None:
    """Best-effort float. Returns None on empty/invalid."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_published_date(s: str) -> datetime | None:
    """Accept ISO 8601 with/without timezone; return None on invalid."""
    if not s:
        return None
    # Trim/normalize common ARG shapes.
    normalized = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_patchable(fix_status: str, fixed_version: str) -> str:
    """Match defender.sh KQL patchable case exactly."""
    s = (fix_status or "").strip().lower()
    if s == "fixavailable":
        return "true"
    if s in ("nofix", "nofixavailable", "willnotfix"):
        return "false"
    if (fixed_version or "").strip():
        return "true"
    return ""


def load_cvedetails(path: Path) -> dict[str, dict[str, Any]]:
    """Load Query B rows into a dict keyed by uppercase CveId.

    Duplicate keys (shouldn't happen — KQL summarizes) keep the last row.
    """
    enrichment: dict[str, dict[str, Any]] = {}
    if not path.exists() or path.stat().st_size == 0:
        return enrichment
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"warn: cvedetails line {line_num} invalid JSON: {exc}",
                    file=sys.stderr,
                )
                continue
            key = str(row.get("cveIdJoin") or "").upper()
            if key:
                enrichment[key] = row
    return enrichment


def load_tag_cache(path: Path) -> dict[str, str]:
    """Load TSV tag cache. Empty file → empty dict."""
    tags: dict[str, str] = {}
    if not path.exists() or path.stat().st_size == 0:
        return tags
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if "\t" not in line:
                continue
            k, v = line.split("\t", 1)
            tags[k] = v
    return tags


def enrich_and_emit(
    assessments: Path,
    cvedetails: Path,
    tag_cache: Path,
    output: Path,
    min_score: float,
    max_score: float,
) -> tuple[int, int, int]:
    """Merge and emit. Returns (rows_read, rows_emitted, rows_enriched).

    `output` is opened in append mode — defender.sh writes the CSV header
    before calling us, so we only append data rows.
    """
    enrichment = load_cvedetails(cvedetails)
    tags = load_tag_cache(tag_cache)

    now = datetime.now(timezone.utc)
    seen: set[tuple] = set()
    rows_read = 0
    rows_emitted = 0
    rows_enriched = 0

    if not assessments.exists() or assessments.stat().st_size == 0:
        return (0, 0, 0)

    with assessments.open("r", encoding="utf-8") as fin, \
         output.open("a", encoding="utf-8") as fout:
        for line_num, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"warn: assessments line {line_num} invalid JSON: {exc}",
                    file=sys.stderr,
                )
                continue

            rows_read += 1
            cve_id = str(row.get("cveId") or "")
            if not cve_id.startswith("CVE-"):
                continue

            enr = enrichment.get(cve_id.upper(), {})
            has_enrichment = bool(enr)
            if has_enrichment:
                rows_enriched += 1

            # ── severity: enrichment → inline → CVSS-derived fallback ──
            severity_raw = (
                str(enr.get("severityEnrich") or "").strip()
                or str(row.get("inlineSeverity") or "").strip()
            )

            # ── cvssScore: enrichment → inline base → case-on-severity ──
            cvss = to_float(enr.get("cvssEnrich"))
            if cvss is None or cvss == 0.0:
                inline = to_float(row.get("inlineCvssBase"))
                if inline and inline > 0:
                    cvss = inline
                else:
                    cvss = cvss_from_severity(severity_raw)

            # ── min/max score filter (matches the KQL where clause) ──
            if cvss < min_score or cvss > max_score:
                continue

            # ── severity final: raw wins, else CVSS-derived ──
            severity = severity_raw or classify_severity(cvss)

            # ── cveAgeDays ──
            published_str = (
                str(enr.get("publishedDateEnrich") or "").strip()
                or str(row.get("inlinePublishedDate") or "").strip()
            )
            published_dt = parse_published_date(published_str)
            if published_dt is not None:
                cve_age_days = (now - published_dt).days
            else:
                cve_age_days = -1

            # ── exploit chips: enrichment > inline ──
            def exploit_flag(enrich_key: str, inline_key: str) -> str:
                v = enr.get(enrich_key)
                if v is not None and str(v).strip() != "":
                    return bool_str(v)
                return bool_str(row.get(inline_key))

            in_kit = exploit_flag("inExploitKitEnrich", "inlineInExploitKit")
            pub_exp = exploit_flag("publishedExpEnrich", "inlinePubliclyDisclosed")
            ver_exp = exploit_flag("verifiedExpEnrich", "inlineVerified")

            # ── patchable ──
            fix_status = str(row.get("fixStatus") or "")
            fixed_version = str(row.get("fixedVersion") or "")
            patchable = compute_patchable(fix_status, fixed_version)

            # ── tag lookup (bash-side cache) ──
            repo = str(row.get("repository") or "")
            digest = str(row.get("digest") or "")
            tag = tags.get(f"{repo}@{digest}", "N/A")

            # ── distinct on all 18 KQL-projected fields (before tag) ──
            # cvss is normalized to a printable string to match KQL semantics
            # (double → tostring in the projection).
            cvss_str = f"{cvss:g}"
            distinct_key = (
                repo, digest, cvss_str, cve_id, severity,
                str(row.get("packageCategory") or ""),
                str(row.get("packageLanguage") or ""),
                str(row.get("packageName") or ""),
                str(row.get("currentVersion") or ""),
                fixed_version, patchable,
                str(row.get("remediation") or ""),
                fix_status, str(cve_age_days),
                in_kit, pub_exp, ver_exp,
                str(row.get("lastPushedToRegistryUTC") or ""),
            )
            if distinct_key in seen:
                continue
            seen.add(distinct_key)

            csv_write_row(fout, [
                repo, digest, tag,
                cvss_str, cve_id, severity,
                str(row.get("packageCategory") or ""),
                str(row.get("packageLanguage") or ""),
                str(row.get("packageName") or ""),
                str(row.get("currentVersion") or ""),
                fixed_version, patchable,
                str(row.get("remediation") or ""),
                fix_status, str(cve_age_days),
                in_kit, pub_exp, ver_exp,
                str(row.get("lastPushedToRegistryUTC") or ""),
            ])
            rows_emitted += 1

    return (rows_read, rows_emitted, rows_enriched)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--assessments", required=True, type=Path)
    ap.add_argument("--cvedetails", required=True, type=Path)
    ap.add_argument("--tag-cache", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--min-score", type=float, default=0.0)
    ap.add_argument("--max-score", type=float, default=10.0)
    args = ap.parse_args()

    read, emitted, enriched = enrich_and_emit(
        args.assessments,
        args.cvedetails,
        args.tag_cache,
        args.output,
        args.min_score,
        args.max_score,
    )
    # Structured stderr line so defender.sh can log the numbers alongside
    # its own timing/log format.
    print(
        f"enrich_cvedetails rows_read={read} rows_emitted={emitted} "
        f"rows_enriched={enriched} cvedetails_keys={_cvedetails_size(args.cvedetails)}",
        file=sys.stderr,
    )
    return 0


def _cvedetails_size(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    n = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


if __name__ == "__main__":
    sys.exit(main())
