#!/usr/bin/env python3
"""
Expand grouped runtime findings into one row per CVE.

Inputs:
1. check_images_in_oc_v3.sh grouped CSV (resultado_cruzamento.csv by default).
   Accepts both uppercase legacy schema (NAMESPACE, REPOSITORY, DIGEST, CVE_LIST)
   and lowercase new schema (namespace, repository, digest, cve_list).
2. defender.sh vulnerability CSV (vulnerable_images_report.csv by default).
   Expected 19-column schema including exploit and package fields.

Output:
One row per unique (namespace, workload, repository, digest, cveId),
enriched with per-CVE fields from defender.sh.
"""

import argparse
import csv
import sys
from pathlib import Path

DEFENDER_COLUMNS = [
    "cvssScore",
    "severity",
    "packageCategory",
    "packageLanguage",
    "packageName",
    "currentVersion",
    "fixedVersion",
    "patchable",
    "remediation",
    "fixStatus",
    "cveAgeDays",
    "isInExploitKit",
    "hasPublishedExploit",
    "hasVerifiedExploit",
    "lastPushedToRegistryUTC",
]

# Output column names — uppercase with underscores for readability
DEFENDER_COLUMNS_OUT = [
    "CVSS_SCORE",
    "SEVERITY",
    "PACKAGE_CATEGORY",
    "PACKAGE_LANGUAGE",
    "PACKAGE_NAME",
    "CURRENT_VERSION",
    "FIXED_VERSION",
    "PATCHABLE",
    "REMEDIATION",
    "FIX_STATUS",
    "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT",
    "HAS_PUBLISHED_EXPLOIT",
    "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]

OUTPUT_FIELDS = [
    "NAMESPACE",
    "PARENT_TYPE",
    "PARENT_NAME",
    "REPOSITORY",
    "DIGEST",
    "TAG",
    "CVE_ID",
    *DEFENDER_COLUMNS_OUT,
]


def get_field(row: dict, *names: str, default: str = "") -> str:
    """Return the first non-empty field among possible new/legacy names."""
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return default


def split_cves(value: str) -> list:
    """Split a comma-separated CVE list and de-duplicate while preserving order."""
    seen = set()
    cves = []
    for item in (value or "").split(","):
        cve = item.strip()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        cves.append(cve)
    return cves


def load_vulnerability_data(filepath: str):
    """Load defender.sh rows keyed by (repository, digest, cveId).

    Also builds a fallback index keyed by (repository, cveId) for the multi-arch
    case where check_images_in_oc_v3.sh carries a manifest-list top-level digest
    while Defender has per-platform child digests.
    A third fallback uses the first 16 hex chars of the digest to tolerate minor
    truncation differences.
    """
    idx_full = {}          # (repo, digest, cveId)
    idx_digest = {}        # (repo, cveId)              — first occurrence wins
    idx_prefix = {}        # (repo, digest[:16], cveId) — truncation fallback

    with open(filepath, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"repository", "digest", "cveId"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"{filepath} is missing required defender.sh columns: "
                f"{', '.join(sorted(missing))}"
            )

        for row in reader:
            repository = get_field(row, "repository")
            digest = get_field(row, "digest")
            cve_id = get_field(row, "cveId")
            if not repository or not digest or not cve_id:
                continue

            detail = {out: row.get(src, "") for src, out in zip(DEFENDER_COLUMNS, DEFENDER_COLUMNS_OUT, strict=False)}
            # Also preserve tag if present
            detail["TAG"] = row.get("tag", row.get("TAG", ""))

            idx_full[(repository, digest, cve_id)] = detail
            idx_digest.setdefault((repository, cve_id), detail)
            prefix = digest.replace("sha256:", "")[:16]
            idx_prefix.setdefault((repository, prefix, cve_id), detail)

    return idx_full, idx_digest, idx_prefix


def _lookup(idx_full, idx_digest, idx_prefix, repository, digest, cve_id):
    """3-level lookup: full → (repo, cve) fallback → digest-prefix fallback."""
    result = idx_full.get((repository, digest, cve_id))
    if result is not None:
        return result
    result = idx_digest.get((repository, cve_id))
    if result is not None:
        return result
    prefix = digest.replace("sha256:", "")[:16]
    return idx_prefix.get((repository, prefix, cve_id), {})


def expand_cves(cruzamento_file: str, idx_full: dict, idx_digest: dict, idx_prefix: dict) -> list:
    """Expand grouped check_images_in_oc_v3.sh rows into one enriched row per CVE."""
    rows_expanded = []
    emitted = set()

    with open(cruzamento_file, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"{cruzamento_file} has no CSV header")

        for row in reader:
            namespace   = get_field(row, "NAMESPACE", "namespace")
            parent_type = get_field(row, "PARENT_TYPE", "parent_type")
            parent_name = get_field(row, "PARENT_NAME", "parent_name")
            repository  = get_field(row, "REPOSITORY", "repository")
            digest      = get_field(row, "DIGEST", "digest")
            tag         = get_field(row, "TAG", "tag")
            cve_list    = get_field(row, "CVE_LIST", "cve_list")

            if not repository or not digest:
                continue

            # CVE_SEVERITY_MAP: "CVE-XXXX:Critical;CVE-YYYY:High"
            sev_map = {}
            raw_sev_map = get_field(row, "CVE_SEVERITY_MAP", "cve_severity_map")
            for entry in raw_sev_map.split(";"):
                if ":" in entry:
                    k, v = entry.split(":", 1)
                    sev_map[k.strip()] = v.strip()

            for cve_id in split_cves(cve_list):
                unique_key = (namespace, parent_type, parent_name, repository, digest, cve_id)
                if unique_key in emitted:
                    continue
                emitted.add(unique_key)

                vuln_info = _lookup(idx_full, idx_digest, idx_prefix, repository, digest, cve_id)

                expanded_row = {
                    "NAMESPACE":   namespace,
                    "PARENT_TYPE": parent_type,
                    "PARENT_NAME": parent_name,
                    "REPOSITORY":  repository,
                    "DIGEST":      digest,
                    "TAG":         tag or vuln_info.get("TAG", ""),
                    "CVE_ID":      cve_id,
                }

                for out_col in DEFENDER_COLUMNS_OUT:
                    val = vuln_info.get(out_col, "")
                    # Severity fallback: use CVE_SEVERITY_MAP from cruzamento if N/A
                    if out_col == "SEVERITY" and (not val or val == "N/A"):
                        val = sev_map.get(cve_id, "N/A")
                    expanded_row[out_col] = val if val not in (None, "") else "N/A"

                rows_expanded.append(expanded_row)

    return rows_expanded


def write_output(rows: list, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expande relatório agrupado para uma linha por CVE.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--cruzamento", "-c",
        default="resultado_cruzamento.csv",
        help="CSV agrupado gerado pelo check_images_in_oc_v3.sh (default: resultado_cruzamento.csv)",
    )
    parser.add_argument(
        "--vulnerabilities", "-v",
        default="vulnerable_images_report.csv",
        help="CSV de vulnerabilidades gerado pelo defender.sh",
    )
    parser.add_argument(
        "--output", "-o",
        default="expanded.csv",
        help="CSV de saída expandido (default: expanded.csv)",
    )

    args = parser.parse_args()

    for filepath, name in [
        (args.cruzamento, "cruzamento"),
        (args.vulnerabilities, "vulnerabilities"),
    ]:
        if not Path(filepath).exists():
            print(f"Erro: arquivo {name} não encontrado: {filepath}", file=sys.stderr)
            sys.exit(1)

    try:
        print(f"Carregando vulnerabilidades de: {args.vulnerabilities}", file=sys.stderr)
        idx_full, idx_digest, idx_prefix = load_vulnerability_data(args.vulnerabilities)
        print(f"  -> {len(idx_full)} registros carregados", file=sys.stderr)

        print(f"Expandindo CVEs de: {args.cruzamento}", file=sys.stderr)
        rows = expand_cves(args.cruzamento, idx_full, idx_digest, idx_prefix)
        print(f"  -> {len(rows)} linhas geradas", file=sys.stderr)

        print(f"Escrevendo resultado em: {args.output}", file=sys.stderr)
        write_output(rows, args.output)
    except Exception as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Concluído!", file=sys.stderr)


if __name__ == "__main__":
    main()
