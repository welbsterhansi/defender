#!/usr/bin/env python3
"""decision_dump.py — run BOTH mergers on the SAME ARG input.

Isolates whether the ~50-row divergence between bash and python full
runs comes from:

  * MERGER CODE (bash's enrich_cvedetails.py vs defender_pipeline's
    enrich.merge) producing different outputs on identical input, or
  * INPUT DATA (same query at slightly different times returning
    non-identical subsets — ARG summarize/distinct tie-breakers, cvedetails
    eventual consistency).

Fetches assessments + cvedetails ONCE, feeds both mergers, compares.

Usage:
    python3 decision_dump.py [ACR] [REPO] [MIN_SCORE] [MAX_SCORE]

Defaults: contosoregistry / contoso/webapp / 7 / 10 (placeholders — passar reais)
"""
from __future__ import annotations

import csv
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def fetch(acr: str, repo: str) -> tuple[list[dict], list[dict]]:
    """Query ARG once — return (assessments_raw, cvedetails_raw)."""
    from defender_pipeline.azure.auth import get_credential
    from defender_pipeline.azure.queries import (
        build_batched_assessments_query,
        build_batched_cvedetails_query,
        build_enumerate_digests_query,
        build_scope_filter,
    )
    from defender_pipeline.azure.resource_graph import ResourceGraphClient
    from defender_pipeline.utils.batching import run_batched_with_split

    client = ResourceGraphClient(get_credential())
    filt = build_scope_filter(repository=repo)

    # Enumerate
    pairs: list[tuple[str, str]] = []
    for page in client.iter_pages(build_enumerate_digests_query(filt)):
        pairs.extend((r.get("_repository", ""), r.get("_digest", "")) for r in page)
    digests = sorted({d for _, d in pairs if d})
    print(f"digests:     {len(digests)}")

    def _run_assess(chunk):
        rows = []
        for page in client.iter_pages(build_batched_assessments_query(chunk)):
            rows.extend(page)
        return rows

    assess = run_batched_with_split(digests, _run_assess, initial_batch_size=50)
    print(f"assessments: {len(assess)}")

    cves = sorted({
        r.get("cveId", "").upper()
        for r in assess if r.get("cveId", "").startswith("CVE-")
    })
    print(f"unique CVEs: {len(cves)}")

    def _run_cve(chunk):
        rows = []
        for page in client.iter_pages(build_batched_cvedetails_query(chunk)):
            rows.extend(page)
        return rows

    cvedetails = run_batched_with_split(cves, _run_cve, initial_batch_size=500)
    print(f"cvedetails:  {len(cvedetails)}")

    return assess, cvedetails


def run_bash_merger(
    assess: list[dict],
    cvedetails: list[dict],
    min_s: float, max_s: float,
    tmp: Path,
) -> list[dict[str, str]]:
    """Import enrich_cvedetails.py as a module and invoke its merger.
    Zero modification to that script — pure import + call."""
    import enrich_cvedetails as bm

    a = tmp / "assess.jsonl"
    c = tmp / "cve.jsonl"
    t = tmp / "tags.tsv"
    o = tmp / "bash.csv"

    a.write_text("\n".join(json.dumps(r) for r in assess) + "\n", encoding="utf-8")
    c.write_text("\n".join(json.dumps(r) for r in cvedetails) + "\n", encoding="utf-8")
    t.touch()
    header = ",".join(f'"{col}"' for col in bm.CSV_HEADER_COLUMNS) + "\n"
    o.write_text(header, encoding="utf-8")

    read, emitted, enriched = bm.enrich_and_emit(a, c, t, o, min_s, max_s)
    print(f"bash merger:   read={read} enriched={enriched} emitted={emitted}")

    with o.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def run_python_merger(
    assess: list[dict],
    cvedetails: list[dict],
    min_s: float, max_s: float,
) -> list[list[str]]:
    """Invoke defender_pipeline.findings.enrich.merge directly."""
    from defender_pipeline.findings.enrich import merge
    from defender_pipeline.findings.models import (
        AssessmentRow,
        EnrichmentRow,
    )

    ao = [AssessmentRow.from_arg_row(r) for r in assess]
    eo: dict[str, EnrichmentRow] = {}
    for r in cvedetails:
        e = EnrichmentRow.from_arg_row(r)
        eo[e.cve_id_join] = e
    findings = merge(ao, eo, {}, min_score=min_s, max_score=max_s)
    print(f"python merger: emitted={len(findings)}")
    return [f.as_csv_values() for f in findings]


def main() -> int:
    _acr  = sys.argv[1] if len(sys.argv) > 1 else "contosoregistry"
    repo  = sys.argv[2] if len(sys.argv) > 2 else "contoso/webapp"
    min_s = float(sys.argv[3] if len(sys.argv) > 3 else 7.0)
    max_s = float(sys.argv[4] if len(sys.argv) > 4 else 10.0)

    print(f"scope: acr={_acr} repo={repo} min={min_s} max={max_s}")
    print("--- fetch ---")
    assess, cvedetails = fetch(_acr, repo)

    print("--- both mergers on identical input ---")
    with tempfile.TemporaryDirectory() as tmp:
        bash_rows = run_bash_merger(assess, cvedetails, min_s, max_s, Path(tmp))
    python_rows = run_python_merger(assess, cvedetails, min_s, max_s)

    # Compare 5-tuple keys. Positions in the CSV row list:
    #   0=repository, 1=digest, 2=tag, 3=cvssScore, 4=cveId, 5=severity,
    #   6=packageCategory, 7=packageLanguage, 8=packageName,
    #   9=currentVersion, 10=fixedVersion, 11=patchable, 12=remediation, ...
    KEY = ("digest", "cveId", "packageName", "currentVersion", "fixedVersion")
    bash_keys: set[tuple[str, ...]] = {
        tuple(r.get(k, "") for k in KEY) for r in bash_rows
    }
    py_keys: set[tuple[str, ...]] = {
        (r[1], r[4], r[8], r[9], r[10]) for r in python_rows
    }

    print("--- key overlap (bash merger vs python merger, same input) ---")
    print(f"bash tuples:  {len(bash_keys)}")
    print(f"py tuples:    {len(py_keys)}")
    print(f"so no bash:   {len(py_keys - bash_keys)}")
    print(f"so no python: {len(bash_keys - py_keys)}")
    print(f"comum:        {len(bash_keys & py_keys)}")

    if bash_keys == py_keys:
        print()
        print("VEREDICTO: mergers CONCORDAM no mesmo input.")
        print("           → divergencia no pipeline vem de dados-fonte (ARG),")
        print("             nao do codigo de merge. Cutover P0.5 aceitavel.")
        return 0
    else:
        print()
        print("VEREDICTO: mergers DISCORDAM no mesmo input.")
        print("           → bug real em um dos merges. Investigar quais tuplas")
        print("             divergem e por que.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
