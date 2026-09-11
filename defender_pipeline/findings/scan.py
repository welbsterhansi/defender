"""Scan orchestrator — Python port of the P2 batched flow in ``defender.sh``.

Phases (same as the bash implementation):

    0. Enumerate unique (repository, digest) pairs.
    1. Resolve tags upfront (one call per unique repo, unless --skip-tags).
    2a. Batched assessments query (no JOIN, ~50 digests per call).
    2b. Extract unique CVE IDs from the assessments rows.
    2c. Batched cvedetails query (~500 CVE IDs per call).
    2d. Local merge via ``findings.enrich``.

Implemented in task P0.5.
"""
from __future__ import annotations
