"""Azure Resource Graph client wrapper.

Uses ``azure-mgmt-resourcegraph`` with api-version 2022-10-01 — the
version proven to correctly resolve JOINs against
``microsoft.security/cvedetails`` (the pre-2022 versions returned
enriched=0 rows; see erros.md).

Implemented in task P0.5.
"""
from __future__ import annotations
