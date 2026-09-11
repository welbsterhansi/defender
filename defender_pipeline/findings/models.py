"""Dataclasses for scan findings.

Kept small and typed. External API contracts (CSV output) go through
``findings.csv_contracts``; these types are the internal representation
between phases.

Concrete fields are added as the P0.5 implementation lands.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DigestPair:
    """A (repository, digest) tuple as emitted by Phase 0 enumerate."""

    repository: str
    digest: str
