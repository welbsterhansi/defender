"""KQL query builders — Python-side ports of the bash builders in
``defender.sh``.

Kept in a single module so the queries are testable in isolation (input
= arg list, output = KQL string) without pulling in the Azure SDK.

Implemented in task P0.5. Queries themselves are already documented in
``defender.sh`` and ``docs/mdvm-two-phase-benchmark.md`` — the ports
must be byte-equivalent (or KQL-semantically equivalent) so the
resulting Azure Resource Graph responses match.
"""
from __future__ import annotations
