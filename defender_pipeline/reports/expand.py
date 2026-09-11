"""Port of ``expandcsv.py`` into the pipeline package.

Grouped CSV → one row per CVE. Preserves the 3-level lookup ladder
that tolerates multi-arch digest mismatches.

Implemented in task P0.7.
"""
from __future__ import annotations
