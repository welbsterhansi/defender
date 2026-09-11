"""Bounded-parallelism helpers on top of ``concurrent.futures``.

The pipeline uses threads (not asyncio) — see
``docs/python-architecture.md`` §5 for the rationale.

Implemented in task P0.5.
"""
from __future__ import annotations
