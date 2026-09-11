"""Retry decorators shared across the pipeline.

Backed by ``tenacity`` (imported lazily so tests that don't touch retry
paths don't fail on missing extras).

Implemented in task P0.5+.
"""
from __future__ import annotations
