"""Batch-split-on-failure helper.

Wraps a callable that operates on a list of items. On
:class:`BatchTooComplex` (Azure Resource Graph's
``UnexpectedQueryExecutionError`` translated by the ARG client), splits
the list in half and retries recursively. Never falls silently to
1-by-1: every split emits a WARN log; a single-item failure raises.

Ports the semantics of ``_scan_batch_recursive`` in ``defender.sh``.

Implemented in task P0.5; here only the exception surface is declared
so tests can import it from the skeleton.
"""
from __future__ import annotations


class BatchTooComplex(Exception):
    """Raised when the ARG engine rejects a batch as too complex
    (``UnexpectedQueryExecutionError``). The caller should split the
    batch in half and retry."""


class BatchExhausted(Exception):
    """Raised when a single-item batch keeps failing — indicates the
    query is structurally broken, not just too large."""
