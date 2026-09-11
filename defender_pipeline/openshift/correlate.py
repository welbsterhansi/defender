"""Workloads × images cross-reference.

For each visited namespace: list pods, extract images/digests from
``containers[].image`` + ``containerStatuses[].imageID``, walk
``ownerReferences`` up to the workload controller
(Deployment/StatefulSet/DaemonSet/Job/Pod-fallback), correlate against
the CVE CSV.

Implemented in task P0.6.
"""
from __future__ import annotations
