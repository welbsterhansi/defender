"""Kubernetes client factory — loads kubeconfig OR in-cluster config.

Uses the official ``kubernetes`` Python client. On dev laptops
``load_kube_config()`` reads ``~/.kube/config`` (or ``$KUBECONFIG``);
in-cluster runs use ``load_incluster_config()`` when the pod's
service-account token is mounted.

No ``oc`` subprocess in the main path. See
``docs/python-architecture.md`` §2.2.

Implemented in task P0.6.
"""
from __future__ import annotations
