"""Azure Container Registry data-plane wrapper.

Uses ``azure-containerregistry.ContainerRegistryClient`` for tag/manifest
listing — replaces ``az acr repository show-tags --detail`` from the
bash pipeline.

Implemented in task P0.5.
"""
from __future__ import annotations
