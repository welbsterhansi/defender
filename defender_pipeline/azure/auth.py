"""Azure authentication — single ``DefaultAzureCredential`` shared by
Resource Graph and Container Registry clients.

Chain (in order tried by DefaultAzureCredential):

    1. Env vars (AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET)
    2. Managed identity (in-cluster / VM)
    3. Azure CLI cache (``az login`` — dev laptop path)
    4. Interactive browser (disabled in headless envs)

Prerequisite: the identity needs **Security Reader at tenant scope** so
``microsoft.security/cvedetails`` enrichment is visible (see erros.md).

Implemented in task P0.5.
"""
from __future__ import annotations
