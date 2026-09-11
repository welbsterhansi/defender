"""Local merge of assessments + cvedetails — Python-native replacement
of the bash-invoked ``enrich_cvedetails.py`` helper.

Merge key: upper-cased CVE ID. Filter: --min-score / --max-score
applied post-enrichment.

Implemented in task P0.5. The current ``enrich_cvedetails.py`` script
stays untouched during the migration; this module ports its logic to
integrate with the SDK-based scan (which produces dataclasses, not
JSONL files).
"""
from __future__ import annotations
