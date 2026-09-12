# PR-UX-5 (future) — cluster-context exploitability score

Not scheduled. Draft spec captured so the context isn't lost between
sessions. Do NOT start work here until the current KQL fix has been
validated in production and the team explicitly asks for it.

## Motivation

The three binary exploit signals we surface today (V/P/K —
`IsVerified` / `IsPubliclyDisclosed` / `IsInExploitKit`) all report
past-observed exploitation. CVSS reports intrinsic severity. Neither
answers the operational question:

> **"How exploitable is this CVE in my cluster right now?"**

A CVE with CVSS 9.8 that only lives in one dev pod behind a firewall
is not the same operational risk as a CVE with CVSS 7.5 that lives
in the base image of 40 production workloads. Today the report treats
them as equal.

Real example from the client tenant (`CVE-2018-11361`, Wireshark
buffer overflow):

```
severity              : "Medium"
IsInExploitKit        : false     ← K chip off
IsPubliclyDisclosed   : false     ← P chip off
IsVerified            : false     ← V chip off
Epss.Score            : 0.0267    (2.67% probability in 30 days)
Epss.Percentile       : 0.84554   (higher than 84.5% of all CVEs)
```

All V/P/K chips dark, "Medium" severity, but EPSS percentile in top
15%. Multiply by "this CVE is present in 12 workloads across 4
namespaces" and it jumps to a real priority. Divide by "only 1
workload, patchable=true" and it drops.

The goal is a single **`clusterExploitability`** score per (CVE,
workload) that fuses:

1. **Intrinsic severity** — `cvssScore` (already in CSV).
2. **Likelihood** — `epssPercentile` from cvedetails (new).
3. **Confirmed exploitation** — V/P/K flags (already in CSV).
4. **Blast radius** — how many workloads / namespaces run this CVE
   (derivable from `resultado_cruzamento.csv` — check_ocp.sh output).
5. **Fixability** — `patchable` (already in CSV; penalty if `false`
   because there's nothing the team can do, so the risk is chronic).
6. **Freshness** — how old is `lastPushedToRegistryUTC` (stale
   images are less likely to be re-pushed with the fix).

## Data pipeline

### New raw inputs (from cvedetails)

`microsoft.security/cvedetails.properties.exploitabilityDetails.Epss`:

```json
{ "Percentile": 0.84554, "Score": 0.0267 }
```

Both fields nullable (rejected / very new CVEs may lack EPSS).

Add two enrichment paths in the KQL:

```
_epssScoreEnrich      = todouble(properties.exploitabilityDetails.Epss.Score),
_epssPercentileEnrich = todouble(properties.exploitabilityDetails.Epss.Percentile)
```

And two extends after the JOIN mapping them to `epssScore` /
`epssPercentile` (no inline fallback — `assessments` never had EPSS).

### CSV additions

Append `epssScore, epssPercentile` at the **end** of the projection
so existing column positions stay stable, but the count changes from
**18 → 20**. Every downstream reader must accept both widths during
rollout.

### Derived scoring — where to compute

**Compute in Python at grouping time** (`group_findings.py`), NOT in
KQL. Reasons:

- Blast radius (workloads-per-CVE) is only known AFTER we've cross-
  referenced Defender with OpenShift. That happens in Python.
- Formula tweaks shouldn't require a Defender re-run. Keeping the
  formula in Python lets us iterate.
- Same input CSV can be re-scored with a different formula for
  A/B testing.

Add a new derived column `CLUSTER_EXPLOITABILITY` to the grouped
CSV. Range 0–100. Formula draft:

```
raw =    cvssScore                          # 0–10
       * (1 + epssPercentile)               # 1–2
       * ln(1 + workloadCount)              # blast radius
       * exploit_multiplier                 # 1.0 / 1.15 / 1.3 / 1.5
       * (1.2 if runs_as_root else 1.0)     # if we can get SCC info
       * (0.7 if patchable else 1.0)        # penalize unpatchable

exploit_multiplier =
    1.5 if hasVerifiedExploit
    1.3 if isInExploitKit
    1.15 if hasPublishedExploit
    1.0 otherwise

clusterExploitability = min(100, round(raw * 5, 1))
```

Numbers above are **starting points** — tune against real data
before shipping. The formula belongs in a single pure function
`compute_cluster_exploitability(cve_row, workload_context)` with
unit tests covering:

- All V/P/K signals off + high EPSS → still ranks high when blast
  radius is high.
- CVSS 10 with no exploit signals + 1 workload + patchable → lands
  below CVSS 7 exploit-in-kit + 20 workloads (the whole point).
- Missing EPSS → treated as 0 (no boost), not as 1 (worst case).

### Priority tiers (secondary; for filtering, not sorting)

```
tier_P0 = clusterExploitability >= 60
tier_P1 = 40 <= clusterExploitability < 60
tier_P2 = 20 <= clusterExploitability < 40
tier_P3 = clusterExploitability < 20
```

Boundaries are arbitrary until we see real distribution — hold
until first run against production CSV.

## Report HTML changes

1. **Primary sort** switches from `cvssScore desc` to
   `clusterExploitability desc`. CVSS stays visible as a column.
2. **New KPI card** — count of tier-P0 CVEs. Replaces or accompanies
   the current severity KPIs.
3. **Priority tier badge** on every CVE row (P0/P1/P2/P3 chip next
   to severity dot).
4. **New chip `E-high`** when `epssPercentile >= 0.9`, for the case
   where a dev wants to spot EPSS-driven risk independent of the
   composite score. Complements V/P/K.
5. **Filter option "Tier P0 only"** — one-click "what's urgent".
6. **Tooltip on the score** explaining the composition:
   `"CVSS 7.5 × EPSS 0.85 × 3 workloads × verified-exploit = 62"`.

## Files touched (when we execute)

| Stage | File | Change |
|---|---|---|
| KQL | `defender.sh` | +2 extends, +2 project cols; +2 test invariants |
| Tests | `tests/test_defender_query_migration.py` | +new EPSS guardrails |
| CSV | `check_ocp.sh` | header line +2 cols |
| Grouping | `group_findings.py` | carry EPSS through; add `compute_cluster_exploitability()`; add `CLUSTER_EXPLOITABILITY` output col |
| Grouping tests | `tests/test_group_findings_unit.py` | scoring invariants |
| Expand | `expandcsv.py` | pass-through (already generic) |
| Report | `report.py` | load new cols; render score / tier / chip / KPI; new sort |
| Report tests | `tests/test_report_unit.py` | new UI states |
| Fixtures | `tests/conftest.py` | rows with / without EPSS; small vs large blast radius |
| Docs | `docs/mdvm-cvedetails-schema-2026-08.md`, `AGENTS.md`, `README.md` | reflect 20-col contract + scoring definition |

## PR split

Do NOT bundle in one PR. Suggested order:

- **PR-UX-5a** — KQL EPSS extraction + CSV 20-col plumbing +
  guardrail tests. Invisible to users (report doesn't render the
  new cols yet). Lets us validate the query in production without
  UI risk.
- **PR-UX-5b** — `compute_cluster_exploitability` function + tier
  classification + unit tests. Still no UI.
- **PR-UX-5c** — HTML rendering (score column, tier badge, KPI,
  filter, sort switch, E-high chip). This is the visible payoff.

Split lets us roll back UI without losing data plumbing.

## Non-goals

- **Not a SIEM.** The score is a triage aid, not an alerting signal.
- **Not a replacement for CVSS.** CVSS stays a visible column;
  score augments it.
- **No client-side JS math** — compute deterministically in Python
  at report render time. Same input → same score.
- **No per-user formula tuning.** One formula, tuned once, checked
  into the repo.

## Open questions to resolve before starting

1. Do we have visibility on `runs_as_root` / SCC in `check_ocp.sh`
   today? If not, drop that factor from the formula or add a
   collection step.
2. Is `lastPushedToRegistryUTC` reliable enough to use as a
   freshness penalty, or does it flap for auto-rebuilt images?
3. Formula weights — validate against a snapshot of production
   CSV data before committing.
