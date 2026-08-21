# Investigation — MDVM individual recommendations migration (2026-08)

**Status**: investigation only — no production code changed.
**Branch**: `investigation/mdvm-individual-probe`
**Not** for merge into `main` as-is. See "Next steps".

## Why this exists

The client's Defender-based scan pipeline (`defender.sh` → `check_ocp.sh` →
`report.py`) started returning far fewer findings than expected. Both the
current KQL and an older variant behaved the same way, which pointed at an
upstream (Azure) change rather than a code regression.

Microsoft's Defender for Cloud release notes confirm a breaking change on
the exact shape our KQL depends on:

- **2026-03-04** — announcement: grouped container vulnerability
  recommendations to be deprecated in favor of "individual" recommendations.
- **2026-04-13** — grouped container vulnerability recommendations deprecated.
- **2026-05-05** — individual recommendations GA; grouped tagged
  "Set for deprecation".
- **2026-07-31** — *"Retirement of legacy grouped recommendations
  (sub-assessments) has started. Customers can no longer access the
  deprecated data through the API. The Azure portal and Azure Resource
  Graph might take a few days to reflect the change."*

The recommendation ID `c0b7cfc6-3172-465a-b378-53c7ff2cc0d5` — the exact
UUID used by `defender.sh`'s Leg A — appears explicitly in the official
[recommendation transition reference table](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
as a grouped recommendation replaced by individual recommendations.

## Impact on the current KQL (both legs)

`defender.sh` builds a `union` of two legs:

**Leg A** — `type =~ "microsoft.security/assessments/subassessments"` +
`id contains ".../c0b7cfc6-.../"`.
→ **Dead**. The `subassessments` type itself was retired on 2026-07-31.
Renaming any `properties.additionalData.*` path inside this leg cannot
bring rows back.

**Leg B** — `type == "microsoft.security/assessments"` +
`recommendationCategory == "SoftwareUpdate"` + `.containerimage` +
`Source == "Azure"`.
→ **Query shape still valid** — these four `where` clauses are exactly
what Microsoft documents as the entry point to the new individual model.
BUT the *data* under these filters moved from the grouped shape
(one row per image, `CvesDetails` array with many CVEs) to the individual
shape (one row per CVE). Fields under `properties.additionalData.*` may
have moved, been renamed, or disappeared. Symptom "few findings" is
consistent with `CvesDetails` mv-expand + `cveId startswith "CVE-"`
silently discarding the new shape.

## What the MS transition doc answered (2026-08-21 update)

Microsoft's [transition reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
answered several of the open questions and moved others from "unknown"
to "likely, needs probe confirmation":

### Container recommendation UUIDs (confirmed)

Three UUIDs now cover ACR containers under `SoftwareUpdate`
(one grouped UUID → three individual). Leg B's `SoftwareUpdate` +
`.containerimage` + `Source=='Azure'` filter should already include all
three, but probe-2 breaks them down so we can verify per-UUID counts:

| UUID | Recommendation | Category |
|---|---|---|
| `c0b7cfc6-3172-465a-b378-53c7ff2cc0d5` | Azure registry container images should have vulnerabilities resolved | `SoftwareUpdate` |
| `33422d8f-ab1e-42be-bc9a-38685bb567b9` | Container images in Azure registry should have vulnerability findings resolved | `SoftwareUpdate` |
| `c609cf0f-71ab-41e9-a3c6-9a1f7fe1b8d5` | Azure **running** container images should have vulnerabilities resolved | `SoftwareUpdate` |
| `24a15fbd-cfe4-4dff-b2be-1c367a6b2031` | AKS nodes should have vulnerability findings resolved | `ServiceUpgrade` ⚠ |

⚠ AKS nodes moved to `ServiceUpgrade` — Leg B filters `SoftwareUpdate`
only, so AKS-node findings are out of scope (they never were in scope
anyway for the ACR pipeline, but worth noting).

### Field mapping (partially confirmed for the VM example)

MS publishes a VM query example that confirms these renames at the
top level of `additionalData`:

| Grouped (old) | Individual (new) |
|---|---|
| `additionalData.softwareVersion` | `additionalData.DetectedSoftwareVersions` |
| `additionalData.recommendedVersion` | `additionalData.FixedVersion` |
| `mv-expand CVE = additionalData.cve` + `CVE.title` | `parse_json(additionalData.CvesDetails)` + `mv-expand CveDetail` + `CveDetail.CveId` |
| `properties.status.severity` | `properties.metadata.severity` |

**Good news for `defender.sh`**: Leg B (lines ~901–960) already uses
the individual-model shape — `parse_json(...CvesDetails)`, `mv-expand cve`,
`cve.CveId`, `cve.FixStatus`, `cve.FixedVersion`, `cve.PublishedDate`,
`cve.ExploitabilityDetails.*`. So the primary broken thing is that
Leg A is dead (subassessments retired 2026-07-31) and its rows just
disappeared — the shape of Leg B was already migrated ahead of time.

### Scope-expansion warning (from the doc)

> "Querying the SoftwareUpdate recommendation category returns findings
> across Azure VMs, EC2, AKS nodes, GCP, and containers combined."

Leg B already narrows with `resourceDetails.ResourceType == '.containerimage'`
and `Source == 'Azure'`, so we're safe — but any future change to Leg B
must preserve both filters.

## What the doc does NOT confirm (still blocked on probe evidence)

The MS transition doc gives ONLY a VM example — it does not publish the
container-case schema for the following, which drive report columns:

1. Exact path of CVSS score inside `cve` (currently `cve.Cvss[0].Value.Base`
   in Leg B). Doc doesn't confirm.
2. `cve.ExploitabilityDetails.{IsInExploitKit,ExploitStepsPublished,ExploitStepsVerified}`
   — powers the V/P/K chips in `report.py`. Doc doesn't confirm.
3. `cve.FixStatus` values (`FixAvailable` / `NoFix` / `NoFixAvailable` / `WillNotFix`)
   — doc doesn't publish the enum.
4. `properties.additionalData.artifactDetails.*` (repo, digest, lastPushed)
   — doc doesn't mention. Leg B avoids this path (uses `resourceDetails.Id`
   regex), but keeping the probe covers the case.
5. **Unknown-unknowns**: MS may have added EPSS score, KEV listing, exploit
   maturity, package purl, layer digest, etc. under the individual model
   without documenting the field paths for containers.

**Probe 5 (`bag_keys` discovery)** addresses point 5 by enumerating every
key that actually appears under each subtree — so brand-new fields we
don't know to ask for will surface with a row count.

## Approach

Run the read-only probe (`scripts/probe-mdvm-individual.sh`) at the client,
with `az` already logged in against the client's subscription. The script
issues **five** Azure Resource Graph queries — no writes, no CSV, no
`show-tags`, no OpenShift, no `defender.sh` — and dumps five JSON files.

| File | Purpose |
|---|---|
| `probe-1-subassessments-count.json` | Confirm Leg A is truly zero |
| `probe-2-assessment-ids.json`       | List UUIDs emitting today with per-known-UUID breakdown (the 3 container UUIDs from the MS doc) |
| `probe-3-raw-sample.json`           | Inspect the real shape of an individual assessment (**contains client data**) |
| `probe-4-field-presence.json`       | `countif` on current-KQL paths vs speculated renamed paths (allowlist) |
| `probe-5-bag-keys.json`             | `bag_keys` discovery — enumerates ALL keys under each subtree (catches unknown-unknowns like EPSS, KEV) |

### Running

```bash
# On a machine where `az login` was already done for the client's tenant:
./scripts/probe-mdvm-individual.sh --acr-name <ACR_NAME>

# Or narrowed to a single known repo (recommended for probe 3):
./scripts/probe-mdvm-individual.sh --acr-name <ACR_NAME> --repository <one/known/repo>
```

Output goes to `./probes/probe-YYYYMMDD-HHMMSS/`.

## Data sensitivity

`probe-3-raw-sample.json` contains **real repository paths and image
digests** from the client's registry. Treat it as sensitive:

- Do not paste unredacted.
- Prefer sharing `probe-1`, `probe-2`, `probe-4` (aggregations only)
  for design discussions.
- Redact repo names before sharing any excerpt of `probe-3`.

## Next steps (once probes come back)

1. Analyze `probe-4` — confirm which of the KNOWN paths exist and which
   are `null`. That validates the current Leg B extends.
2. Analyze `probe-5` — look for keys we didn't ask about. Rank by
   `rows_with_key` — any key populated on >50% of rows and not already
   in Leg B is a candidate for a new CSV column (proposal, not silent add —
   requires PR review and CSV-order guardrails).
3. Analyze `probe-3` payload with the maps from (1)+(2) — validate that
   the whole CSV column set can be recovered, or note which columns
   become `N/A` (leading candidate: exploitability V/P/K if not present).
4. Draft the migration PR against `defender.sh`:
   - **Remove Leg A entirely** (dead upstream — `subassessments` retired
     2026-07-31, no field-path change can bring it back).
   - Update the `[DEBUG] MDVM findings` sanity block (line ~984 —
     currently queries `subassessments` and will always show 0 rows now).
   - Verify Leg B captures all 3 container UUIDs from probe-2. If one
     is missing (e.g. the client tenant hasn't propagated `c609cf0f`
     for running images yet), add explicit `id contains` clauses.
   - Adjust Leg B's `extend` / `mv-expand` **only** if probe-4 or
     probe-5 shows drift from the current shape.
   - Preserve CSV column order and semantics — downstream stages
     (`expandcsv.py`, `report.py`) must not change.
5. Run in dry-run mode against a copy of production data before merging;
   compare row counts and severity distribution with the pre-retirement
   baseline (last known-good CSV).
6. **No changes to `check_ocp.sh`, `expandcsv.py`, `group_findings.py`,
   or `report.py`** unless the field map forces it.

## References

- [What's new in Defender for Cloud features](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes)
- [Transition from grouped to individual recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
- [Vulnerability management for containers (MDVM)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/agentless-container-registry-vulnerability-assessment)
- [Container security recommendations reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container)
