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

## What we still don't know

Microsoft's docs show the top-level filter for the new model but never
publish a complete field-by-field mapping for the ACR container case.
The following are unresolved and blocking the migration design:

1. Is `properties.additionalData.CvesDetails` still an array, or was the
   CVE promoted to a scalar under a different key in the individual model?
2. Do `properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.{isInExploitKit,exploitStepsPublished,exploitStepsVerified}`
   still exist? (These drive the V/P/K chips in `report.py`.)
3. Where does the CVSS score live now? Still `additionalData.cvssV30Score`,
   or renamed to `cvssV31Score` / `vulnerabilityDetails.cvssV3Score`?
4. Is `properties.additionalData.softwareDetails.fixStatus` still there
   or was it renamed to `vulnerabilityDetails.fixState`?
5. Which recommendation UUIDs replace `c0b7cfc6-…` for ACR?

The other paths (repo, digest, lastPushedToRegistryUTC) may or may not
still be nested under `artifactDetails` — only real payload can tell.

## Approach

Run the read-only probe (`scripts/probe-mdvm-individual.sh`) at the client,
with `az` already logged in against the client's subscription. The script
issues four Azure Resource Graph queries — no writes, no CSV, no
`show-tags`, no OpenShift, no `defender.sh` — and dumps four JSON files.

| File | Purpose |
|---|---|
| `probe-1-subassessments-count.json` | Confirm Leg A is truly zero |
| `probe-2-assessment-ids.json`       | List the new recommendation UUIDs emitting today |
| `probe-3-raw-sample.json`           | Inspect the real shape of an individual assessment (**contains client data**) |
| `probe-4-field-presence.json`       | Compare current-KQL paths vs speculated renamed paths, row by row |

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

1. Analyze `probe-4` — confirm which paths exist and which are `null`.
   That produces the definitive field map for the individual model.
2. Analyze `probe-3` payload with the map from (1) — validate that the
   whole CSV column set can be recovered, or note which columns become
   `N/A` (leading candidate: exploitability V/P/K if not present).
3. Draft the migration PR against `defender.sh`:
   - Remove Leg A entirely (dead upstream).
   - Adjust Leg B's `extend` / `mv-expand` to the new field paths.
   - Preserve CSV column order and semantics — downstream stages
     (`expandcsv.py`, `report.py`) must not change.
4. Run in dry-run mode against a copy of production data before merging;
   compare row counts and severity distribution with the pre-retirement
   baseline (last known-good CSV).
5. **No changes to `check_ocp.sh`, `expandcsv.py`, `group_findings.py`,
   or `report.py`** unless the field map forces it.

## References

- [What's new in Defender for Cloud features](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes)
- [Transition from grouped to individual recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
- [Vulnerability management for containers (MDVM)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/agentless-container-registry-vulnerability-assessment)
- [Container security recommendations reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container)
