# MDVM individual-recommendations migration (2026-08)

## Context

Microsoft retired the legacy grouped `microsoft.security/assessments/subassessments`
type on **2026-07-31**, breaking the shape of `defender.sh`'s pre-existing KQL.
The retired path emitted rich per-CVE rows keyed by the assessment
`c0b7cfc6-3172-465a-b378-53c7ff2cc0d5`; those rows now return zero.

Microsoft's replacement is the "individual recommendations" model:

- Reference: <https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations>
- Community tracking issue (open, unresolved by MS at time of writing):
  <https://github.com/Azure/Microsoft-Defender-for-Cloud/issues/1056>

## What changed in `defender.sh`

**Single-leg query** against `microsoft.security/assessments`, filtered by:

```kql
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == ".containerimage"
| where properties.resourceDetails.Source == "Azure"
```

All CVE fields are read **inline** from `properties.additionalData.CvesDetails[]`
after `mv-expand`. There is **no JOIN** with `microsoft.security/cvedetails`
— that resource type was tried and proved empty in the target tenant (0 rows
across all subscriptions). Everything the query needs is confirmed present
under `cve.*` via a `bag_keys` probe:

```
CveId, AdditionalIdentifiers, Description, ExtendedDescription,
Cvss (array of {Key, Value: {Base, CvssVectorString}}), CvssSource,
Severity, PublishedDate, LastModifiedDate, Weaknesses, FixStatus,
FixedVersion, ExploitabilityDetails, References, Tags
```

## Field-source map (18 CSV columns, order preserved)

| CSV column | KQL source | Notes |
|---|---|---|
| `repository` | `parse_json(resourceAdditionalData).RepositoryDetails.RepositoryName` | Structured — no URL regex |
| `digest` | `parse_json(resourceAdditionalData).Digest` | Structured — no URL regex |
| `cvssScore` | `coalesce(todouble(cve.Cvss[0].Value.Base), case(cve.Severity, ...))` | First array entry is the operative score in every sample; case-on-severity is the deterministic fallback for null CVSS |
| `cveId` | `tostring(cve.CveId)` | Filtered `startswith "CVE-"` post-extend |
| `severityRaw` | `tostring(cve.Severity)` | Values: Critical / High / Medium / Low / Unknown / "" |
| `packageCategory` | `coalesce(additionalData.PackageType, ScannersDetails.mdvm.category, ScannersDetails.mdvm.PackageType)` | 3 candidate paths — first non-null wins |
| `packageLanguage` | `coalesce(additionalData.Language, ScannersDetails.mdvm.Language)` | |
| `packageName` | `tostring(additionalData.SoftwareName)` | |
| `currentVersion` | `tostring(ScannersDetails.mdvm.DetectedSoftwareVersions[0])` | Array; take first |
| `fixedVersion` | `tostring(cve.FixedVersion)` | |
| `patchable` | Derived: `case(fixStatus, isnotempty(fixedVersion))` | `FixAvailable` → true, `NoFix/NoFixAvailable/WillNotFix` → false, else infer from fixedVersion presence |
| `remediation` | `coalesce(cve.Description, properties.remediation, properties.description)` | Description is AI-generated at MS side and includes remediation guidance |
| `fixStatus` | `coalesce(cve.FixStatus, additionalData.FixStatus, ScannersDetails.mdvm.FixStatus)` | 3 candidates |
| `cveAgeDays` | `datetime_diff('day', now(), todatetime(cve.PublishedDate))` | `-1` when null |
| `isInExploitKit` | `iff(tobool(cve.ExploitabilityDetails.IsInExploitKit))` | Only one path — MS did not rename this in the individual model |
| `hasPublishedExploit` | `iff(tobool(coalesce(cve.ExploitabilityDetails.ExploitStepsPublished, cve.ExploitabilityDetails.IsPubliclyDisclosed)))` | Defensive coalesce — legacy vs. newer name; either may appear per tenant |
| `hasVerifiedExploit` | `iff(tobool(coalesce(cve.ExploitabilityDetails.ExploitStepsVerified, cve.ExploitabilityDetails.IsVerified)))` | Same defensive coalesce |
| `lastPushedToRegistryUTC` | `coalesce(resourceAdditionalData.LastPushedToRegistryUTC, resourceAdditionalData.RepositoryDetails.LastPushedToRegistryUTC)` | Top-level or nested — MS emits both across tenants |

## Attempts that were tried and discarded

**JOIN with `microsoft.security/cvedetails`** — an intermediate commit
JOINed on `cveId` to pull `severity`, `cvss[<version>].base`,
`exploitabilityDetails.*` from the normalized CVE catalog resource type.
Client-tenant probe returned zero rows for `microsoft.security/cvedetails`
across all subscriptions; the whole query silently filtered to empty.
The join was removed and CVE fields are now read directly from
`cve.*` inside `CvesDetails[]`.

**Casing-defensive `coalesce(PascalCase, camelCase)` on every read** — an
earlier commit followed the pattern from the community SQL VA migration
(<https://github.com/Azure/Microsoft-Defender-for-Cloud/pull/1047>). The
client-tenant probe showed all fields emit consistent PascalCase, so the
defensive coalesce was pruned back to the specific fields where two paths
genuinely exist (`packageCategory`, `packageLanguage`, `fixStatus`,
`lastPushedToRegistryUTC`) and the exploit-signal renames.

## Known limitation: partial data for some repos

Some repositories (observed with base OS images and system-level layers)
return CVEs where every row has `cve.Severity == "Unknown"` and
`cve.Cvss[0].Value.Base` is null. Example diagnostic output:

```json
{
  "total": 24198,
  "com_cvss_num": 0,
  "cvss_ge_7": 0,
  "sev_critical": 0, "sev_high": 0, "sev_medium": 0, "sev_low": 0,
  "sev_unknown": 24198
}
```

For those rows the case-on-severity fallback lands at `0.0`, which is
filtered out by any positive `--min-score`. This is a Microsoft-side data
gap in the individual model — the retired subassessments type carried
richer per-CVE CVSS data (`additionalData.cvssV30Score`) that is not
replicated in the individual-model payload for these repositories.

Options:

1. Accept the reduced volume for affected repos (default).
2. Track the underlying MS issue: <https://github.com/Azure/Microsoft-Defender-for-Cloud/issues/1056>.
3. Business decision: change severity-Unknown mapping to a non-zero default
   (would require agreement on report semantics).

## Regression safety

31 KQL invariants live in `tests/test_defender_query_migration.py`. Any
future change to the heredoc must keep them green:

```bash
pytest tests/test_defender_query_migration.py -q
```

Coverage highlights:

- Subassessments type and `c0b7cfc6-*` filter never re-appear.
- The four entry-point where-clauses are all present.
- No JOIN with `microsoft.security/cvedetails`.
- Every CVE field is read from `cve.*` (severity, CVSS, exploit signals,
  fix status, published date, description).
- Image identity from parsed `resourceAdditionalData`; digest is not
  regex-extracted from the URL.
- CSV column order matches the 18-column contract exactly.
