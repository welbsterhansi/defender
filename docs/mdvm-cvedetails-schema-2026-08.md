# microsoft.security/cvedetails — schema reference (2026-08)

Reference doc for the CVE-enrichment resource type that Microsoft moved
to **management-group scope** after the MDVM data-consumption changes.
Source: <https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#update-to-cve-details-data-consumption-in-azure-resource-graph>.

Captured from a real client-tenant Azure Resource Graph query
(2026-08). Do NOT paste tenant IDs, subscription IDs, or client names
here — this doc is checked into the public repo. All CVE payloads
below are public NVD data.

## Why this doc exists

`defender.sh` used to read CVE fields (cvss, severity, exploitability)
inline from `properties.additionalData.CvesDetails[]` inside
`microsoft.security/assessments`. That inline path is now
**empty/stale** in target tenants — CVSS lands at `0.0`, severity
comes back empty, exploit flags all `false`. The correct source is
`microsoft.security/cvedetails`.

## Access requirements

- **Scope**: management group. Resource does NOT appear at
  subscription scope.
- **ARG flag**: `az graph query --management-groups <MG_ID>`.
- **Minimum role**: `Security Reader` (built-in) at the management
  group. Includes `Microsoft.Management/managementGroups/read` needed
  to target `--management-groups`.

## Resource shape

```
id:            /providers/microsoft.security/cvedetails/cve-2024-6179   (lowercase)
name:          cve-2024-6179                                            (lowercase)
type:          microsoft.security/cvedetails
tenantId:      (empty at MG scope)
subscriptionId:(empty at MG scope)
resourceGroup: (empty at MG scope)
properties:    { …see below… }
```

## `properties` keys (populated case)

Example: `CVE-2024-6179` (LG Electronics SuperSign CMS, Reflected XSS,
Medium severity, has both CVSS 3.x and CVSS 4.x).

```json
{
    "cveId": "CVE-2024-6179",
    "severity": "Medium",
    "status": "",
    "cvssSource": "Nvd",
    "publishedDate": "2024-06-20T01:53:11.588Z",
    "lastModifiedDate": "2026-06-17T08:17:26.793Z",

    "cvss": {
        "3.0": { "base": 6.1, "cvssVectorString": "CVSS:3.1/AV:N/…" },
        "2.0": null,
        "4.0": { "base": 4.8, "cvssVectorString": "CVSS:4.0/AV:A/…" }
    },

    "exploitabilityDetails": {
        "IsPubliclyDisclosed": false,
        "IsInExploitKit":      false,
        "IsVerified":          false,
        "ExploitUris":         [],
        "ExploitUri":          null,
        "Types":               [],
        "Epss": {
            "Percentile": 0.17104,
            "Score":      0.00253
        }
    },

    "weaknesses": [ { "Id": "CWE-79" } ],
    "references": [
        { "Source": "Nvd", "Title": "CVE-2024-6179", "Url": "https://…" }
    ],

    "description":          "Summary: …",
    "extendedDescription":  { "Summary": "…", "Impact": "…", "Remediation": "…", "AdditionalInformation": "…" },

    "DSag": true,
    "key":  { "id": "CVE-2024-6179" }
}
```

## `properties.cvss` — the trap that ate the client's data

Keys are **exactly** `"4.0"`, `"3.0"`, `"2.0"`. There is NO `"3.1"`
key. A coalesce that includes `properties.cvss['3.1'].base` will
always return `null` for that leg and silently drop the CVSS 3.x
score for CVEs that only have a 3.x vector.

Each populated version is an object with lowercase keys:
`{ "base": <number>, "cvssVectorString": <string> }`.

Individual versions can be `null` (see `CVE-2024-6179` where `2.0`
is null, or rejected CVEs where all three are null).

**Correct coalesce order**:

```
cvssScore = coalesce(
    todouble(cvedetail.properties.cvss['4.0'].base),
    todouble(cvedetail.properties.cvss['3.0'].base),
    todouble(cvedetail.properties.cvss['2.0'].base)
)
```

Note the `cvssVectorString` under key `"3.0"` may itself contain the
string `"CVSS:3.1/"` — Microsoft stores the vector under the closest
supported bucket. Only match on the KEY, never grep the vector string
for `3.1`.

## Rejected / withdrawn CVEs

Example: `CVE-2024-5776`, `CVE-2024-5779`, `CVE-2024-5656`.

```json
{
    "cveId":    "CVE-2024-5776",
    "severity": "",
    "status":   "Reject",
    "cvss":     { "3.0": null, "2.0": null, "4.0": null },
    …
}
```

Signals to filter these out:

- `properties.status =~ "Reject"`, or
- all three `properties.cvss.*` are null, or
- `properties.severity` empty.

Filtering on `status` is the cleanest — the other two indicators may
also occur legitimately for CVEs that are simply missing enrichment
data.

## Field mapping for `defender.sh` CSV (post-fix)

| CSV column                | Source                                                              |
|---------------------------|---------------------------------------------------------------------|
| `cvssScore`               | `cvedetails.properties.cvss['4.0'\|'3.0'\|'2.0'].base`              |
| `severity` (`severityRaw`)| `cvedetails.properties.severity`                                    |
| `cveAgeDays`              | `datetime_diff('day', now(), cvedetails.properties.publishedDate)`  |
| `isInExploitKit`          | `cvedetails.properties.exploitabilityDetails.IsInExploitKit`        |
| `hasPublishedExploit`     | `cvedetails.properties.exploitabilityDetails.IsPubliclyDisclosed`   |
| `hasVerifiedExploit`      | `cvedetails.properties.exploitabilityDetails.IsVerified`            |
| `repository`, `digest`, …  | still from `assessments.properties.resourceAdditionalData.*`        |
| `packageName`, `currentVersion`, `packageCategory`, `packageLanguage`, `remediation` | still from `assessments.properties.additionalData.*` |
| `cveId`, `fixedVersion`, `fixStatus` | still from `assessments.properties.additionalData.CvesDetails[]` (inline — the per-package linkage lives here, not in cvedetails) |

## Available but not yet surfaced

- `properties.exploitabilityDetails.Epss.Score` — 0.0–1.0 exploit
  prediction. Higher than any other signal we have today for
  prioritization. Candidate for a future PR-UX.
- `properties.exploitabilityDetails.Epss.Percentile` — companion to
  Score.
- `properties.weaknesses[].Id` — CWE IDs. Useful for grouping (e.g.
  "5 CVEs are all CWE-79 XSS").
- `properties.references[]` — clickable NVD/vendor links in the HTML
  report.

## Empty-JOIN failure mode

If `defender.sh` runs WITHOUT `--management-groups` (or the caller
lacks Security Reader on the MG), the LEFT OUTER JOIN with
`cvedetails` returns zero enrichment rows. Every CVE row gets
`cvssScore=0.0`, `severity=""`, all exploit flags `false` — exactly
today's bug. Detect and warn: pre-flight a
`securityresources | where type == 'microsoft.security/cvedetails' | limit 1`
probe before the main query; if it returns 0 rows, emit a WARN and
proceed (rows still land, only enrichment is degraded).
