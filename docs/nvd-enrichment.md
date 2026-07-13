# NVD Enrichment

Invoke-NvdCveExport.ps1 builds a compact NvdCve_Current.json.gz cache under the exports directory. When that cache is present, Generate-VulnerabilityDashboard.ps1 loads it and merges the NVD data into the dashboard payload automatically.

## Why This Exists

The dashboard already gets high-value CVE enrichment from Defender Advanced Hunting. NVD adds a second, optional source that is useful for:

- CVE metadata that Advanced Hunting does not always provide consistently
- CISA KEV-related fields when NVD has them
- CVSS vectors and severity/base-score detail from NVD's preferred metric set
- CWE-style weakness text for the CVE

The NVD cache is intentionally optional and standalone. Dashboard generation still works without it.

## How Target CVEs Are Chosen

The exporter uses one of two target-selection modes:

1. Explicit mode: if you pass -CveId, only those CVEs are requested.
2. Discovery mode: otherwise the script scans the current dashboard source rows and collects the distinct CVE IDs present in the local export set.

That means the script does not try to mirror the full NVD catalog. It only asks for the CVEs that matter to the current dashboard dataset.

It also does not consume the yearly NVD JSON feed files directly and it does not walk backward from the oldest vulnerability date in the dashboard data. The request surface is driven by the current target CVE set.

## Request Strategy

The script uses two request paths.

### Cold cache or missing CVEs

- Small cold starts still use targeted NVD CVE 2.0 requests with the cveId query parameter.
- Large cold starts now switch automatically to a catalog bootstrap path: the script pages through the NVD CVE API in large collection requests, scans newest pages first, and filters those pages down to the target CVEs locally.
- The current default threshold for switching to catalog bootstrap is 250 missing CVEs.
- After catalog bootstrap, any remaining misses fall back to targeted cveId requests.

The newest-first catalog scan is page-based, not publish-date-based. In other words, the exporter does not start with the oldest CVE in your environment and count backward from today. It starts with the newest NVD catalog pages and stops as soon as it has found the missing target CVEs.

This avoids the worst-case one-request-per-CVE behavior for large first runs.

### Warm cache refresh

- After the cache exists, the script stores the previous lastModifiedEndUtc value.
- Later runs call the NVD API with lastModStartDate and lastModEndDate to fetch only CVEs whose NVD records changed since the last sync window.
- The returned records are filtered down to CVEs already relevant to the dashboard target set.

This is why the first run is the expensive one and later runs are usually much cheaper.

## Data Pulled From NVD

For each CVE record, the exporter keeps a compact subset of the NVD payload:

- CveId
- PublishedDate
- LastModifiedDate
- VulnerabilityDescription
- BaseScore
- BaseSeverity
- Vector
- CisaExploitAdd
- CisaActionDue
- CisaRequiredAction
- Weaknesses

Metric selection prefers the best available CVSS set in this order:

1. cvssMetricV40
2. cvssMetricV31
3. cvssMetricV30
4. cvssMetricV2

If NVD omits optional properties, the exporter now treats them as absent instead of failing. That matters especially for the CISA KEV-related fields, which are not present on most CVEs.

## How The Dashboard Uses It

When Generate-VulnerabilityDashboard.ps1 runs, the NVD cache is read into a CVE-keyed map and merged during normalization.

The Azure Automation compatibility path receives this map alongside Advanced Hunting CVE, device-user, and inventory data. High-cardinality content-only workloads may use the compiled bounded projector, but a workload with a present NVD cache is deliberately kept on the enrichment-capable compatibility path until a compiled enrichment join is available. This preserves the optional NVD fields instead of trading correctness for memory.

Merge behavior:

- Advanced Hunting remains the primary source for PublishedDate and VulnerabilityDescription when it has values.
- NVD fills those two fields only as fallback values.
- NVD also adds fields that Defender does not already supply in the same shape:
  - NvdLastModifiedDate
  - NvdBaseScore
  - NvdBaseSeverity
  - NvdVector
  - NvdKevDate
  - NvdActionDue
  - NvdRequiredAction
  - NvdWeaknesses

Those values are written into the normalized CVE lookup in the payload, then denormalized into the browser row model with the rest of the dashboard data.

## Cache Behavior

- Output file: NvdCve_Current.json.gz
- Scope: only CVEs relevant to the current dashboard dataset
- Cache invalidation: the dashboard payload cache fingerprint includes NvdCve_Current.json.gz, so changing the NVD cache forces normalized payload regeneration

## Usage

First build or refresh the NVD cache, then generate the dashboard.

```powershell
./Invoke-NvdCveExport.ps1 -ApiKey $env:NVD_API_KEY
./Generate-VulnerabilityDashboard.ps1 -ExportMachineData $false
```

Focused test against one CVE:

```powershell
./Invoke-NvdCveExport.ps1 -ApiKey $env:NVD_API_KEY -CveId CVE-2025-32462 -ForceFullRefresh -ThrottleSeconds 0
```

## Practical Notes

- The NVD API key is optional, but it is recommended.
- The default throttle is 6 seconds between requests.
- A large first run can still take a while, but it now uses paged catalog bootstrap first instead of immediately issuing one targeted request per missing CVE.
- Subsequent runs are expected to be much faster because they reuse the local cache and refresh by last-modified window instead of re-requesting every CVE.
- You can tune when catalog bootstrap engages with -CatalogBootstrapThreshold if you want to force or delay that behavior.
