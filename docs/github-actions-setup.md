# GitHub Actions Setup

This revision changes dashboard publication only. The PDF workflow, its trigger and read-only permissions remain unchanged; it has no publishing steps and stays disabled for public use. Local output paths remain ignored.

As of November 25, 2026, the public owner's dashboard workflow is manually disabled while its unsanitized demo-data policy is unresolved. Scheduled and manual runs are paused, but the existing public `demo-data` snapshot and historical copies remain accessible. This GitHub workflow setting does not affect the deployed Azure Function or the state of workflows in private repositories.

## Dashboard admission

The dashboard job checks this condition before checkout, authentication, collection or live logging; the staging helper repeats it using `GITHUB_REF`:

```yaml
if: ${{ (github.repository == 'nathanmcnulty/defender-reporting' && github.ref == 'refs/heads/main') || github.event.repository.private == true }}
```

| Repository | Ref | Privacy | Dashboard job |
|---|---|---|---|
| `nathanmcnulty/defender-reporting` | `refs/heads/main` | Public or unknown | Admitted, subject to verified demo tenant binding |
| Owner repository | Other branch, tag, or missing ref | Public or unknown | Skipped |
| Any repository | Existing supported ref | Private (`true`) | Admitted under existing private rules |
| Any other repository | Any | Public or unknown | Skipped |

Public forks and other public repositories owned by Nathan are excluded. Missing metadata fails closed outside the exact owner/main exception. The PDF job continues requiring `private: true` and does not commit or upload PDFs.

## Tenant binding before owner activation

**Keep the public dashboard workflow disabled until the owner has approved a safe publication policy.** If the chosen policy uses live demo data, also verify the configured tenant as the approved demo tenant. A source check cannot prove which directory is configured in GitHub or that its output is safe to publish. Offline tests need no tenant lookup, sign-in, credentials, new permissions or live dry run.

For the owner repository, `build/Invoke-LiveDashboardDryRun.ps1` requires the GitHub OIDC parameter set and an explicit nonempty tenant GUID. It rejects an ambient existing context as an authentication mode. After the existing OIDC connection, it checks that the Az context tenant matches that GUID, requests the Defender token with that explicit tenant, and checks the returned token tenant. Missing/mismatched context or token metadata, failed Az token acquisition, or a missing Az token command stops the run. Owner runs never fall back to the Azure CLI’s ambient account. Other private/local calls retain their existing fallback behavior. The source guard also protects owner-repository runs when that repository is private.

Before activation, an authorized maintainer must verify this nonsecret binding metadata through the approved administrative path, without posting secret values or operational data:

- The intended demo directory’s tenant GUID equals the configured `AZURE_TENANT_ID`; use a GUID, not a domain alias.
- The configured `AZURE_CLIENT_ID` identifies the intended application/service principal in that demo directory.
- The existing federated credential has issuer `https://token.actions.githubusercontent.com`, subject `repo:nathanmcnulty/defender-reporting:ref:refs/heads/main`, and audience `api://AzureADTokenExchange`.
- The approved branch, existing Defender access and public demo destination/logging approval refer to that same demo tenant. This revision grants no new Entra rights.

No actual binding values were retrieved or verified by the offline tests. `dry_run: true` still reads live Defender data and can emit public logs; it is not an offline activation test.

## Dashboard outputs

The workflow definition retains its daily `02:00 UTC` schedule and manual trigger, which do not run while the workflow is disabled. When enabled, it first restores incremental export state from the `demo-data` branch, then runs the existing exporter with Advanced Hunting still included by default; collection is not widened. After validation, the staging helper force-stages only these paths into an empty orphan worktree:

- `VulnerabilityDashboard.html`
- `exports/VulnExport_current.json.gz`, `VulnContentDictionary.json.gz`, `VulnCurrentRefs.json.gz`
- `exports/VulnHistory_YYYY[Q1-Q4].json.gz`, `VulnHistoryRows_YYYY[Q1-Q4].json.gz`, `VulnHistoryRefs_YYYY[Q1-Q4].json.gz` (quarter suffix optional)
- `exports/Machines_Current.json.gz`, `Machines_History.json.gz`, `Machines_History_YYYYQ[1-4].json.gz`, `Machines_History_YYYYMMDDTHHMMSSZ_abcdefgh.json.gz` (eight lowercase hexadecimal suffix characters)
- `exports/AdvancedHunting_Current.json.gz`

Only the HTML is uploaded as a 30-day Actions artifact. Audit and manifest files remain under ignored `.local/` and are neither committed nor uploaded. Raw responses, legacy downloads, NVD cache files, credentials/configuration, locks, staging directories, arbitrary files and PDFs are excluded. The source export directory must be a real directory, copies do not dereference links, and the helper requires an empty index and rejects nonregular outputs, including dangling links, before staging any file. The snapshot is committed and force-pushed to `refs/heads/demo-data`, so that branch always holds exactly one commit and `main` no longer grows with daily data. Validation failure prevents publication; manual `dry_run: true` skips staging, commits and artifacts.

This is a filename allowlist, not content redaction. Owner demo outputs and logs are public if published. Private repository status does not make Pages, blob storage, Container Apps or other external destinations private. These workflows do not deploy to those destinations. History cleanup and issue #68 remain separate.

## Existing private setup

Use `Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo "yourorg/defender-reporting" -IncludeAdvancedHunting` for the existing OIDC setup, and configure the returned client and tenant identifiers as `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`. OIDC uses no stored client secret. This change does not run setup or alter credentials or service permissions. The exporter’s existing Advanced Hunting default still requires its existing `AdvancedQuery.Read.All` access alongside `Vulnerability.Read.All` and `Machine.Read.All`.

Only the guarded dashboard job receives `contents: write` and `id-token: write`; top-level contents remain read-only. The only push is the force-replace of the unprotected `demo-data` snapshot branch; nothing is pushed to `main` and there is no protection bypass. Private forks retain their admission behavior and must review their own destination access controls before live collection.

## Offline and hosted checks

Run `node tests/Assert-DashboardWorkflowPrivacy.js` for admission, allowlist and isolated Git staging checks. Run `./tests/Run-SharedHelperRegression.ps1 -TestName Test-LiveDashboardTenantBinding` for extracted-function tests with synthetic Az/CLI mocks; it never executes the live wrapper or signs in. The normal `./build/Invoke-RegressionValidation.ps1` includes these checks and the repository parser/analyzer checks.

Before re-enabling the public workflow, decide how demo outputs and logs can be published safely. If using live data, verify the nonsecret demo binding above and explicitly approve the public destination. Re-enabling restores the unchanged `02:00 UTC` schedule and manual trigger; it does not remove past snapshots or history. Keep the PDF workflow disabled for public use.

Related: [workflow notes](workflows.md), [Azure setup](azure-setup.md).
