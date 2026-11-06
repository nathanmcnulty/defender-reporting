# GitHub Actions Setup

Nathan intentionally publishes his real lab exports, dashboard, and PDFs as demos in `nathanmcnulty/defender-reporting`. Live jobs admit that exact repository or a repository whose GitHub event reports `private: true`:

```yaml
if: ${{ github.repository == 'nathanmcnulty/defender-reporting' || github.event.repository.private == true }}
```

The condition is on each job, before checkout, authentication, collection, or exporter logs. Other public repositories, including public forks and other repositories owned by Nathan, skip both live jobs. Missing privacy metadata fails closed outside the exact owner repository. Fork owners can change their own workflow code; this guard prevents accidental execution with the shipped configuration.

| Repository | Privacy | Live update/PDF jobs | Synthetic validation |
|---|---|---|---|
| `nathanmcnulty/defender-reporting` | Public or private | Allowed | Available |
| Any other repository | Private | Allowed | Available |
| Any other repository | Public or unknown | Skipped | Available |

## Output destinations

The update job exports to `exports/` and generates `VulnerabilityDashboard.html` through `build/Invoke-LiveDashboardDryRun.ps1 -UseRepositoryOutputPaths`. After successful validation it commits only canonical Defender gzip stores and the self-contained HTML to the selected branch. The staging helper includes deletions of recognized history files. It excludes raw download responses, legacy downloads, credential/configuration files, locks, caches, temporary staging files, and arbitrary additional files. OIDC tokens stay in the authentication flow; no token response or credential file is an output destination. The exporter's existing URI sanitization remains in place.

The HTML is also uploaded as an Actions artifact with 30-day retention. Audit and manifest files remain under ignored `.local/` on the runner and are neither committed nor uploaded. Failed validation does not publish partial results. Manual `dry_run: true` still authenticates and collects live data, but skips commits and uploads; the daily schedule publishes normally.

The PDF job reads the committed `VulnerabilityDashboard.html`, renders five named report families, commits only their dated PDFs (including recognized deletions), and uploads those families as a 30-day Actions artifact. It is manual by default and does not authenticate to Azure. Run the update job successfully first to create the HTML; historical demo payloads are not restored by this source change.

Repository commits and Actions artifacts follow that repository's access controls. In Nathan's public repository these are intentionally public lab demos, and exporter logs can reveal lab group IDs and counts. In a private fork these outputs and logs contain that fork's tenant data. **Private repository status does not make GitHub Pages, Azure blobs, Container Apps, release assets, or any external destination private.** These two workflows do not deploy to those destinations; review separate publishing automation and its access controls before collecting live data. Public forks may inherit Nathan's published demos in Git history, but their shipped live jobs cannot collect and publish their own tenant data.

Output paths remain ignored for ordinary local work. The CI helper force-stages an explicit filename allowlist, requires an empty Git index, rejects non-regular outputs, and rechecks repository admission. Do not replace it with broad or whole-directory staging. This is output scoping, not general content redaction: review exporter/schema changes for credential-bearing fields before allowing them into demo output.

## Setup for the owner repository or a private repository

1. Create the Entra app and federated credential:

```powershell
.\Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo "yourorg/defender-reporting" -IncludeAdvancedHunting
```

Use `-Branch` for a branch other than `main`. Add the returned `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` as Actions secrets. OIDC needs no stored client secret. The wrapper includes Advanced Hunting unless explicitly skipped, so grant `AdvancedQuery.Read.All` alongside `Vulnerability.Read.All` and `Machine.Read.All`.

2. Review branch protection and write permissions. Only guarded live jobs get `contents: write`; only the update job gets `id-token: write`. The PDF job has no OIDC permission. A protected branch can reject the bot push; no bypass or forced push is attempted.
3. When ready for live work, use Actions → Update Vulnerability Dashboard → Run workflow on the intended branch, or the daily `02:00 UTC` schedule. Use dry-run for live validation without commits or artifacts. This local patch does not enable or dispatch workflows.

## Offline validation

`Validate Dashboard` remains available on all forks with read-only repository permissions and synthetic fixtures, independent of root demo files. Run `node tests/Assert-DashboardWorkflowPrivacy.js` for the admission matrix and isolated Git staging checks, or `./build/Invoke-RegressionValidation.ps1` for the normal deterministic preflight. Neither needs live collection.

Related: [workflow notes](workflows.md), [Azure setup](azure-setup.md).
