# GitHub Actions Setup

The repo includes an automated dashboard update workflow for private repositories only that authenticates to Azure using OIDC federated credentials. That means the workflow does not need a stored client secret.

The live dashboard update and PDF export jobs require `${{ github.event.repository.private == true }}`. Keep both workflows disabled in public repositories; their job-level guards skip execution even if triggered. Live exporter logs can expose RBAC group IDs and counts even when no output files are published.

## What the workflow does

`.github/workflows/update-vulnerability-dashboard.yml`:

- Signs in to Azure using GitHub's OIDC token
- Exports the latest Defender data into the runner's ignored `.local/` directory
- Regenerates and validates a self-contained dashboard on the ephemeral runner
- Does not upload or commit live exports, dashboards, or audit data to this public repository

Keep live dashboard outputs in access-controlled storage, not in a public repository or workflow artifacts. Generate a distinct split-assets build such as `VulnerabilityDashboard.Hosted.html` for protected hosting. When you need both from the same run, prefer `-DualPackage` so the outputs share the same normalized payload.

## Recommended setup (private repositories only)

1. Create the Entra app and federated credential.

```powershell
.\Setup-GitHubActionServicePrincipal.ps1 `
    -GitHubRepo "yourorg/defender-reporting" `
    -IncludeAdvancedHunting
```

Use `-Branch` if the workflow should trust a branch other than `main`.

2. Add these repository secrets under Settings -> Secrets and variables -> Actions.

| Secret | Value |
|---|---|
| `AZURE_CLIENT_ID` | Application (client) ID returned by the setup script |
| `AZURE_TENANT_ID` | Tenant ID returned by the setup script |

3. Protect the default branch and review access to the private dashboard destination separately. The workflow needs only read access to repository content.

4. Run the workflow manually once.

In a private repository, use Actions -> `Update Vulnerability Dashboard` -> `Run workflow`, or wait for the daily `02:00 UTC` schedule. Public-repository workflows must remain disabled and their jobs are skipped if triggered.

## Why `-IncludeAdvancedHunting` is recommended

The current update workflow calls the repo-owned wrapper:

```powershell
.\build\Invoke-LiveDashboardDryRun.ps1 -AzureClientId $env:AZURE_CLIENT_ID -AzureTenantId $env:AZURE_TENANT_ID
```

The wrapper defaults to ignored `.local/` output paths and includes Advanced Hunting unless explicitly skipped. That means the GitHub Actions service principal should also have `AdvancedQuery.Read.All`, not just `Vulnerability.Read.All` and `Machine.Read.All`.

## Existing public data

Changing the workflow prevents future publication, but does not remove previously committed exports, dashboards, PDFs, or copies in Git history. The checked-in dataset is still used by regression tests. Replace it with verified synthetic fixtures before removing tracked data, and coordinate history retention or disclosure through a private security review; do not paste tenant data into a public issue.

## Related docs

- [Azure setup](azure-setup.md)
- [Workflow notes](workflows.md)
