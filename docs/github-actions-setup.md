# GitHub Actions Setup

The repo includes an automated dashboard update workflow that authenticates to Azure using OIDC federated credentials. That means the workflow does not need a stored client secret.

## What the workflow does

`.github/workflows/update-vulnerability-dashboard.yml`:

- Signs in to Azure using GitHub's OIDC token
- Exports the latest Defender data into `exports/`
- Regenerates `VulnerabilityDashboard.html`
- Validates the dashboard and uploads the audit as an artifact
- Commits updated exports and dashboard output unless you run in dry-run mode

## Recommended setup

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

3. Protect the default branch.

Because the update workflow commits generated content back to the repository, add a ruleset or branch protection policy that matches how you want automation to behave.

4. Run the workflow manually once.

Use Actions -> `Update Vulnerability Dashboard` -> `Run workflow`, or wait for the daily `02:00 UTC` schedule.

## Why `-IncludeAdvancedHunting` is recommended

The current update workflow calls:

```powershell
.\Invoke-VulnerabilityExport.ps1 -AccessToken $accessToken -OutputPath .\exports -IncludeAdvancedHunting
```

That means the GitHub Actions service principal should also have `AdvancedQuery.Read.All`, not just `Vulnerability.Read.All` and `Machine.Read.All`.

## Dry-run behavior

The workflow exposes a `dry_run` input:

- `false`: commits and pushes generated changes
- `true`: shows what would change without committing

Pushes to `test/**` branches also behave like dry runs for the commit step.

## Related docs

- [Azure setup](azure-setup.md)
- [Workflow notes](workflows.md)
