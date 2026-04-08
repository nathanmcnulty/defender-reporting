# Workflow Notes

This repo currently ships three GitHub Actions workflows.

## Workflow summary

| Workflow | File | Purpose |
|---|---|---|
| Update Vulnerability Dashboard | `.github/workflows/update-vulnerability-dashboard.yml` | Run the live export and dashboard validation path, upload artifacts, and optionally publish repo outputs |
| Validate Dashboard | `.github/workflows/validate-dashboard.yml` | Run the deterministic repo preflight used for local and PR validation |
| Export Dashboard PDFs | `.github/workflows/export-pdf-reports.yml` | Render PDF report variants from the latest committed dashboard |

## Flow

```mermaid
flowchart TD
    A["Update dashboard"] --> B["Live export dry run"]
    B --> C["Generate HTML"]
    C --> D["Validate output and emit artifacts"]
    D --> E["Optional publish to repo paths"]
    C --> F["Optional PDF export workflow"]
    F --> G["Commit PDF reports"]
```

## Update Vulnerability Dashboard

Trigger sources:

- Daily schedule at `02:00 UTC`
- Manual run with optional `dry_run`

Key behavior:

- Uses repo-owned Azure OIDC logic through `Invoke-LiveDashboardDryRun.ps1`
- Runs the live export and dashboard validation path before any publish step
- Uploads `dashboard-audit.json`, `dashboard-live-run-manifest.json`, and the generated `VulnerabilityDashboard.html` as workflow artifacts
- Commits `exports/` and `VulnerabilityDashboard.html` only when the run is not a dry run

## Validate Dashboard

Trigger sources:

- Pull requests that touch scripts, templates, exports, or workflow files
- Pushes to `main` for the same paths
- Manual run

Key behavior:

- Installs `PSScriptAnalyzer`
- Calls the repo-owned `Invoke-RegressionValidation.ps1` entrypoint
- Validates generated deployment artifacts, source scripts, regression helpers, and committed-export dashboard generation through one deterministic path

## Export Dashboard PDFs

Trigger sources:

- Manual run today
- Optional scheduled run if you uncomment the cron entry in the workflow

Key behavior:

- Checks whether committed PDF exports are older than `VulnerabilityDashboard.html`
- Uses Playwright and `.github/scripts/export-pdf-reports.js`
- Commits updated files under `reports/`
- Uploads generated PDFs as a workflow artifact

## Suggested operating model

- Use the update workflow for the regular daily refresh
- Let the validation workflow protect changes to scripts and templates through the same deterministic preflight used locally
- Run the PDF workflow only when the HTML dashboard changes enough to warrant fresh report exports
- Use `Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext` locally when you need exact-path validation for the live export flow before publishing

## Related docs

- [Azure setup](azure-setup.md)
- [GitHub Actions setup](github-actions-setup.md)
