# Source Layout

This repository now treats generated helper bundles as build artifacts, not as the source of truth.

## Principles

- PowerShell source lives under `src/powershell/` and is organized by domain.
- Generated helper bundles under `build/generated/` are assembled from explicit manifests.
- Build order is declared in `build/manifests/*.json`; it is no longer inferred from filename prefixes.
- Import wrappers and Azure packaging scripts consume the generated bundles, but maintainers should edit the domain source files.
- Regression validation enforces manifest coverage so orphaned source files are caught before merge.

## Current domains

- `src/powershell/Shared/Core`: shared primitives, store utilities, cache helpers, and serialization helpers.
- `src/powershell/Shared/Stores`: canonical storage readers, migration helpers, and snapshot import/publish logic.
- `src/powershell/Shared/DefenderApi`: Microsoft Defender API export and refresh workflows.
- `src/powershell/Shared/Enrichment`: Advanced Hunting and NVD readers plus shared enrichment/source-row projection helpers.
- `src/powershell/Shared/Dashboard`: normalization, payload generation, HTML assembly, and dashboard-side support.
- `src/powershell/Provisioning/Azure`: Azure provisioning entrypoint support, including ARM/Graph request helpers and polling utilities.
- `src/powershell/Validation/Audit`: regression and semantic validation helpers.
- `src/powershell/Validation/Orchestration`: dashboard validation entrypoints and failure shaping.

## Build graph

- `build/manifests/shared-helpers.json` defines the shared helper bundle.
- `build/manifests/validation-helpers.json` defines the validation helper bundle.
- `build/private/ArtifactManifestTools.ps1` resolves manifests, builds artifacts, and validates source coverage.

## Maintainer workflow

1. Edit the relevant file under `src/powershell/`.
2. If you add, remove, or reorder a source file, update the owning manifest under `build/manifests/`.
3. Rebuild with `./build/Build-SharedHelpers.ps1` or `./build/Build-ValidationHelpers.ps1` as needed.
4. Run `./build/Invoke-RegressionValidation.ps1` before merge.

## Agent-safe change guardrails

- Treat `src/powershell/**`, `build/private/**`, `build/manifests/**`, and `build/azure/**` as the authoritative sources.
- Treat `build/generated/*.ps1`, `azure/Invoke-DashboardPipeline.ps1`, and `azure/function-app/ExportAndGenerate/run.ps1` as derived outputs.
- Keep each tracked source file owned by one manifest and keep generated outputs outside tracked source roots.
- If you add a new maintainer workflow or validation lane, update the matching maintainer docs (`build/README.md`, `tests/README.md`, and `docs/workflows.md`) in the same PR.
- Reuse helpers from `tests/helpers/` or `build/private/` before introducing duplicate utility functions in new scripts.

## Remaining decomposition watchlist

The current overhaul has moved helper ownership out of the large top-level entry scripts and into explicit source-first domains. The remaining follow-up work is narrower and currently centered on:

- further dashboard payload/cache decomposition if the shared dashboard domain needs smaller ownership boundaries
