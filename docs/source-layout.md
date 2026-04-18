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

## Next decomposition targets

The current overhaul only moved the helper bundles onto explicit domains and manifests. The next likely candidates for further decomposition are:

- Azure provisioning and packaging entrypoints
- remaining large top-level scripts that still embed workflow-specific functions
- further dashboard payload/cache decomposition if the shared dashboard domain needs smaller ownership boundaries
