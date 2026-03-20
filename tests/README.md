# Tests

This folder contains lightweight PowerShell regression coverage for the Defender reporting pipeline.

## Runbook-safe regression entrypoint

Run the full local regression bundle with:

```powershell
pwsh -NoProfile -File .\Invoke-RegressionValidation.ps1
```

That script rebuilds the generated helper/runbook artifacts, runs parser and PSScriptAnalyzer checks, executes focused shared-helper regression tests, and performs a small dashboard fixture smoke generation.

## Legacy migration fixture

`tests/fixtures/legacy-migration` contains a tiny synthetic dataset used to exercise the temporary legacy vulnerability migration path.

Important note:
- the fixture files named `*.json` are intentionally a mix of formats
- `VulnExport_*.json` and `AdvancedHunting_Current.json` are NDJSON-style files, where each line is an individual JSON object
- `Machines_Current.json` is a single JSON object

These shapes match what the pipeline readers already support, even though NDJSON files are not a single valid JSON document when opened in a generic JSON validator.
