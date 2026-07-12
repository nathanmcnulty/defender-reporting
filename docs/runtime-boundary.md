# PowerShell and compiled runtime boundary

The reporting pipeline keeps its public and operational contract in PowerShell while using narrowly scoped compiled helpers for high-volume, allocation-sensitive work.

## PowerShell owns

- public parameters and backward compatibility;
- Azure authentication, control-plane calls, job orchestration, and status reporting;
- resource and cardinality preflight policy;
- staging, transactions, rollback, cleanup, and publication;
- manifests, hashes, validation decisions, and actionable diagnostics.

## Compiled helpers own

- streaming UTF-8 JSON parsing and serialization;
- deterministic procedural record generation;
- compact indexes, joins, partition scattering, and bounded caches;
- gzip streams and fixed-size buffers for high-volume artifacts.

Compiled helpers must not authenticate to Azure, select subscriptions, deploy resources, publish runbooks, or silently change dataset formats. PowerShell creates their staged paths, supplies validated arguments, consumes counts and diagnostics, and decides whether staged output is committed.

## Compatibility and fallback

Existing canonical, content dictionary/ref, legacy array, and NDJSON formats remain supported. A compiled path must have deterministic parity tests against the PowerShell compatibility path for row counts, expanded data, optional fields, Unicode, and failure cleanup. Model or wire-format changes require an explicit version change; they are never inferred from file size or runtime environment.

## Memory policy

High-volume helpers must retain state according to configured dimension or partition cardinality, not total observation rows. Execution preflight rejects a workload before allocation when no measured mode fits the Automation envelope. Working set, private memory, and GC heap are reported independently.
