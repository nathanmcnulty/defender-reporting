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

## Bounded content-store path

The content-store publisher has two bounded passes after scatter:

1. device partitions deduplicate device profiles while writing staged device dictionary fragments and carrying observation envelopes forward;
2. content partitions deduplicate vulnerability templates and emit refs against the resolved device/template indexes.

Only the active partition's signature map and templates are retained. The final dictionary is assembled from staged fragments with `deviceProfileOrder = "partitioned"`, preserving the existing `content-dictionary-v1` object and ref line formats while making ordering non-contractual. The publisher keeps transactional staging, cleanup, Unicode handling, optional properties, and gzip output behavior. Because partitioned ordering cannot satisfy the old exact-order optimization, the execution plan selects the file-backed machine lookup instead of attempting direct merge.

The compiled standard-payload projector follows the same principle: dictionary arrays and ref fragments are written to disk, refs are projected through a streaming pass, and completed lookup collections are released before vulnerability fragments are copied into the final gzip payload. Its telemetry checkpoints cover scatter, dictionary/template assembly, ref projection, lookup/payload assembly, cleanup, and working-set trim.

## Compatibility and fallback

Existing canonical, content dictionary/ref, legacy array, and NDJSON formats remain supported. A compiled path must have deterministic parity tests against the PowerShell compatibility path for row counts, expanded data, optional fields, Unicode, and failure cleanup. Model or wire-format changes require an explicit version change; they are never inferred from file size or runtime environment.

The compatibility path must receive all available enrichment inputs. Advanced Hunting CVE, device-user, and inventory data plus NVD CVE data are optional, but when present they are passed into normalization and source metadata rather than dropped for memory reasons. Machine `machineTags` accepts both scalar and array JSON forms and normalizes both to the same tag collection.

## Memory policy

High-volume helpers must retain state according to configured dimension or partition cardinality, not total observation rows. Execution preflight rejects a workload before allocation when no measured mode fits the Automation envelope. Working set, private memory, and GC heap are reported independently.

For acceptance, use the true compiled pre-trim working-set high-water mark rather than a status-boundary sample. The current gate is below 400 MB in Azure Automation, with additional headroom preferred; private memory and GC heap are tracked independently because trimming the working set does not necessarily return committed private bytes to the OS.
