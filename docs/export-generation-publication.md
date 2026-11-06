# Azure export generations

The Azure pipeline stores each complete export under an immutable
`exports/_generations/<generation>/` prefix. Its single commit point is
`exports/_publication/exports.current.json`. The pointer includes the exact
filenames, lengths and SHA-256 hashes for that generation. This covers raw
current/history stores, dictionary/ref projections and optional enrichment
together. Dashboard HTML publication remains a separate transaction.

At startup the pipeline reads the pointer and its ETag in one GET. It downloads
only that manifest's generation and verifies every file before processing data.
An invalid pointer, missing member or mismatched hash stops the run; it never
combines generation files with the older root layout. A reader already holding
the previous pointer can finish while a newer generation is being published.

Publication uploads new generation files with create-only conditions and verifies
their stored bytes before committing the pointer. Pointer replacement uses the
ETag captured before the run read its inputs. If a concurrent publisher advances
the pointer before this export commit, the stale run stops before reaching
dashboard publication. A first publication uses create-only pointer publication instead.
When a PUT commits but its response is lost, exact readback can reconcile success.
If readback is unavailable or differs, the run stops with an uncertain outcome;
the pointer still selects either a complete prior or complete new generation.

The export pointer and dashboard roots remain separate commit points. This
protocol prevents mixed export generations; it does not impose completion order
on independently running export and HTML transactions. A run that already
committed its export can finish HTML publication after a newer run. Coordinate
refreshes when strict dashboard freshness ordering is required.

## Migration and operation

When no pointer exists, the pipeline reads the legacy root layout and creates the
first generation on successful publication. This assumes the legacy store is
internally consistent; it cannot establish whether an older failed upload already
mixed its dictionary and refs. Check or rebuild a suspect legacy store from a
trusted complete source before migration.

Pause older pipeline versions during cutover and update every scheduled or manual
publisher together. Older versions do not understand the pointer. Legacy root
files are deliberately left untouched after migration so an older reader does not
observe a half-updated root store; those files are a frozen historical snapshot,
not the current export. External consumers must use the manifest and verify its
files, or obtain a complete local export from the updated pipeline. Reverting to
an older pipeline is not a rollback to the latest export generation.

The pipeline does not prune generation files, including abandoned staging
generations. Deleting an old generation can break an in-flight reader that holds
its pointer. Retention or rollback needs a separately coordinated maintenance
procedure with publishers/readers stopped, a verified complete retained manifest,
and normal deployment approval. Do not manually overwrite individual members or
delete the pointer to conceal a failed generation. Storage retention changes and
live Azure fault injection are not established by offline regression checks.

## Regression coverage

Run `pwsh -NoProfile -File tests/Invoke-AtomicExportPublicationRegression.ps1`.
The test uses the real local store publisher and dictionary/ref reader with an
in-memory Azure boundary. It covers every file and pointer upload interruption,
successful retry, committed response loss with and without readback, incorrect
upload bytes, concurrent stale writers, readers holding prior snapshots,
create-only legacy migration, frozen legacy roots and fail-closed manifest/file
validation. It proves protocol behavior under the injected boundary, not Azure
authentication, actual storage conditional-request behavior or deployment/runtime
acceptance.
