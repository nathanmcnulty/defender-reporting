# Windows browser outer supervisor

Run `Invoke-OuterBrowserSupervisor.ps1` in a fresh PowerShell 7.6+ process.
Pass the absolute executable and an argument array; the supervisor does not
invoke a shell. For example, from PowerShell after setting `PLAYWRIGHT_MODULE`
and preparing the private control inputs:

```powershell
& .\tests\Invoke-OuterBrowserSupervisor.ps1 `
    -Executable (Get-Command node.exe).Source `
    -Arguments @(
        (Join-Path $PWD 'tests\Measure-DashboardWorkerTransfer.js'),
        (Join-Path $PWD '.local\two-row-control'),
        (Join-Path $PWD '.local\worker-control.json'),
        '1', '2', '--positive-control'
    )
if ($LASTEXITCODE -ne 0) { throw 'Measurement failed or cleanup was not confirmed.' }
```

The standard input of the guarded process is NUL. Its stdout and stderr are
passed through unchanged, so treat those streams and harness evidence as
private. The supervisor writes a JSON status to stderr with admission sample
times and bytes, sampled runtime counts/peaks and cleanup confirmation; it
also reports fixed failure phase/step/category labels and a native error code
when applicable, without paths, arguments or exception messages. The peak is
sampled, not an OS high-water mark.
`CleanupConfirmed` covers the retained root and outer job, not browser profile
removal or complete output after a failed run. Retain telemetry separately when
evidence is required.
Exit zero requires root exit zero, two consistent empty job censuses,
complete output streams and successful supervisor handle cleanup. Any guard,
sampling, exit, stream or cleanup uncertainty returns nonzero. A root exit
with surviving descendants is a failure and triggers job termination.

The immutable policy is an unnamed, non-inheritable outer job with flags
`0x2200`, 2 GiB job commit, no UI restrictions, a 240-second wall deadline,
2 GiB summed whole-job working set, 3 GiB available-physical-memory floor,
and 500 ms runtime sampling. Five admission readings must each exceed
5.25 GiB and be at least 500 ms apart. A host below that threshold is rejected;
there is no production bypass. A census that proves process churn is retried
only within the current 500 ms sampling interval; persistent churn, inconsistent
accounting or an inaccessible counter fails closed. Every observed partial sum
over the working-set cap fails immediately. A failure status does not certify cleanup: retain
private evidence and investigate any unconfirmed cleanup before another run.
This guard does not replace the harness's inner owner, profile, readiness,
offline or semantic checks.

Run browser-free deterministic and Windows native regression controls with:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\Invoke-OuterBrowserSupervisorRegression.ps1
```

These controls use internal-only fakes for admission and faults, and launch
only PowerShell fixtures, never a browser. They exercise nested inner job
compatibility but do not establish browser or large-data acceptance.
