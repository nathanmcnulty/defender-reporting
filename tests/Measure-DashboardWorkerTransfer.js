const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const zlib = require('zlib');
const { Writable } = require('stream');
const { pipeline } = require('stream/promises');
const { execFile, spawn, spawnSync } = require('child_process');
const { performance } = require('perf_hooks');
const { loadDashboardSource } = require('./helpers/dashboard-test-harness');

function safeInventoryDiagnostic(value = {}) {
    const categories = ['timeout', 'aborted', 'execution', 'response', 'InvalidOperation', 'InvalidArgument', 'InvalidData', 'OperationStopped', 'WriteError', 'ObjectNotFound', 'PermissionDenied', 'SecurityError', 'ResourceUnavailable', 'NotSpecified'];
    const types = ['RuntimeException', 'CimException', 'MethodInvocationException', 'PSInvalidOperationException', 'SessionStateUnauthorizedAccessException', 'UnauthorizedAccessException', 'InvalidOperationException', 'ArgumentException', 'Win32Exception'];
    const phases = ['execute', 'compile', 'cim', 'selection', 'memory', 'termination', 'response'];
    const steps = ['fresh-cim', 'fresh-identity', 'fresh-process-identity', 'fresh-root-identity', 'get-process', 'start-identity', 'kill', 'kill-exit-check', 'wait-exit'];
    return {
        category: categories.includes(value.category) ? value.category : 'execution',
        exceptionType: types.includes(value.exceptionType) ? value.exceptionType : 'unclassified',
        exitCode: Number.isInteger(value.exitCode) && value.exitCode >= 0 && value.exitCode <= 255 ? value.exitCode : null,
        phase: phases.includes(value.phase) ? value.phase : 'execute',
        ...(steps.includes(value.step) ? { step: value.step } : {}),
        ...(types.includes(value.innerExceptionType) ? { innerExceptionType: value.innerExceptionType } : {}),
        ...(Number.isInteger(value.nativeErrorCode) && value.nativeErrorCode >= 0 && value.nativeErrorCode <= 65535 ? { nativeErrorCode: value.nativeErrorCode } : {})
    };
}

function safeFailure(error, phase = 'unknown') {
    const phases = ['unknown', 'arguments', 'provenance', 'assets', 'browser', 'evidence-write', 'preflight'];
    const codes = ['ENOENT', 'EACCES', 'EBUSY', 'EPERM', 'EINVAL', 'ENOSPC', 'Z_DATA_ERROR', 'Z_BUF_ERROR'];
    const reasons = new Map([
        ['Browser family memory cap exceeded.', 'family-cap'],
        ['Safety memory floor prevents launch or continuation.', 'memory-floor'],
        ['Owned process inventory/termination failed.', 'process-inventory'],
        ['Invalid process inventory response.', 'process-inventory'],
        ['Owned cleanup failed.', 'cleanup'],
        ['Microsoft Edge is required.', 'edge-unavailable']
    ]);
    return {
        phase: phases.includes(phase) ? phase : 'unknown',
        reason: reasons.get(error?.message) || (error?.code === 'ENOENT' ? 'missing-input' : 'operation-failed'),
        code: codes.includes(error?.code) ? error.code : 'unclassified',
        ...(error?.inventoryDiagnostic ? { inventoryDiagnostic: safeInventoryDiagnostic(error.inventoryDiagnostic) } : {})
    };
}

class ResourceGuard {
    constructor({ inventory, terminate, freeMemory = os.freemem, limits, interval = 1500 }) {
        Object.assign(this, { inventory, terminate, freeMemory, limits, interval });
        this.trace = [];
        this.peakBytes = 0;
        this.minimumFreeBytes = Infinity;
        this.failure = new Promise((resolve, reject) => { this.rejectFailure = reject; });
        this.failure.catch(() => {});
    }

    abort(error) {
        if (!this.error) {
            this.error = error;
            clearInterval(this.timer);
            this.kill = bounded(Promise.resolve().then(this.terminate), 'Safety termination', 15000);
            this.kill.catch(() => {});
            this.rejectFailure(error);
        }
        return this.error;
    }

    check() {
        if (this.error) throw this.error;
    }

    async wait(operation) {
        this.check();
        const result = await Promise.race([operation, this.failure]);
        this.check();
        return result;
    }

    sample(stage) {
        if (this.inflight) return this.inflight;
        const startedAt = performance.now();
        this.inflight = (async () => {
            try {
                this.check();
                const inventory = await this.inventory();
                const freeBytes = this.freeMemory();
                assert(Number.isFinite(inventory.bytes) && inventory.bytes >= 0 && Array.isArray(inventory.pids), 'Invalid process inventory.');
                assert(Number.isFinite(freeBytes) && freeBytes >= 0, 'Invalid free memory inventory.');
                this.peakBytes = Math.max(this.peakBytes, inventory.bytes);
                this.minimumFreeBytes = Math.min(this.minimumFreeBytes, freeBytes);
                this.trace.push({ stage, startedAtHostMs: startedAt, sampledAtHostMs: performance.now(), sampledAtEpochMs: Date.now(), browserFamilyBytes: inventory.bytes, browserFamilyPrivateBytes: inventory.privateBytes ?? null, freeMemoryBytes: freeBytes, ownedProcessCount: inventory.pids.length });
                assert(inventory.bytes <= this.limits.browserFamilyBytes, 'Browser family memory cap exceeded.');
                assert(freeBytes >= this.limits.freeMemoryBytes, 'Safety memory floor prevents launch or continuation.');
                this.check();
            } catch (error) {
                throw this.abort(error);
            }
        })().finally(() => { this.inflight = null; });
        return this.inflight;
    }

    start() {
        this.check();
        this.sample('post-spawn').catch(() => {});
        this.timer = setInterval(() => this.sample(this.stage || 'startup').catch(() => {}), this.interval);
    }

    async finish() {
        if (this.inflight) await this.inflight;
        await this.sample('final');
        this.check();
    }

    async stop() {
        clearInterval(this.timer);
        if (this.inflight) await this.inflight.catch(() => {});
        if (this.kill) await this.kill;
    }
}

async function guardProbes() {
    let kills = 0;
    let bytes = 1;
    const guard = new ResourceGuard({ inventory: async () => ({ bytes, pids: [] }), terminate: async () => { kills++; }, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    await guard.sample('prelaunch');
    bytes = 3;
    await assert.rejects(guard.finish(), /cap exceeded/);
    await guard.stop();
    assert.strictEqual(kills, 1);
    assert.strictEqual(guard.peakBytes, 3);
    assert.strictEqual(guard.trace.at(-1).stage, 'final');
    const failed = new ResourceGuard({ inventory: async () => { throw new Error('inventory failed'); }, terminate: async () => { kills++; }, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    failed.start();
    await assert.rejects(failed.wait(new Promise(() => {})), /inventory failed/);
    await failed.stop();
    assert.strictEqual(kills, 2);
    console.log('PASS guard final cap and pre-CDP inventory failure');
}

async function bounded(operation, label, timeout = 5000) {
    let timer;
    try {
        return await Promise.race([operation, new Promise((resolve, reject) => {
            timer = setTimeout(() => reject(new Error(`${label} exceeded ${timeout} ms`)), timeout);
        })]);
    } finally {
        clearTimeout(timer);
    }
}

function powershell(script, environment, timeout = 5000, signal) {
    return new Promise((resolve, reject) => {
        const wrapped = `& { $issue70Phase = 'execute'; $issue70Step = $null; try {\n${script}\n} catch { $inner = $_.Exception.GetBaseException(); @{ issue70Failure = @{ category = $_.CategoryInfo.Category.ToString(); exceptionType = $_.Exception.GetType().Name; phase = $issue70Phase; step = $issue70Step; innerExceptionType = $inner.GetType().Name; nativeErrorCode = if ($inner -is [ComponentModel.Win32Exception]) { $inner.NativeErrorCode } else { $null } } } | ConvertTo-Json -Compress; exit 1 } }`;
        execFile('pwsh', ['-NoProfile', '-Command', wrapped], {
            env: { ...process.env, ...environment }, encoding: 'utf8', timeout, signal, windowsHide: true, maxBuffer: 1024 * 1024
        }, (error, stdout) => {
            let result;
            try { result = JSON.parse(stdout.trim()); } catch {}
            if (error || result?.issue70Failure || !result) {
                const failure = new Error(error || result?.issue70Failure ? 'Owned process inventory/termination failed.' : 'Invalid process inventory response.');
                failure.inventoryDiagnostic = safeInventoryDiagnostic({
                    ...result?.issue70Failure,
                    ...(error?.code === 'ABORT_ERR' ? { category: 'aborted' } : error?.killed ? { category: 'timeout' } : !result ? { category: 'response', phase: 'response' } : {}),
                    exitCode: typeof error?.code === 'number' ? error.code : null
                });
                return reject(failure);
            }
            resolve(result);
        });
    });
}

function ownedProcesses(profile, execute = powershell) {
    assert.strictEqual(process.platform, 'win32', 'Windows process inventory is required.');
    let known = [];
    let launcherPid = 0;
    let launcherCreated = '';
    const selection = `
$ErrorActionPreference = 'Stop'
$issue70Phase = 'compile'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Issue70Arguments {
    [DllImport("shell32.dll", SetLastError = true)]
    static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string command, out int count);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    public static string[] Parse(string command) {
        int count;
        var pointer = CommandLineToArgvW(command, out count);
        if (pointer == IntPtr.Zero) throw new InvalidOperationException();
        try {
            var result = new string[count];
            for (int index = 0; index < count; index++) result[index] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, index * IntPtr.Size));
            return result;
        } finally { LocalFree(pointer); }
    }
}
'@
function Normalize-Profile([string]$value) {
    if (-not [IO.Path]::IsPathFullyQualified($value)) { return $null }
    try { return [IO.Path]::GetFullPath($value.Replace('/', '\\')).TrimEnd('\\') } catch { return $null }
}
$profile = Normalize-Profile $env:ISSUE70_PROFILE
if (-not $profile) { throw 'Invalid profile.' }
function Test-OwnedRoot($item) {
    if ($item.Name -ne 'msedge.exe' -or -not $item.CommandLine) { return $false }
    $arguments = [Issue70Arguments]::Parse($item.CommandLine)
    $values = @()
    for ($index = 1; $index -lt $arguments.Length; $index++) {
        $argument = $arguments[$index]
        if ($argument.StartsWith('--user-data-dir=', [StringComparison]::Ordinal)) { $values += $argument.Substring(16) }
        elseif ($argument -ceq '--user-data-dir') {
            if (++$index -ge $arguments.Length) { return $false }
            $values += $arguments[$index]
        }
    }
    if ($values.Count -ne 1) { return $false }
    $candidate = Normalize-Profile $values[0]
    return $candidate -and [string]::Equals($candidate, $profile, [StringComparison]::OrdinalIgnoreCase)
}
function Get-Created($item) {
    if ($null -eq $item -or $item.CreationDate -isnot [datetime]) { throw 'Unknown owned identity.' }
    return $item.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
$issue70Phase = 'cim'
$all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$issue70Phase = 'selection'
$byId = @{}
foreach ($item in $all) { $byId[[int]$item.ProcessId] = $item }
$ids = [Collections.Generic.HashSet[int]]::new()
$provenance = @{}
$known = @($env:ISSUE70_KNOWN | ConvertFrom-Json)
$retained = @{}
$invalidRoots = [Collections.Generic.HashSet[int]]::new()
foreach ($previous in $known) {
    $root = $byId[[int]$previous.rootPid]
    if ($null -ne $root -and -not $root.CommandLine) { throw 'Unknown owned root profile.' }
    $rootValid = $null -eq $root -or ((Get-Created $root) -ceq $previous.rootCreated -and (Test-OwnedRoot $root))
    if (-not $rootValid) { [void]$invalidRoots.Add([int]$previous.rootPid) }
    $item = $byId[[int]$previous.pid]
    if ($previous.rootPid -and $rootValid -and $null -ne $item -and (Get-Created $item) -ceq $previous.created) {
        $retained[[int]$previous.pid] = $previous
    }
}
$launcherProcessId = [int]$env:ISSUE70_LAUNCHER_PID
$launcher = if ($launcherProcessId -gt 0) { $byId[$launcherProcessId] } else { $null }
if ($null -ne $launcher) {
    if (-not $launcher.CommandLine) { throw 'Unknown launcher profile.' }
    $created = Get-Created $launcher
    if (-not $env:ISSUE70_LAUNCHER_CREATED -and -not (Test-OwnedRoot $launcher)) { throw 'Unknown launcher profile.' }
    if ($env:ISSUE70_LAUNCHER_CREATED -and ($created -cne $env:ISSUE70_LAUNCHER_CREATED -or -not (Test-OwnedRoot $launcher))) { [void]$invalidRoots.Add($launcherProcessId) }
}
foreach ($item in $all) {
    if ($invalidRoots.Contains([int]$item.ProcessId)) { continue }
    if (Test-OwnedRoot $item) {
        [void]$ids.Add([int]$item.ProcessId)
        $provenance[[int]$item.ProcessId] = @{ rootPid = [int]$item.ProcessId; rootCreated = (Get-Created $item) }
    }
    $previous = $retained[[int]$item.ProcessId]
    if ($null -ne $previous) {
        [void]$ids.Add([int]$item.ProcessId)
        $provenance[[int]$item.ProcessId] = @{ rootPid = $previous.rootPid; rootCreated = $previous.rootCreated }
    }
}
do {
    $added = $false
    foreach ($item in $all) {
        if (-not $ids.Contains([int]$item.ParentProcessId)) { continue }
        $parent = $byId[[int]$item.ParentProcessId]
        if ($null -eq $parent.CreationDate -or $null -eq $item.CreationDate) { throw 'Unknown owned identity.' }
        if ($parent.CreationDate -le $item.CreationDate -and $ids.Add([int]$item.ProcessId)) {
            $provenance[[int]$item.ProcessId] = $provenance[[int]$item.ParentProcessId]
            $added = $true
        }
    }
} while ($added)
$owned = @($all | Where-Object { $ids.Contains([int]$_.ProcessId) })
`;
    const environment = () => ({ ISSUE70_PROFILE: profile, ISSUE70_KNOWN: JSON.stringify(known), ISSUE70_LAUNCHER_PID: String(launcherPid), ISSUE70_LAUNCHER_CREATED: launcherCreated });
    const inventory = async () => {
        const result = await execute(selection + `
    $issue70Phase = 'memory'
$bytes = [long]0
$privateBytes = [long]0
$records = @()
foreach ($item in $owned) {
    $source = $provenance[[int]$item.ProcessId]
    $records += @{ pid = [int]$item.ProcessId; created = (Get-Created $item); rootPid = $source.rootPid; rootCreated = $source.rootCreated }
    $bytes += [long]$item.WorkingSetSize
    $process = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
    if ($process) { $privateBytes += $process.PrivateMemorySize64 }
}
@{ bytes = $bytes; privateBytes = $privateBytes; pids = @($ids); records = $records } | ConvertTo-Json -Compress -Depth 4
`, environment());
        assert(Array.isArray(result.records), 'Invalid owned process identities.');
        for (const record of result.records) {
            assert(Number.isSafeInteger(record.pid) && Number.isSafeInteger(record.rootPid) && typeof record.created === 'string' && /^\d{18}$/.test(record.created) && typeof record.rootCreated === 'string' && /^\d{18}$/.test(record.rootCreated), 'Invalid owned process identities.');
        }
        known = result.records;
        const launcherRecord = known.find(record => record.pid === launcherPid);
        if (launcherRecord) launcherCreated ||= launcherRecord.created;
        return result;
    };
    const terminate = async () => {
        await execute(selection + `
    $issue70Phase = 'termination'
$processes = @()
$terminationOrder = @($owned | Sort-Object { $_.ProcessId -eq $provenance[[int]$_.ProcessId].rootPid })
foreach ($item in $terminationOrder) {
    $issue70Step = 'fresh-cim'
    $fresh = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId) OR ProcessId=$($provenance[[int]$item.ProcessId].rootPid)" -ErrorAction Stop)
    $issue70Step = 'fresh-identity'
    $current = @($fresh | Where-Object { $_.ProcessId -eq $item.ProcessId -and $_.CreationDate -eq $item.CreationDate })
    $source = $provenance[[int]$item.ProcessId]
    $root = @($fresh | Where-Object { $_.ProcessId -eq $source.rootPid })
    $candidate = @($fresh | Where-Object { $_.ProcessId -eq $item.ProcessId })
    if ($candidate.Count -gt 0 -and $null -eq $candidate[0].CreationDate) { $issue70Step = 'fresh-process-identity'; throw 'Unknown fresh process identity.' }
    if ($root.Count -gt 0 -and (-not $root[0].CommandLine -or $null -eq $root[0].CreationDate)) { $issue70Step = 'fresh-root-identity'; throw 'Unknown fresh root identity.' }
    if ($current.Count -ne 1 -or ($root.Count -gt 0 -and ($root[0].CreationDate.ToUniversalTime().Ticks.ToString() -ne $source.rootCreated -or -not (Test-OwnedRoot $root[0])))) { continue }
    $issue70Step = 'get-process'
    $process = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
    $issue70Step = 'start-identity'
    if ($process -and [Math]::Abs($process.StartTime.ToUniversalTime().Ticks - $item.CreationDate.ToUniversalTime().Ticks) -lt 10000) {
        $issue70Step = 'kill'
        try { $process.Kill() } catch { $issue70Step = 'kill-exit-check'; if (-not $process.HasExited) { throw } }
        $processes += $process
    }
}
$deadline = [DateTime]::UtcNow.AddSeconds(5)
foreach ($process in $processes) {
    $issue70Step = 'wait-exit'
    $remaining = [Math]::Max(0, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $process.WaitForExit($remaining)) { throw 'Owned Edge did not exit.' }
}
@{ stoppedCount = $processes.Count } | ConvertTo-Json -Compress
`, environment(), 12000);
    };
    return { inventory, terminate, setLauncher(pid) { assert(Number.isSafeInteger(pid) && pid > 0); launcherPid = pid; } };
}

async function terminateSpawned(launcher, launcherExit, execute = execFile, exitTimeout = 5000) {
    if (!launcher || launcher.exitCode !== null || launcher.signalCode !== null) return;
    await bounded(launcherExit, 'Spawned Edge exit', exitTimeout);
}

async function terminateFamily(state) {
    const outcomes = await Promise.allSettled([
        terminateSpawned(state.launcher, state.launcherExit),
        state.owned.terminate()
    ]);
    for (const outcome of outcomes) if (outcome.status === 'rejected') throw outcome.reason;
}

async function cleanupOwned({ guard, browser, page, cdp, launcher, launcherExit, owned, profile }, overrides = {}) {
    const result = { remainingOwned: null, profileExists: profile ? true : false, errors: [] };
    const attempt = async (label, operation, timeout = 5000) => {
        const started = performance.now();
        try { await bounded(Promise.resolve().then(operation), label, timeout); } catch (error) {
            if (!/Target page, context or browser has been closed/.test(error.message)) {
                result.errors.push(label);
                (result.diagnostics ||= []).push({ label, elapsedMs: Math.round(performance.now() - started), code: error.message === `${label} exceeded ${timeout} ms` ? 'deadline' : error.inventoryDiagnostic ? 'process-inventory' : 'unclassified', ...(error.inventoryDiagnostic ? { inventoryDiagnostic: safeInventoryDiagnostic(error.inventoryDiagnostic) } : {}) });
            }
        }
    };
    await attempt('Guard stop', () => guard?.stop(), 15000);
    await attempt('Owned family termination', () => owned?.terminate(), 15000);
    await attempt('Spawned family termination', () => (overrides.terminateSpawned || terminateSpawned)(launcher, launcherExit));
    await attempt('Launcher exit', async () => {
        if (launcherExit) await launcherExit;
    });
    await attempt('CDP detach', () => cdp && browser?.isConnected() && page && !page.isClosed() ? cdp.detach() : undefined);
    await attempt('Page close', () => page && !page.isClosed() ? page.close({ runBeforeUnload: false }) : undefined);
    await attempt('Browser disconnect', () => browser?.close());
    await attempt('Final owned inventory', async () => {
        const actual = owned ? await owned.inventory() : { pids: [] };
        result.remainingOwned = actual.pids.length;
        assert.strictEqual(result.remainingOwned, 0, 'Owned processes remain.');
    });
    await attempt('Profile removal', async () => {
        if (profile && result.remainingOwned === 0) await (overrides.removeProfile || fs.promises.rm)(profile, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
        result.profileExists = Boolean(profile && fs.existsSync(profile));
        assert(!result.profileExists, 'Owned profile remains.');
    });
    return result;
}

async function withServer(server, evidence, operation) {
    let originalError;
    try {
        await bounded(new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen(0, '127.0.0.1', resolve);
        }), 'HTTP server start');
        await operation(`http://127.0.0.1:${server.address().port}`);
    } catch (error) {
        originalError = error;
    } finally {
        try {
            if (server.listening) await bounded(new Promise((resolve, reject) => {
                server.close(error => error ? reject(error) : resolve());
                server.closeAllConnections();
            }), 'HTTP server close');
            evidence.serverClosed = !server.listening;
        } catch {
            evidence.serverClosed = false;
            evidence.serverError = 'HTTP server close failed';
        }
    }
    if (originalError) throw originalError;
    assert(evidence.serverClosed, 'HTTP server close failed.');
}

const REPORTS = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

async function fingerprintPayload(filename) {
    const compressedHash = crypto.createHash('sha256');
    const decompressedHash = crypto.createHash('sha256');
    let payloadBytes = 0;
    let decompressedBytes = 0;
    const input = fs.createReadStream(filename);
    input.on('data', chunk => { payloadBytes += chunk.length; compressedHash.update(chunk); });
    await pipeline(input, zlib.createGunzip(), new Writable({
        write(chunk, encoding, callback) {
            decompressedBytes += chunk.length;
            decompressedHash.update(chunk);
            callback();
        }
    }));
    return { payloadBytes, payloadSha256: compressedHash.digest('hex'), decompressedBytes, decompressedSha256: decompressedHash.digest('hex') };
}

function assertRuntimeAsset(source, label) {
    assert(source.length > 1024 && !source.includes('offline regression fixture'), `${label} must be a real runtime library, not a regression placeholder.`);
}

function assertRun(run, expectedRows, first) {
    assert(Number.isSafeInteger(expectedRows) && expectedRows > 0, 'Expected rows must be a positive integer.');
    assert.strictEqual(run.snapshot.rows, expectedRows, 'Normalized row count differs from expected rows.');
    assert(run.snapshot.rawRows >= expectedRows, 'Raw row count is incomplete.');
    assert(Number.isSafeInteger(run.snapshot.activeRows) && run.snapshot.activeRows >= 0, 'Invalid active row count.');
    if (run.positiveControl) {
        assert.strictEqual(expectedRows, 2, 'Positive control requires the two-row synthetic fixture.');
        assert.strictEqual(run.snapshot.rawRows, 2, 'Positive control requires exactly two raw rows.');
        assert.strictEqual(run.controlObservation.filteredSourceRows, 2, 'Positive control must select both source rows.');
        assert.strictEqual(run.controlObservation.selectedRows, 1, 'Positive control requires one active table row.');
        assert.strictEqual(run.controlObservation.impactRows, 1, 'Positive control requires one impact row.');
        assert.strictEqual(run.controlObservation.cardTotal, 1, 'Positive control requires one severity-card total.');
        assert.strictEqual(run.controlObservation.dateRange, '2026-01-01/2026-01-02');
        if (first) assert.deepStrictEqual(run.controlObservation, first.controlObservation, 'Cold/reload positive-control counts differ.');
    }
    for (const report of REPORTS) assert(run.reportIds.includes(report), `Required report missing: ${report}`);
    const policy = run.cachePolicy;
    assert(Number.isSafeInteger(policy.maxRowsExclusive) && policy.maxRowsExclusive > 0, 'Invalid cache row policy.');
    assert.strictEqual(policy.eligible, policy.available && expectedRows < policy.maxRowsExclusive, 'Cache eligibility differs from production policy.');
    run.cachedEligible = policy.eligible;
    run.cacheState = policy.eligible ? first ? 'hit' : 'cold' : 'ineligible-production-guard';
    run.cacheReason = policy.eligible ? 'production-policy-eligible' : policy.available ? 'row-limit' : 'indexeddb-unavailable';
    if (policy.eligible) {
        assert(run.cacheEntries.matchingRows === expectedRows, 'Matching compressed cache entry is missing or incomplete.');
        assert(run.cacheEntries.count <= policy.maxEntries, 'Cache entry limit exceeded.');
        assert.strictEqual(Boolean(run.snapshot.counts.compressedCacheHits), Boolean(first), 'Eligible reload must hit cache; cold load must not.');
    } else {
        assert(!run.snapshot.counts.compressedCacheHits, 'Ineligible reload cannot be labelled cached.');
    }
    if (first) {
        for (const key of ['rows', 'rawRows', 'activeRows']) assert.strictEqual(run.snapshot[key], first.snapshot[key], `Cold/reload ${key} differs.`);
        assert.strictEqual(run.impactRows, first.impactRows, 'Cold/reload impact count differs.');
        assert.deepStrictEqual(run.reportIds, first.reportIds, 'Cold/reload reports differ.');
        assert.deepStrictEqual(run.cachePolicy, first.cachePolicy, 'Cold/reload cache policy differs.');
        assert.strictEqual(digest(JSON.stringify(run.snapshot.summaryCards)), digest(JSON.stringify(first.snapshot.summaryCards)), 'Cold/reload severity summary differs.');
        assert.strictEqual(run.readinessCacheDigest, first.readinessCacheDigest, 'Cold/reload readiness/cache digest differs.');
    }
    assert.strictEqual(run.externalRequests, 0, 'All assets must be same-origin.');
    assert.strictEqual(run.pageErrors, 0, 'Dashboard page errors.');
}

async function completeRun(run, guard, validate) {
    try {
        validate();
        await guard.finish();
        guard.check();
        run.status = 'passed';
        run.stage = 'complete';
    } catch (error) {
        run.status = 'failed';
        throw error;
    }
}

function installInstrumentation() {
    const phaseNames = ['loadDataMs', 'denormalizeMs', 'applyFiltersMs', 'initTotalMs', 'workerInflateMs', 'workerParseMs', 'workerWaitMs', 'workerDeliveryMs', 'mainInflateMs', 'mainParseMs', 'mainFallbackMs'];
    const functionNames = ['init', 'loadData', 'denormalizeWithCaching', 'ensureChartJsLoaded'];
    window.__issue70 = { phases: [], workerMessages: [], initialization: [] };
    window.addEventListener('DOMContentLoaded', () => {
        for (const name of ['init', 'loadData', 'denormalizeWithCaching', 'ensureChartJsLoaded']) {
            const original = window[name];
            if (typeof original !== 'function') continue;
            window[name] = async function(...args) {
                const record = { name, startedBrowserMs: performance.now(), status: 'running' };
                window.__issue70.initialization.push(record);
                try {
                    const result = await original.apply(this, args);
                    record.status = 'completed';
                    return result;
                } catch (error) {
                    record.status = 'failed';
                    record.errorType = error?.name === 'TypeError' ? 'TypeError' : 'Error';
                    record.errorFrames = String(error?.stack || '').split('\n').slice(1, 7).map(frame => {
                        const match = frame.match(/at ([\w.]+).*?:(\d+):(\d+)\)?$/);
                        return match && functionNames.includes(match[1]) ? { functionName: match[1], line: Number(match[2]), column: Number(match[3]) } : null;
                    }).filter(Boolean);
                    throw error;
                } finally { record.finishedBrowserMs = performance.now(); }
            };
        }
    });
    const capturePhases = () => {
        if (typeof getDashboardMetricsSnapshot !== 'function') return;
        const metrics = getDashboardMetricsSnapshot() || {};
        const previous = window.__issue70.lastPhases || {};
        for (const [name, durationMs] of Object.entries(metrics.phases || {})) {
            if (!phaseNames.includes(name) || !Number.isFinite(durationMs) || durationMs < 0) continue;
            if (previous[name] !== durationMs) window.__issue70.phases.push({ name, durationMs, observedBrowserMs: performance.now(), observedEpochMs: performance.timeOrigin + performance.now() });
        }
        window.__issue70.lastPhases = Object.fromEntries(Object.entries(metrics.phases || {}).filter(([name, durationMs]) => phaseNames.includes(name) && Number.isFinite(durationMs) && durationMs >= 0));
    };
    window.addEventListener('dashboard-ready', event => {
        if (window.__issue70.ready) return;
        window.__issue70.ready = { browserMs: performance.now(), epochMs: performance.timeOrigin + performance.now() };
        capturePhases();
    });
    setInterval(capturePhases, 100);
    const OriginalWorker = window.Worker;
    window.Worker = class extends OriginalWorker {
        constructor(...args) {
            super(...args);
            this.addEventListener('message', event => {
                const data = event.data || {};
                const format = data.phase ? 'phase' : Array.isArray(data) ? 'legacy-array' : data.rows === null ? 'lookups-raw-columns' : Array.isArray(data.rows) ? 'row-envelope' : 'unknown';
                window.__issue70.workerMessages.push({ format, phase: phaseNames.includes(data.phase) ? data.phase : null, durationMs: Number.isFinite(data.duration) ? data.duration : null, postedAtEpochMs: Number.isFinite(data.postedAt) ? data.postedAt : null, receivedBrowserMs: performance.now(), receivedEpochMs: performance.timeOrigin + performance.now() });
                capturePhases();
            });
        }
    };
}

async function inspectCache(page, fingerprint) {
    return page.evaluate(async key => {
        const database = await openVulnDB();
        try {
            return await new Promise((resolve, reject) => {
                const transaction = database.transaction(VULNDB_STORE, 'readonly');
                const store = transaction.objectStore(VULNDB_STORE);
                const countRequest = store.count();
                const entryRequest = store.get(key);
                transaction.oncomplete = () => resolve({ count: countRequest.result, matchingRows: entryRequest.result?.data?.length || 0 });
                transaction.onerror = transaction.onabort = () => reject(new Error('IndexedDB inspection failed.'));
            });
        } finally { database.close(); }
    }, fingerprint);
}

async function readDevToolsPort(portFile, guard, read = fs.readFileSync) {
    const launchStart = performance.now();
    while (performance.now() - launchStart < 15000) {
        guard.check();
        try {
            const port = Number(read(portFile, 'utf8').split('\n')[0]);
            if (Number.isInteger(port) && port > 0 && port < 65536) return port;
        } catch (error) {
            if (!['ENOENT', 'EBUSY', 'EACCES'].includes(error.code)) throw error;
        }
        await guard.wait(new Promise(resolve => setTimeout(resolve, 100)));
    }
    throw new Error('Edge CDP startup failed.');
}

async function finishHeapSample(run, sample, timeout = 5000) {
    if (!sample) return;
    try { await bounded(sample, 'Final observational sample', timeout); }
    catch { run.incompleteHeapSample = true; }
}

async function measureIteration({ chromium, edge, origin, evidence, expectedRows, fingerprint, iteration, positiveControl }) {
    const state = {};
    let measurementError;
    try {
        state.profile = fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-edge-'));
        state.owned = ownedProcesses(state.profile);
        state.guard = new ResourceGuard({ inventory: state.owned.inventory, terminate: () => terminateFamily(state), limits: evidence.limits });
        await state.guard.sample('prelaunch');
        state.guard.check();
        state.launcher = spawn(edge, ['--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${state.profile}`, '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: 'ignore', windowsHide: true });
        if (state.launcher.pid) state.owned.setLauncher(state.launcher.pid);
        state.launcherExit = new Promise(resolve => {
            state.launcher.once('exit', resolve);
            state.launcher.once('error', error => { state.guard.abort(error); resolve(); });
        });
        state.guard.start();
        const portFile = path.join(state.profile, 'DevToolsActivePort');
        const port = await readDevToolsPort(portFile, state.guard);
        const connection = chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 15000 });
        connection.then(browser => { state.browser = browser; }, () => {});
        state.browser = await state.guard.wait(connection);
        const context = state.browser.contexts()[0];
        state.page = context.pages()[0];
        state.cdp = await state.guard.wait(context.newCDPSession(state.page));
        await state.guard.wait(state.cdp.send('Performance.enable'));
        await state.guard.wait(context.route('**/*', route => route.request().url().startsWith(origin + '/') ? route.continue() : route.abort()));
        await state.guard.wait(context.addInitScript(installInstrumentation));
        let first;
        for (const load of ['first', 'reload']) {
            const run = { iteration, load, positiveControl, stage: 'navigation', status: 'running', peakMainHeapBytes: 0, externalRequests: 0, pageErrors: 0, failedResources: 0, failedResponses: 0 };
            evidence.runs.push(run);
            state.guard.stage = `${load}:navigation`;
            const traceStart = state.guard.trace.length;
            const onError = () => { run.pageErrors++; };
            const onRequest = request => { if (!request.url().startsWith(origin + '/')) run.externalRequests++; };
            const onFailure = () => { run.failedResources++; };
            const onResponse = response => { if (response.status() >= 400) run.failedResponses++; };
            state.page.on('pageerror', onError);
            state.page.on('request', onRequest);
            state.page.on('requestfailed', onFailure);
            state.page.on('response', onResponse);
            let heapSample;
            const sampleHeap = () => {
                if (heapSample) return;
                heapSample = Promise.all([state.cdp.send('Performance.getMetrics'), state.page.evaluate(() => ({
                    instrumentationPresent: Boolean(window.__issue70), readyEventSeen: Boolean(window.__issue70?.ready), dashboardReady: Boolean(window._dashboardReady),
                    metricsPresent: typeof getDashboardMetricsSnapshot === 'function', filtersApplied: window.dashboardMetrics?.counts.applyFilters || 0,
                    activeReportRenders: window.dashboardMetrics?.reports['active-vulnerabilities']?.count || 0,
                    initialization: window.__issue70?.initialization || [],
                    phases: window.__issue70?.phases || [], workerMessages: window.__issue70?.workerMessages || [],
                    documentReadyState: document.readyState
                })).catch(() => null)]).then(([metrics, readiness]) => {
                    const heap = metrics.metrics.find(metric => metric.name === 'JSHeapUsedSize');
                    run.peakMainHeapBytes = Math.max(run.peakMainHeapBytes, heap?.value || 0);
                    if (readiness) run.lastReadiness = readiness;
                }).catch(() => { run.failedHeapSamples = (run.failedHeapSamples || 0) + 1; }).finally(() => { heapSample = null; });
            };
            const heapTimer = setInterval(sampleHeap, 100);
            try {
                run.navigationStartedAtHostMs = performance.now();
                run.navigationStartedAtEpochMs = Date.now();
                const navigation = load === 'first' ? state.page.goto(origin + '/', { waitUntil: 'domcontentloaded', timeout: evidence.limits.readinessWallMs }) : state.page.reload({ waitUntil: 'domcontentloaded', timeout: evidence.limits.readinessWallMs });
                await state.guard.wait(navigation);
                run.stage = 'readiness';
                state.guard.stage = `${load}:readiness`;
                await state.guard.wait(state.page.waitForFunction(() => window.__issue70.initialization.some(record => record.name === 'init' && record.status === 'failed') || (window.__issue70.ready && window._dashboardReady && dashboardMetrics.counts.applyFilters > 0 && dashboardMetrics.reports['active-vulnerabilities']?.count > 0), null, { timeout: evidence.limits.readinessWallMs }));
                run.initialization = await state.guard.wait(state.page.evaluate(() => window.__issue70.initialization));
                assert(!run.initialization.some(record => record.name === 'init' && record.status === 'failed'), 'Dashboard initialization failed; inspect sanitized function frames.');
                run.readinessObservedHostWallMs = performance.now() - run.navigationStartedAtHostMs;
                if (positiveControl) {
                    const controlRange = await state.guard.wait(state.page.evaluate(() => filterState.startDate === '2026-01-01' && filterState.endDate === '2026-01-02'));
                    if (!controlRange) {
                        await state.guard.wait(state.page.locator('#filterPillDate').click());
                        await state.guard.wait(state.page.locator('#filterPopoverStartDate').fill('2026-01-01'));
                        await state.guard.wait(state.page.locator('#filterPopoverEndDate').fill('2026-01-02'));
                        await state.guard.wait(state.page.locator('#filterPopoverApplyButton').click());
                    }
                    await state.guard.wait(state.page.waitForFunction(() => filterState.startDate === '2026-01-01' && filterState.endDate === '2026-01-02' && filteredData.length === 2, null, { timeout: evidence.limits.readinessWallMs }));
                }
                run.snapshot = await state.guard.wait(state.page.evaluate(() => ({
                    snapshotBrowserMs: performance.now(), snapshotEpochMs: performance.timeOrigin + performance.now(), ready: window.__issue70.ready,
                    rawRows: getRawVulnCount(), rows: vulnerabilityData.length, activeRows: filteredData.length,
                    phases: Object.fromEntries(window.__issue70.phases.map(record => [record.name, record.durationMs])), counts: { compressedCacheHits: getDashboardMetricsSnapshot().counts.compressedCacheHits || 0 },
                    summaryCards: buildDashboardValidationSnapshot().summaryCards,
                    phaseTrace: window.__issue70.phases, workerMessages: window.__issue70.workerMessages,
                    cachePolicy: { available: typeof indexedDB !== 'undefined' && !!indexedDB, maxRowsExclusive: MAX_IDB_CACHE_ROWS, maxEntries: MAX_IDB_CACHE_ENTRIES, eligible: typeof indexedDB !== 'undefined' && !!indexedDB && vulnerabilityData.length < MAX_IDB_CACHE_ROWS, byteSoftMax: null, featureFlag: null }
                })));
                run.phaseTrace = run.snapshot.phaseTrace;
                run.workerMessages = run.snapshot.workerMessages;
                run.workerReturnFormats = [...new Set(run.workerMessages.filter(message => message.format !== 'phase').map(message => message.format))];
                run.ttiBrowserMs = run.snapshot.ready.browserMs;
                run.cachePolicy = run.snapshot.cachePolicy;
                assert(Number.isFinite(run.ttiBrowserMs), 'Missing browser readiness timestamp.');
                run.stage = 'reports';
                state.guard.stage = `${load}:reports`;
                for (const report of REPORTS.slice(1).concat(REPORTS[0])) {
                    await state.guard.wait(state.page.evaluate(reportId => selectReportById(reportId), report));
                    await state.guard.wait(state.page.waitForFunction(reportId => dashboardMetrics.reports[reportId]?.count > 0, report, { timeout: evidence.limits.readinessWallMs }));
                }
                const reports = await state.guard.wait(state.page.evaluate(() => ({
                    reportIds: Object.keys(getDashboardMetricsSnapshot().reports).sort(), impactRows: impactAnalysisAllData.length,
                    summaryCards: buildDashboardValidationSnapshot().summaryCards, activeRows: filteredData.length, selectedRows: remediationAllData.length,
                    reportSections: buildDashboardValidationSnapshot().reportSections,
                    phases: window.__issue70.phases, workerMessages: window.__issue70.workerMessages
                })));
                run.reportIds = reports.reportIds.filter(report => REPORTS.includes(report));
                run.impactRows = reports.impactRows;
                run.phaseTrace = reports.phases;
                run.workerMessages = reports.workerMessages;
                run.workerReturnFormats = [...new Set(reports.workerMessages.filter(message => message.format !== 'phase').map(message => message.format))];
                run.readinessCacheDigest = digest(JSON.stringify({ summaryCards: reports.summaryCards, activeRows: reports.activeRows, impactRows: reports.impactRows, reportIds: run.reportIds, reportSections: reports.reportSections }));
                if (positiveControl) run.controlObservation = { filteredSourceRows: reports.activeRows, selectedRows: reports.selectedRows, impactRows: reports.impactRows, cardTotal: Object.values(reports.summaryCards).reduce((total, value) => total + Number(value), 0), dateRange: '2026-01-01/2026-01-02' };
                run.summaryCardsSha256 = digest(JSON.stringify(run.snapshot.summaryCards));
                run.stage = 'cache';
                state.guard.stage = `${load}:cache`;
                if (run.cachePolicy.available) {
                    const deadline = performance.now() + 5000;
                    do {
                        run.cacheEntries = await state.guard.wait(bounded(inspectCache(state.page, fingerprint), 'Cache inspection'));
                        if (!run.cachePolicy.eligible || run.cacheEntries.matchingRows === expectedRows) break;
                        await state.guard.wait(new Promise(resolve => setTimeout(resolve, 100)));
                    } while (performance.now() < deadline);
                } else run.cacheEntries = { count: 0, matchingRows: 0 };
                clearInterval(heapTimer);
                await state.guard.wait(finishHeapSample(run, heapSample));
                await completeRun(run, state.guard, () => assertRun(run, expectedRows, first));
                if (!first) first = run;
            } catch (error) {
                run.status = 'failed';
                state.guard.abort(error);
                throw error;
            } finally {
                clearInterval(heapTimer);
                await finishHeapSample(run, heapSample);
                run.memoryTrace = state.guard.trace.slice(traceStart);
                run.peakBrowserFamilyBytes = Math.max(0, ...run.memoryTrace.map(sample => sample.browserFamilyBytes));
                run.peakBrowserFamilyPrivateBytes = Math.max(0, ...run.memoryTrace.map(sample => sample.browserFamilyPrivateBytes || 0));
                run.minimumFreeMemoryBytes = run.memoryTrace.length ? Math.min(...run.memoryTrace.map(sample => sample.freeMemoryBytes)) : null;
                state.page.off('pageerror', onError);
                state.page.off('request', onRequest);
                state.page.off('requestfailed', onFailure);
                state.page.off('response', onResponse);
            }
        }
    } catch (error) {
        measurementError = error;
        state.guard?.abort(error);
    } finally {
        const cleanup = await cleanupOwned(state);
        evidence.cleanups.push({ iteration, ...cleanup });
        if (state.guard) {
            evidence.resourceTraces.push({ iteration, samples: state.guard.trace, peakBrowserFamilyBytes: state.guard.peakBytes, minimumFreeMemoryBytes: Number.isFinite(state.guard.minimumFreeBytes) ? state.guard.minimumFreeBytes : null });
            if (state.guard.error) {
                measurementError ||= state.guard.error;
                const lastRun = evidence.runs.filter(run => run.iteration === iteration).at(-1);
                if (lastRun) lastRun.status = 'failed';
            }
        }
        if (!measurementError && (cleanup.errors.length || cleanup.remainingOwned !== 0 || cleanup.profileExists)) measurementError = new Error('Owned cleanup failed.');
    }
    if (measurementError) throw measurementError;
}

async function main() {
    let phase = 'arguments';
    const [rootArgument, outputArgument, repeatsArgument = '3', expectedArgument] = process.argv.slice(2);
    assert(rootArgument && outputArgument && process.env.PLAYWRIGHT_MODULE, 'Supply retained Hosted dashboard directory, evidence path, repeats, expected rows, and PLAYWRIGHT_MODULE.');
    const expectedRows = Number(expectedArgument);
    const repeats = Number(repeatsArgument);
    const positiveControl = process.argv.includes('--positive-control');
    assert(Number.isSafeInteger(expectedRows) && expectedRows > 0, 'Explicit expected rows are required; use 2 for the committed control fixture.');
    assert(Number.isSafeInteger(repeats) && repeats > 0 && repeats <= 10, 'Repeats must be between 1 and 10.');
    assert(!positiveControl || expectedRows === 2, 'Positive control requires two expected rows.');
    const evidence = {
        schemaVersion: 2, expectedRows,
        limits: { browserFamilyBytes: 2 * 1024 ** 3, freeMemoryBytes: 3 * 1024 ** 3, readinessWallMs: 120000, inventoryTimeoutMs: 5000, terminationTimeoutMs: 15000 },
        heapScope: 'CDP JSHeapUsedSize is main-renderer only; sampled family working set and private memory include owned workers and descendants. Observational CDP probes are single-flight and may stall with the renderer; independent resource inventory remains bounded and fail-closed.',
        timingScope: 'ttiBrowserMs is first dashboard-ready performance.now from navigation timeOrigin, not a true interaction latency; readinessObservedHostWallMs includes host polling; snapshotBrowserMs is later.',
        deliveryScope: 'workerDeliveryMs includes serialization, queue, deserialization; phase observations are sampled, not exact boundaries. Worker return envelopes remain backward-compatible.',
        runs: [], cleanups: [], resourceTraces: [], status: 'running'
    };
    try {
        phase = 'provenance';
        const root = fs.realpathSync(rootArgument);
        const htmlName = 'VulnerabilityDashboard.Hosted.html';
        const html = fs.readFileSync(path.join(root, htmlName), 'utf8');
        const config = JSON.parse(html.match(/<script id="dashboardConfig"[^>]*>([\s\S]*?)<\/script>/)[1]);
        const resolveAsset = relative => {
            const filename = path.resolve(root, relative);
            assert(filename.startsWith(root + path.sep), 'Asset outside retained dashboard root.');
            return filename;
        };
        const payloadIdentity = await fingerprintPayload(resolveAsset(config.payloadUrl));
        const summary = fs.readFileSync(resolveAsset(config.payloadSummaryUrl));
        phase = 'assets';
        const runtime = loadDashboardSource().dashboardSource;
        const chart = fs.readFileSync(resolveAsset(config.chartJsUrl), 'utf8');
        const pakoUrl = html.match(/<script\s+src="([^"]*\/runtime\/pako\.js)"/)[1];
        const pako = fs.readFileSync(resolveAsset(pakoUrl), 'utf8');
        assertRuntimeAsset(chart, 'Chart.js');
        assertRuntimeAsset(pako, 'pako');
        evidence.assetHashes = { chart: digest(chart), pako: digest(pako) };
        Object.assign(evidence, payloadIdentity, { summarySha256: digest(summary), htmlSha256: digest(html), runtimeSha256: digest(runtime) });
        const server = http.createServer((request, response) => {
            try {
                const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
                const relative = pathname === '/' ? htmlName : pathname.slice(1);
                const filename = resolveAsset(relative);
                if (relative.endsWith('/runtime/dashboard.js')) { response.setHeader('Content-Type', 'text/javascript'); response.end(runtime); return; }
                if (!fs.existsSync(filename) || !fs.statSync(filename).isFile()) { response.writeHead(404).end(); return; }
                response.setHeader('Content-Type', filename.endsWith('.js') ? 'text/javascript' : filename.endsWith('.css') ? 'text/css' : filename.endsWith('.html') ? 'text/html' : 'application/octet-stream');
                const stream = fs.createReadStream(filename);
                stream.on('error', () => response.destroy());
                stream.pipe(response);
            } catch { response.writeHead(403).end(); }
        });
        phase = 'browser';
        await withServer(server, evidence, async origin => {
            const candidates = [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean).map(base => path.join(base, 'Microsoft/Edge/Application/msedge.exe'));
            const edge = candidates.find(candidate => fs.existsSync(candidate));
            assert(edge, 'Microsoft Edge is required.');
            const { chromium } = require(process.env.PLAYWRIGHT_MODULE);
            for (let iteration = 1; iteration <= repeats; iteration++) await measureIteration({ chromium, edge, origin, evidence, expectedRows, fingerprint: `cfp_${payloadIdentity.payloadBytes}_${payloadIdentity.payloadSha256}`, iteration, positiveControl });
        });
        evidence.status = 'completed';
    } catch (error) {
        evidence.status = 'blocked-or-failed';
        evidence.measurementError = 'Measurement failed.';
        evidence.failure = safeFailure(error, phase);
        process.exitCode = 1;
    } finally {
        evidence.remainingOwned = evidence.cleanups.length ? evidence.cleanups.some(cleanup => cleanup.remainingOwned === null) ? null : evidence.cleanups.reduce((total, cleanup) => total + cleanup.remainingOwned, 0) : null;
        try {
            fs.mkdirSync(path.dirname(path.resolve(outputArgument)), { recursive: true });
            fs.writeFileSync(outputArgument, JSON.stringify(evidence, null, 2));
        } catch (error) {
            evidence.status = 'blocked-or-failed';
            evidence.measurementError = 'Evidence write failed.';
            evidence.writeFailure = safeFailure(error, 'evidence-write');
            process.exitCode = 1;
        }
        console.log(JSON.stringify({ status: evidence.status, limits: evidence.limits, measurementError: evidence.measurementError, failure: evidence.failure, writeFailure: evidence.writeFailure, serverClosed: evidence.serverClosed, cleanups: evidence.cleanups, runs: evidence.runs.map(run => ({ iteration: run.iteration, load: run.load, status: run.status, ttiBrowserMs: run.ttiBrowserMs, cachedEligible: run.cachedEligible, cacheState: run.cacheState, rows: run.snapshot?.rows })) }));
    }
}

async function ownershipProbes() {
    const fixture = `
$script:killed = @()
$script:calls = 0
$script:items = @($env:ISSUE70_FIXTURE | ConvertFrom-Json | ForEach-Object {
    if ($null -ne $_.CreationDate) { $_.CreationDate = [datetime]$_.CreationDate }
    $_
})
function Get-CimInstance {
    $script:calls++
    if ($env:ISSUE70_REUSE -eq 'gone' -and $script:calls -gt 1) { return }
    if ($env:ISSUE70_REUSE -eq 'unknown' -and $script:calls -gt 1) { $script:items[0].CommandLine = $null }
    if ($env:ISSUE70_REUSE -eq 'root-shutdown' -and 101 -in $script:killed) { $script:items[0].CommandLine = $null }
    if ($env:ISSUE70_REUSE -eq 'fresh' -and $script:calls -gt 1) {
        $script:items[0].CreationDate = $script:items[0].CreationDate.AddMinutes(1)
        $script:items[0].CommandLine = 'msedge.exe --user-data-dir=C:/neighbor'
    }
    $script:items | Select-Object *
}
function Get-Process {
    param($Id, $ErrorAction)
    $item = $script:items | Where-Object { $_.ProcessId -eq $Id }
    if (-not $item) { return }
    $process = [pscustomobject]@{ Id=$Id; StartTime=$item.CreationDate; PrivateMemorySize64=1; HasExited=$false }
    $process | Add-Member ScriptMethod Kill { if ($env:ISSUE70_REUSE -eq 'kill-failure') { throw [ComponentModel.Win32Exception]::new(87) }; $script:killed += $this.Id; $this.HasExited=$true }
    $process | Add-Member ScriptMethod WaitForExit { param($remaining); return $true }
    $process
}
`;
    const make = (pid, parent, command, minute = 0) => ({ ProcessId: pid, ParentProcessId: parent, Name: 'msedge.exe', CommandLine: command, CreationDate: `2026-09-30T00:0${minute}:00Z`, WorkingSetSize: 1 });
    for (const command of [
        'msedge.exe --user-data-dir="C:/Profile Owned"',
        'msedge.exe --user-data-dir "c:\\profile owned"',
        'msedge.exe "--user-data-dir=C:\\Profile Owned/"',
        'msedge.exe --user-data-dir=C:/PROFILE/../ProfileOwned'
    ]) {
        const profile = command.includes('ProfileOwned') ? 'C:/ProfileOwned' : 'C:/Profile Owned';
        let items = [make(101, 0, command), make(102, 101, 'msedge.exe --type=renderer', 1), make(201, 0, `msedge.exe --user-data-dir="${profile}-neighbor"`), make(202, 201, 'msedge.exe --type=renderer', 1), make(301, 0, `msedge.exe --other="literal --user-data-dir=${profile}"`), make(302, 0, `msedge.exe --user-data-dir="${profile}" --user-data-dir=C:/neighbor`), { ...make(0, 0, null), Name: 'System Idle Process', CreationDate: null }, { ...make(401, 0, null), CreationDate: null }];
        let reuse = '';
        let last;
        const execute = async (script, environment, timeout) => {
            const response = await powershell(fixture + '\n$result = . {\n' + script + '\n}\n@{ result = ($result | ConvertFrom-Json); killed = @($script:killed); survivors = @($script:items | Where-Object { $_.ProcessId -notin $script:killed } | ForEach-Object { [int]$_.ProcessId }) } | ConvertTo-Json -Compress -Depth 6', { ...environment, ISSUE70_FIXTURE: JSON.stringify(items), ISSUE70_REUSE: reuse }, timeout || 12000);
            last = response;
            return response.result;
        };
        const owned = ownedProcesses(profile, execute);
        assert.deepStrictEqual((await owned.inventory()).pids.sort(), [101, 102]);
        await owned.terminate();
        assert.deepStrictEqual(last.killed.sort(), [101, 102]);
        assert.deepStrictEqual(last.survivors.sort((left, right) => left - right), [0, 201, 202, 301, 302, 401]);
        reuse = 'root-shutdown';
        await owned.terminate();
        assert.deepStrictEqual(last.killed, [102, 101], 'Root shutdown must not invalidate the fresh ownership proof needed by descendants.');
        assert.deepStrictEqual(last.survivors.sort((left, right) => left - right), [0, 201, 202, 301, 302, 401]);
        reuse = 'fresh';
        await owned.terminate();
        assert.deepStrictEqual(last.killed, []);
        reuse = 'gone';
        await owned.terminate();
        assert.deepStrictEqual(last.killed, []);
        reuse = 'unknown';
        await assert.rejects(owned.terminate(), error => error.inventoryDiagnostic?.category === 'OperationStopped' && error.inventoryDiagnostic?.exceptionType === 'RuntimeException' && error.inventoryDiagnostic?.exitCode === 1);
        reuse = 'kill-failure';
        await assert.rejects(owned.terminate(), error => error.inventoryDiagnostic?.step === 'kill-exit-check' && error.inventoryDiagnostic?.innerExceptionType === 'Win32Exception' && error.inventoryDiagnostic?.nativeErrorCode === 87);
        reuse = '';
        items[0] = make(101, 0, command, 2);
        assert.deepStrictEqual((await owned.inventory()).pids, [], 'Same-profile root PID reuse must exclude prior descendants.');
        items[0] = make(101, 0, 'msedge.exe --user-data-dir=C:/neighbor', 2);
        assert.deepStrictEqual((await owned.inventory()).pids, []);
        const unknown = ownedProcesses(profile, execute);
        unknown.setLauncher(401);
        await assert.rejects(unknown.inventory(), error => error.inventoryDiagnostic?.exceptionType === 'RuntimeException');
        items[0] = make(101, 0, command);
        const protectedRoot = ownedProcesses(profile, execute);
        await protectedRoot.inventory();
        items[0].CommandLine = null;
        await assert.rejects(protectedRoot.inventory(), error => error.inventoryDiagnostic?.exceptionType === 'RuntimeException');
    }
    console.log('PASS actual PowerShell argv/profile selection, literal/duplicate/prefix exclusion, independent snapshots, descendants-before-root shutdown race, unexpected native kill rejection, same-profile/fresh root PID reuse, nullable unrelated/PID-zero exclusion, unknown owned root fail-closed.');
}

async function inventoryProbes() {
    if (process.platform !== 'win32') return;
    const sentinel = 'SYNTHETIC_PRIVATE_PATH_TOKEN';
    for (const [phase, script, type] of [
        ['selection', `$ErrorActionPreference = 'Stop'; $issue70Phase = 'selection'; throw '${sentinel}'`, 'RuntimeException'],
        ['selection', `$ErrorActionPreference = 'Stop'; $issue70Phase = 'selection'; $pid = 1`, 'SessionStateUnauthorizedAccessException'],
        ['compile', `$ErrorActionPreference = 'Stop'; $issue70Phase = 'compile'; Add-Type -TypeDefinition '${sentinel}'`, 'unclassified'],
        ['compile', `$ErrorActionPreference = 'Stop'; $issue70Phase = 'compile'; throw [System.InvalidOperationException]::new('${sentinel}')`, 'InvalidOperationException']
    ]) {
        await assert.rejects(powershell(script, {}, 12000), error => {
            assert.strictEqual(error.message, 'Owned process inventory/termination failed.');
            const failure = safeFailure(error, 'preflight');
            assert.strictEqual(failure.inventoryDiagnostic.phase, phase);
            assert.strictEqual(failure.inventoryDiagnostic.exceptionType, type);
            assert.strictEqual(failure.inventoryDiagnostic.exitCode, 1);
            assert(!JSON.stringify(failure).includes(sentinel));
            return true;
        });
    }
    await assert.rejects(powershell('while ($true) {}', {}, 100), error => error.inventoryDiagnostic?.category === 'timeout');
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(powershell('while ($true) {}', {}, 5000, controller.signal), error => error.inventoryDiagnostic?.category === 'aborted');
    const unusedProfile = path.join(os.tmpdir(), `issue70-unused-${crypto.randomUUID()}`);
    const actual = await ownedProcesses(unusedProfile).inventory();
    assert.deepStrictEqual(actual.pids, []);
    assert.strictEqual(actual.bytes, 0);
    await ownedProcesses(unusedProfile).terminate();
    const invalidTicks = ownedProcesses(unusedProfile, async () => ({ records: [{ pid: 1, rootPid: 1, created: 638974368000000000, rootCreated: '638974368000000000' }] }));
    await assert.rejects(invalidTicks.inventory(), /Invalid owned process identities/);
    assert.deepStrictEqual(safeInventoryDiagnostic({ category: sentinel, exceptionType: sentinel, phase: sentinel, exitCode: -1 }), { category: 'execution', exceptionType: 'unclassified', exitCode: null, phase: 'execute' });
    console.log('PASS real CIM empty-profile inventory, actual readonly PID/compile errors, allowlisted diagnostics, timeout versus cancellation, numeric tick rejection.');
}

async function privacyProbes() {
    const sentinel = 'SYNTHETIC_PRIVATE_PATH_TOKEN';
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `issue70-${sentinel}-`));
    try {
        const html = path.join(root, 'VulnerabilityDashboard.Hosted.html');
        const output = path.join(root, 'evidence.json');
        const invoke = args => {
            const result = spawnSync(process.execPath, [__filename, ...args], { encoding: 'utf8', env: { ...process.env, PLAYWRIGHT_MODULE: sentinel }, timeout: 15000 });
            assert.strictEqual(result.status, 1, 'Privacy repro must fail with a controlled exit.');
            assert(!result.stdout.includes(sentinel) && !result.stderr.includes(sentinel), 'Private sentinel escaped to process output.');
            assert(!result.stderr.includes(' at '), 'Exception stack escaped to stderr.');
            if (fs.existsSync(output)) {
                assert(!fs.readFileSync(output, 'utf8').includes(sentinel), 'Private sentinel escaped to evidence.');
                fs.unlinkSync(output);
            }
        };
        invoke([]);
        invoke([root, output, 'invalid', '2']);
        invoke([path.join(root, 'missing'), output, '1', '2']);
        fs.writeFileSync(html, '<script id="dashboardConfig">{"payloadUrl":"missing-' + sentinel + '.gz"}</script>');
        invoke([root, output, '1', '2']);
        fs.writeFileSync(html, '<script id="dashboardConfig">{invalid-' + sentinel + '}</script>');
        invoke([root, output, '1', '2']);
        fs.writeFileSync(html, '<script id="dashboardConfig">{"payloadUrl":"broken.gz"}</script>');
        fs.writeFileSync(path.join(root, 'broken.gz'), Buffer.from('invalid-' + sentinel));
        invoke([root, output, '1', '2']);
        invoke([root, path.join(html, sentinel), '1', '2']);
        const error = Object.assign(new Error(`C:/${sentinel} https://private.invalid/?key=${sentinel}`), { name: sentinel, code: sentinel });
        assert.deepStrictEqual(safeFailure(error, sentinel), { phase: 'unknown', reason: 'operation-failed', code: 'unclassified' });
        assert.deepStrictEqual(safeInventoryDiagnostic({ step: sentinel, innerExceptionType: sentinel, nativeErrorCode: sentinel }), { category: 'execution', exceptionType: 'unclassified', exitCode: null, phase: 'execute' });
        const callbacks = {};
        let sample;
        const metrics = { phases: { workerParseMs: 1, [sentinel]: 9 } };
        const context = {
            performance, setInterval: callback => { sample = callback; },
            getDashboardMetricsSnapshot: () => metrics,
            window: { addEventListener: (name, callback) => { callbacks[name] = callback; }, Worker: class {}, init: async () => { throw error; } }
        };
        error.stack = `Error: ${sentinel}\n at init (C:/${sentinel}:12:34)\n at ${sentinel} (https://private.invalid/?key=${sentinel}:56:78)`;
        require('vm').runInNewContext(`(${installInstrumentation.toString()})()`, context);
        callbacks.DOMContentLoaded();
        await assert.rejects(context.window.init());
        sample();
        metrics.phases.workerParseMs = 2;
        sample();
        assert.strictEqual(context.window.__issue70.phases.length, 2, 'Fresh metric snapshots must observe mutations.');
        assert(!JSON.stringify(context.window.__issue70).includes(sentinel), 'Dynamic instrumentation leaked private input.');
        delete context.getDashboardMetricsSnapshot;
        sample();
        console.log('PASS privacy repros: invalid CLI/config/gzip, missing root/blob, write failure, unknown names/codes/URLs, dynamic phases/frames, fresh optional metrics.');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

async function mockProbes() {
    await privacyProbes();
    if (process.platform === 'win32') await ownershipProbes();
    await inventoryProbes();
    const incompleteProbe = {};
    await finishHeapSample(incompleteProbe, new Promise(() => {}), 5);
    assert.strictEqual(incompleteProbe.incompleteHeapSample, true);
    const completedProbe = {};
    await finishHeapSample(completedProbe, Promise.resolve(), 5);
    assert.strictEqual(completedProbe.incompleteHeapSample, undefined);
    const fingerprintRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-fingerprint-'));
    try {
        const content = Buffer.from('fixture');
        const compressed = zlib.gzipSync(content);
        const filename = path.join(fingerprintRoot, 'payload.gz');
        fs.writeFileSync(filename, compressed);
        assert.deepStrictEqual(await fingerprintPayload(filename), { payloadBytes: compressed.length, payloadSha256: digest(compressed), decompressedBytes: content.length, decompressedSha256: digest(content) });
        fs.writeFileSync(filename, compressed.subarray(0, 8));
        await assert.rejects(fingerprintPayload(filename));
        await assert.rejects(fingerprintPayload(path.join(fingerprintRoot, 'missing.gz')));
    } finally { fs.rmSync(fingerprintRoot, { recursive: true, force: true }); }
    let portReads = 0;
    const portGuard = { check() {}, wait: operation => operation };
    assert.strictEqual(await readDevToolsPort('fixture', portGuard, () => {
        if (portReads++ === 0) throw Object.assign(new Error('locked'), { code: 'EBUSY' });
        return '12345\n/browser';
    }), 12345);
    await assert.rejects(readDevToolsPort('fixture', portGuard, () => { throw new Error('unexpected'); }), /unexpected/);
    assert.throws(() => assertRuntimeAsset('/* offline regression fixture: Chart.js */', 'Chart.js'), /real runtime library/);
    assert.throws(() => assertRuntimeAsset('x'.repeat(1024), 'pako'), /real runtime library/);
    assertRuntimeAsset('x'.repeat(1025), 'fixture');
    await guardProbes();
    let kills = 0;
    const guard = new ResourceGuard({ inventory: async () => ({ bytes: 3, pids: [123] }), terminate: async () => { kills++; }, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    const run = { status: 'running' };
    await assert.rejects(completeRun(run, guard, () => {}), /cap exceeded/);
    await guard.stop();
    assert.strictEqual(run.status, 'failed');
    assert.strictEqual(kills, 1);
    const evidence = {};
    const server = http.createServer();
    await assert.rejects(withServer(server, evidence, async () => { throw new Error('Microsoft Edge is required.'); }), /Edge is required/);
    assert.strictEqual(evidence.serverClosed, true);
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-mock-'));
    const cleanup = await cleanupOwned({ profile, owned: { terminate: async () => {}, inventory: async () => ({ pids: [] }) } });
    assert.deepStrictEqual(cleanup, { remainingOwned: 0, profileExists: false, errors: [] });
    for (const category of ['timeout', 'aborted', 'OperationStopped']) {
        const sentinel = 'SYNTHETIC_PRIVATE_PATH_TOKEN';
        const termination = Object.assign(new Error(sentinel), { inventoryDiagnostic: { category, exceptionType: 'RuntimeException', phase: 'termination', exitCode: 1 } });
        const diagnostic = await cleanupOwned({ owned: { terminate: async () => { throw termination; }, inventory: async () => ({ pids: [] }) } });
        assert.deepStrictEqual(diagnostic.errors, ['Owned family termination']);
        assert.strictEqual(diagnostic.remainingOwned, 0);
        assert.strictEqual(diagnostic.diagnostics[0].code, 'process-inventory');
        assert.strictEqual(diagnostic.diagnostics[0].inventoryDiagnostic.category, category);
        assert.strictEqual(diagnostic.diagnostics[0].inventoryDiagnostic.phase, 'termination');
        assert(Number.isSafeInteger(diagnostic.diagnostics[0].elapsedMs) && diagnostic.diagnostics[0].elapsedMs >= 0);
        assert(!JSON.stringify(diagnostic).includes(sentinel));
    }
    await assert.rejects(bounded(new Promise(() => {}), 'Termination probe', 5), /Termination probe exceeded 5 ms/);
    console.log('PASS cleanup diagnostics retain timeout/cancellation/shutdown failure despite final zero; private messages excluded; unresolved promise remains bounded.');
    const valid = { snapshot: { rows: 2, rawRows: 2, activeRows: 2, counts: {}, summaryCards: { high: '2' } }, reportIds: [...REPORTS].sort(), impactRows: 2, readinessCacheDigest: 'fixture', cachePolicy: { eligible: true, available: true, maxRowsExclusive: 500000, maxEntries: 4 }, cacheEntries: { matchingRows: 2, count: 2 }, externalRequests: 0, pageErrors: 0 };
    assertRun(valid, 2);
    const positive = { ...valid, positiveControl: true, controlObservation: { filteredSourceRows: 2, selectedRows: 1, impactRows: 1, cardTotal: 1, dateRange: '2026-01-01/2026-01-02' } };
    assertRun(positive, 2);
    for (const key of ['selectedRows', 'impactRows', 'cardTotal']) assert.throws(() => assertRun({ ...positive, controlObservation: { ...positive.controlObservation, [key]: 0 } }, 2));
    assert.throws(() => assertRun({ ...valid, snapshot: { ...valid.snapshot, rows: 0 } }, 2), /row count/);
    assert.throws(() => assertRun({ ...valid, snapshot: { ...valid.snapshot, counts: {} } }, 2, valid), /must hit cache/);
    assertRun({ ...valid, snapshot: { ...valid.snapshot, counts: { compressedCacheHits: 1 } } }, 2, valid);
    const failedFinal = new ResourceGuard({ inventory: async () => { throw new Error('final inventory failed'); }, terminate: async () => { kills++; }, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    const failedRun = { status: 'running' };
    await assert.rejects(completeRun(failedRun, failedFinal, () => {}), /final inventory failed/);
    await failedFinal.stop();
    assert.strictEqual(failedRun.status, 'failed');
    const floor = new ResourceGuard({ inventory: async () => ({ bytes: 1, pids: [] }), terminate: async () => { kills++; }, freeMemory: () => 1, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    await assert.rejects(floor.finish(), /memory floor/);
    await floor.stop();
    assert.strictEqual(floor.minimumFreeBytes, 1);
    let release;
    let inventories = 0;
    let heartbeat = false;
    const single = new ResourceGuard({ inventory: () => { inventories++; return new Promise(resolve => { release = resolve; }); }, terminate: async () => {}, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    const pending = single.sample('startup');
    assert.strictEqual(single.sample('overlap'), pending);
    await new Promise(resolve => setImmediate(() => { heartbeat = true; resolve(); }));
    assert(heartbeat);
    assert.strictEqual(inventories, 1);
    release({ bytes: 1, pids: [] });
    await pending;
    assert(single.trace[0].sampledAtHostMs >= single.trace[0].startedAtHostMs);
    assert(Number.isFinite(single.trace[0].sampledAtEpochMs));
    let rejectInventory;
    const interrupted = new ResourceGuard({ inventory: () => new Promise((resolve, reject) => { rejectInventory = reject; }), terminate: async () => {}, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 }, interval: 500 });
    const delayed = interrupted.sample('pending');
    assert.strictEqual(interrupted.sample('scheduler-overlap'), delayed);
    const originalAbort = new Error('Expected caller abort.');
    interrupted.abort(originalAbort);
    rejectInventory(new Error('Owned process inventory/termination failed.'));
    await assert.rejects(delayed, error => error === originalAbort);
    await interrupted.stop();
    const familyActions = [];
    const independent = await cleanupOwned({
        browser: { close: async () => { familyActions.push('browser'); throw new Error('disconnect failed'); } },
        owned: { terminate: async () => { familyActions.push('kill'); throw new Error('inventory failed'); }, inventory: async () => { familyActions.push('reinventory'); return { pids: [123] }; } }
    }, { terminateSpawned: async () => { familyActions.push('spawned-kill'); } });
    assert.strictEqual(independent.remainingOwned, 1);
    assert.deepStrictEqual(familyActions, ['kill', 'spawned-kill', 'browser', 'reinventory']);
    assert(independent.errors.includes('Final owned inventory'));
    const uncached = { ...valid, snapshot: { ...valid.snapshot, rows: 500000, rawRows: 500000 }, cachePolicy: { ...valid.cachePolicy, eligible: false }, cacheEntries: { count: 0, matchingRows: 0 } };
    assertRun(uncached, 500000);
    assert.strictEqual(uncached.cachedEligible, false);
    assert.strictEqual(uncached.cacheReason, 'row-limit');
    const launcher = { pid: 123, exitCode: null, signalCode: null };
    const alreadyExited = () => { throw new Error('Unchecked PID termination forbidden.'); };
    await terminateSpawned(launcher, Promise.resolve(), alreadyExited);
    await assert.rejects(terminateSpawned(launcher, new Promise(() => {}), alreadyExited, 5), /Spawned Edge exit exceeded/);
    console.log('PASS lifecycle missing Edge/server close, owned profile removal, final status, row-zero/cache-miss rejection');
    console.log('PASS final inventory exception/minimum RAM, async single-flight/timestamps, independent cleanup/actual remaining count, ineligible cache');
    console.log('PASS bounded owned-root termination and already-exited race');
}

module.exports = { mockProbes, ownershipProbes, privacyProbes, inventoryProbes, safeFailure };
if (require.main === module) (process.argv.includes('--privacy') ? privacyProbes() : process.argv.includes('--ownership') ? ownershipProbes() : process.argv.includes('--mock') ? mockProbes() : main()).catch(error => { console.error(JSON.stringify({ status: 'blocked-or-failed', failure: safeFailure(error, process.argv.includes('--mock') || process.argv.includes('--ownership') || process.argv.includes('--privacy') ? 'preflight' : 'arguments') })); process.exitCode = 1; });