const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const zlib = require('zlib');
const { Readable, Writable } = require('stream');
const { pipeline } = require('stream/promises');
const { execFile, spawn, spawnSync } = require('child_process');
const { performance } = require('perf_hooks');
const { LaunchBoundClient } = require('./helpers/launch-bound-owner');
const { loadDashboardSource, loadDashboardHarness } = require('./helpers/dashboard-test-harness');
const { exerciseAdmin, assertAdminExercise, getPdfBuffer } = require('./helpers/dashboard-admin-exercise');
const { isAllowedDashboardRequest } = require('./helpers/offline-request-policy');
const { readDashboardInput } = require('./helpers/dashboard-artifact-input');
const { exerciseSavedArtifacts, assertArtifactAcceptance } = require('./helpers/dashboard-artifact-acceptance');

// Fixed-size diagnostics survive an outer stop without retaining rows, DOM text
// or an ever-growing copy of the browser's phase history.
function compactReadinessSample(readiness) {
    if (!readiness) return null;
    const phaseNames = new Set(['loadDataMs', 'denormalizeMs', 'applyFiltersMs', 'initTotalMs', 'workerInflateMs', 'workerParseMs', 'workerWaitMs', 'workerDeliveryMs', 'mainInflateMs', 'mainDecodeMs', 'mainParseMs', 'mainFallbackMs', 'cacheReadMs', 'cacheDerivedMs']);
    const functions = new Set(['init', 'loadData', 'denormalizeWithCaching', 'ensureChartJsLoaded']);
    const phases = {};
    const initialization = {};
    for (const row of readiness.phases || []) {
        if (phaseNames.has(row.name) && Number.isFinite(row.durationMs) && row.durationMs >= 0) phases[row.name] = row.durationMs;
    }
    for (const row of readiness.initialization || []) {
        if (functions.has(row.name) && ['running', 'completed', 'failed'].includes(row.status)) initialization[row.name] = row.status;
    }
    return { instrumentationPresent: readiness.instrumentationPresent === true, readyEventSeen: readiness.readyEventSeen === true,
        dashboardReady: readiness.dashboardReady === true, initialization, phases,
        workerMessageCount: Array.isArray(readiness.workerMessages) ? readiness.workerMessages.length : null,
        filtersApplied: Number.isSafeInteger(readiness.filtersApplied) && readiness.filtersApplied >= 0 ? readiness.filtersApplied : null,
        activeReportRenders: Number.isSafeInteger(readiness.activeReportRenders) && readiness.activeReportRenders >= 0 ? readiness.activeReportRenders : null,
        documentReadyState: ['loading', 'interactive', 'complete'].includes(readiness.documentReadyState) ? readiness.documentReadyState : null };
}

function harnessMemorySample() {
    const memory = process.memoryUsage();
    return { rssBytes: memory.rss, heapUsedBytes: memory.heapUsed, heapTotalBytes: memory.heapTotal,
        externalBytes: memory.external, arrayBufferBytes: memory.arrayBuffers };
}

function readDiagnosticCheckpoint(text) {
    if (typeof text !== 'string' || text.length > 1024 || !text.startsWith('ISSUE70_CHECKPOINT:')) return null;
    let value;
    try { value = JSON.parse(text.slice('ISSUE70_CHECKPOINT:'.length)); } catch { return null; }
    const names = ['init', 'loadData', 'denormalizeWithCaching', 'ensureChartJsLoaded', 'worker-delivery',
        'workerInflateMs', 'workerParseMs', 'loadDataMs', 'denormalizeMs', 'applyFiltersMs', 'initTotalMs', 'workerWaitMs', 'workerDeliveryMs', 'mainInflateMs', 'mainDecodeMs', 'mainParseMs', 'mainFallbackMs', 'cacheReadMs', 'cacheDerivedMs',
        'admin-filter', 'admin-runtime', 'admin-libraries', 'admin-switch', 'admin-detail', 'admin-pdf', 'admin-pdf-header', 'admin-pdf-buffer'];
    if (!value || !names.includes(value.name) || !['start', 'completed', 'failed'].includes(value.state)
        || value.report !== null && !REPORTS.includes(value.report)
        || !Number.isFinite(value.browserMs) || value.browserMs < 0 || !Number.isFinite(value.epochMs)) return null;
    const record = { name: value.name, state: value.state, report: value.report, browserMs: value.browserMs, epochMs: value.epochMs,
        durationMs: Number.isFinite(value.durationMs) && value.durationMs >= 0 ? value.durationMs : null };
    if (Object.hasOwn(value, 'counts')) {
        if (!value.counts || typeof value.counts !== 'object' || Array.isArray(value.counts)) return null;
        const entries = Object.entries(value.counts);
        if (!entries.length || entries.some(([key, count]) => !['sourceRows', 'reportRows'].includes(key)
            || !Number.isInteger(count) || count < 0 || count > 2147483647)) return null;
        record.counts = Object.fromEntries(entries);
    }
    return record;
}

function writeBrowserDiagnostic(guard, writer, sample) {
    try { writer(sample); }
    catch (error) { guard.abort(error); throw error; }
}

function safeInventoryDiagnostic(value = {}) {
    const categories = ['timeout', 'aborted', 'execution', 'response', 'InvalidOperation', 'InvalidArgument', 'InvalidData', 'OperationStopped', 'WriteError', 'ObjectNotFound', 'PermissionDenied', 'SecurityError', 'ResourceUnavailable', 'NotSpecified'];
    const types = ['RuntimeException', 'CimException', 'MethodInvocationException', 'PSInvalidOperationException', 'SessionStateUnauthorizedAccessException', 'UnauthorizedAccessException', 'InvalidOperationException', 'ArgumentException', 'Win32Exception'];
    const phases = ['execute', 'compile', 'cim', 'selection', 'memory', 'termination', 'response'];
    const steps = ['fresh-cim', 'fresh-identity', 'fresh-process-identity', 'fresh-root-identity', 'get-process', 'start-identity', 'handle-open', 'kill', 'kill-exit-check', 'wait-exit', 'dispose'];
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
        ['Owned process accounting is incomplete.', 'process-accounting'],
        ['Launch-bound owner state unknown.', 'launch-owner'],
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
    constructor({ inventory, terminate, freeMemory = os.freemem, limits, interval = 1500, recordSample = () => {} }) {
        Object.assign(this, { inventory, terminate, freeMemory, limits, interval, recordSample });
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
                const inventoryStartedAtHostMs = performance.now();
                const inventory = await this.inventory();
                const inventoryCompletedAtHostMs = performance.now();
                const freeBytes = this.freeMemory();
                assert(Number.isFinite(inventory.bytes) && inventory.bytes >= 0 && Array.isArray(inventory.pids), 'Invalid process inventory.');
                assert(Number.isFinite(freeBytes) && freeBytes >= 0, 'Invalid free memory inventory.');
                this.peakBytes = Math.max(this.peakBytes, inventory.bytes);
                this.minimumFreeBytes = Math.min(this.minimumFreeBytes, freeBytes);
                const validatedAtHostMs = performance.now();
                this.trace.push({ stage, startedAtHostMs: startedAt, inventoryStartedAtHostMs, inventoryCompletedAtHostMs, validatedAtHostMs, sampledAtHostMs: performance.now(), sampledAtEpochMs: Date.now(), browserFamilyBytes: inventory.bytes, browserFamilyPrivateBytes: inventory.privateBytes ?? null, freeMemoryBytes: freeBytes, ownedProcessCount: inventory.pids.length });
                this.recordSample(this.trace.at(-1));
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
    const observedRoots = new Set();
    let accountingComplete = true;
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
$all = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,CreationDate,WorkingSetSize,PrivatePageCount -ErrorAction Stop)
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
# Inventory-only accountability must not broaden termination authorization.
# Retained children also seed accounting for their later descendants.
if ($env:ISSUE70_ACCOUNTING -eq '1') {
    foreach ($previous in $known) {
        $item = $byId[[int]$previous.pid]
        if ($null -ne $item -and (Get-Created $item) -ceq $previous.created -and $ids.Add([int]$item.ProcessId)) {
            $provenance[[int]$item.ProcessId] = @{ rootPid = $previous.rootPid; rootCreated = $previous.rootCreated }
        }
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
    const environment = () => ({ ISSUE70_PROFILE: profile, ISSUE70_ACCOUNTING: '0', ISSUE70_KNOWN: JSON.stringify(known), ISSUE70_LAUNCHER_PID: String(launcherPid), ISSUE70_LAUNCHER_CREATED: launcherCreated });
    const remember = records => {
        assert(Array.isArray(records), 'Invalid owned process identities.');
        for (const record of records) {
            assert(Number.isSafeInteger(record.pid) && Number.isSafeInteger(record.rootPid) && typeof record.created === 'string' && /^\d{18}$/.test(record.created) && typeof record.rootCreated === 'string' && /^\d{18}$/.test(record.rootCreated), 'Invalid owned process identities.');
        }
        for (const record of records) {
            if (record.pid === record.rootPid && record.created === record.rootCreated) observedRoots.add(`${record.pid}:${record.created}`);
        }
        return records;
    };
    const inventory = async () => {
        assert(accountingComplete, 'Owned process accounting is incomplete.');
        try {
        const result = await execute(selection + `
    $issue70Phase = 'memory'
$bytes = [long]0
$privateBytes = [long]0
$records = @()
foreach ($item in $owned) {
    $source = $provenance[[int]$item.ProcessId]
    $records += @{ pid = [int]$item.ProcessId; created = (Get-Created $item); rootPid = $source.rootPid; rootCreated = $source.rootCreated }
    $workingSet = [long]0
    $privateCount = [long]0
    if (-not [long]::TryParse([string]$item.WorkingSetSize, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$workingSet) -or
        -not [long]::TryParse([string]$item.PrivatePageCount, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$privateCount)) { throw 'Invalid owned process memory.' }
    # Use both byte counters from the same identity-bound CIM snapshot.
    # A separate process open can disappear or fail and silently undercount private memory.
    $bytes += $workingSet
    $privateBytes += $privateCount
}
@{ bytes = $bytes; privateBytes = $privateBytes; pids = @($ids); records = $records } | ConvertTo-Json -Compress -Depth 4
`, { ...environment(), ISSUE70_ACCOUNTING: '1' });
        const current = remember(result.records);
        const present = new Set(current.map(record => `${record.pid}:${record.created}`));
        // Root lifetime history is accounting-only and never enters PowerShell selection.
        // Once an observed root is gone/reused, snapshots cannot exclude an unseen late child.
        if ([...observedRoots].some(identity => !present.has(identity))) accountingComplete = false;
        assert(accountingComplete, 'Owned process accounting is incomplete.');
        known = current;
        const launcherRecord = known.find(record => record.pid === launcherPid);
        if (launcherRecord) launcherCreated ||= launcherRecord.created;
        return result;
        } catch (error) {
            // An incomplete snapshot cannot later establish lifetime absence either.
            accountingComplete = false;
            throw error;
        }
    };
    const terminateSelected = async () => {
        const result = await execute(selection + `
    $issue70Phase = 'termination'
$records = @($owned | ForEach-Object {
    $source = $provenance[[int]$_.ProcessId]
    @{ pid = [int]$_.ProcessId; created = (Get-Created $_); rootPid = $source.rootPid; rootCreated = $source.rootCreated }
})
$processes = @()
$processObjects = @()
$terminationFailure = $null
$disposeFailure = $null
$skipped = @{ processIdentity = 0; rootCommandLine = 0; rootCreationDate = 0 }
$terminationOrder = @($owned | Sort-Object { $_.ProcessId -eq $provenance[[int]$_.ProcessId].rootPid })
try {
foreach ($item in $terminationOrder) {
    $issue70Step = 'fresh-cim'
    $fresh = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId) OR ProcessId=$($provenance[[int]$item.ProcessId].rootPid)" -ErrorAction Stop)
    $issue70Step = 'fresh-identity'
    $current = @($fresh | Where-Object { $_.ProcessId -eq $item.ProcessId -and $_.CreationDate -eq $item.CreationDate })
    $source = $provenance[[int]$item.ProcessId]
    $root = @($fresh | Where-Object { $_.ProcessId -eq $source.rootPid })
    $candidate = @($fresh | Where-Object { $_.ProcessId -eq $item.ProcessId })
    if ($candidate.Count -gt 0 -and $null -eq $candidate[0].CreationDate) { $skipped.processIdentity++; continue }
    if ($root.Count -gt 0 -and (-not $root[0].CommandLine -or $null -eq $root[0].CreationDate)) {
        if (-not $root[0].CommandLine) { $skipped.rootCommandLine++ }
        if ($null -eq $root[0].CreationDate) { $skipped.rootCreationDate++ }
        continue
    }
    if ($current.Count -ne 1 -or ($root.Count -gt 0 -and ($root[0].CreationDate.ToUniversalTime().Ticks.ToString() -ne $source.rootCreated -or -not (Test-OwnedRoot $root[0])))) { continue }
    $issue70Step = 'get-process'
    $process = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
    if ($process) {
        $processObjects += $process
        $issue70Step = 'handle-open'
        $handle = $process.SafeHandle
        if ($null -eq $handle -or $handle.IsInvalid -or $handle.IsClosed) { throw 'Process handle unavailable.' }
    }
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
} catch { $terminationFailure = $_; throw }
finally {
    foreach ($processObject in $processObjects) {
        try { $processObject.Dispose() } catch { if ($null -eq $disposeFailure) { $disposeFailure = $_ } }
    }
    if ($null -ne $disposeFailure -and $null -eq $terminationFailure) { $issue70Step = 'dispose'; throw $disposeFailure }
}
@{ stoppedCount = $processes.Count; skippedUnverified = $skipped; records = $records } | ConvertTo-Json -Compress -Depth 4
`, environment(), 12000);
        // Retain every selected identity, including children first seen at termination.
        // Final inventory also checks root lifetime uncertainty; kill eligibility never proves exit.
        const selected = remember(result.records);
        known = [...new Map([...known, ...selected].map(record => [`${record.pid}:${record.created}`, record])).values()];
        return { stoppedCount: result.stoppedCount, skippedUnverified: result.skippedUnverified };
    };
    const terminate = async () => {
        try { return await terminateSelected(); } catch (error) {
            // A partial termination may discover identities that never reach JavaScript.
            // No later empty inventory can prove their absence on this owner instance.
            accountingComplete = false;
            throw error;
        }
    };
    return { inventory, terminate, setLauncher(pid) { assert(Number.isSafeInteger(pid) && pid > 0); launcherPid = pid; } };
}

async function terminateSpawned(launcher, launcherExit, execute = execFile, exitTimeout = 5000) {
    if (!launcher || launcher.exitCode !== null || launcher.signalCode !== null) return;
    await bounded(launcherExit, 'Spawned Edge exit', exitTimeout);
}

async function terminateFamily(state) {
    if (state.authority) { await state.authority.terminate(); return; }
    const outcomes = await Promise.allSettled([
        terminateSpawned(state.launcher, state.launcherExit),
        state.owned.terminate()
    ]);
    for (const outcome of outcomes) if (outcome.status === 'rejected') throw outcome.reason;
}

function launchOwnerGuard(state, limits) {
    return new ResourceGuard({ inventory: () => state.authority.inventory(), terminate: () => terminateFamily(state), limits, recordSample: state.recordSample });
}

async function cleanupOwned({ guard, browser, page, cdp, launcher, launcherExit, owned, profile, authority, profileFinalizers, launchBoundMode }, overrides = {}) {
    const result = { remainingOwned: null, profileExists: profile ? true : false, errors: [] };
    const authoritative = Boolean(authority || launchBoundMode);
    let terminalTargetConfirmed = false;
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
    await attempt('Owned family termination', async () => {
        if (authoritative) {
            assert(authority, 'Launch-bound owner state unknown.');
            const proof = await authority.terminate();
            authority.validate(proof, true);
            terminalTargetConfirmed = true;
            return;
        }
        const termination = await owned?.terminate();
        if (termination) {
            assert(Number.isSafeInteger(termination.stoppedCount) && termination.stoppedCount >= 0, 'Invalid stopped count.');
            result.termination = { stoppedCount: termination.stoppedCount, skippedUnverified: {} };
            for (const key of ['processIdentity', 'rootCommandLine', 'rootCreationDate']) {
                const count = termination.skippedUnverified?.[key];
                assert(Number.isSafeInteger(count) && count >= 0, 'Invalid skipped identity count.');
                result.termination.skippedUnverified[key] = count;
            }
        }
    }, 15000);
    await attempt('Spawned family termination', () => (overrides.terminateSpawned || terminateSpawned)(launcher, launcherExit));
    await attempt('Launcher exit', async () => {
        if (launcherExit) await launcherExit;
    });
    // The exclusive target is gone after a validated terminal proof. Keep
    // transport closure below; sending a target command now can wait forever.
    await attempt('CDP detach', () => !terminalTargetConfirmed && cdp && browser?.isConnected() && page && !page.isClosed() ? cdp.detach() : undefined);
    await attempt('Page close', () => page && !page.isClosed() ? page.close({ runBeforeUnload: false }) : undefined);
    await attempt('Browser disconnect', () => browser?.close());
    await attempt('Final owned inventory', async () => {
        if (authoritative) {
            assert(authority, 'Launch-bound owner state unknown.');
            const proof = await authority.finish();
            authority.validate(proof, true);
            result.ownerCompletion = { confirmed: true, activeProcesses: 0, forced: proof.Forced, streamsComplete: true, assignedBeforeResume: proof.Created && proof.Assigned && proof.Resumed && proof.Sealed };
            result.remainingOwned = 0;
            return;
        }
        const actual = owned ? await owned.inventory() : { pids: [] };
        result.remainingOwned = actual.pids.length;
        assert.strictEqual(result.remainingOwned, 0, 'Owned processes remain.');
    });
    if (authoritative) result.ownerSetup = authority?.setup || null;
    const removeProfile = async serverClosed => {
        if (authoritative && (!serverClosed || result.errors.length || result.remainingOwned !== 0)) throw new Error('Owned cleanup failed.');
        if (profile && result.remainingOwned === 0) await (overrides.removeProfile || fs.promises.rm)(profile, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
        result.profileExists = Boolean(profile && fs.existsSync(profile));
        assert(!result.profileExists, 'Owned profile remains.');
    };
    if (authoritative) {
        if (result.remainingOwned === null) authority?.abort();
        if (Array.isArray(profileFinalizers)) {
            result.profileDeferred = true;
            profileFinalizers.push(async serverClosed => {
                try { await removeProfile(serverClosed); result.profileDeferred = false; }
                catch (error) { result.errors.push('Profile removal'); throw error; }
            });
        } else result.errors.push('Profile removal requires server closure');
    } else await attempt('Profile removal', () => removeProfile(true));
    return result;
}

async function withServer(server, evidence, operation, profileFinalizers = []) {
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
        for (const finalize of profileFinalizers) {
            try { await bounded(finalize(evidence.serverClosed), 'Profile removal'); }
            catch { if (!originalError) originalError = new Error('Owned cleanup failed.'); }
        }
    }
    if (originalError) throw originalError;
    assert(evidence.serverClosed, 'HTTP server close failed.');
}

const REPORTS = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

// Browser choice changes only the installed executable. Both engines use the
// same launch-bound native owner, all-image containment and resource limits.
function selectInstalledBrowser(environment = process.env, exists = fs.existsSync) {
    const engine = environment.DASHBOARD_BROWSER_ENGINE || 'edge';
    assert(['edge', 'chrome'].includes(engine), 'Unsupported browser engine.');
    const relative = engine === 'chrome' ? 'Google/Chrome/Application/chrome.exe' : 'Microsoft/Edge/Application/msedge.exe';
    const candidates = [environment['ProgramFiles(x86)'], environment.ProgramFiles, environment.LOCALAPPDATA]
        .filter(Boolean).map(base => path.join(base, relative));
    const executable = candidates.find(candidate => exists(candidate));
    assert(executable, 'Requested installed browser is unavailable.');
    return { engine, executable };
}

function isReportReady(reportId) {
    return activeReportId === reportId
        && document.getElementById(reportId + '-section')?.classList.contains('active')
        && initializedReports.has(reportId) && !dirtyReports.has(reportId)
        && document.getElementById(reportId + '-section')?.getAttribute('aria-busy') !== 'true';
}

async function fingerprintPayload(filename) {
    const compressedHash = crypto.createHash('sha256');
    const decompressedHash = crypto.createHash('sha256');
    let payloadBytes = 0;
    let decompressedBytes = 0;
    const input = Buffer.isBuffer(filename) ? Readable.from([filename]) : fs.createReadStream(filename);
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

function measurementWorkflow(args) {
    const admin = args.includes('--admin-exercise');
    const saved = args.includes('--saved-artifacts');
    const scopedAdminFirst = args.includes('--scoped-admin-first');
    assert(!saved || !admin, 'Saved-artifact acceptance is separate from getBuffer timing.');
    assert(!scopedAdminFirst || admin || saved, '--scoped-admin-first requires --admin-exercise or --saved-artifacts.');
    return { scopedAdminFirst, workload: scopedAdminFirst ? 'load-filter-scoped-reports-detail-pdf-restore' : 'load-unfiltered-report-tour-then-optional-scoped-exercise' };
}

function summarizeScopedExercise(result, savedArtifacts) {
    if (savedArtifacts) assertArtifactAcceptance(result);
    else assertAdminExercise(result);
    const steps = result.reports.map(row => {
        const state = savedArtifacts ? row.before : row;
        const cards = savedArtifacts ? state.cards : state.summaryCards;
        assert(Number.isSafeInteger(state.reportRows) && state.reportRows >= 0, 'Missing or invalid scoped report rows.');
        assert(cards && Object.keys(cards).length > 0, 'Missing scoped report summary cards.');
        const summaryCards = Object.fromEntries(Object.keys(cards).sort().map(key => {
            const value = cards[key];
            assert((typeof value === 'number' || typeof value === 'string' && value.trim() !== '') && Number.isSafeInteger(Number(value)) && Number(value) >= 0, 'Invalid scoped summary count.');
            if (row.scope === 'empty') assert.strictEqual(Number(value), 0, 'Empty scoped cards broadened.');
            return [key, Number(value)];
        }));
        if (row.scope === 'empty') assert.strictEqual(state.reportRows, 0, 'Empty scoped report broadened.');
        return { scope: row.scope, report: row.report, sourceRows: state.sourceRows, reportRows: state.reportRows, summaryCards,
            ...(savedArtifacts ? { mode: state.mode } : {}) };
    }).sort((a, b) => `${a.scope}/${a.report}`.localeCompare(`${b.scope}/${b.report}`));
    return { representativeRows: result.representativeRows, steps };
}

function recordScopedExercise(run, savedArtifacts) {
    const summary = summarizeScopedExercise(savedArtifacts ? run.savedArtifacts : run.adminExercise, savedArtifacts);
    run.scopedWorkloadSummary = summary;
    run.scopedWorkloadDigest = digest(JSON.stringify(summary));
    const representative = summary.steps.filter(step => step.scope === 'representative');
    run.reportIds = representative.map(step => step.report).sort();
    run.reportRows = Object.fromEntries(representative.map(step => [step.report, step.reportRows]));
    run.impactRows = run.reportRows['impact-analysis'];
    run.readinessCacheDigest = null;
    if (run.positiveControl) {
        const active = representative.find(step => step.report === 'active-vulnerabilities');
        run.controlObservation = { filteredSourceRows: active.sourceRows, selectedRows: active.reportRows, impactRows: run.impactRows,
            cardTotal: Object.values(active.summaryCards).reduce((total, value) => total + value, 0), dateRange: '2026-01-01/2026-01-02' };
    }
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
        assert.strictEqual(run.controlObservation.selectedRows, 2, 'Positive control requires two active table rows.');
        assert.strictEqual(run.controlObservation.impactRows, 2, 'Positive control requires two impact rows.');
        assert.strictEqual(run.controlObservation.cardTotal, 2, 'Positive control requires a severity-card total of two.');
        assert.strictEqual(run.controlObservation.dateRange, '2026-01-01/2026-01-02');
        if (first) assert.deepStrictEqual(run.controlObservation, first.controlObservation, 'Cold/reload positive-control counts differ.');
    }
    for (const report of REPORTS) assert(run.reportIds.includes(report), `Required report missing: ${report}`);
    if (run.scopedAdminFirst) {
        assert.strictEqual(run.workload, 'load-filter-scoped-reports-detail-pdf-restore');
        assert.deepStrictEqual(run.reportSwitches, [], 'Scoped-first evidence must not claim an unfiltered report tour.');
        assert.strictEqual(run.readinessCacheDigest, null, 'Scoped-first evidence cannot claim full-tour readiness/cache consistency.');
        const summary = summarizeScopedExercise(run.savedArtifacts || run.adminExercise, Boolean(run.savedArtifacts));
        assert.deepStrictEqual(run.scopedWorkloadSummary, summary, 'Scoped summary differs from actual helper receipts.');
        assert.strictEqual(run.scopedWorkloadDigest, digest(JSON.stringify(summary)), 'Scoped receipt digest differs.');
        const representative = summary.steps.filter(step => step.scope === 'representative');
        assert.deepStrictEqual(run.reportIds, representative.map(step => step.report).sort());
        assert.deepStrictEqual(run.reportRows, Object.fromEntries(representative.map(step => [step.report, step.reportRows])));
        assert.strictEqual(run.impactRows, run.reportRows['impact-analysis']);
    }
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
    requireCapturedFingerprint([run.compressedFingerprint]);
    if (first) {
        assert.strictEqual(run.compressedFingerprint, first.compressedFingerprint, 'Cold/reload compressed fingerprint differs.');
        for (const key of ['rows', 'rawRows', 'activeRows']) assert.strictEqual(run.snapshot[key], first.snapshot[key], `Cold/reload ${key} differs.`);
        assert.strictEqual(run.impactRows, first.impactRows, 'Cold/reload impact count differs.');
        assert.deepStrictEqual(run.reportIds, first.reportIds, 'Cold/reload reports differ.');
        assert.deepStrictEqual(run.cachePolicy, first.cachePolicy, 'Cold/reload cache policy differs.');
        assert.strictEqual(digest(JSON.stringify(run.snapshot.summaryCards)), digest(JSON.stringify(first.snapshot.summaryCards)), 'Cold/reload severity summary differs.');
        assert.strictEqual(Boolean(run.scopedAdminFirst), Boolean(first.scopedAdminFirst), 'Cold/reload workflow differs.');
        if (run.scopedAdminFirst) assert.strictEqual(run.scopedWorkloadDigest, first.scopedWorkloadDigest, 'Cold/reload scoped source/report/card counts differ.');
        else assert.strictEqual(run.readinessCacheDigest, first.readinessCacheDigest, 'Cold/reload readiness/cache digest differs.');
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

function requireCapturedFingerprint(values) {
    assert(Array.isArray(values) && values.length === 1 && typeof values[0] === 'string' && /^[A-Za-z0-9_]{1,256}$/.test(values[0]), 'Expected exactly one valid runtime compressed fingerprint.');
    return values[0];
}

function installInstrumentation({ progressJournal = false } = {}) {
    const phaseNames = ['loadDataMs', 'denormalizeMs', 'applyFiltersMs', 'initTotalMs', 'workerInflateMs', 'workerParseMs', 'workerWaitMs', 'workerDeliveryMs', 'mainInflateMs', 'mainDecodeMs', 'mainParseMs', 'mainFallbackMs', 'cacheReadMs', 'cacheDerivedMs'];
    const functionNames = ['init', 'loadData', 'denormalizeWithCaching', 'ensureChartJsLoaded'];
    window.__issue70 = { phases: [], workerMessages: [], initialization: [], compressedFingerprints: [] };
    if (progressJournal) window.__issue70.checkpoint = (name, state, report = null, durationMs = null, counts) => {
        try { console.debug('ISSUE70_CHECKPOINT:' + JSON.stringify({ name, state, report, durationMs, ...(counts === undefined ? {} : { counts }),
            browserMs: performance.now(), epochMs: performance.timeOrigin + performance.now() })); } catch { /* diagnostic only */ }
    };
    window.addEventListener('DOMContentLoaded', () => {
        const originalCacheRead = window.getCachedData;
        if (typeof originalCacheRead === 'function') {
            window.getCachedData = async function(...args) {
                const start = performance.now();
                try { return await originalCacheRead.apply(this, args); }
                finally {
                    try { recordDashboardPhaseTiming('cacheReadMs', performance.now() - start); } catch { /* instrumentation must not change the result */ }
                }
            };
        }
        const originalCacheDerived = window.applyDerivedVulnerabilityFields;
        if (typeof originalCacheDerived === 'function') {
            // This production function is synchronous: an async wrapper would
            // turn thrown errors into rejections and change its callers.
            window.applyDerivedVulnerabilityFields = function(...args) {
                const start = performance.now();
                try { return originalCacheDerived.apply(this, args); }
                finally {
                    try { recordDashboardPhaseTiming('cacheDerivedMs', performance.now() - start); } catch { /* instrumentation must not change the result */ }
                }
            };
        }
        const originalFingerprint = window.computeCompressedFingerprint;
        if (typeof originalFingerprint === 'function') {
            window.computeCompressedFingerprint = async function(...args) {
                const fingerprint = await originalFingerprint.apply(this, args);
                window.__issue70.compressedFingerprints.push(fingerprint);
                return fingerprint;
            };
        }
        for (const name of ['init', 'loadData', 'denormalizeWithCaching', 'ensureChartJsLoaded']) {
            const original = window[name];
            if (typeof original !== 'function') continue;
            window[name] = async function(...args) {
                const record = { name, startedBrowserMs: performance.now(), status: 'running' };
                window.__issue70.initialization.push(record);
                window.__issue70.checkpoint?.(name, 'start');
                try {
                    const result = await original.apply(this, args);
                    record.status = 'completed';
                    window.__issue70.checkpoint?.(name, 'completed');
                    return result;
                } catch (error) {
                    record.status = 'failed';
                    window.__issue70.checkpoint?.(name, 'failed');
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
            if (previous[name] !== durationMs) {
                window.__issue70.phases.push({ name, durationMs, observedBrowserMs: performance.now(), observedEpochMs: performance.timeOrigin + performance.now() });
                window.__issue70.checkpoint?.(name, 'completed', null, durationMs);
            }
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
                const format = data.phase ? 'phase' : Array.isArray(data) ? 'legacy-array' : data.jsonUtf8 ? 'utf8-json-buffer' : data.rows === null ? 'lookups-raw-columns' : Array.isArray(data.rows) ? 'row-envelope' : 'unknown';
                if (phaseNames.includes(data.phase)) window.__issue70.checkpoint?.(data.phase, 'completed', null, data.duration);
                else if (!data.phase) window.__issue70.checkpoint?.('worker-delivery', 'completed');
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

async function measureIteration({ chromium, edge, origin, fileUrl, artifactRoot, evidence, expectedRows, iteration, positiveControl, profileFinalizers, recordSample }) {
    const state = {};
    if (recordSample) state.recordSample = sample => recordSample({ iteration, ...sample });
    let measurementError;
    try {
        state.profile = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-edge-')));
        state.launchBoundMode = true;
        state.profileFinalizers = profileFinalizers;
        state.authority = new LaunchBoundClient(state.profile);
        await state.authority.ready;
        state.owned = state.authority;
        state.profileFinalizers = profileFinalizers;
        state.guard = launchOwnerGuard(state, evidence.limits);
        await state.guard.sample('prelaunch');
        state.guard.check();
        await state.authority.start(edge, ['--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${state.profile}`, '--no-first-run', '--no-default-browser-check', 'about:blank']);
        state.guard.start();
        const portFile = path.join(state.profile, 'DevToolsActivePort');
        const port = await readDevToolsPort(portFile, state.guard);
        const connectionOptions = { timeout: 15000 };
        if (evidence.savedArtifactsEnabled) {
            connectionOptions.artifactsDir = path.join(artifactRoot, `native-downloads-${iteration}`);
            fs.mkdirSync(connectionOptions.artifactsDir);
        }
        const connection = chromium.connectOverCDP(`http://127.0.0.1:${port}`, connectionOptions);
        connection.then(browser => { state.browser = browser; }, () => {});
        state.browser = await state.guard.wait(connection);
        const browserVersion = state.browser.version();
        if (evidence.browserEngine.version) assert.strictEqual(browserVersion, evidence.browserEngine.version, 'Browser version changed between iterations.');
        evidence.browserEngine.version = browserVersion;
        const context = state.browser.contexts()[0];
        state.page = context.pages()[0];
        state.cdp = await state.guard.wait(context.newCDPSession(state.page));
        await state.guard.wait(state.cdp.send('Performance.enable'));
        if (evidence.savedArtifactsEnabled) {
            await state.guard.wait(state.page.setViewportSize({ width: 1440, height: 1000 }));
        }
        await state.guard.wait(context.route('**/*', route => isAllowedDashboardRequest(route.request().url(), origin, fileUrl) ? route.continue() : route.abort()));
        await state.guard.wait(context.addInitScript(installInstrumentation, { progressJournal: Boolean(recordSample) }));
        let first;
        for (const load of ['first', 'reload']) {
            const run = { iteration, load, positiveControl, stage: 'navigation', status: 'running', peakMainHeapBytes: 0, externalRequests: 0, pageErrors: 0, failedResources: 0, failedResponses: 0 };
            evidence.runs.push(run);
            state.guard.stage = `${load}:navigation`;
            const traceStart = state.guard.trace.length;
            const onError = () => { run.pageErrors++; };
            const onRequest = request => { if (!isAllowedDashboardRequest(request.url(), origin, fileUrl)) run.externalRequests++; };
            const onFailure = () => { run.failedResources++; };
            const onResponse = response => { if (response.status() >= 400) run.failedResponses++; };
            const onConsole = message => {
                if (!recordSample) return;
                const checkpoint = readDiagnosticCheckpoint(message.text());
                if (!checkpoint) return;
                try { writeBrowserDiagnostic(state.guard, recordSample, { kind: 'browser-checkpoint', iteration, load, stage: state.guard.stage,
                    sampledAtEpochMs: Date.now(), ...checkpoint }); }
                catch { /* The guard is already aborted; event handlers must not throw. */ }
            };
            state.page.on('pageerror', onError);
            state.page.on('request', onRequest);
            state.page.on('requestfailed', onFailure);
            state.page.on('response', onResponse);
            state.page.on('console', onConsole);
            let heapSample;
            let lastHeapJournalAt = -Infinity;
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
                    if (recordSample && performance.now() - lastHeapJournalAt >= 500) {
                        lastHeapJournalAt = performance.now();
                        writeBrowserDiagnostic(state.guard, recordSample, { kind: 'browser-heap', iteration, load, stage: state.guard.stage,
                            sampledAtEpochMs: Date.now(), mainHeapUsedBytes: heap?.value ?? null,
                            readiness: compactReadinessSample(readiness) });
                    }
                }).catch(() => { run.failedHeapSamples = (run.failedHeapSamples || 0) + 1; }).finally(() => { heapSample = null; });
            };
            const heapTimer = setInterval(sampleHeap, 100);
            try {
                run.navigationStartedAtHostMs = performance.now();
                run.navigationStartedAtEpochMs = Date.now();
                const navigationTarget = load === 'first' ? fileUrl || origin + '/' : state.page.url();
                assert(isAllowedDashboardRequest(navigationTarget, origin, fileUrl), 'Navigation escaped its retained product.');
                run.navigationPolicy = fileUrl ? 'exact-self-contained-file-with-optional-single-view' : 'same-hosted-origin';
                const navigation = load === 'first' ? state.page.goto(navigationTarget, { waitUntil: 'domcontentloaded', timeout: evidence.limits.readinessWallMs }) : state.page.reload({ waitUntil: 'domcontentloaded', timeout: evidence.limits.readinessWallMs });
                await state.guard.wait(navigation);
                run.stage = 'readiness';
                state.guard.stage = `${load}:readiness`;
                await state.guard.wait(state.page.waitForFunction(() => window.__issue70.initialization.some(record => record.name === 'init' && record.status === 'failed') || (window.__issue70.ready && window._dashboardReady && dashboardMetrics.counts.applyFilters > 0 && dashboardMetrics.reports['active-vulnerabilities']?.count > 0), null, { timeout: evidence.limits.readinessWallMs }));
                run.initialization = await state.guard.wait(state.page.evaluate(() => window.__issue70.initialization));
                assert(!run.initialization.some(record => record.name === 'init' && record.status === 'failed'), 'Dashboard initialization failed; inspect sanitized function frames.');
                run.readinessObservedHostWallMs = performance.now() - run.navigationStartedAtHostMs;
                if (evidence.fixedDateRange && !positiveControl) {
                    const [start, end] = evidence.fixedDateRange.split('/');
                    const alreadySelected = await state.guard.wait(state.page.evaluate(({ start, end }) => filterState.startDate === start && filterState.endDate === end, { start, end }));
                    if (!alreadySelected) {
                        await state.guard.wait(state.page.locator('#filterPillDate').click());
                        await state.guard.wait(state.page.locator('#filterPopoverStartDate').fill(start));
                        await state.guard.wait(state.page.locator('#filterPopoverEndDate').fill(end));
                        await state.guard.wait(state.page.locator('#filterPopoverApplyButton').click());
                    }
                    run.fixtureDateRange = { start, end, reusedSelectedRange: alreadySelected };
                    await state.guard.wait(state.page.waitForFunction(({ start, end }) => filterState.startDate === start && filterState.endDate === end
                        && initializedReports.has(activeReportId) && !dirtyReports.has(activeReportId)
                        && document.getElementById(activeReportId + '-section').getAttribute('aria-busy') !== 'true', { start, end }, { timeout: evidence.limits.readinessWallMs }));
                }
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
                run.scopedAdminFirst = evidence.scopedAdminFirst;
                run.workload = evidence.workload;
                run.reportSwitches = [];
                const exerciseScoped = async () => {
                    if (evidence.adminExerciseEnabled) {
                        run.stage = 'admin-exercise';
                        state.guard.stage = `${load}:admin-exercise`;
                        run.adminExercise = await exerciseAdmin(state.page, state.guard, evidence.limits.readinessWallMs);
                        assertAdminExercise(run.adminExercise);
                    }
                    if (evidence.savedArtifactsEnabled) {
                        run.stage = 'saved-artifacts';
                        state.guard.stage = `${load}:saved-artifacts`;
                        run.savedArtifacts = await exerciseSavedArtifacts(state.page, state.guard, evidence.limits.readinessWallMs,
                            path.join(artifactRoot, `iteration-${iteration}-${load}`));
                        assertArtifactAcceptance(run.savedArtifacts);
                    }
                };
                if (evidence.scopedAdminFirst) {
                    await exerciseScoped();
                    recordScopedExercise(run, evidence.savedArtifactsEnabled);
                    const observations = await state.guard.wait(state.page.evaluate(() => ({ phases: window.__issue70.phases, workerMessages: window.__issue70.workerMessages })));
                    run.phaseTrace = observations.phases;
                    run.workerMessages = observations.workerMessages;
                    run.workerReturnFormats = [...new Set(observations.workerMessages.filter(message => message.format !== 'phase').map(message => message.format))];
                } else {
                    run.stage = 'reports';
                    state.guard.stage = `${load}:reports`;
                    for (const report of REPORTS.slice(1).concat(REPORTS[0])) {
                        const switchStarted = performance.now();
                        await state.guard.wait(state.page.evaluate(reportId => selectReportById(reportId), report));
                        await state.guard.wait(state.page.waitForFunction(isReportReady, report, { timeout: evidence.limits.readinessWallMs }));
                        run.reportSwitches.push({ report, completedHostWallMs: performance.now() - switchStarted });
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
                }
                run.summaryCardsSha256 = digest(JSON.stringify(run.snapshot.summaryCards));
                run.stage = 'cache';
                state.guard.stage = `${load}:cache`;
                run.compressedFingerprint = requireCapturedFingerprint(await state.guard.wait(state.page.evaluate(() => window.__issue70.compressedFingerprints)));
                if (run.cachePolicy.available) {
                    const deadline = performance.now() + 5000;
                    do {
                        run.cacheEntries = await state.guard.wait(bounded(inspectCache(state.page, run.compressedFingerprint), 'Cache inspection'));
                        if (!run.cachePolicy.eligible || run.cacheEntries.matchingRows === expectedRows) break;
                        await state.guard.wait(new Promise(resolve => setTimeout(resolve, 100)));
                    } while (performance.now() < deadline);
                } else run.cacheEntries = { count: 0, matchingRows: 0 };
                if (!evidence.scopedAdminFirst) await exerciseScoped();
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
                state.page.off('console', onConsole);
            }
        }
    } catch (error) {
        measurementError = error;
        state.guard?.abort(error);
    } finally {
        const cleanup = await cleanupOwned(state);
        cleanup.iteration = iteration;
        evidence.cleanups.push(cleanup);
        if (state.guard) {
            evidence.resourceTraces.push({ iteration, samples: state.guard.trace, peakBrowserFamilyBytes: state.guard.peakBytes, minimumFreeMemoryBytes: Number.isFinite(state.guard.minimumFreeBytes) ? state.guard.minimumFreeBytes : null });
            if (state.guard.error) {
                measurementError ||= state.guard.error;
                const lastRun = evidence.runs.filter(run => run.iteration === iteration).at(-1);
                if (lastRun) lastRun.status = 'failed';
            }
        }
        if (!measurementError && (cleanup.errors.length || cleanup.remainingOwned !== 0 || (cleanup.profileExists && !cleanup.profileDeferred))) measurementError = new Error('Owned cleanup failed.');
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
    const selfContained = process.argv.includes('--self-contained');
    const savedArtifacts = process.argv.includes('--saved-artifacts');
    const workflow = measurementWorkflow(process.argv);
    assert(!savedArtifacts || process.argv.includes('--generated-runtime'), 'Saved artifacts require the actual generated product runtime.');
    const dateArguments = process.argv.filter(value => value.startsWith('--date-range='));
    assert(dateArguments.length <= 1, 'Only one fixture date range may be supplied.');
    const fixedDateRange = dateArguments[0]?.slice('--date-range='.length) || null;
    if (fixedDateRange) {
        assert(/^\d{4}-\d{2}-\d{2}\/\d{4}-\d{2}-\d{2}$/.test(fixedDateRange), 'Invalid fixed date range.');
        const [start, end] = fixedDateRange.split('/');
        for (const value of [start, end]) assert(new Date(value).toISOString().slice(0, 10) === value, 'Invalid fixed calendar date.');
        assert(start <= end && (!positiveControl || fixedDateRange === '2026-01-01/2026-01-02'), 'Date range conflicts with fixture control.');
    }
    assert(Number.isSafeInteger(expectedRows) && expectedRows > 0, 'Explicit expected rows are required; use 2 for the committed control fixture.');
    assert(Number.isSafeInteger(repeats) && repeats > 0 && repeats <= 10, 'Repeats must be between 1 and 10.');
    assert(!positiveControl || expectedRows === 2, 'Positive control requires two expected rows.');
    const evidence = {
        schemaVersion: 3, expectedRows, ...workflow, deliveryMode: selfContained ? 'self-contained-file' : 'hosted-http', savedArtifactsEnabled: savedArtifacts, fixedDateRange, adminExerciseEnabled: process.argv.includes('--admin-exercise'),
        limits: { browserFamilyBytes: 2 * 1024 ** 3, freeMemoryBytes: 3 * 1024 ** 3, readinessWallMs: 120000, inventoryTimeoutMs: 5000, terminationTimeoutMs: 15000 },
        heapScope: 'CDP JSHeapUsedSize is main-renderer only; sampled family working set and private memory include owned workers and descendants. Observational CDP probes are single-flight and may stall with the renderer; independent resource inventory remains bounded and fail-closed.',
        timingScope: 'ttiBrowserMs is first dashboard-ready performance.now from navigation timeOrigin, not a true interaction latency; readinessObservedHostWallMs includes host polling; snapshotBrowserMs is later.',
        deliveryScope: 'workerDeliveryMs includes serialization, queue, deserialization; phase observations are sampled, not exact boundaries. Worker return envelopes remain backward-compatible.',
        runs: [], cleanups: [], resourceTraces: [], status: 'running'
    };
    try {
        phase = 'provenance';
        const root = fs.realpathSync(rootArgument);
        const input = readDashboardInput(root, selfContained, process.argv.includes('--generated-runtime'), () => loadDashboardSource().dashboardSource);
        const { htmlName, html, fileUrl, resolveAsset, runtime, chart, pako } = input;
        const payloadIdentity = await fingerprintPayload(input.payload);
        phase = 'assets';
        assertRuntimeAsset(chart, 'Chart.js');
        assertRuntimeAsset(pako, 'pako');
        evidence.runtimeMode = input.runtimeMode;
        evidence.runtimeBytes = Buffer.byteLength(runtime);
        evidence.assetHashes = { chart: digest(chart), pako: digest(pako), pdfBundle: digest(input.pdfBundle) };
        Object.assign(evidence, payloadIdentity, { summarySha256: input.summary ? digest(input.summary) : null, htmlSha256: digest(html), runtimeSha256: digest(runtime) });
        let recordSample;
        if (process.argv.includes('--progress-journal')) {
            const requestedJournal = path.resolve(outputArgument + '.progress.jsonl');
            const journal = path.join(fs.realpathSync.native(path.dirname(requestedJournal)), path.basename(requestedJournal));
            const relative = path.relative(root, journal);
            assert(relative && (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)), 'Progress journal must be outside retained inputs.');
            fs.writeFileSync(journal, JSON.stringify({ schema: 'dashboard-progress-v2', status: 'diagnostic-only-not-run-acceptance', htmlSha256: evidence.htmlSha256, payloadSha256: evidence.payloadSha256 }) + '\n', { flag: 'wx' });
            recordSample = sample => {
                const line = JSON.stringify({ kind: 'resource', ...sample, harnessNodeMemory: harnessMemorySample() }) + '\n';
                assert(fs.statSync(journal).size + Buffer.byteLength(line) <= 2 * 1024 ** 2, 'Progress journal exceeded its size bound.');
                fs.appendFileSync(journal, line);
            };
            evidence.progressJournal = { file: path.basename(journal), scope: 'Partial diagnostic samples survive outer termination; this file never establishes run completion or cleanup.' };
        }
        const artifactRoot = path.resolve(outputArgument + '.artifacts');
        if (savedArtifacts) {
            assert(!fs.existsSync(outputArgument) && !fs.existsSync(artifactRoot), 'Artifact acceptance requires a fresh evidence destination.');
            assert(!artifactRoot.startsWith(root + path.sep) && !root.startsWith(artifactRoot + path.sep), 'Evidence must be outside the retained product.');
            fs.mkdirSync(artifactRoot, { recursive: true });
        }
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
        const profileFinalizers = [];
        await withServer(server, evidence, async origin => {
            const selectedBrowser = selectInstalledBrowser();
            const edge = fs.realpathSync.native(selectedBrowser.executable);
            evidence.browserEngine = { engine: selectedBrowser.engine, executable: edge, executableSha256: digest(fs.readFileSync(edge)), qualificationScope: 'Selected installed engine only; other engine acceptance remains separate.' };
            const { chromium } = require(process.env.PLAYWRIGHT_MODULE);
            for (let iteration = 1; iteration <= repeats; iteration++) await measureIteration({ chromium, edge, origin, fileUrl, artifactRoot, evidence, expectedRows, iteration, positiveControl, profileFinalizers, recordSample });
        }, profileFinalizers);
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
    param($ClassName, $Filter, $Property, $ErrorAction)
    $script:calls++
    if ($env:ISSUE70_REUSE -eq 'gone' -and $script:calls -gt 1) { return }
    if ($env:ISSUE70_REUSE -eq 'unknown') { $script:items[0].CommandLine = $null }
    if ($env:ISSUE70_REUSE -eq 'root-shutdown' -and 101 -in $script:killed) { $script:items[0].CommandLine = $null }
    if ($env:ISSUE70_REUSE -eq 'fresh' -and $script:calls -gt 1) {
        $script:items[0].CreationDate = $script:items[0].CreationDate.AddMinutes(1)
        $script:items[0].CommandLine = 'msedge.exe --user-data-dir=C:/neighbor'
    }
    $copy = @($script:items | Select-Object *)
    if ($Filter -and $env:ISSUE70_REUSE -eq 'fresh-root-command') { $copy[0].CommandLine = $null }
    if ($Filter -and $env:ISSUE70_REUSE -eq 'fresh-root-created') { $copy[0].CreationDate = $null }
    if ($Filter -and $env:ISSUE70_REUSE -eq 'fresh-child-created') { $copy[1].CreationDate = $null }
    $copy
}
function Get-Process {
    param($Id, $ErrorAction)
    if ($env:ISSUE70_REUSE -eq 'memory-open-forbidden') { throw 'Inventory must not reopen processes.' }
    $item = $script:items | Where-Object { $_.ProcessId -eq $Id }
    if (-not $item) { return }
    $process = [pscustomobject]@{ Id=$Id; StartTime=$item.CreationDate; PrivateMemorySize64=1; HasExited=$false; SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false} }
    $process | Add-Member ScriptMethod Kill { if ($env:ISSUE70_REUSE -eq 'kill-failure') { throw [ComponentModel.Win32Exception]::new(87) }; $script:killed += $this.Id; $this.HasExited=$true }
    $process | Add-Member ScriptMethod WaitForExit { param($remaining); return $true }
    $process | Add-Member ScriptMethod Dispose { }
    $process
}
`;
    const make = (pid, parent, command, minute = 0) => ({ ProcessId: pid, ParentProcessId: parent, Name: 'msedge.exe', CommandLine: command, CreationDate: `2026-09-30T00:0${minute}:00Z`, WorkingSetSize: 1, PrivatePageCount: 1 });
    let memoryValidationChecked = false;
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
        reuse = 'memory-open-forbidden';
        const memorySnapshot = await owned.inventory();
        assert.strictEqual(memorySnapshot.bytes, 2, 'Working set must use the identity-bound CIM snapshot.');
        assert.strictEqual(memorySnapshot.privateBytes, 2, 'Private memory must use the same CIM snapshot without process opens.');
        reuse = '';
        if (!memoryValidationChecked) {
            for (const field of ['WorkingSetSize', 'PrivatePageCount']) {
                for (const value of [null, '-1', 'invalid', '9223372036854775808']) {
                    items[1][field] = value;
                    await assert.rejects(ownedProcesses(profile, execute).inventory(), error => error.inventoryDiagnostic?.phase === 'memory', 'Invalid owned memory must fail closed.');
                }
                items[1][field] = 1;
            }
            memoryValidationChecked = true;
        }
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
        for (const [mode, category] of [['fresh-root-command', 'rootCommandLine'], ['fresh-root-created', 'rootCreationDate'], ['fresh-child-created', 'processIdentity']]) {
            reuse = mode;
            const receipt = await owned.terminate();
            assert(receipt.skippedUnverified[category] > 0, mode);
            assert(!last.killed.includes(102), 'A child with unverified fresh identity must never be killed.');
            if (mode !== 'fresh-child-created') assert.deepStrictEqual(last.killed, [], 'No kill without fresh root identity.');
            assert(!JSON.stringify(receipt).includes(profile), 'Termination receipt must contain counters only.');
        }
        reuse = 'unknown';
        await assert.rejects(owned.terminate(), error => error.inventoryDiagnostic?.category === 'OperationStopped' && error.inventoryDiagnostic?.exceptionType === 'RuntimeException' && error.inventoryDiagnostic?.exitCode === 1);
        reuse = 'kill-failure';
        await assert.rejects(owned.terminate(), error => error.inventoryDiagnostic?.step === 'kill-exit-check' && error.inventoryDiagnostic?.innerExceptionType === 'Win32Exception' && error.inventoryDiagnostic?.nativeErrorCode === 87);
        reuse = '';
        await assert.rejects(owned.inventory(), /accounting is incomplete/);
        const retained = ownedProcesses(profile, execute);
        await retained.inventory();
        items[0] = make(101, 0, command, 2);
        await assert.rejects(retained.inventory(), /accounting is incomplete/, 'Root PID reuse cannot prove descendant absence.');
        items[0] = make(101, 0, 'msedge.exe --user-data-dir=C:/neighbor', 2);
        await assert.rejects(retained.inventory(), /accounting is incomplete/);
        const unknown = ownedProcesses(profile, execute);
        unknown.setLauncher(401);
        await assert.rejects(unknown.inventory(), error => error.inventoryDiagnostic?.exceptionType === 'RuntimeException');
        items[0] = make(101, 0, command);
        const protectedRoot = ownedProcesses(profile, execute);
        await protectedRoot.inventory();
        items[0].CommandLine = null;
        await assert.rejects(protectedRoot.inventory(), error => error.inventoryDiagnostic?.exceptionType === 'RuntimeException');
    }
    await handleBindingProbes();
    console.log('PASS actual PowerShell argv/profile selection, literal/duplicate/prefix exclusion, independent snapshots, descendants-before-root shutdown race, unexpected native kill rejection, same-profile/fresh root PID reuse, nullable unrelated/PID-zero exclusion, unknown owned root fail-closed.');
}

async function handleBindingProbes() {
    const fixture = `
$script:operations = @(); $script:disposed = 0; $script:wrongKills = 0
$script:created = [datetime]'2026-01-01T00:00:00Z'
$script:items = @([pscustomobject]@{Name='msedge.exe';ProcessId=101;ParentProcessId=0;CreationDate=$script:created;CommandLine=('msedge.exe --user-data-dir="'+$env:ISSUE70_PROFILE+'"');WorkingSetSize=1;PrivatePageCount=1})
function Get-CimInstance { param($ClassName,$Filter,$Property,$ErrorAction) $script:items }
function Get-Process {
 param($Id,$ErrorAction)
 $p=[pscustomobject]@{Id=$Id;Pinned=$false;BoundCreated=$script:created;HasExited=$false}
 $p|Add-Member ScriptProperty SafeHandle {
  $script:operations+='open'
  if($env:HANDLE_CASE-eq'open-failure'){throw [ComponentModel.Win32Exception]::new(5)}
  if($env:HANDLE_CASE-eq'reuse-before-open'){$this.BoundCreated=$this.BoundCreated.AddHours(1)}
  $this.Pinned=$true
  [pscustomobject]@{IsInvalid=($env:HANDLE_CASE-eq'invalid');IsClosed=($env:HANDLE_CASE-eq'closed')}
 }
 $p|Add-Member ScriptProperty StartTime {
  $script:operations+='start'
  if($env:HANDLE_CASE-eq'reuse-after-start'){$script:items=@([pscustomobject]@{Name='unrelated.exe';ProcessId=101;ParentProcessId=0;CreationDate=$script:created.AddHours(1);CommandLine='unrelated';WorkingSetSize=1;PrivatePageCount=1});$this.HasExited=$true}
  $this.BoundCreated
 }
 $p|Add-Member ScriptMethod Kill {
  $script:operations+='kill'
  if(-not $this.Pinned){$script:wrongKills++}
  if($env:HANDLE_CASE-eq'kill-failure'){throw [ComponentModel.Win32Exception]::new(87)}
  $this.HasExited=$true
 }
 $p|Add-Member ScriptMethod WaitForExit {param($remaining) $script:operations+='wait';$env:HANDLE_CASE-ne'wait-failure'}
 $p|Add-Member ScriptMethod Dispose {$script:operations+='dispose';$script:disposed++;if($env:HANDLE_CASE-eq'dispose-failure'){throw 'Synthetic disposal failure'}}
 $p
}
`;
    for (const mode of ['success', 'reuse-after-start', 'reuse-before-open', 'open-failure', 'invalid', 'closed', 'kill-failure', 'wait-failure', 'dispose-failure']) {
        let last;
        const execute = async (script, environment, timeout) => {
            last = await powershell(fixture + '\n$failed=$false; $value=$null; try { $text=. {\n' + script + '\n}; $value=$text|ConvertFrom-Json } catch {$failed=$true}\n@{failed=$failed;value=$value;operations=@($script:operations);disposed=$script:disposed;wrongKills=$script:wrongKills;step=$issue70Step}|ConvertTo-Json -Compress -Depth 8', {...environment,HANDLE_CASE:mode}, timeout || 12000);
            if (last.failed) { const error = new Error('Owned process inventory/termination failed.'); error.inventoryDiagnostic=safeInventoryDiagnostic({phase:'termination',step:last.step}); throw error; }
            return last.value;
        };
        const owned=ownedProcesses('C:/issue70-handle-owned',execute);
        const fails=['open-failure','invalid','closed','kill-failure','wait-failure','dispose-failure'].includes(mode);
        if(fails)await assert.rejects(owned.terminate());else await owned.terminate();
        assert.strictEqual(last.disposed,1,`Process disposal count: ${mode}`);
        assert.strictEqual(last.wrongKills,0,`Unpinned replacement kill: ${mode}`);
        const ops=last.operations;
        assert.strictEqual(ops[0],'open');
        if(['open-failure','invalid','closed'].includes(mode))assert.deepStrictEqual(ops,['open','dispose']);
        if(mode==='reuse-after-start')assert(ops.indexOf('open')<ops.indexOf('start')&&ops.indexOf('start')<ops.indexOf('kill'));
        if(mode==='reuse-before-open')assert(!ops.includes('kill')&&!ops.includes('wait'));
        if(fails)await assert.rejects(owned.inventory(),/accounting is incomplete/);
    }
    console.log('PASS retained-handle binding before StartTime, post-validation PID reuse, handle failures and exact-once disposal');
}

async function cleanupAccountingProbes() {
    // Exercise actual selection, termination and final inventory across snapshots.
    // Only process APIs are mocked; profile deletion uses an owned temporary folder.
    const fixture = `
$script:killed = @()
$script:handles = @()
$script:items = @($env:ISSUE70_FIXTURE | ConvertFrom-Json | ForEach-Object {
    if ($null -ne $_.CreationDate) { $_.CreationDate = [datetime]$_.CreationDate }
    $_
})
function Get-CimInstance {
    param($ClassName, $Filter, $Property, $ErrorAction)
    $copy = @($script:items | Select-Object *)
    if ($Filter -and $Filter.StartsWith('ProcessId=102 ')) {
        ($copy | Where-Object ProcessId -eq 102).CreationDate = $null
    }
    $copy
}
function Get-Process {
    param($Id, $ErrorAction)
    $script:handles += $Id
    $item = $script:items | Where-Object ProcessId -eq $Id
    if (-not $item) { return }
    $process = [pscustomobject]@{ Id=$Id; StartTime=$item.CreationDate; PrivateMemorySize64=1; HasExited=$false; SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false} }
    $process | Add-Member ScriptMethod Kill { $script:killed += $this.Id; $this.HasExited=$true }
    $process | Add-Member ScriptMethod WaitForExit { param($remaining); return $true }
    $process | Add-Member ScriptMethod Dispose { }
    $process
}
`;
    const make = (pid, parent, command, minute = 0) => ({ ProcessId: pid, ParentProcessId: parent, Name: 'msedge.exe', CommandLine: command, CreationDate: `2026-10-24T00:0${minute}:00Z`, WorkingSetSize: 1, PrivatePageCount: 1 });
    for (const mode of ['new-child-orphan', 'known-child-root-reuse', 'child-disappeared', 'child-pid-reused', 'child-identity-unknown', 'orphan-descendant', 'termination-failure']) {
        const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-accounting-'));
        const rootCommand = `msedge.exe --user-data-dir="${profile}"`;
        let items = [make(101, 0, rootCommand), make(201, 0, 'msedge.exe --user-data-dir=C:/neighbor')];
        if (!['new-child-orphan', 'termination-failure'].includes(mode)) items.push(make(102, 101, 'msedge.exe --type=renderer', 1));
        const killed = [];
        const terminationHandles = [];
        let started = false;
        const execute = async (script, environment, timeout) => {
            const terminating = script.includes("$issue70Phase = 'termination'");
            if (terminating && !started) {
                started = true;
                if (['new-child-orphan', 'termination-failure'].includes(mode)) items.push(make(102, 101, 'msedge.exe --type=renderer', 1));
            }
            const response = await powershell(fixture + '\n$result = . {\n' + script + '\n}\n@{ result=($result | ConvertFrom-Json); killed=@($script:killed); handles=@($script:handles) } | ConvertTo-Json -Depth 8 -Compress', { ...environment, ISSUE70_FIXTURE: JSON.stringify(items) }, timeout || 12000);
            killed.push(...response.killed);
            items = items.filter(row => !response.killed.includes(row.ProcessId));
            if (terminating) {
                terminationHandles.push(...response.handles);
                if (mode !== 'new-child-orphan') items.push(make(101, 0, 'msedge.exe --user-data-dir=C:/neighbor', 2));
                if (mode === 'child-disappeared') items = items.filter(row => row.ProcessId !== 102);
                if (mode === 'child-pid-reused') items = items.map(row => row.ProcessId === 102 ? make(102, 0, 'unrelated replacement child', 3) : row);
                if (mode === 'orphan-descendant') items.push(make(103, 102, 'msedge.exe --type=renderer', 2));
                if (mode === 'termination-failure') throw new Error('Synthetic failure after partial termination.');
                if (mode === 'child-identity-unknown') items.find(row => row.ProcessId === 102).CreationDate = null;
            }
            return response.result;
        };
        try {
            const owned = ownedProcesses(profile, execute);
            await owned.inventory();
            const cleanup = await cleanupOwned({ profile, owned });
            assert.deepStrictEqual(killed, [101], `${mode}: never kill skipped child or unrelated/reused root`);
            assert.deepStrictEqual(terminationHandles, [101], `${mode}: no unverified process handle`);
            assert(items.some(row => row.ProcessId === 201), 'Neighbor must survive.');
            if (mode === 'termination-failure') assert(cleanup.errors.includes('Owned family termination'));
            else assert.strictEqual(cleanup.termination.skippedUnverified.processIdentity, 1);
            assert.strictEqual(cleanup.profileExists, true, mode);
            assert.strictEqual(fs.existsSync(profile), true, mode);
            assert.strictEqual(cleanup.remainingOwned, null, mode);
            assert(cleanup.errors.includes('Final owned inventory'), mode);
            // Even actual disappearance/PID reuse cannot prove no unseen child was born.
            if (!['child-disappeared', 'child-pid-reused'].includes(mode)) assert(items.some(row => row.ProcessId === 102), mode);
        } finally { fs.rmSync(profile, { recursive: true, force: true }); }
    }
    console.log('PASS integrated cleanup accounting: newly discovered orphan, known child/root reuse, actual disappearance, own-PID reuse, uncertain final identity; unverified handles/kills excluded and neighbor preserved.');
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

async function measurementControlProbes() {
    const journalError = new Error('Synthetic one-shot diagnostic write failure');
    let journalKills = 0;
    const journalGuard = new ResourceGuard({ inventory: async () => ({ bytes: 0, pids: [] }), terminate: async () => { journalKills++; },
        freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    assert.throws(() => writeBrowserDiagnostic(journalGuard, () => { throw journalError; }, { kind: 'browser-heap' }), error => error === journalError);
    // A later successful append cannot turn a partially failed journal into a pass.
    writeBrowserDiagnostic(journalGuard, () => {}, { kind: 'browser-heap' });
    await assert.rejects(journalGuard.wait(Promise.resolve()), error => error === journalError);
    const journalRun = { status: 'running' };
    await assert.rejects(completeRun(journalRun, journalGuard, () => {}), error => error === journalError);
    assert.strictEqual(journalRun.status, 'failed');
    await journalGuard.stop();
    assert.strictEqual(journalKills, 1);
    const diagnosticSentinel = 'synthetic-private-row-content';
    const compact = compactReadinessSample({ instrumentationPresent: true, readyEventSeen: false, dashboardReady: false,
        phases: [...Array.from({ length: 1000 }, (_, durationMs) => ({ name: 'workerParseMs', durationMs })),
            { name: diagnosticSentinel, durationMs: 1 }, { name: 'denormalizeMs', durationMs: NaN }],
        initialization: [{ name: 'init', status: 'running', error: diagnosticSentinel }, { name: diagnosticSentinel, status: 'completed' }],
        workerMessages: [{ data: diagnosticSentinel }], filtersApplied: -1, activeReportRenders: 0, documentReadyState: diagnosticSentinel });
    assert.deepStrictEqual(compact.phases, { workerParseMs: 999 });
    assert.deepStrictEqual(compact.initialization, { init: 'running' });
    assert.strictEqual(compact.filtersApplied, null);
    assert.strictEqual(compact.activeReportRenders, 0);
    assert.strictEqual(compact.documentReadyState, null);
    assert.strictEqual(compactReadinessSample(null), null);
    assert(!JSON.stringify(compact).includes(diagnosticSentinel), 'Partial diagnostics must not copy row content or arbitrary strings.');
    assert(Buffer.byteLength(JSON.stringify(compact)) < 2048, 'Diagnostic size must not grow with phase history.');
    assert(Object.values(harnessMemorySample()).every(value => Number.isSafeInteger(value) && value >= 0));
    const checkpoint = { name: 'admin-pdf', state: 'start', report: REPORTS[0], browserMs: 1, epochMs: 2, privateRow: diagnosticSentinel };
    const checkpointText = value => 'ISSUE70_CHECKPOINT:' + JSON.stringify(value);
    assert(!JSON.stringify(readDiagnosticCheckpoint(checkpointText(checkpoint))).includes(diagnosticSentinel));
    for (const value of [{ ...checkpoint, name: diagnosticSentinel }, { ...checkpoint, state: 'unknown' },
        { ...checkpoint, report: diagnosticSentinel }, { ...checkpoint, browserMs: -1 }, { ...checkpoint, epochMs: null }]) {
        assert.strictEqual(readDiagnosticCheckpoint(checkpointText(value)), null);
    }
    assert(!Object.hasOwn(readDiagnosticCheckpoint(checkpointText(checkpoint)), 'counts'));
    assert.deepStrictEqual(readDiagnosticCheckpoint(checkpointText({ ...checkpoint, counts: { sourceRows: 2147483647, reportRows: 0 } })).counts,
        { sourceRows: 2147483647, reportRows: 0 });
    for (const counts of [null, [], {}, { privateRow: diagnosticSentinel }, { sourceRows: diagnosticSentinel },
        { sourceRows: -1 }, { sourceRows: 1.5 }, { sourceRows: 2147483648 }, { sourceRows: null },
        { sourceRows: 2, unexpected: 1 }]) assert.strictEqual(readDiagnosticCheckpoint(checkpointText({ ...checkpoint, counts })), null);
    for (const name of ['admin-pdf-header', 'admin-pdf-buffer']) for (const state of ['start', 'completed', 'failed'])
        assert.strictEqual(readDiagnosticCheckpoint(checkpointText({ ...checkpoint, name, state })).state, state);
    assert.strictEqual(readDiagnosticCheckpoint('ISSUE70_CHECKPOINT:{'), null);
    assert.strictEqual(readDiagnosticCheckpoint('x'.repeat(1025)), null);
    assert.strictEqual(readDiagnosticCheckpoint(diagnosticSentinel), null);
    console.log('PASS diagnostic write failure prevents acceptance, bounded phases, absent-versus-zero observations, content exclusion and separate Node memory');
    const timingCallbacks = {};
    const timingMetrics = { phases: {} };
    const timingResult = {};
    const timingError = new Error('Synthetic operation failure');
    const timingReceiver = {};
    let timingNow = 0;
    let timingSample;
    let recordingFails = false;
    const timingContext = {
        performance: { now: () => timingNow, timeOrigin: 0 },
        setInterval(callback) { timingSample = callback; },
        getDashboardMetricsSnapshot: () => timingMetrics,
        recordDashboardPhaseTiming(name, value) {
            if (recordingFails) throw new Error('Synthetic instrumentation failure');
            timingMetrics.phases[name] = value;
        },
        window: {
            addEventListener(name, callback) { timingCallbacks[name] = callback; }, Worker: class {},
            async getCachedData(...args) {
                assert.strictEqual(this, timingReceiver);
                assert.strictEqual(args[1], timingResult);
                await Promise.resolve(); timingNow += 5;
                if (args[0] === 'failure') throw timingError;
                return timingResult;
            },
            applyDerivedVulnerabilityFields(...args) {
                assert.strictEqual(this, timingReceiver);
                assert.strictEqual(args[1], timingResult);
                timingNow += 7;
                if (args[0] === 'failure') throw timingError;
                return timingResult;
            }
        }
    };
    require('vm').runInNewContext(`(${installInstrumentation.toString()})()`, timingContext);
    timingCallbacks.DOMContentLoaded();
    assert.strictEqual(await timingContext.window.getCachedData.call(timingReceiver, 'success', timingResult), timingResult);
    await assert.rejects(timingContext.window.getCachedData.call(timingReceiver, 'failure', timingResult), error => error === timingError);
    assert.strictEqual(timingContext.window.applyDerivedVulnerabilityFields.call(timingReceiver, 'success', timingResult), timingResult, 'Derived instrumentation must remain synchronous.');
    assert.throws(() => timingContext.window.applyDerivedVulnerabilityFields.call(timingReceiver, 'failure', timingResult), error => error === timingError);
    assert.strictEqual(timingMetrics.phases.cacheReadMs, 5);
    assert.strictEqual(timingMetrics.phases.cacheDerivedMs, 7);
    timingSample();
    assert.deepStrictEqual(Array.from(timingContext.window.__issue70.phases, record => record.name).sort(), ['cacheDerivedMs', 'cacheReadMs']);
    recordingFails = true;
    assert.strictEqual(await timingContext.window.getCachedData.call(timingReceiver, 'success', timingResult), timingResult);
    await assert.rejects(timingContext.window.getCachedData.call(timingReceiver, 'failure', timingResult), error => error === timingError);
    assert.strictEqual(timingContext.window.applyDerivedVulnerabilityFields.call(timingReceiver, 'success', timingResult), timingResult);
    assert.throws(() => timingContext.window.applyDerivedVulnerabilityFields.call(timingReceiver, 'failure', timingResult), error => error === timingError);
    console.log('PASS actual cache read/derived instrumentation preserves async/sync results, receiver, arguments, errors and allowlisted phase capture');
    const checkpointEvents = [];
    let checkpointReady;
    let consoleFails = false;
    const checkpointContext = {
        console: { debug(text) { if (consoleFails) throw new Error('Synthetic console failure'); checkpointEvents.push(readDiagnosticCheckpoint(text)); } },
        performance: { now: () => 10, timeOrigin: 100 }, setInterval() {},
        window: { addEventListener(name, callback) { if (name === 'DOMContentLoaded') checkpointReady = callback; },
            Worker: class { addEventListener(name, callback) { this.message = callback; } },
            async init(value) { if (value === 'failure') throw timingError; return timingResult; } }
    };
    require('vm').runInNewContext(`(${installInstrumentation.toString()})({ progressJournal: true })`, checkpointContext);
    checkpointReady();
    assert.strictEqual(await checkpointContext.window.init('success'), timingResult);
    await assert.rejects(checkpointContext.window.init('failure'), error => error === timingError);
    assert.deepStrictEqual(checkpointEvents.map(row => [row.name, row.state]),
        [['init', 'start'], ['init', 'completed'], ['init', 'start'], ['init', 'failed']]);
    const diagnosticWorker = new checkpointContext.window.Worker();
    diagnosticWorker.message({ data: { phase: 'workerParseMs', duration: 5 } });
    diagnosticWorker.message({ data: { rows: null, lookups: {}, rawVulns: {} } });
    assert.deepStrictEqual(checkpointEvents.slice(-2).map(row => row.name), ['workerParseMs', 'worker-delivery']);
    assert(checkpointEvents.every(row => !Object.hasOwn(row, 'counts')), 'Existing checkpoint shape must remain unchanged.');
    checkpointContext.window.__issue70.checkpoint('admin-pdf', 'start', REPORTS[0], null, { sourceRows: 2, reportRows: 1 });
    assert.deepStrictEqual(checkpointEvents.at(-1).counts, { sourceRows: 2, reportRows: 1 }, 'The actual fifth checkpoint argument must survive the sanitized console boundary.');
    consoleFails = true;
    assert.strictEqual(await checkpointContext.window.init('success'), timingResult, 'Console diagnostics must not alter initialization.');
    console.log('PASS opt-in initialization/worker checkpoints survive partial runs without changing return values or errors');
    await require('./Assert-DashboardArtifactAcceptance').run();
    const installed = { ProgramFiles: 'C:/Installed' };
    const edgeChoice = selectInstalledBrowser(installed, candidate => candidate.endsWith('msedge.exe'));
    assert.strictEqual(edgeChoice.engine, 'edge');
    const chromeChoice = selectInstalledBrowser({ ...installed, DASHBOARD_BROWSER_ENGINE: 'chrome' }, candidate => candidate.endsWith('chrome.exe'));
    assert.strictEqual(chromeChoice.engine, 'chrome');
    assert.throws(() => selectInstalledBrowser({ ...installed, DASHBOARD_BROWSER_ENGINE: 'chrome' }, candidate => candidate.endsWith('msedge.exe')), /unavailable/);
    assert.throws(() => selectInstalledBrowser({ ...installed, DASHBOARD_BROWSER_ENGINE: 'custom' }, () => true), /Unsupported/);
    console.log('PASS installed engine choice, missing Chrome fails without Edge fallback, unknown engine rejected');
    const readiness = { activeReportId: 'active-vulnerabilities', initializedReports: new Set(['active-vulnerabilities']), dirtyReports: new Set(), busy: false, active: true };
    readiness.document = { getElementById: () => ({ classList: { contains: () => readiness.active }, getAttribute: () => readiness.busy ? 'true' : null }) };
    const reportReady = require('vm').runInNewContext(`(${isReportReady.toString()})`, readiness);
    assert.strictEqual(reportReady('active-vulnerabilities'), true);
    readiness.dirtyReports.add('active-vulnerabilities');
    assert.strictEqual(reportReady('active-vulnerabilities'), false, 'Old render must not satisfy a dirty report switch.');
    readiness.dirtyReports.clear(); readiness.busy = true;
    assert.strictEqual(reportReady('active-vulnerabilities'), false, 'Deferred render must finish before a switch is timed.');
    readiness.busy = false; readiness.active = false;
    assert.strictEqual(reportReady('active-vulnerabilities'), false);
    const admin = { restored: true, representativeRows: 2, pdfLibrarySourceRows: 2, reports: ['representative', 'empty'].flatMap(scope => REPORTS.map(report => {
        const modal = scope === 'representative' && ['active-vulnerabilities', 'impact-analysis', 'remediation-activity'].includes(report);
        return { scope, report, sourceRows: scope === 'empty' ? 0 : 2, reportRows: scope === 'empty' ? 0 : 2, summaryCards: { high: scope === 'empty' ? '0' : '2' }, switchMs: 1,
            detailKind: scope === 'empty' ? 'empty-scope' : modal ? 'modal' : 'inline-card',
            detailMs: modal ? 1 : null, scopedFilterMs: 1, pdfPreparationMs: 1,
            pdf: { bytes: 101, sha256: 'a'.repeat(64) } };
    })) };
    assertAdminExercise(admin);
    assert.throws(() => measurementWorkflow(['--scoped-admin-first']), /requires/);
    assert.throws(() => measurementWorkflow(['--scoped-admin-first', '--admin-exercise', '--saved-artifacts']), /separate/);
    for (const lane of ['--admin-exercise', '--saved-artifacts']) assert.strictEqual(measurementWorkflow(['--scoped-admin-first', lane]).scopedAdminFirst, true);
    assert.strictEqual(measurementWorkflow([]).scopedAdminFirst, false);
    const scopedRun = { scopedAdminFirst: true, workload: measurementWorkflow(['--scoped-admin-first', '--admin-exercise']).workload,
        reportSwitches: [], adminExercise: admin };
    recordScopedExercise(scopedRun, false);
    assert.deepStrictEqual(scopedRun.reportIds, [...REPORTS].sort());
    assert.strictEqual(scopedRun.impactRows, 2);
    assert.strictEqual(scopedRun.readinessCacheDigest, null);
    const reordered = structuredClone(admin); reordered.reports.reverse();
    assert.deepStrictEqual(summarizeScopedExercise(reordered, false), scopedRun.scopedWorkloadSummary);
    for (const mutate of [result => result.reports.pop(), result => { result.reports[0].report = 'wrong'; },
        result => { result.reports[0].sourceRows = 3; }, result => { delete result.reports[0].reportRows; },
        result => { result.reports[5].reportRows = 1; }, result => { result.reports[5].summaryCards.high = '1'; },
        result => { result.restored = false; }]) {
        const invalid = structuredClone(admin); mutate(invalid);
        assert.throws(() => summarizeScopedExercise(invalid, false));
    }
    const changedRows = structuredClone(admin); changedRows.reports[0].reportRows = 1;
    assert.notDeepStrictEqual(summarizeScopedExercise(changedRows, false), scopedRun.scopedWorkloadSummary);
    const scopedCold = { ...structuredClone(scopedRun), compressedFingerprint: 'runtime_fixture',
        snapshot: { rows: 2, rawRows: 2, activeRows: 2, counts: {}, summaryCards: { high: '2' } },
        cachePolicy: { eligible: true, available: true, maxRowsExclusive: 500000, maxEntries: 4 },
        cacheEntries: { matchingRows: 2, count: 1 }, externalRequests: 0, pageErrors: 0 };
    assertRun(scopedCold, 2);
    const scopedWarm = structuredClone(scopedCold); scopedWarm.snapshot.counts.compressedCacheHits = 1;
    assertRun(scopedWarm, 2, scopedCold);
    for (const mutate of [value => { value.reportSwitches.push({ report: REPORTS[0], completedHostWallMs: 1 }); },
        value => { value.readinessCacheDigest = 'invented-full-tour'; }, value => { value.reportRows[REPORTS[0]]++; },
        value => { value.impactRows++; }, value => { value.scopedWorkloadSummary.steps[0].sourceRows++; },
        value => { value.scopedWorkloadDigest = 'invented'; }]) {
        const invalid = structuredClone(scopedCold); mutate(invalid); assert.throws(() => assertRun(invalid, 2));
    }
    for (const key of ['reportRows', 'summaryCards']) {
        const changed = structuredClone(scopedWarm);
        if (key === 'reportRows') changed.adminExercise.reports[0].reportRows = 1;
        else changed.adminExercise.reports[0].summaryCards.high = '1';
        recordScopedExercise(changed, false);
        assert.throws(() => assertRun(changed, 2, scopedCold), /scoped source\/report\/card counts differ/);
    }
    const saved = { status: 'captured', restored: true, representativeRows: 2, runtimePreloadSourceRows: 2,
        uiExercise: { status: 'exercised', path: 'locator-facet-click-check-apply', selectedFacet: 'filterSeverity', deselectionRows: 0,
            hiddenSelection: { status: 'unavailable-fixture-intersection' } },
        reports: admin.reports.concat(['devices-by-remediation', 'remediations-by-device'].map(report => ({ scope: 'representative-range', report, sourceRows: 2, reportRows: 2, summaryCards: { high: '2' } }))).map(row => {
            const device = ['devices-by-remediation', 'remediations-by-device'].includes(row.report);
            const mode = row.scope === 'representative-range' ? 'range' : 'snapshot';
            const before = { report: row.report, reportLabel: row.report, sourceRows: row.sourceRows, reportRows: row.reportRows,
                cards: row.summaryCards, expandedText: 'Synthetic exact report text', mode,
                modeSummary: device ? 'Synthetic mode summary' : null, includeResolvedText: device ? mode === 'range' ? 'Yes' : 'No' : null,
                cardDetails: device ? Array.from({ length: row.reportRows }, () => ({ title: 'Synthetic card', metadata: ['Patch: KB1'], statBadges: ['Devices: 1'] })) : [] };
            const file = { bytes: 150, sha256: 'a'.repeat(64) };
            return { scope: row.scope, report: row.report, before, after: structuredClone(before),
                modeAction: device ? { mode, path: 'shared-toolbar-button', action: 'clicked' } : null,
                pdf: { ...file, suggestedFilename: `Vulnerability_Dashboard_${row.report}_2026-11-06.pdf`, exportUtcDayBefore: '2026-11-06', exportUtcDayAfter: '2026-11-06' },
                screenshot: file, receipt: file };
        }) };
    const savedSummary = summarizeScopedExercise(saved, true);
    assert.strictEqual(savedSummary.steps.length, 12);
    assert.strictEqual(savedSummary.steps.filter(step => step.scope === 'representative-range' && step.mode === 'range').length, 2);
    for (const mutate of [value => { value.reports.pop(); }, value => { value.reports[0].before.report = 'wrong'; },
        value => { value.reports[0].before.sourceRows = value.reports[0].after.sourceRows = 3; },
        value => { delete value.reports[0].before.cards; delete value.reports[0].after.cards; },
        value => { value.reports[5].before.reportRows = value.reports[5].after.reportRows = 1; },
        value => { value.reports[5].before.cards.high = value.reports[5].after.cards.high = '1'; }]) {
        const invalid = structuredClone(saved); mutate(invalid); assert.throws(() => summarizeScopedExercise(invalid, true));
    }
    console.log('PASS scoped-first dependencies, both helper receipt summaries, full-tour claim rejection and cold/reload source/report/card consistency controls');
    // Execute the actual serialized page helper with a modeled page boundary;
    // this proves workflow ordering/restoration, not browser or PDF acceptance.
    for (const fault of [null, 'disabled', 'runtime', 'libraries', 'oversize', 'header', 'buffer']) {
        const events = [];
        const failure = new Error('Synthetic preparation failure');
        const originalDownload = async () => {};
        const headerThis = {};
        const headerArgument = {};
        const headerResult = {};
        const originalHeader = async function(argument) {
            assert.strictEqual(this, headerThis);
            assert.strictEqual(argument, headerArgument);
            if (fault === 'header') throw failure;
            return headerResult;
        };
        const diagnostics = [];
        const originalState = { deviceNames: [], hasDeviceNames: true, severities: [], hasSeverities: true };
        const source = fault === 'oversize' ? Array.from({ length: 251 }, () => ({ id: 'a' })) : [{ id: 'a' }, { id: 'a' }, { id: 'b' }];
        let clock = 0;
        const context = {
            filterState: structuredClone(originalState), filteredData: source, activeReportId: 'active-vulnerabilities', remediationReportMode: 'snapshot',
            initializedReports: new Set(REPORTS), dirtyReports: new Set(), window: { ...(fault === 'disabled' ? {} : { __issue70: { checkpoint: (name, state, report, duration, counts) => diagnostics.push({ name, state, report, counts }) } }), ...(fault === 'libraries' ? { __skipPdfExportPageWarning: false } : {}) },
            cloneFilterState: state => structuredClone(state), finalizeFilterState: state => state,
            getDeviceNameFilterValue: row => row.id, performance: { now: () => ++clock },
            requestAnimationFrame: callback => queueMicrotask(callback), setTimeout, clearTimeout,
            crypto: crypto.webcrypto, pdfExportInProgress: false, closeModal() {},
            document: { getElementById: id => ({
                classList: { contains: () => id === context.activeReportId + '-section' },
                getAttribute: () => null, querySelector: () => null
            }) },
            applyFilters() {
                context.filteredData = !context.filterState.hasSeverities ? [] : source.filter(row => !context.filterState.deviceNames.length || context.filterState.deviceNames.includes(row.id));
                events.push('apply:' + context.filteredData.length);
            },
            get remediationAllData() { return context.filteredData; },
            get impactAnalysisAllData() { return context.filteredData; },
            get remediationDetailsAllData() { return context.filteredData; },
            get devicesByRemediationAllData() { return context.filteredData; },
            get remediationsByDeviceAllData() { return context.filteredData; },
            buildDashboardValidationSnapshot: () => ({ summaryCards: { high: String(context.filteredData.length) } }),
            selectReportById: report => { context.activeReportId = report; },
            async ensurePdfExportRuntimeLoaded() {
                events.push('runtime:' + context.filteredData.length);
                assert(context.filteredData.length > 0 && context.filteredData.length <= 250);
                context.remediationReportMode = 'range'; // Failure cleanup must restore the saved mode too.
                if (fault === 'runtime') throw failure;
                context.downloadPdfDocument = originalDownload;
                context.capturePdfHeaderImage = originalHeader;
            },
            async loadPdfLibraries() {
                events.push('libraries:' + context.filteredData.length);
                assert(context.filteredData.length > 0 && context.filteredData.length <= 250);
                if (fault === 'libraries') throw failure;
            },
            async exportToPDF() {
                if (fault === 'disabled') assert.strictEqual(context.capturePdfHeaderImage, originalHeader);
                assert.strictEqual(await context.capturePdfHeaderImage.call(headerThis, headerArgument), headerResult);
                await context.downloadPdfDocument({ getBuffer: done => {
                    if (fault === 'buffer') throw failure;
                    done(Buffer.from('%PDF-synthetic\n' + 'x'.repeat(110) + '\n%%EOF'));
                } });
            }
        };
        const operation = exerciseAdmin({ evaluate: script => require('vm').runInNewContext(script, context) }, { wait: promise => promise }, 1000);
        if (fault === 'oversize') await assert.rejects(operation, /1-250/);
        else if (fault && fault !== 'disabled') await assert.rejects(operation, error => error === failure);
        else {
            const result = await operation;
            assertAdminExercise(result);
            assert.strictEqual(result.pdfLibrarySourceRows, 2);
        }
        if (fault === 'disabled') assert.deepStrictEqual(diagnostics, []);
        assert.strictEqual(context.capturePdfHeaderImage, fault === 'runtime' || fault === 'oversize' ? undefined : originalHeader);
        if (!fault || fault === 'header' || fault === 'buffer') {
            const starts = diagnostics.filter(row => row.name === 'admin-pdf' && row.state === 'start');
            assert.strictEqual(starts[0].counts.sourceRows, 2);
            assert.strictEqual(starts[0].counts.reportRows, 2);
            const header = diagnostics.filter(row => row.name === 'admin-pdf-header');
            assert.deepStrictEqual(header.slice(0, 2).map(row => row.state), ['start', fault === 'header' ? 'failed' : 'completed']);
            const buffer = diagnostics.filter(row => row.name === 'admin-pdf-buffer');
            if (fault === 'header') assert.strictEqual(buffer.length, 0);
            else assert.deepStrictEqual(buffer.slice(0, 2).map(row => row.state), ['start', fault === 'buffer' ? 'failed' : 'completed']);
        }
        assert.deepStrictEqual(context.filterState, originalState);
        assert.strictEqual(context.activeReportId, 'active-vulnerabilities');
        assert.strictEqual(context.remediationReportMode, 'snapshot');
        assert.strictEqual(Object.hasOwn(context.window, '__skipPdfExportPageWarning'), fault === 'libraries');
        if (fault === 'libraries') assert.strictEqual(context.window.__skipPdfExportPageWarning, false);
        assert.strictEqual(context.downloadPdfDocument, fault === 'runtime' || fault === 'oversize' ? undefined : originalDownload);
        if (fault === 'oversize') assert(!events.some(event => event.startsWith('runtime:') || event.startsWith('libraries:')));
        else {
            assert.strictEqual(events[0], 'apply:2');
            assert.strictEqual(events[1], 'runtime:2');
            if (fault !== 'runtime') assert.strictEqual(events[2], 'libraries:2');
        }
    }
    console.log('PASS serialized admin scope-before-library ordering, opt-in PDF header/buffer diagnostics, exact scope counts, result/error preservation and all failure restorations');
    const invalidAdmin = structuredClone(admin); invalidAdmin.reports[5].sourceRows = 1;
    assert.throws(() => assertAdminExercise(invalidAdmin));
    const duplicateAdmin = structuredClone(admin); duplicateAdmin.reports[1] = duplicateAdmin.reports[0];
    assert.throws(() => assertAdminExercise(duplicateAdmin));
    const missingDetailTime = structuredClone(admin); missingDetailTime.reports[0].detailMs = null;
    assert.throws(() => assertAdminExercise(missingDetailTime));
    const inventedDetailTime = structuredClone(admin); inventedDetailTime.reports[5].detailMs = 1;
    assert.throws(() => assertAdminExercise(inventedDetailTime));
    const broadenedScope = structuredClone(admin); broadenedScope.reports[0].sourceRows = 3;
    assert.throws(() => assertAdminExercise(broadenedScope));
    const mislabeledScope = structuredClone(admin); mislabeledScope.reports[0].detailKind = 'empty-scope';
    mislabeledScope.reports[0].detailMs = null;
    assert.throws(() => assertAdminExercise(mislabeledScope));
    const wrongDetailType = structuredClone(admin); wrongDetailType.reports[0].detailKind = 'inline-card';
    wrongDetailType.reports[0].detailMs = null;
    assert.throws(() => assertAdminExercise(wrongDetailType));
    console.log('PASS actual switch readiness rejects stale/dirty/deferred/inactive sections and admin evidence rejects broadened empty/duplicate reports');
    const timers = new Map();
    let timerId = 0;
    const boundedBuffer = require('vm').runInNewContext(`(${getPdfBuffer.toString()})`, {
        setTimeout(callback) { timers.set(++timerId, callback); return timerId; },
        clearTimeout(id) { timers.delete(id); }
    });
    let callback;
    const success = boundedBuffer({ getBuffer(resolve) { callback = resolve; } }, 25);
    assert.strictEqual(timers.size, 1);
    const bytes = Buffer.from('%PDF-synthetic');
    callback(bytes);
    assert.strictEqual(await success, bytes);
    assert.strictEqual(timers.size, 0, 'Successful PDF callback must clear its timer.');
    await assert.rejects(boundedBuffer({ getBuffer() { throw new Error('Synthetic layout failure'); } }, 25), /Synthetic layout failure/);
    assert.strictEqual(timers.size, 0, 'Synchronous PDF failure must clear its timer.');
    await assert.rejects(boundedBuffer({ getBuffer() { return Promise.reject(new Error('Synthetic asynchronous failure')); } }, 25), /Synthetic asynchronous failure/);
    assert.strictEqual(timers.size, 0, 'Asynchronous PDF failure must clear its timer.');
    const timeout = boundedBuffer({ getBuffer() {} }, 25);
    assert.strictEqual(timers.size, 1);
    timers.values().next().value();
    await assert.rejects(timeout, /callback did not complete/);
    assert.strictEqual(timers.size, 0, 'Expired PDF deadline must clear its timer.');
    for (const invalid of [0, -1, NaN, 120001]) await assert.rejects(boundedBuffer({ getBuffer() {} }, invalid), /Invalid PDF callback deadline/);
    assert.strictEqual(timers.size, 0);
    console.log('PASS serialized PDF buffer wrapper handles success, synchronous/asynchronous failure and missing callbacks with no pending deadline timer');
}

async function mockProbes() {
    await measurementControlProbes();
    const runtime = loadDashboardHarness('module.exports = { computeCompressedFingerprint };');
    const bytes = new Uint8Array([1, 2, 3]);
    const actualKey = await runtime.computeCompressedFingerprint(bytes);
    const callbacks = {};
    let calls = 0;
    const context = { performance, setInterval() {}, window: {
        Worker: class {}, addEventListener(name, callback) { callbacks[name] = callback; },
        async computeCompressedFingerprint(input) {
            assert.strictEqual(this, context.window);
            assert.strictEqual(input, bytes);
            calls++;
            return actualKey;
        }
    } };
    require('vm').runInNewContext(`(${installInstrumentation.toString()})()`, context);
    callbacks.DOMContentLoaded();
    assert.strictEqual(await context.window.computeCompressedFingerprint(bytes), actualKey);
    assert.strictEqual(calls, 1);
    assert.strictEqual(requireCapturedFingerprint(context.window.__issue70.compressedFingerprints), actualKey);
    for (const values of [undefined, [], [''], ['a', 'b'], ['private/path'], [null]]) assert.throws(() => requireCapturedFingerprint(values));
    const rejection = new Error('fixture');
    const rejectedCallbacks = {};
    const rejected = { performance, setInterval() {}, window: { Worker: class {}, addEventListener(name, callback) { rejectedCallbacks[name] = callback; }, async computeCompressedFingerprint() { throw rejection; } } };
    require('vm').runInNewContext(`(${installInstrumentation.toString()})()`, rejected);
    rejectedCallbacks.DOMContentLoaded();
    await assert.rejects(rejected.window.computeCompressedFingerprint(bytes), error => error === rejection);
    assert.strictEqual(rejected.window.__issue70.compressedFingerprints.length, 0);
    console.log('PASS actual runtime fingerprint capture, invocation identity, rejection, and missing/ambiguous key guards.');
    await privacyProbes();
    if (process.platform === 'win32') { await ownershipProbes(); await cleanupAccountingProbes(); }
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
    const valid = { compressedFingerprint: 'runtime_fixture', snapshot: { rows: 2, rawRows: 2, activeRows: 2, counts: {}, summaryCards: { high: '2' } }, reportIds: [...REPORTS].sort(), impactRows: 2, readinessCacheDigest: 'fixture', cachePolicy: { eligible: true, available: true, maxRowsExclusive: 500000, maxEntries: 4 }, cacheEntries: { matchingRows: 2, count: 2 }, externalRequests: 0, pageErrors: 0 };
    assertRun(valid, 2);
    const positive = { ...valid, positiveControl: true, controlObservation: { filteredSourceRows: 2, selectedRows: 2, impactRows: 2, cardTotal: 2, dateRange: '2026-01-01/2026-01-02' } };
    assertRun(positive, 2);
    for (const key of ['filteredSourceRows', 'selectedRows', 'impactRows', 'cardTotal']) {
        for (const value of [0, 1, 3]) assert.throws(() => assertRun({ ...positive, controlObservation: { ...positive.controlObservation, [key]: value } }, 2));
    }
    assert.throws(() => assertRun({ ...positive, controlObservation: { ...positive.controlObservation, dateRange: '2026-01-01/2026-01-03' } }, 2));
    assert.throws(() => assertRun({ ...valid, compressedFingerprint: 'different', snapshot: { ...valid.snapshot, counts: { compressedCacheHits: 1 } } }, 2, valid), /fingerprint differs/);
    assert.throws(() => assertRun({ ...valid, snapshot: { ...valid.snapshot, rows: 0 } }, 2), /row count/);
    assert.throws(() => assertRun({ ...valid, snapshot: { ...valid.snapshot, counts: {} } }, 2, valid), /must hit cache/);
    assertRun({ ...valid, snapshot: { ...valid.snapshot, counts: { compressedCacheHits: 1 } } }, 2, valid);
    const failedFinal = new ResourceGuard({ inventory: async () => { throw new Error('final inventory failed'); }, terminate: async () => { kills++; }, freeMemory: () => 3, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 } });
    const failedRun = { status: 'running' };
    await assert.rejects(completeRun(failedRun, failedFinal, () => {}), /final inventory failed/);
    await failedFinal.stop();
    assert.strictEqual(failedRun.status, 'failed');
    let sampleClock = 0;
    const TimedGuard = require('vm').runInNewContext(`(${ResourceGuard.toString()})`, { performance: { now: () => sampleClock }, assert });
    const timed = new TimedGuard({
        inventory: async () => { sampleClock = 11; return { bytes: 1, pids: [] }; },
        freeMemory: () => { sampleClock = 31; return 3; }, terminate: async () => {}, limits: { browserFamilyBytes: 2, freeMemoryBytes: 2 }
    });
    await timed.sample('timing-boundaries');
    assert.strictEqual(timed.trace[0].inventoryStartedAtHostMs, 0);
    assert.strictEqual(timed.trace[0].inventoryCompletedAtHostMs, 11);
    assert.strictEqual(timed.trace[0].validatedAtHostMs, 31);
    assert.strictEqual(timed.trace[0].sampledAtHostMs, 31);
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
    const skipReceipt = { stoppedCount: 0, skippedUnverified: { processIdentity: 0, rootCommandLine: 2, rootCreationDate: 0 } };
    for (const survivors of [[123], []]) {
        const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-skip-'));
        try {
            const cleanup = await cleanupOwned({ profile, owned: { terminate: async () => skipReceipt, inventory: async () => ({ pids: survivors }) } });
            assert.deepStrictEqual(cleanup.termination, skipReceipt);
            assert.strictEqual(cleanup.remainingOwned, survivors.length);
            assert.strictEqual(cleanup.profileExists, survivors.length > 0);
            if (survivors.length) assert(cleanup.errors.includes('Final owned inventory'));
            else assert.deepStrictEqual(cleanup.errors, []);
        } finally { fs.rmSync(profile, { recursive: true, force: true }); }
    }
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

module.exports = { mockProbes, ownershipProbes, privacyProbes, inventoryProbes, safeFailure, measurementControlProbes };
if (require.main === module) (process.argv.includes('--privacy') ? privacyProbes() : process.argv.includes('--ownership') ? ownershipProbes() : process.argv.includes('--mock') ? mockProbes() : main()).catch(error => { console.error(JSON.stringify({ status: 'blocked-or-failed', failure: safeFailure(error, process.argv.includes('--mock') || process.argv.includes('--ownership') || process.argv.includes('--privacy') ? 'preflight' : 'arguments') })); process.exitCode = 1; });
