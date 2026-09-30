const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');
const { performance } = require('perf_hooks');
const { loadDashboardSource } = require('./helpers/dashboard-test-harness');

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
                this.trace.push({ stage, startedAtHostMs: startedAt, sampledAtHostMs: performance.now(), sampledAtEpochMs: Date.now(), browserFamilyBytes: inventory.bytes, freeMemoryBytes: freeBytes, ownedProcessCount: inventory.pids.length });
                assert(inventory.bytes <= this.limits.browserFamilyBytes, 'Browser family memory cap exceeded.');
                assert(freeBytes >= this.limits.freeMemoryBytes, 'Safety memory floor prevents launch or continuation.');
                this.check();
            } catch (error) {
                this.abort(error);
                throw error;
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

function powershell(script, environment, timeout = 5000) {
    return new Promise((resolve, reject) => {
        execFile('pwsh', ['-NoProfile', '-Command', script], {
            env: { ...process.env, ...environment }, encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 1024 * 1024
        }, (error, stdout) => {
            if (error) return reject(new Error('Owned process inventory/termination failed.'));
            try { resolve(JSON.parse(stdout.trim())); } catch { reject(new Error('Invalid process inventory response.')); }
        });
    });
}

function ownedProcesses(profile) {
    let known = [];
    const selection = `
$ErrorActionPreference = 'Stop'
$all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$ids = [Collections.Generic.HashSet[int]]::new()
$known = @($env:ISSUE70_KNOWN | ConvertFrom-Json)
foreach ($item in $all) {
    if ($item.Name -eq 'msedge.exe' -and $item.CommandLine -and $item.CommandLine.Contains('--user-data-dir=' + $env:ISSUE70_PROFILE)) { [void]$ids.Add([int]$item.ProcessId) }
    foreach ($previous in $known) {
        if ($item.ProcessId -eq $previous.pid -and $item.CreationDate.ToUniversalTime().Ticks.ToString() -eq $previous.created) { [void]$ids.Add([int]$item.ProcessId) }
    }
}
do {
    $added = $false
    foreach ($item in $all) {
        if ($ids.Contains([int]$item.ParentProcessId) -and $ids.Add([int]$item.ProcessId)) { $added = $true }
    }
} while ($added)
$owned = @($all | Where-Object { $ids.Contains([int]$_.ProcessId) })
`;
    const inventory = async () => {
        const result = await powershell(selection + `
$bytes = [long]0
$records = @()
foreach ($item in $owned) {
    $records += @{ pid = [int]$item.ProcessId; created = $item.CreationDate.ToUniversalTime().Ticks.ToString() }
    $bytes += [long]$item.WorkingSetSize
}
@{ bytes = $bytes; pids = @($ids); records = $records } | ConvertTo-Json -Compress -Depth 4
`, { ISSUE70_PROFILE: profile, ISSUE70_KNOWN: JSON.stringify(known) });
        assert(Array.isArray(result.records), 'Invalid owned process identities.');
        known = result.records;
        return result;
    };
    const terminate = async () => {
        await powershell(selection + `
$processes = @()
foreach ($item in $owned) {
    $process = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
    if ($process -and [Math]::Abs($process.StartTime.ToUniversalTime().Ticks - $item.CreationDate.ToUniversalTime().Ticks) -lt 10000) { $processes += $process }
}
foreach ($process in $processes) { try { $process.Kill() } catch { if (-not $process.HasExited) { throw } } }
$deadline = [DateTime]::UtcNow.AddSeconds(5)
foreach ($process in $processes) {
    $remaining = [Math]::Max(0, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $process.WaitForExit($remaining)) { throw 'Owned Edge did not exit.' }
}
@{ stoppedCount = $processes.Count } | ConvertTo-Json -Compress
`, { ISSUE70_PROFILE: profile, ISSUE70_KNOWN: JSON.stringify(known) }, 12000);
    };
    return { inventory, terminate };
}

async function terminateSpawned(launcher, launcherExit, execute = execFile, exitTimeout = 5000) {
    if (!launcher || launcher.exitCode !== null || launcher.signalCode !== null) return;
    await new Promise(resolve => {
        execute('taskkill.exe', ['/PID', String(launcher.pid), '/T', '/F'], { timeout: 5000, windowsHide: true }, () => resolve());
    });
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
        try { await bounded(Promise.resolve().then(operation), label, timeout); } catch (error) {
            if (!/Target page, context or browser has been closed/.test(error.message)) result.errors.push(label);
        }
    };
    await attempt('Guard stop', () => guard?.stop(), 15000);
    await attempt('Owned family termination', () => owned?.terminate(), 15000);
    await attempt('Spawned family termination', () => (overrides.terminateSpawned || terminateSpawned)(launcher, launcherExit));
    await attempt('Launcher exit', async () => {
        if (launcher && launcher.exitCode === null && launcher.signalCode === null) launcher.kill();
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

function assertRun(run, expectedRows, first) {
    assert(Number.isSafeInteger(expectedRows) && expectedRows > 0, 'Expected rows must be a positive integer.');
    assert.strictEqual(run.snapshot.rows, expectedRows, 'Normalized row count differs from expected rows.');
    assert(run.snapshot.rawRows >= expectedRows, 'Raw row count is incomplete.');
    assert(Number.isSafeInteger(run.snapshot.activeRows) && run.snapshot.activeRows >= 0, 'Invalid active row count.');
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
        assert.strictEqual(run.reportHash, first.reportHash, 'Cold/reload report semantics differ.');
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
    window.__issue70 = { phases: [], workerMessages: [] };
    const capturePhases = () => {
        if (typeof getDashboardMetricsSnapshot !== 'function') return;
        const metrics = getDashboardMetricsSnapshot();
        const previous = window.__issue70.lastPhases || {};
        for (const [name, durationMs] of Object.entries(metrics.phases)) {
            if (previous[name] !== durationMs) window.__issue70.phases.push({ name, durationMs, observedBrowserMs: performance.now(), observedEpochMs: performance.timeOrigin + performance.now() });
        }
        window.__issue70.lastPhases = metrics.phases;
    };
    window.addEventListener('dashboard-ready', event => {
        if (window.__issue70.ready) return;
        window.__issue70.ready = { browserMs: performance.now(), epochMs: performance.timeOrigin + performance.now(), metrics: event.detail.metrics };
        capturePhases();
    });
    setInterval(capturePhases, 100);
    const OriginalWorker = window.Worker;
    window.Worker = class extends OriginalWorker {
        constructor(...args) {
            super(...args);
            this.addEventListener('message', event => {
                const data = event.data;
                const format = data.phase ? 'phase' : Array.isArray(data) ? 'legacy-array' : data.rows === null ? 'lookups-raw-columns' : Array.isArray(data.rows) ? 'row-envelope' : 'unknown';
                window.__issue70.workerMessages.push({ format, phase: data.phase || null, durationMs: data.duration ?? null, postedAtEpochMs: data.postedAt ?? null, receivedBrowserMs: performance.now(), receivedEpochMs: performance.timeOrigin + performance.now() });
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

async function measureIteration({ chromium, edge, origin, evidence, expectedRows, fingerprint, iteration }) {
    const state = {};
    let measurementError;
    try {
        state.profile = fs.mkdtempSync(path.join(os.tmpdir(), 'issue70-edge-'));
        state.owned = ownedProcesses(state.profile);
        state.guard = new ResourceGuard({ inventory: state.owned.inventory, terminate: () => terminateFamily(state), limits: evidence.limits });
        await state.guard.sample('prelaunch');
        state.guard.check();
        state.launcher = spawn(edge, ['--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${state.profile}`, '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: 'ignore', windowsHide: true });
        state.launcherExit = new Promise(resolve => {
            state.launcher.once('exit', resolve);
            state.launcher.once('error', error => { state.guard.abort(error); resolve(); });
        });
        state.guard.start();
        const portFile = path.join(state.profile, 'DevToolsActivePort');
        const launchStart = performance.now();
        while (!fs.existsSync(portFile)) {
            assert(performance.now() - launchStart < 15000, 'Edge CDP startup failed.');
            await state.guard.wait(new Promise(resolve => setTimeout(resolve, 100)));
        }
        const port = Number(fs.readFileSync(portFile, 'utf8').split('\n')[0]);
        assert(Number.isInteger(port) && port > 0 && port < 65536, 'Invalid Edge CDP port.');
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
            const run = { iteration, load, stage: 'navigation', status: 'running', peakMainHeapBytes: 0, externalRequests: 0, pageErrors: 0, failedResources: 0, failedResponses: 0 };
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
                heapSample = bounded(Promise.all([state.cdp.send('Performance.getMetrics'), state.page.evaluate(() => ({
                    instrumentationPresent: Boolean(window.__issue70), readyEventSeen: Boolean(window.__issue70?.ready), dashboardReady: Boolean(window._dashboardReady),
                    metricsPresent: typeof getDashboardMetricsSnapshot === 'function', filtersApplied: window.dashboardMetrics?.counts.applyFilters || 0,
                    activeReportRenders: window.dashboardMetrics?.reports['active-vulnerabilities']?.count || 0
                })).catch(() => null)]), 'Heap sample').then(([metrics, readiness]) => {
                    const heap = metrics.metrics.find(metric => metric.name === 'JSHeapUsedSize');
                    run.peakMainHeapBytes = Math.max(run.peakMainHeapBytes, heap?.value || 0);
                    if (readiness) run.lastReadiness = readiness;
                }).catch(error => { state.guard.abort(error); }).finally(() => { heapSample = null; });
            };
            const heapTimer = setInterval(sampleHeap, 100);
            try {
                run.navigationStartedAtHostMs = performance.now();
                run.navigationStartedAtEpochMs = Date.now();
                const navigation = load === 'first' ? state.page.goto(origin + '/', { waitUntil: 'domcontentloaded', timeout: evidence.limits.readinessWallMs }) : state.page.reload({ waitUntil: 'domcontentloaded', timeout: evidence.limits.readinessWallMs });
                await state.guard.wait(navigation);
                run.stage = 'readiness';
                state.guard.stage = `${load}:readiness`;
                await state.guard.wait(state.page.waitForFunction(() => window.__issue70.ready && window._dashboardReady && dashboardMetrics.counts.applyFilters > 0 && dashboardMetrics.reports['active-vulnerabilities']?.count > 0, null, { timeout: evidence.limits.readinessWallMs }));
                run.readinessObservedHostWallMs = performance.now() - run.navigationStartedAtHostMs;
                run.snapshot = await state.guard.wait(state.page.evaluate(() => ({
                    snapshotBrowserMs: performance.now(), snapshotEpochMs: performance.timeOrigin + performance.now(), ready: window.__issue70.ready,
                    rawRows: getRawVulnCount(), rows: vulnerabilityData.length, activeRows: filteredData.length,
                    phases: getDashboardMetricsSnapshot().phases, counts: getDashboardMetricsSnapshot().counts,
                    summaryCards: buildDashboardValidationSnapshot().summaryCards,
                    cachePolicy: { available: typeof indexedDB !== 'undefined' && !!indexedDB, maxRowsExclusive: MAX_IDB_CACHE_ROWS, maxEntries: MAX_IDB_CACHE_ENTRIES, eligible: typeof indexedDB !== 'undefined' && !!indexedDB && vulnerabilityData.length < MAX_IDB_CACHE_ROWS, byteSoftMax: null, featureFlag: null }
                })));
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
                    summaryCards: buildDashboardValidationSnapshot().summaryCards, activeRows: filteredData.length,
                    reportSections: buildDashboardValidationSnapshot().reportSections,
                    phases: window.__issue70.phases, workerMessages: window.__issue70.workerMessages
                })));
                run.reportIds = reports.reportIds;
                run.impactRows = reports.impactRows;
                run.phaseTrace = reports.phases;
                run.workerMessages = reports.workerMessages;
                run.workerReturnFormats = [...new Set(reports.workerMessages.filter(message => message.format !== 'phase').map(message => message.format))];
                run.reportHash = digest(JSON.stringify({ summaryCards: reports.summaryCards, activeRows: reports.activeRows, impactRows: reports.impactRows, reportIds: reports.reportIds, reportSections: reports.reportSections }));
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
                if (heapSample) await state.guard.wait(heapSample);
                await completeRun(run, state.guard, () => assertRun(run, expectedRows, first));
                if (!first) first = run;
            } catch (error) {
                run.status = 'failed';
                state.guard.abort(error);
                throw error;
            } finally {
                clearInterval(heapTimer);
                if (heapSample) await heapSample;
                run.memoryTrace = state.guard.trace.slice(traceStart);
                run.peakBrowserFamilyBytes = Math.max(0, ...run.memoryTrace.map(sample => sample.browserFamilyBytes));
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
    const [rootArgument, outputArgument, repeatsArgument = '3', expectedArgument] = process.argv.slice(2);
    assert(rootArgument && outputArgument && process.env.PLAYWRIGHT_MODULE, 'Supply retained Hosted dashboard directory, evidence path, repeats, expected rows, and PLAYWRIGHT_MODULE.');
    const expectedRows = Number(expectedArgument);
    const repeats = Number(repeatsArgument);
    assert(Number.isSafeInteger(expectedRows) && expectedRows > 0, 'Explicit expected rows are required; use 2 for the committed control fixture.');
    assert(Number.isSafeInteger(repeats) && repeats > 0 && repeats <= 10, 'Repeats must be between 1 and 10.');
    const evidence = {
        schemaVersion: 2, expectedRows,
        limits: { browserFamilyBytes: 3 * 1024 ** 3, freeMemoryBytes: 2 * 1024 ** 3, readinessWallMs: 120000, inventoryTimeoutMs: 5000, terminationTimeoutMs: 15000 },
        heapScope: 'CDP JSHeapUsedSize is main-renderer only; family working set includes owned workers and descendants.',
        timingScope: 'ttiBrowserMs is first dashboard-ready performance.now from navigation timeOrigin, not a true interaction latency; readinessObservedHostWallMs includes host polling; snapshotBrowserMs is later.',
        deliveryScope: 'workerDeliveryMs includes serialization, queue, deserialization; phase observations are sampled, not exact boundaries. Worker return envelopes remain backward-compatible.',
        runs: [], cleanups: [], resourceTraces: [], status: 'running'
    };
    try {
        const root = fs.realpathSync(rootArgument);
        const htmlName = 'VulnerabilityDashboard.Hosted.html';
        const html = fs.readFileSync(path.join(root, htmlName), 'utf8');
        const config = JSON.parse(html.match(/<script id="dashboardConfig"[^>]*>([\s\S]*?)<\/script>/)[1]);
        const resolveAsset = relative => {
            const filename = path.resolve(root, relative);
            assert(filename.startsWith(root + path.sep), 'Asset outside retained dashboard root.');
            return filename;
        };
        const payload = fs.readFileSync(resolveAsset(config.payloadUrl));
        const summary = fs.readFileSync(resolveAsset(config.payloadSummaryUrl));
        const runtime = loadDashboardSource().dashboardSource;
        Object.assign(evidence, { payloadBytes: payload.length, payloadSha256: digest(payload), summarySha256: digest(summary), htmlSha256: digest(html), runtimeSha256: digest(runtime) });
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
        await withServer(server, evidence, async origin => {
            const candidates = [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean).map(base => path.join(base, 'Microsoft/Edge/Application/msedge.exe'));
            const edge = candidates.find(candidate => fs.existsSync(candidate));
            assert(edge, 'Microsoft Edge is required.');
            const { chromium } = require(process.env.PLAYWRIGHT_MODULE);
            for (let iteration = 1; iteration <= repeats; iteration++) await measureIteration({ chromium, edge, origin, evidence, expectedRows, fingerprint: `cfp_${payload.length}_${digest(payload)}`, iteration });
        });
        evidence.status = 'completed';
    } catch (error) {
        evidence.status = 'blocked-or-failed';
        evidence.measurementError = error.message;
        process.exitCode = 1;
    } finally {
        evidence.remainingOwned = evidence.cleanups.length ? evidence.cleanups.some(cleanup => cleanup.remainingOwned === null) ? null : evidence.cleanups.reduce((total, cleanup) => total + cleanup.remainingOwned, 0) : null;
        fs.mkdirSync(path.dirname(path.resolve(outputArgument)), { recursive: true });
        fs.writeFileSync(outputArgument, JSON.stringify(evidence, null, 2));
        console.log(JSON.stringify({ status: evidence.status, limits: evidence.limits, measurementError: evidence.measurementError, serverClosed: evidence.serverClosed, cleanups: evidence.cleanups, runs: evidence.runs.map(run => ({ iteration: run.iteration, load: run.load, status: run.status, ttiBrowserMs: run.ttiBrowserMs, cachedEligible: run.cachedEligible, cacheState: run.cacheState, rows: run.snapshot?.rows })) }));
    }
}

async function mockProbes() {
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
    const valid = { snapshot: { rows: 2, rawRows: 2, activeRows: 2, counts: {}, summaryCards: { high: '2' } }, reportIds: [...REPORTS].sort(), impactRows: 2, reportHash: 'fixture', cachePolicy: { eligible: true, available: true, maxRowsExclusive: 500000, maxEntries: 4 }, cacheEntries: { matchingRows: 2, count: 2 }, externalRequests: 0, pageErrors: 0 };
    assertRun(valid, 2);
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
    let rootKills = 0;
    const alreadyExited = (file, args, options, callback) => {
        assert.strictEqual(file, 'taskkill.exe');
        assert.deepStrictEqual(args, ['/PID', '123', '/T', '/F']);
        rootKills++;
        callback(new Error('already stopped'));
    };
    await terminateSpawned(launcher, Promise.resolve(), alreadyExited);
    await assert.rejects(terminateSpawned(launcher, new Promise(() => {}), alreadyExited, 5), /Spawned Edge exit exceeded/);
    assert.strictEqual(rootKills, 2);
    console.log('PASS lifecycle missing Edge/server close, owned profile removal, final status, row-zero/cache-miss rejection');
    console.log('PASS final inventory exception/minimum RAM, async single-flight/timestamps, independent cleanup/actual remaining count, ineligible cache');
    console.log('PASS bounded owned-root termination and already-exited race');
}

module.exports = { mockProbes };
if (require.main === module) (process.argv.includes('--mock') ? mockProbes() : main()).catch(error => { console.error(error.message); process.exitCode = 1; });