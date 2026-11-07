const assert = require('assert');
const { reportSwitchCheckpoint, switchUnfilteredReport } = require('./Measure-DashboardWorkerTransfer');
const run = () => ({ snapshot: { rawRows: 1187395, rows: 1187395, activeRows: 1187395, privateRows: ['PRIVATE_SENTINEL'] }, lastReadiness: { activeReportRenders: 2, privateFilter: 'PRIVATE_SENTINEL' }, peakMainHeapBytes: 350657372 });
function fixture({ writer, fault } = {}) {
 const order = [], rows = [], sourceError = new Error('PRIVATE_SENTINEL operation');
 const page = {
  evaluate(fn, report) { assert.strictEqual(this, page); assert.strictEqual(report, 'impact-analysis'); assert.strictEqual(typeof fn, 'function'); order.push('evaluate'); if (fault === 'evaluate') throw sourceError; return Promise.resolve('unchanged-result'); },
  waitForFunction(fn, report, options) { assert.strictEqual(this, page); assert.strictEqual(report, 'impact-analysis'); assert.strictEqual(typeof fn, 'function'); assert.deepStrictEqual(options, { timeout: 120000 }); order.push('waitForFunction'); return fault === 'wait' ? Promise.reject(sourceError) : Promise.resolve(true); }
 };
 const aborts = [], guard = { wait(promise) { assert.strictEqual(this, guard); order.push('guard.wait'); return promise; }, abort(error) { assert.strictEqual(this, guard); aborts.push(error); } };
 const input = { page, guard, report: 'impact-analysis', readinessWallMs: 120000, recordSample: record => { rows.push(record); order.push(record.state); if (writer) writer(record); }, iteration: 1, load: 'first', run: run() };
 return { input, order, rows, aborts, sourceError };
}
async function main() {
 const f = fixture(), original = JSON.stringify(f.input.run);
 const result = await switchUnfilteredReport(f.input);
 assert.deepStrictEqual(f.order, ['start', 'evaluate', 'guard.wait', 'waitForFunction', 'guard.wait', 'completed']);
 assert.deepStrictEqual(f.rows.map(x => x.state), ['start', 'completed']);
 assert.strictEqual(result.report, 'impact-analysis'); assert(result.completedHostWallMs >= 0); assert.strictEqual(result.completedHostWallMs, f.rows[1].durationHostWallMs);
 assert.strictEqual(JSON.stringify(f.input.run), original); assert(!JSON.stringify(f.rows).includes('PRIVATE_SENTINEL'));
 assert.deepStrictEqual(Object.keys(f.rows[0]).sort(), ['kind','name','iteration','load','report','state','observationScope','sampledAtEpochMs','observedHostMs','counts','peakMainHeapBytes','durationHostWallMs'].sort());
 assert.strictEqual(f.rows[0].observationScope, 'prior-snapshot-and-sampled-run-peak');
 assert.deepStrictEqual(f.rows[0].counts, { rawRows: 1187395, normalizedRows: 1187395, filteredRows: 1187395, activeReportRenders: 2 });
 for (const fault of ['evaluate','wait']) {
  const x = fixture({ fault }); await assert.rejects(switchUnfilteredReport(x.input), error => error === x.sourceError);
  assert.deepStrictEqual(x.rows.map(x => x.state), ['start','failed']); assert(!JSON.stringify(x.rows).includes('PRIVATE_SENTINEL')); assert.strictEqual(x.aborts.length, 0);
 }
 // START is durable before a blocked renderer operation settles.
 const pending = fixture(); let reject;
 pending.input.page.evaluate = function () { assert.strictEqual(this, pending.input.page); return new Promise((resolve, rejectPromise) => { reject = rejectPromise; }); };
 const promise = switchUnfilteredReport(pending.input); assert.deepStrictEqual(pending.rows.map(x => x.state), ['start']);
 reject(pending.sourceError); await assert.rejects(promise, error => error === pending.sourceError); assert.deepStrictEqual(pending.rows.map(x => x.state), ['start','failed']);
 // Disabled diagnostics neither read metadata nor write records; original two guarded calls remain.
 const off = fixture(); off.input.recordSample = undefined;
 off.input.run = new Proxy({}, { get() { throw new Error('Metadata read while disabled'); } });
 await switchUnfilteredReport(off.input); assert.deepStrictEqual(off.order, ['evaluate','guard.wait','waitForFunction','guard.wait']); assert.strictEqual(off.rows.length, 0);
 const diagnosticError = new Error('PRIVATE_SENTINEL disk');
 for (const state of ['start','completed']) {
  const x = fixture({ writer: row => { if (row.state === state) throw diagnosticError; } });
  await assert.rejects(switchUnfilteredReport(x.input), error => error === diagnosticError); assert.deepStrictEqual(x.aborts, [diagnosticError]);
  if (state === 'start') assert.deepStrictEqual(x.order, ['start']);
 }
 const dual = fixture({ fault: 'wait', writer: row => { if (row.state === 'failed') throw diagnosticError; } });
 await assert.rejects(switchUnfilteredReport(dual.input), error => error === dual.sourceError); assert.deepStrictEqual(dual.aborts, [diagnosticError]);
 for (const value of [{ report: 'PRIVATE_SENTINEL' }, { state: 'PRIVATE_SENTINEL' }, { load: 'PRIVATE_SENTINEL' }, { iteration: -1 }]) {
  assert.throws(() => reportSwitchCheckpoint({ iteration: 1, load: 'first', report: 'impact-analysis', state: 'start', run: run(), ...value }));
 }
 const invalid = run(); invalid.snapshot.rawRows = -1; invalid.snapshot.rows = 'PRIVATE_SENTINEL'; invalid.snapshot.activeRows = 2147483648; invalid.lastReadiness.activeReportRenders = 1.5; invalid.peakMainHeapBytes = NaN;
 const clean = reportSwitchCheckpoint({ iteration: 1, load: 'reload', report: 'impact-analysis', state: 'failed', run: invalid, durationHostWallMs: Infinity });
 assert.deepStrictEqual(clean.counts, {}); assert.strictEqual(clean.peakMainHeapBytes, null); assert.strictEqual(clean.durationHostWallMs, null); assert(!JSON.stringify(clean).includes('PRIVATE_SENTINEL'));
 console.log('PASS actual unfiltered-switch helper ordering, stalled-renderer START, genuine sync/async errors, this/args, privacy, strict bounds, opt-out, writer fail-closed and dual-fault provenance');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
