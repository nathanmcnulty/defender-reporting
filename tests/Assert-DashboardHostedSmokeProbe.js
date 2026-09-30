'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'Invoke-HostedDashboardRuntimeSmoke.ps1'), 'utf8');
const match = source.match(/\$probeScript = @'\r?\n<script>\r?\n([\s\S]*?)\r?\n<\/script>\r?\n'@/);
assert.ok(match, 'Extract the actual hosted smoke probe');
const script = match[1].replace('__PROBE_TIMEOUT_MS__', '1000');
const privateError = new Error('PRIVATE_SECRET C:\\PRIVATE_PATH\\token');
Object.defineProperty(privateError, 'name', { get() { throw new Error('Exception name must not be read'); } });

async function runProbe(mode) {
    let now = 0;
    const timers = [];
    const elements = new Map();
    const reports = ['active-vulnerabilities', 'remediation-activity', 'impact-analysis', 'devices-by-remediation', 'remediations-by-device'];
    const validation = { ready: mode !== 'readiness', deliveryMode: 'split-assets', activeReportId: reports[0] };
    const node = () => ({
        attributes: {}, hidden: true, textContent: '',
        setAttribute(key, value) { this.attributes[key] = value; },
        getAttribute(key) { return this.attributes[key]; },
        hasAttribute(key) { return key in this.attributes; }
    });
    const popover = node();
    popover.attributes['aria-hidden'] = 'true';
    elements.set('filterPopover', popover);
    elements.set('filterPillSeverity', { click() {
        if (mode === 'filter-operation') { throw privateError; }
        if (mode === 'filter-timeout') { return; }
        popover.hidden = false;
        popover.attributes['aria-hidden'] = 'false';
        popover.attributes['data-filter-key'] = 'filterSeverity';
    } });
    for (const id of ['filterPopoverBody', 'filterPopoverApplyButton']) { elements.set(id, node()); }
    elements.set('filterPopoverCloseButton', { click() { popover.hidden = true; popover.attributes['aria-hidden'] = 'true'; } });
    const selector = { options: reports.map(value => ({ value })), value: reports[0], dispatchEvent() {
        if (mode !== 'report-timeout') { validation.activeReportId = this.value; }
    } };
    if (mode !== 'report-assertion') { elements.set('reportSelector', selector); }
    for (const report of reports) {
        const section = node();
        section.id = report + '-section';
        section.classList = { contains() { return mode !== 'report-timeout' && validation.activeReportId === report; } };
        elements.set(section.id, section);
    }
    if (mode !== 'payload-config') {
        elements.set('dashboardConfig', { textContent: JSON.stringify(mode === 'payload-url' ? {} : { payloadUrl: 'PRIVATE_URL' }) });
    }
    const document = {
        readyState: 'complete',
        getElementById(id) { return elements.get(id) || null; },
        createElement: node,
        body: { appendChild(element) { elements.set(element.id, element); } },
        querySelectorAll() { return [elements.get(validation.activeReportId + '-section')]; }
    };
    const window = {
        dashboardValidation: validation,
        pako: { inflate() {
            if (mode === 'inflate') { throw privateError; }
            if (mode === 'parse') { return 'PRIVATE_SECRET'; }
            return JSON.stringify({ vulns: mode === 'count' ? [] : [{}, {}] });
        } },
        addEventListener() {},
        setTimeout(callback, delay) { timers.push({ callback, at: now + delay }); }
    };
    const context = {
        window, document, Uint8Array, Event: class {},
        Date: { now: () => now },
        fetch: async () => {
            if (mode === 'fetch') { throw privateError; }
            if (mode === 'fetch-timeout') { return new Promise(() => {}); }
            return { ok: mode !== 'payload-response', statusText: 'PRIVATE_SECRET', arrayBuffer: async () => new ArrayBuffer(1) };
        }
    };
    vm.runInNewContext(script, context);
    for (let turn = 0; turn < 200; turn++) {
        for (let flush = 0; flush < 20; flush++) { await Promise.resolve(); }
        const probe = elements.get('hostedDashboardSmokeProbe');
        if (probe) {
            assert.ok(!JSON.stringify(probe).includes('PRIVATE'), 'Probe output contains no raw errors/URLs/paths');
            return probe.attributes;
        }
        timers.sort((first, second) => first.at - second.at);
        const timer = timers.shift();
        assert.ok(timer, 'Pending probe has a virtual timer');
        now = timer.at;
        timer.callback();
    }
    assert.fail('Probe did not complete within bounded virtual time');
}

(async () => {
    const cases = [
        ['readiness', 'timeout', 'wait-ready', 'readiness-timeout', 'timeout'],
        ['payload-config', 'error', 'payload', 'payload-config', 'assertion'],
        ['payload-url', 'error', 'payload', 'payload-url', 'assertion'],
        ['payload-response', 'error', 'payload', 'payload-response', 'assertion'],
        ['fetch', 'error', 'payload', 'payload-fetch', 'operation'],
        ['fetch-timeout', 'timeout', 'payload', 'payload-fetch', 'timeout'],
        ['inflate', 'error', 'inflate', 'inflate-operation', 'operation'],
        ['parse', 'error', 'inflate', 'inflate-parse', 'operation'],
        ['count', 'error', 'count', 'payload-count', 'assertion'],
        ['report-assertion', 'error', 'report-switch', 'report-selector', 'assertion'],
        ['report-timeout', 'timeout', 'report-switch', 'report-activation-timeout', 'timeout'],
        ['filter-operation', 'error', 'filter-popover', 'filter-open', 'operation'],
        ['filter-timeout', 'timeout', 'filter-popover', 'filter-open-timeout', 'timeout'],
        ['success', 'ready', 'complete', 'none', undefined]
    ];
    for (const [mode, state, phase, reason, errorClass] of cases) {
        const actual = await runProbe(mode);
        assert.deepEqual([actual['data-state'], actual['data-failure-phase'], actual['data-failure-reason'], actual['data-error-class']], [state, phase, reason, errorClass], mode);
        if (mode === 'success') { assert.equal(actual['data-payload-rows'], '2'); }
    }
    console.log(`Hosted smoke extracted-probe virtual-clock checks passed (${cases.length} cases; readiness/payload/assertion/operation/timeout/privacy).`);
})().catch(error => { console.error(error); process.exitCode = 1; });