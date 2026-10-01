const assert = require('assert');
const {
    createDocumentStub,
    createStubElement,
    loadDashboardHarness
} = require('./helpers/dashboard-test-harness');

function createClassList() {
    const classes = new Set();

    return {
        add(value) {
            classes.add(value);
        },
        remove(value) {
            classes.delete(value);
        },
        toggle(value) {
            if (classes.has(value)) {
                classes.delete(value);
                return false;
            }

            classes.add(value);
            return true;
        },
        contains(value) {
            return classes.has(value);
        }
    };
}

function createDetail(index, overrides = {}) {
    const suffix = String(index).padStart(4, '0');

    return {
        DeviceId: `device-${suffix}`,
        DeviceName: `device-${suffix}.contoso.com`,
        CveId: `CVE-2026-${suffix}`,
        SoftwareVersion: `10.0.${index}`,
        VulnerabilitySeverityLevel: 'High',
        CvssScore: 7.1,
        EpssScore: 0.00042,
        ExploitabilityLevel: 'ExploitIsNotPubliclyKnown',
        PublishedDate: '2026-04-14',
        FirstSeenTimestamp: '2026-04-15',
        LastSeenTimestamp: '2026-04-16',
        MachineInfo: {
            ip: `10.0.0.${(index % 250) + 1}`,
            ls: '2026-04-16'
        },
        ...overrides
    };
}

function createDashboardForSchedulingTest() {
    const documentStub = createDocumentStub();
    const rafQueue = [];
    const modal = createStubElement({
        classList: createClassList(),
        attributes: {},
        setAttribute(name, value) {
            this.attributes[name] = value;
        }
    });
    const modalTitle = createStubElement();
    const modalTbody = createStubElement();
    const scrollContainer = createStubElement({
        querySelector() {
            return modalTbody;
        }
    });
    const impactElements = new Map();
    for (const selector of ['tbody[data-impact-device-rows]', '[data-impact-page-status]', '[data-impact-page-input]',
        '[data-impact-first]', '[data-impact-previous]', '[data-impact-next]', '[data-impact-last]']) {
        impactElements.set(selector, createStubElement({
            handlers: {},
            addEventListener(event, handler) { this.handlers[event] = handler; }
        }));
    }
    const modalBody = createStubElement({
        querySelector(selector) { return impactElements.get(selector) || null; },
        closest() {
            return scrollContainer;
        }
    });
    const closeButton = createStubElement({
        focus() {
            this.focused = true;
        }
    });

    documentStub.activeElement = createStubElement();
    documentStub.contains = () => true;
    documentStub.elements.set('detailModal', modal);
    documentStub.elements.set('modalTitle', modalTitle);
    documentStub.elements.set('modalBody', modalBody);
    documentStub.elements.set('closeModalButton', closeButton);
    documentStub.elements.set('cve-global-tooltip', createStubElement());

    const scheduleRaf = callback => {
        rafQueue.push(callback);
        return rafQueue.length;
    };

    const dashboard = loadDashboardHarness(`
module.exports = {
    showDetails,
    showRemediationDetails,
    showImpactAnalysisDetails,
    closeModal,
    trackTable(table) { activeVirtualTables.push(table); }
};
`, {
        document: documentStub,
        window: {
            addEventListener() {},
            removeEventListener() {},
            confirm() { return true; },
            setTimeout,
            clearTimeout,
            innerHeight: 1080,
            innerWidth: 1920,
            requestAnimationFrame: scheduleRaf
        },
        requestAnimationFrame: scheduleRaf,
        HTMLElement: Object
    });

    return {
        dashboard,
        modal,
        modalBody,
        modalTitle,
        closeButton,
        rafQueue,
        impactElements
    };
}

function runNextAnimationFrame(rafQueue) {
    assert.ok(rafQueue.length > 0, 'Expected a queued animation frame callback.');
    const callback = rafQueue.shift();
    callback();
}

function assertDeferredModalRender(trigger, expectedFinalContent) {
    const context = createDashboardForSchedulingTest();
    const {
        modal,
        modalBody,
        closeButton,
        rafQueue
    } = context;

    trigger(context.dashboard);

    assert.strictEqual(modalBody.innerHTML, '<p class="loading">Loading details...</p>');
    assert.ok(modal.classList.contains('active'));
    assert.ok(closeButton.focused, 'Expected the modal close button to receive focus immediately.');
    assert.strictEqual(rafQueue.length, 1, 'Expected the first animation frame to be queued.');

    runNextAnimationFrame(rafQueue);

    assert.strictEqual(modalBody.innerHTML, '<p class="loading">Loading details...</p>');
    assert.strictEqual(rafQueue.length, 1, 'Expected rendering to wait until a second animation frame.');

    runNextAnimationFrame(rafQueue);

    assert.ok(
        modalBody.innerHTML.includes(expectedFinalContent),
        `Expected modal content to include '${expectedFinalContent}' after deferred rendering.`
    );
}

function main() {
    const detailRecord = createDetail(1);

    const impactContext = createDashboardForSchedulingTest();
    const impactDetails = Array.from({ length: 123 }, (_, index) => createDetail(index + 1));
    for (let index = 0; index < 75; index++) {
        impactDetails.push(createDetail(1, { CveId: `CVE-long-list-${index}` }));
    }
    impactContext.dashboard.showImpactAnalysisDetails({
        name: 'Paged impact', vulnerabilities: impactDetails, updateEntries: []
    });
    while (impactContext.rafQueue.length) runNextAnimationFrame(impactContext.rafQueue);
    const impactRows = impactContext.impactElements.get('tbody[data-impact-device-rows]');
    const input = impactContext.impactElements.get('[data-impact-page-input]');
    const click = selector => impactContext.impactElements.get(selector).handlers.click();
    const rowCount = () => (impactRows.innerHTML.match(/<tr>/g) || []).length;
    assert.ok((impactContext.modalBody.innerHTML.match(/<tr>/g) || []).length <= 50, 'Impact shell HTML must not contain all device rows.');
    assert.strictEqual(rowCount(), 50, 'Impact rendering must bound device rows.');
    assert.ok(!impactContext.modalBody.innerHTML.includes('device-0123.contoso.com'));
    assert.ok(impactRows.innerHTML.includes('CVE-long-list-74'), 'Wrapped CVE lists must remain complete.');
    const pages = [impactRows.innerHTML];
    click('[data-impact-next]');
    assert.strictEqual(rowCount(), 50);
    assert.ok(impactRows.innerHTML.includes('device-0051.contoso.com'));
    pages.push(impactRows.innerHTML);
    click('[data-impact-last]');
    assert.strictEqual(rowCount(), 23);
    assert.ok(impactRows.innerHTML.includes('device-0123.contoso.com'));
    pages.push(impactRows.innerHTML);
    for (const detail of impactDetails) {
        assert.ok(pages.join('').includes(detail.DeviceName));
        assert.ok(pages.join('').includes(detail.CveId));
    }
    assert.strictEqual(impactContext.impactElements.get('[data-impact-next]').disabled, true);
    click('[data-impact-previous]');
    assert.strictEqual(input.value, '2');
    input.value = '999';
    input.handlers.change();
    assert.strictEqual(input.value, '3');
    input.value = 'invalid';
    input.handlers.change();
    assert.strictEqual(input.value, '3');
    click('[data-impact-first]');
    assert.strictEqual(input.value, '1');
    assert.strictEqual(impactContext.impactElements.get('[data-impact-previous]').disabled, true);
    const obsoleteNext = impactContext.impactElements.get('[data-impact-next]').handlers.click;
    impactContext.dashboard.closeModal();
    impactContext.dashboard.showImpactAnalysisDetails({ name: 'New impact', vulnerabilities: [createDetail(999)], updateEntries: [] });
    const previousRows = impactRows.innerHTML;
    obsoleteNext();
    assert.strictEqual(impactRows.innerHTML, previousRows, 'Old pagination handlers must not render after replacement.');
    while (impactContext.rafQueue.length) runNextAnimationFrame(impactContext.rafQueue);
    assert.strictEqual(rowCount(), 1);

    const openers = [
        (dashboard, detail) => dashboard.showDetails({ details: [detail], updateEntries: [] }),
        (dashboard, detail) => dashboard.showRemediationDetails({
            date: '2026-04-16', remediation: 'Replacement', details: [detail],
            devices: new Set([detail.DeviceId]), vulnerabilities: new Set([detail.CveId]), updateEntries: []
        }),
        (dashboard, detail) => dashboard.showImpactAnalysisDetails({
            name: 'Replacement', vulnerabilities: [detail], updateEntries: []
        })
    ];
    for (const open of openers) {
        for (const closeFirst of [false, true]) {
            for (const advanceFrame of [false, true]) {
                const context = createDashboardForSchedulingTest();
                open(context.dashboard, createDetail(1, { DeviceName: 'obsolete-device' }));
                if (advanceFrame) runNextAnimationFrame(context.rafQueue);
                if (closeFirst) context.dashboard.closeModal();
                let disposed = 0;
                context.dashboard.trackTable({ destroy() { disposed++; } });
                open(context.dashboard, createDetail(2, { DeviceName: 'current-device' }));
                assert.strictEqual(disposed, 1, 'Replacement must dispose prior virtual tables.');
                while (context.rafQueue.length) {
                    runNextAnimationFrame(context.rafQueue);
                    const content = context.modalBody.innerHTML + context.impactElements.get('tbody[data-impact-device-rows]').innerHTML;
                    assert.ok(!content.includes('obsolete-device'), 'Obsolete modal content must never render.');
                }
                assert.ok((context.modalBody.innerHTML + context.impactElements.get('tbody[data-impact-device-rows]').innerHTML).includes('current-device'));
                for (let iteration = 0; iteration < 3; iteration++) {
                    context.dashboard.closeModal();
                    open(context.dashboard, createDetail(iteration + 3));
                }
                context.dashboard.closeModal();
                while (context.rafQueue.length) runNextAnimationFrame(context.rafQueue);
                assert.strictEqual(context.modalBody.innerHTML, '<p class="loading">Loading details...</p>');
            }
        }
    }

    assertDeferredModalRender(dashboard => {
        dashboard.showDetails({
            modalTitle: 'Windows 11: April 2026 Security Updates',
            remediation: 'Windows 11: April 2026 Security Updates',
            details: [detailRecord],
            devices: new Set([detailRecord.DeviceId]),
            vulnerabilities: new Set([detailRecord.CveId]),
            updateEntries: []
        });
    }, 'Affected Devices and Vulnerabilities');

    assertDeferredModalRender(dashboard => {
        dashboard.showRemediationDetails({
            date: '2026-04-16',
            remediation: 'Windows 11: April 2026 Security Updates',
            details: [detailRecord],
            devices: new Set([detailRecord.DeviceId]),
            vulnerabilities: new Set([detailRecord.CveId]),
            updateEntries: []
        });
    }, 'Summary');

    assertDeferredModalRender(dashboard => {
        dashboard.showImpactAnalysisDetails({
            name: 'Windows 11: April 2026 Security Updates',
            vulnerabilities: [detailRecord],
            updateEntries: []
        });
    }, 'Affected Devices');

    console.log('Dashboard modal open scheduling assertions passed.');
}

main();

