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
    const modalBody = createStubElement({
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
    showImpactAnalysisDetails
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
        rafQueue
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

