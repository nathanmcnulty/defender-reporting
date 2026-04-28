const fs = require('fs');
const path = require('path');
const vm = require('vm');

function createStubElement(overrides = {}) {
    return {
        textContent: '',
        innerHTML: '',
        value: '',
        checked: false,
        disabled: false,
        style: {},
        dataset: {},
        classList: {
            add() {},
            remove() {},
            toggle() {},
            contains() { return false; }
        },
        appendChild() {},
        removeChild() {},
        remove() {},
        setAttribute() {},
        getAttribute() { return null; },
        addEventListener() {},
        removeEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        closest() { return null; },
        focus() {},
        click() {},
        getBoundingClientRect() {
            return { top: 0, bottom: 0, left: 0, width: 0, height: 0 };
        },
        ...overrides
    };
}

function createDocumentStub() {
    const elements = new Map();

    function getOrCreateElement(id) {
        if (!elements.has(id)) {
            const element = createStubElement();
            if (id === 'dataFormat') {
                element.textContent = 'normalized';
            }
            elements.set(id, element);
        }

        return elements.get(id);
    }

    return {
        elements,
        body: {
            classList: {
                add() {},
                remove() {}
            },
            appendChild() {}
        },
        getElementById(id) {
            return getOrCreateElement(id);
        },
        querySelector() {
            return null;
        },
        querySelectorAll() {
            return [];
        },
        createElement() {
            return createStubElement();
        },
        createDocumentFragment() {
            return createStubElement();
        },
        addEventListener() {},
        removeEventListener() {}
    };
}

function loadDashboardHarness(exportSource, sandboxOverrides = {}) {
    const dashboardPath = path.join(__dirname, '..', '..', 'templates', 'dashboard.js');
    const dashboardSource = fs.readFileSync(dashboardPath, 'utf8');
    const documentStub = createDocumentStub();

    const sandbox = {
        console,
        require,
        module: { exports: {} },
        exports: {},
        document: documentStub,
        window: {
            addEventListener() {},
            removeEventListener() {},
            innerHeight: 1080,
            innerWidth: 1920
        },
        navigator: {
            clipboard: {
                writeText: async () => {}
            }
        },
        performance: {
            now() { return 0; }
        },
        TextEncoder,
        Buffer,
        URL,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        alert() {},
        confirm() { return true; },
        ...sandboxOverrides
    };
    sandbox.globalThis = sandbox;

    vm.runInNewContext(`${dashboardSource}\n${exportSource}`, sandbox, { filename: dashboardPath });
    return sandbox.module.exports;
}

module.exports = {
    createStubElement,
    createDocumentStub,
    loadDashboardHarness
};