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

function loadDashboardSource() {
    const templatesRoot = path.join(__dirname, '..', '..', 'templates');
    const manifestPath = path.join(templatesRoot, 'dashboard.modules.json');
    if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        const modulePaths = Array.isArray(manifest.modules) ? manifest.modules : [];
        if (modulePaths.length === 0) {
            throw new Error(`No dashboard modules were defined in ${manifestPath}`);
        }

        const dashboardSource = modulePaths
            .map((relativePath) => {
                const modulePath = path.join(templatesRoot, ...String(relativePath).split(/[\\/]/));
                return fs.readFileSync(modulePath, 'utf8');
            })
            .join('\n\n');

        return {
            dashboardPath: manifestPath,
            dashboardSource
        };
    }

    const dashboardPath = path.join(templatesRoot, 'dashboard.js');
    return {
        dashboardPath,
        dashboardSource: fs.readFileSync(dashboardPath, 'utf8')
    };
}

function loadDashboardHarness(exportSource, sandboxOverrides = {}) {
    const { dashboardPath, dashboardSource } = loadDashboardSource();
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
            confirm() { return true; },
            setTimeout,
            clearTimeout,
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
    loadDashboardSource,
    loadDashboardHarness
};
