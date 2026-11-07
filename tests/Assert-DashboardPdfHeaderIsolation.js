const assert = require('assert');
const { loadDashboardHarness, createDocumentStub } = require('./helpers/dashboard-test-harness');

function node(name, parent = null) {
    return { name, parent, contains(other) {
        for (let current = other; current; current = current.parent) if (current === this) return true;
        return false;
    } };
}

async function main() {
    const document = createDocumentStub();
    const html = node('html');
    const head = document.head = node('head', html);
    const style = node('style', head);
    const stylesheet = node('stylesheet', head);
    const body = Object.assign(document.body, node('body', html));
    const main = node('dashboard', body);
    const visitedReport = node('hidden visited report', main);
    const tableRow = node('unrelated table row', visitedReport);
    const tooltip = node('unrelated tooltip', body);
    const header = Object.assign(node('header'), { ownerDocument: document });
    const filter = node('snapshot filter label', header);
    const chart = node('snapshot chart image', header);
    const foreign = node('foreign document');
    let removes = 0;
    body.appendChild = element => { assert.strictEqual(element, header); element.parent = body; };
    body.removeChild = element => { assert.strictEqual(element, header); removes++; element.parent = null; };
    const originalError = new Error('Synthetic capture failure');
    let fail = false;
    const capture = loadDashboardHarness('module.exports = capturePdfHeaderImage;', {
        document,
        html2canvas: async (target, options) => {
            assert.strictEqual(target, header);
            assert.strictEqual(options.scale, 2.5);
            assert.strictEqual(options.backgroundColor, '#ffffff');
            for (const element of [html, head, style, stylesheet, body, header, filter, chart]) {
                assert.strictEqual(options.ignoreElements(element), false, `Keep header/style context: ${element.name}`);
            }
            for (const element of [main, visitedReport, tableRow, tooltip, foreign]) {
                assert.strictEqual(options.ignoreElements(element), true, `Prune unrelated subtree: ${element.name}`);
            }
            if (fail) throw originalError;
            return { toDataURL: type => { assert.strictEqual(type, 'image/png'); return 'snapshot-png'; } };
        }
    });
    assert.strictEqual(await capture(header), 'snapshot-png');
    assert.strictEqual(header.parent, null);
    fail = true;
    await assert.rejects(capture(header), error => error === originalError);
    assert.strictEqual(header.parent, null);
    assert.strictEqual(removes, 2, 'Detach the temporary header on success and failure.');
    assert.strictEqual(main.parent, body, 'Pruning affects the clone only, never the live dashboard.');
    assert.strictEqual(visitedReport.parent, main);
    console.log('PASS PDF header capture preserves ancestors/styles/snapshot content, excludes unrelated report subtrees and retains cleanup/error identity.');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
