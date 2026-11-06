const assert = require('assert');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { pathToFileURL } = require('url');

function embeddedBytes(html, id) {
    const match = html.match(new RegExp(`<script id="${id}"[^>]*>([\\s\\S]*?)<\\/script>`));
    assert(match, 'Required embedded input is missing.');
    const base64 = match[1].replace(/\s+/g, '');
    assert(base64.length > 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64), 'Invalid embedded base64.');
    return Buffer.from(base64, 'base64');
}

function readDashboardInput(root, selfContained, generatedRuntime, sourceLoader) {
    const htmlName = selfContained ? 'VulnerabilityDashboard.html' : 'VulnerabilityDashboard.Hosted.html';
    const html = fs.readFileSync(path.join(root, htmlName), 'utf8');
    const config = JSON.parse(html.match(/<script id="dashboardConfig"[^>]*>([\s\S]*?)<\/script>/)[1]);
    const resolveAsset = relative => {
        assert(typeof relative === 'string' && relative.length > 0, 'Asset path is required.');
        const filename = path.resolve(root, relative);
        assert(filename.startsWith(root + path.sep), 'Asset outside retained dashboard root.');
        return filename;
    };
    if (selfContained) {
        assert(generatedRuntime, 'Self-contained acceptance requires --generated-runtime; no source overlay is executed.');
        assert(/<script id="dataFormat"[^>]*>compressed<\/script>/.test(html), 'Expected a compressed self-contained product.');
        assert(!config.payloadUrl && (!config.chartJsMode || config.chartJsMode === 'embedded')
            && (!config.pdfExportRuntimeMode || config.pdfExportRuntimeMode === 'embedded')
            && (!config.pdfExportBundleMode || config.pdfExportBundleMode === 'embedded'), 'Self-contained product references external delivery.');
        const scripts = Array.from(html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g), match => ({ attributes: match[1], source: match[2] }));
        const runtimes = scripts.filter(script => script.source.includes('function init()') && script.source.includes('let vulnerabilityData'));
        assert.strictEqual(runtimes.length, 1, 'Expected exactly one executed inline dashboard runtime.');
        const pako = scripts.find(script => !script.attributes.includes('src=') && !script.attributes.includes('application/')
            && script.source.length > 1024 && script.source.includes('pako') && !script.source.includes('function init()') && !script.source.includes('__inflateEmbeddedScript'))?.source;
        assert(pako, 'Executed inline pako library is missing.');
        return { htmlName, html, config, resolveAsset, fileUrl: pathToFileURL(path.join(root, htmlName)).href,
            payload: embeddedBytes(html, 'vulnsData'), summary: null, runtime: runtimes[0].source,
            chart: zlib.gunzipSync(embeddedBytes(html, 'chartJsLib'), { maxOutputLength: 16 * 1024 ** 2 }).toString('utf8'), pako,
            pdfBundle: zlib.gunzipSync(embeddedBytes(html, 'pdfExportBundleLib'), { maxOutputLength: 32 * 1024 ** 2 }), runtimeMode: 'generated-inline-assets' };
    }
    const runtimeUrl = generatedRuntime ? html.match(/<script\s+src="([^"]*\/runtime\/dashboard\.js)"/)?.[1] : null;
    assert(!generatedRuntime || runtimeUrl, 'Generated runtime URL is required.');
    const pakoUrl = html.match(/<script\s+src="([^"]*\/runtime\/pako\.js)"/)[1];
    return { htmlName, html, config, resolveAsset, fileUrl: null,
        payload: resolveAsset(config.payloadUrl), summary: fs.readFileSync(resolveAsset(config.payloadSummaryUrl)),
        runtime: generatedRuntime ? fs.readFileSync(resolveAsset(runtimeUrl), 'utf8') : sourceLoader(),
        chart: fs.readFileSync(resolveAsset(config.chartJsUrl), 'utf8'), pako: fs.readFileSync(resolveAsset(pakoUrl), 'utf8'),
        pdfBundle: fs.readFileSync(resolveAsset(config.pdfExportBundleUrl)),
        runtimeMode: generatedRuntime ? 'generated-hosted-assets' : 'current-source-overlay' };
}

module.exports = { readDashboardInput, embeddedBytes };
