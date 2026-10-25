const assert = require('assert');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { performance } = require('perf_hooks');

function parseProtocol(text) {
    const parsed = JSON.parse(text);
    let at = 0;
    const space = () => { while (/\s/.test(text[at] || '') && at < text.length) at++; };
    const string = () => {
        const begin = at++;
        while (at < text.length) { if (text[at++] === '\\') at++; else if (text[at - 1] === '"') return JSON.parse(text.slice(begin, at)); }
        throw new Error('Invalid protocol string.');
    };
    const value = depth => {
        assert(depth <= 8); space();
        if (text[at] === '"') { string(); return; }
        if (text[at] === '{') {
            at++; space(); const keys = new Set();
            while (text[at] !== '}') {
                space(); const key = string(); assert(!keys.has(key)); keys.add(key); space(); assert(text[at++] === ':'); value(depth + 1); space();
                if (text[at] === '}') break; assert(text[at++] === ',');
            }
            at++; return;
        }
        if (text[at] === '[') { at++; space(); while (text[at] !== ']') { value(depth + 1); space(); if (text[at] === ']') break; assert(text[at++] === ','); } at++; return; }
        while (at < text.length && !/[\s,}\]]/.test(text[at])) at++;
    };
    value(0); space(); assert(at === text.length);
    return parsed;
}

// Private, one-client anonymous pipes. The helper owns the browser job; it is not
// part of the browser-memory sum. The outer supervisor still includes all helpers.
class LaunchBoundClient {
    constructor(profile, create = spawn) {
        this.profile = path.resolve(profile);
        this.runId = crypto.randomBytes(16).toString('hex');
        this.key = crypto.createHash('sha256').update(this.profile.replace(/\//g, '\\').replace(/\\+$/, '').toUpperCase()).digest('hex');
        this.seq = 0;
        this.child = create('pwsh', ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'Invoke-LaunchBoundOwner.ps1')], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
        this.ready = new Promise((resolve, reject) => { this.waiting = { resolve, reject, ready: true, started: performance.now(), timeout: 15000, timer: setTimeout(() => this.fail(), 15000) }; });
        this.ready.catch(() => {});
        let buffer = '', stderrBytes = 0;
        this.child.stdout.on('data', bytes => {
            buffer += bytes.toString('utf8');
            if (Buffer.byteLength(buffer) > 1024 * 1024) return this.fail();
            let split;
            while ((split = buffer.indexOf('\n')) >= 0) {
                const line = buffer.slice(0, split); buffer = buffer.slice(split + 1);
                try { this.receive(parseProtocol(line)); } catch { this.fail(); }
            }
        });
        this.child.stdout.once('end', () => { if (!this.closing || this.waiting) this.fail(); });
        this.child.stderr.on('data', bytes => { stderrBytes += bytes.length; if (stderrBytes > 32768) this.fail(); });
        this.child.stdin.on('error', () => this.fail());
        this.exit = new Promise(resolve => this.child.once('exit', (code, signal) => { this.exited = true; this.exitCode = code; this.exitSignal = signal; if (!this.closing || this.waiting) this.fail(); resolve(); }));
        this.child.once('error', () => { this.fail(); });
    }
    fail() {
        if (this.failed) return;
        this.failed = true;
        const pending = this.waiting; this.waiting = null;
        if (pending) { clearTimeout(pending.timer); pending.reject(new Error('Launch-bound owner state unknown.')); }
        // Containment only. Never manufacture a completion response on owner loss.
        try { this.child.stdin.end(); } catch { }
        try { if (!this.exited) this.child.kill(); } catch { }
    }
    receive(message) {
        const pending = this.waiting;
        assert(pending && !this.failed && message && typeof message === 'object' && !Array.isArray(message));
        assert(performance.now() - pending.started < pending.timeout, 'Late owner response.');
        if (pending.ready) {
            assert.deepStrictEqual(Object.keys(message).sort(), ['nonce', 'ready', 'v']);
            assert(message.v === 1 && message.ready === true && /^[a-f0-9]{64}$/.test(message.nonce));
            this.nonce = message.nonce;
        } else {
            if (message.ok === false) {
                assert.deepStrictEqual(Object.keys(message).sort(), ['category','nativeErrorCode','nonce','ok','profile','runId','seq','setup','v']);
                assert(message.v === 1 && message.category === 'owner-operation' && message.nonce === this.nonce && message.runId === this.runId && message.profile === this.profile && message.seq === this.seq);
                if (message.setup) {
                    assert(message.setup.RunId === this.runId && message.setup.ProfileKey === this.key);
                    this.recordSetup(message.setup, message.nativeErrorCode);
                }
                this.fail(); return;
            }
            assert.deepStrictEqual(Object.keys(message).sort(), ['command', 'nonce', 'ok', 'profile', 'runId', 'seq', 'v', 'value']);
            assert(message.v === 1 && message.ok === true && message.nonce === this.nonce && message.runId === this.runId && message.profile === this.profile && message.seq === this.seq && message.command === pending.command);
            this.validate(message.value);
            this.recordSetup(message.value);
        }
        assert(performance.now() - pending.started < pending.timeout, 'Late owner response.');
        clearTimeout(pending.timer); this.waiting = null; pending.resolve(message.value);
    }
    recordSetup(value, code = null) {
        const setup = {};
        for (const name of ['Created','Assigned','Resumed','Sealed']) { assert.strictEqual(typeof value[name], 'boolean'); setup[name] = value[name]; }
        setup.NativeErrorCode = Number.isInteger(code) && code >= 0 && code <= 65535 ? code : null;
        this.setup = setup;
    }
    validate(value, terminal = false) {
        assert(value && value.RunId === this.runId && value.ProfileKey === this.key);
        assert.deepStrictEqual(Object.keys(value).sort(), ['ActiveProcesses','Assigned','Confirmed','Created','ExitCode','Forced','Pids','PrivateBytes','ProfileKey','Resumed','RunId','Sealed','StreamsComplete','Terminal','WorkingSetBytes']);
        for (const key of ['Created', 'Assigned', 'Resumed', 'Sealed']) assert.strictEqual(value[key], true);
        for (const key of ['Terminal', 'Confirmed', 'Forced', 'StreamsComplete']) assert.strictEqual(typeof value[key], 'boolean');
        assert(Array.isArray(value.Pids) && value.Pids.every(pid => Number.isSafeInteger(pid) && pid > 0) && new Set(value.Pids).size === value.Pids.length);
        assert(Number.isSafeInteger(value.ActiveProcesses) && value.ActiveProcesses === value.Pids.length);
        for (const key of ['WorkingSetBytes', 'PrivateBytes']) assert(Number.isSafeInteger(value[key]) && value[key] >= 0);
        assert(value.ExitCode === null || (Number.isInteger(value.ExitCode) && value.ExitCode >= -2147483648 && value.ExitCode <= 2147483647));
        if (value.Terminal) assert(value.ActiveProcesses === 0 && value.WorkingSetBytes === 0 && value.PrivateBytes === 0);
        if (value.Confirmed) assert(value.Terminal && value.StreamsComplete);
        if (terminal) assert(value.Terminal && value.Confirmed && value.StreamsComplete && value.ActiveProcesses === 0 && value.Pids.length === 0);
        return value;
    }
    async request(command, extra = {}, timeout = 5000) {
        await this.ready;
        assert(!this.failed && !this.waiting && !this.exited, 'Launch-bound owner state unknown.');
        this.seq++;
        const response = new Promise((resolve, reject) => { this.waiting = { command, resolve, reject, started: performance.now(), timeout, timer: setTimeout(() => this.fail(), timeout) }; });
        this.child.stdin.write(JSON.stringify({ v: 1, nonce: this.nonce, runId: this.runId, profile: this.profile, seq: this.seq, command, ...extra }) + '\n');
        try { return await response; } catch (error) { this.fail(); throw error; }
    }
    async start(executable, argumentsList) {
        assert(!this.attempted, 'One launch only.'); this.attempted = true;
        return this.request('start', { executable, arguments: argumentsList }, 15000);
    }
    async inventory() {
        if (!this.attempted) { await this.ready; assert(!this.failed); return { bytes: 0, privateBytes: 0, pids: [] }; }
        const value = await this.request('query');
        return { bytes: value.WorkingSetBytes, privateBytes: value.PrivateBytes, pids: value.Pids };
    }
    async terminate() {
        try { const value = await this.request('terminate', {}, 15000); return this.validate(value, true); }
        catch (error) { this.fail(); throw error; }
    }
    async finish() {
        const proof = await this.terminate();
        this.closing = true;
        try { this.validate(await this.request('dispose'), true); } catch (error) { this.fail(); throw error; }
        this.child.stdin.end();
        let timer;
        try { await Promise.race([this.exit, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('Owner exit exceeded budget.')), 5000); })]); }
        catch (error) { this.fail(); throw error; }
        finally { clearTimeout(timer); }
        assert(!this.failed && this.exitCode === 0 && this.exitSignal === null, 'Launch-bound owner state unknown.');
        return proof;
    }
    abort() { this.fail(); }
}
module.exports = { LaunchBoundClient, parseProtocol };
