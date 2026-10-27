const assert = require('assert');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { performance } = require('perf_hooks');
const { TextDecoder } = require('util');

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
        this.child = create('pwsh', ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'Invoke-LaunchBoundOwnerBridge.ps1')], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
        this.ready = new Promise((resolve, reject) => { this.waiting = { resolve, reject, ready: true, started: performance.now(), timeout: 15000, timer: setTimeout(() => this.fail(), 15000) }; });
        this.ready.catch(() => {});
        let buffer = Buffer.alloc(0), stderrBytes = 0;
        const decoder = new TextDecoder('utf-8', { fatal: true });
        this.child.stdout.on('data', bytes => {
            if (this.failed) return;
            buffer = Buffer.concat([buffer, bytes]);
            if (buffer.length > 1024 * 1024) return this.fail();
            let split;
            while ((split = buffer.indexOf(10)) >= 0) {
                const line = buffer.slice(0, split); buffer = buffer.slice(split + 1);
                try { this.receive(parseProtocol(decoder.decode(line))); } catch { this.fail(); }
            }
        });
        this.child.stdout.once('end', () => {
            this.stdoutEnded = true;
            if (buffer.length || !this.closing || this.waiting) this.fail();
        });
        this.child.stderr.on('data', bytes => { stderrBytes += bytes.length; if (stderrBytes > 32768) this.fail(); });
        this.child.stderr.once('end', () => { this.stderrEnded = true; });
        for (const stream of [this.child.stdout, this.child.stderr]) stream.once('error', () => this.fail());
        this.child.stdin.on('error', () => this.fail());
        // exit may precede delivery of buffered replies. Only clean stdio closure ends the protocol.
        this.exit = new Promise(resolve => this.child.once('exit', (code, signal) => { this.exited = true; this.exitCode = code; this.exitSignal = signal; if (!this.closing) this.fail(); resolve(); }));
        this.closed = new Promise(resolve => this.child.once('close', (code, signal) => {
            if (!this.exited || code !== this.exitCode || signal !== this.exitSignal || !this.stdoutEnded || !this.stderrEnded || buffer.length || this.waiting) this.fail();
            resolve();
        }));
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
            if(!this.bridge){
                assert.deepStrictEqual(Object.keys(message).sort(),['bootstrap','bridge','node','nonce','owner','v']);
                assert(message.v===1&&message.bridge===true&&typeof message.nonce==='string'&&message.nonce.length===64&&/^[a-f0-9]{64}$/.test(message.nonce));
                for(const actor of [message.bootstrap,message.node,message.owner])this.validateActor(actor);
                assert(message.bootstrap.Pid===this.child.pid&&message.bootstrap.ParentPid===process.pid&&message.node.Pid===process.pid&&message.node.ParentPid===process.ppid&&message.owner.ParentPid===message.bootstrap.Pid&&message.owner.Pid!==message.bootstrap.Pid);
                assert(path.resolve(message.node.ImagePath).toUpperCase()===path.resolve(process.execPath).toUpperCase()&&path.resolve(message.owner.ImagePath).toUpperCase()===path.resolve(message.bootstrap.ImagePath).toUpperCase()&&path.basename(message.owner.ImagePath).toLowerCase()==='pwsh.exe');
                assert(performance.now()-pending.started<pending.timeout,'Late owner creator observation.');
                this.bridge=Object.freeze({nonce:message.nonce,owner:Object.freeze(message.owner),bootstrap:Object.freeze(message.bootstrap),node:Object.freeze(message.node)});
                this.child.stdin.write(JSON.stringify({v:1,command:'bridge-ready',bridgeNonce:this.bridge.nonce,actor:this.bridge.owner})+'\n');
                return;
            }
            assert.deepStrictEqual(Object.keys(message).sort(), ['actor','bridgeNonce','nonce', 'ready', 'v']);
            assert(message.v === 1 && message.ready === true && typeof message.nonce==='string' && message.nonce.length===64 && /^[a-f0-9]{64}$/.test(message.nonce));
            assert(message.bridgeNonce===this.bridge.nonce);this.validateActor(message.actor);assert.deepStrictEqual(message.actor,this.bridge.owner);
            this.actor=Object.freeze(message.actor);
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
    validateActor(actor){
        assert(actor&&typeof actor==='object'&&!Array.isArray(actor));
        assert.deepStrictEqual(Object.keys(actor).sort(),['CreationFileTime','ImagePath','ParentPid','Pid']);
        assert(Number.isSafeInteger(actor.Pid)&&actor.Pid>0&&Number.isSafeInteger(actor.ParentPid)&&actor.ParentPid>0&&actor.Pid!==actor.ParentPid);
        assert(typeof actor.CreationFileTime==='string'&&actor.CreationFileTime.length<=19&&/^[1-9][0-9]*$/.test(actor.CreationFileTime)&&!/\s/.test(actor.CreationFileTime));
        assert(typeof actor.ImagePath==='string'&&path.isAbsolute(actor.ImagePath)&&!actor.ImagePath.includes('\0'));
    }
    recordSetup(value, code = null) {
        const setup = {};
        for (const name of ['Created','Assigned','Resumed','Sealed','RootInOuterBeforeInner','OuterPolicyConfirmed']) { assert.strictEqual(typeof value[name], 'boolean'); setup[name] = value[name]; }
        assert([0, 2 * 1024 ** 3, 3 * 1024 ** 3].includes(value.OuterJobLimitBytes));setup.OuterJobLimitBytes=value.OuterJobLimitBytes;
        setup.NativeErrorCode = Number.isInteger(code) && code >= 0 && code <= 65535 ? code : null;
        this.setup = setup;
    }
    validate(value, terminal = false) {
        assert(value && value.RunId === this.runId && value.ProfileKey === this.key);
        assert.deepStrictEqual(Object.keys(value).sort(), ['ActiveProcesses','Assigned','Confirmed','Created','ExitCode','Forced','OuterJobLimitBytes','OuterPolicyConfirmed','Pids','PrivateBytes','ProfileKey','Resumed','RootInOuterBeforeInner','RunId','Sealed','StreamsComplete','Terminal','WorkingSetBytes']);
        for (const key of ['Created', 'Assigned', 'Resumed', 'Sealed']) assert.strictEqual(value[key], true);
        assert.strictEqual(value.OuterPolicyConfirmed, true);
        assert.strictEqual(value.RootInOuterBeforeInner, true);
        assert([2 * 1024 ** 3, 3 * 1024 ** 3].includes(value.OuterJobLimitBytes));
        for (const key of ['Terminal', 'Confirmed', 'Forced', 'StreamsComplete']) assert.strictEqual(typeof value[key], 'boolean');
        assert(Array.isArray(value.Pids) && value.Pids.every(pid => Number.isSafeInteger(pid) && pid > 0) && new Set(value.Pids).size === value.Pids.length);
        for(const actor of [this.actor,this.bridge.bootstrap,this.bridge.node])assert(!value.Pids.includes(actor.Pid),'Owner/ancestor counted as owned fixture.');
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
        try { await Promise.race([this.closed, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('Owner protocol closure exceeded budget.')), 5000); })]); }
        catch (error) { this.fail(); throw error; }
        finally { clearTimeout(timer); }
        assert(!this.failed && this.exitCode === 0 && this.exitSignal === null, 'Launch-bound owner state unknown.');
        return proof;
    }
    abort() { this.fail(); }
}
module.exports = { LaunchBoundClient, parseProtocol };
