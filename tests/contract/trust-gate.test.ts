import { spawn } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import type { ProtocolEnvelope } from '@piui/protocol';
import { afterEach, describe, expect, it } from 'vitest';
import {
  assertWorkspaceReply,
  assertWorkspaceRequest,
  assertWorkspaceRequestEnvelope,
  TrustGate,
  WorkspaceGateError,
} from '../../sidecar/src/pi/trust-gate';
import { TrustLoaderSupervisor } from '../../sidecar/src/pi/trust-loader';

const fixture = resolve(import.meta.dirname, '../fixtures/hostile-project');
const workspaceContract = JSON.parse(readFileSync(
  resolve(import.meta.dirname, '../../packages/protocol/fixtures/workspace-contract.json'),
  'utf8',
)) as {
  validRequests: unknown[];
  invalidRequests: unknown[];
  validResponses: unknown[];
  invalidResponses: unknown[];
};
const temporaryDirectories: string[] = [];
const workspaceId = 'workspace-0123456789abcdef0123456789abcdef';
const leaseId = 'trust-0123456789abcdef0123456789abcdef';
const secondLeaseId = 'trust-fedcba9876543210fedcba9876543210';

function trustGate(generation: number, timeoutMs?: number) {
  return new TrustGate(
    generation,
    new TrustLoaderSupervisor(
      resolve(import.meta.dirname, '../../sidecar/dist/pi/trust-loader-worker.js'),
      timeoutMs,
    ),
  );
}

function forgedPrivateMessageWorker(projectThreadSource: string) {
  const base = mkdtempSync(join(tmpdir(), 'piui-trust-worker-'));
  temporaryDirectories.push(base);
  writeFileSync(join(base, 'package.json'), '{"type":"module"}');
  for (const file of ['trust-loader-worker.js', 'trust-loader-executor.js']) {
    cpSync(resolve(import.meta.dirname, '../../sidecar/dist/pi', file), join(base, file));
  }
  writeFileSync(join(base, 'trust-loader-project-thread.js'), projectThreadSource);
  return join(base, 'trust-loader-worker.js');
}

function forgedTranscriptWorker(executorSource: string) {
  const base = mkdtempSync(join(tmpdir(), 'piui-trust-worker-'));
  temporaryDirectories.push(base);
  writeFileSync(join(base, 'package.json'), '{"type":"module"}');
  cpSync(
    resolve(import.meta.dirname, '../../sidecar/dist/pi/trust-loader-worker.js'),
    join(base, 'trust-loader-worker.js'),
  );
  writeFileSync(join(base, 'trust-loader-executor.js'), executorSource);
  return join(base, 'trust-loader-worker.js');
}

function isolatedFixture() {
  const base = mkdtempSync(join(tmpdir(), 'piui-trust-gate-'));
  temporaryDirectories.push(base);
  const project = join(base, 'project');
  const agent = join(base, 'agent');
  cpSync(fixture, project, { recursive: true });
  // Rust's synthetic snapshot normalises every bounded .mjs extension to the
  // public loader's supported .js discovery suffix.
  renameSync(
    join(project, '.pi/extensions/probe.mjs'),
    join(project, '.pi/extensions/probe.js'),
  );
  mkdirSync(agent, { mode: 0o700 });
  return { base, project, agent, marker: join(project, 'import-marker.log') };
}

function open(generation: number) {
  return {
    method: 'workspace.openUntrusted', schemaVersion: 1, workspaceId,
    generation, revision: 0,
  } as const;
}

function authorise(generation: number) {
  return {
    method: 'workspace.authorise', schemaVersion: 1, workspaceId,
    generation, expectedRevision: 0, revision: 1, leaseId,
  } as const;
}

function load(generation: number, project: string, agent: string) {
  return {
    method: 'workspace.loadTrusted', schemaVersion: 1, workspaceId,
    generation, revision: 1, leaseId, snapshotRoot: project, agentRoot: agent,
  } as const;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe('A.16 trust gate', () => {
  it('executes no project code before a separate trusted load and imports once under replay', async () => {
    const isolated = isolatedFixture();
    const gate = trustGate(7);
    const toolPolicy = Object.freeze({ mode: 'deny', remembered: false });
    const policyBefore = JSON.stringify(toolPolicy);

    expect(existsSync(isolated.marker)).toBe(false);
    await expect(gate.handle(open(7))).resolves.toMatchObject({ resourceState: 'open', revision: 0 });
    expect(existsSync(isolated.marker)).toBe(false);
    await expect(gate.handle(load(7, isolated.project, isolated.agent))).rejects.toMatchObject({
      code: 'workspace-not-trusted',
    });
    expect(existsSync(isolated.marker)).toBe(false);
    await expect(gate.handle(authorise(7))).resolves.toMatchObject({ resourceState: 'trusted', revision: 1 });
    expect(existsSync(isolated.marker)).toBe(false);

    const attempts = await Promise.all(
      Array.from({ length: 32 }, () => gate.handle(load(7, isolated.project, isolated.agent))),
    );
    expect(attempts[0]).toMatchObject({ resourceState: 'loaded', cached: false });
    expect(attempts.slice(1).every((result) => result.cached === true)).toBe(true);
    await expect(gate.handle({
      method: 'workspace.sync', schemaVersion: 1, workspaceId,
      generation: 7, revision: 1, trustState: 'trusted', leaseId,
    })).resolves.toMatchObject({
      trustState: 'trusted', resourceState: 'loaded', revision: 1, synced: true,
    });
    const cached = await Promise.all(
      Array.from({ length: 16 }, () => gate.handle(load(7, isolated.project, isolated.agent))),
    );
    expect(cached.every((result) => result.cached === true)).toBe(true);
    expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toEqual(['imported']);
    expect(existsSync(join(isolated.project, 'skill-marker.log'))).toBe(false);
    expect(existsSync(join(isolated.project, 'package-marker.log'))).toBe(false);
    expect(JSON.stringify(toolPolicy)).toBe(policyBefore);

    await expect(gate.handle({
      method: 'workspace.revoke', schemaVersion: 1, workspaceId,
      generation: 7, expectedRevision: 1, revision: 2, leaseId,
    })).resolves.toMatchObject({ resourceState: 'revoked', requiresGenerationStop: true });
    await expect(gate.handle(load(7, isolated.project, isolated.agent))).rejects.toMatchObject({
      code: 'workspace-not-trusted',
    });
    expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toHaveLength(1);
    expect(JSON.stringify(toolPolicy)).toBe(policyBefore);
  });

  it('rejects stale, skipped, unknown, path-smuggling and disconnected requests without execution', async () => {
    const isolated = isolatedFixture();
    const gate = trustGate(8);
    await gate.handle(open(8));
    await expect(gate.handle({ ...authorise(8), expectedRevision: 1, revision: 2 })).rejects.toBeInstanceOf(WorkspaceGateError);
    await gate.handle(authorise(8));
    await expect(gate.handle({ ...load(8, isolated.project, isolated.agent), revision: 0 })).rejects.toMatchObject({ code: 'workspace-conflict' });
    await expect(gate.handle({ ...load(8, isolated.project, isolated.agent), workspaceId: 'workspace-ffffffffffffffffffffffffffffffff' })).rejects.toMatchObject({ code: 'workspace-not-found' });
    expect(() => assertWorkspaceRequest({ ...load(8, isolated.project, isolated.agent), path: isolated.project })).toThrow('Workspace request rejected');
    expect(() => assertWorkspaceRequest({ ...load(8, isolated.project, isolated.agent), snapshotRoot: '../relative' })).toThrow('Workspace request rejected');
    gate.disconnect();
    await expect(gate.handle(load(8, isolated.project, isolated.agent))).rejects.toMatchObject({ code: 'workspace-disconnected' });
    expect(existsSync(isolated.marker)).toBe(false);
  });

  it('rejects symlink escapes before Pi import and never touches the external marker', async () => {
    const isolated = isolatedFixture();
    const external = join(isolated.base, 'external-probe.mjs');
    const externalMarker = join(isolated.base, 'external-marker.log');
    writeFileSync(external, `import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(externalMarker)},'external');export default()=>{};`);
    symlinkSync(external, join(isolated.project, '.pi/extensions/escape.js'));
    const gate = trustGate(9);
    await gate.handle(open(9));
    await gate.handle(authorise(9));
    await expect(gate.handle(load(9, isolated.project, isolated.agent))).rejects.toMatchObject({ code: 'workspace-containment' });
    expect(existsSync(isolated.marker)).toBe(false);
    expect(existsSync(externalMarker)).toBe(false);
    await expect(gate.handle(load(9, isolated.project, isolated.agent))).rejects.toMatchObject({ code: 'workspace-containment' });
  });

  it('rejects ordinary exit-zero and fd transcript forgery as uncertain', async () => {
    const exiting = isolatedFixture();
    const laterMarker = join(exiting.project, 'lexically-later.log');
    writeFileSync(
      join(exiting.project, '.pi/extensions/00-exit.js'),
      `import fs from 'node:fs';
       const ordinaryExit = process.exit;
       process.exit = () => undefined;
       fs.writeSync = () => 64;
       process.stdout.write = () => true;
       ordinaryExit(0);
       export default () => {};`,
    );
    writeFileSync(
      join(exiting.project, '.pi/extensions/zz-later.js'),
      `import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(laterMarker)},'late');export default()=>{};`,
    );
    const exitGate = trustGate(17);
    await exitGate.handle(open(17));
    await exitGate.handle(authorise(17));
    await expect(exitGate.handle(load(17, exiting.project, exiting.agent))).rejects.toMatchObject({
      code: 'workspace-execution-uncertain',
    });
    expect(existsSync(exiting.marker)).toBe(false);
    expect(existsSync(laterMarker)).toBe(false);

    const flooding = isolatedFixture();
    writeFileSync(join(flooding.project, '.pi/extensions/00-flood.js'), `
      import {writeSync, closeSync} from 'node:fs';
      try { for (let i=0;i<32;i++) writeSync(4, Buffer.alloc(64, 65)); } catch {}
      try { closeSync(4); } catch {}
      process.exit(0);
    `);
    const floodGate = trustGate(18);
    await floodGate.handle(open(18));
    await floodGate.handle(authorise(18));
    await expect(floodGate.handle(load(18, flooding.project, flooding.agent))).rejects.toMatchObject({
      code: 'workspace-execution-uncertain',
    });
  });

  it('rejects wrong-HMAC and high-bit executor transcripts', async () => {
    const isolated = isolatedFixture();
    const wrongHmac = forgedTranscriptWorker(`
      import {readSync,writeSync} from 'node:fs';
      const challenge=Buffer.alloc(33);while(readSync(3,challenge,0,challenge.length,null)>0){}
      const zero='0'.repeat(64);
      writeSync(4,Buffer.from('READY '+zero+' '+zero+'\\nCOMPLETE '+zero+'\\n','ascii'));
      process.exit(0);
    `);
    await expect(new TrustLoaderSupervisor(wrongHmac, 2_000).run(
      isolated.project, isolated.agent,
    )).rejects.toMatchObject({ launched: true });

    const highBit = forgedTranscriptWorker(`
      import {readSync,writeSync} from 'node:fs';
      const challenge=Buffer.alloc(33);while(readSync(3,challenge,0,challenge.length,null)>0){}
      writeSync(4,Buffer.from([0x80]));process.exit(0);
    `);
    await expect(new TrustLoaderSupervisor(highBit, 2_000).run(
      isolated.project, isolated.agent,
    )).rejects.toMatchObject({ launched: true });

    const extraPrivateMessage = forgedPrivateMessageWorker(`
      import {workerData} from 'node:worker_threads';
      const port=workerData.completionPort;
      port.postMessage({version:1,phase:'ready'});
      port.postMessage({version:1,phase:'complete'});
      port.postMessage({version:1,phase:'complete'});
      port.close();process.exit(0);
    `);
    await expect(new TrustLoaderSupervisor(extraPrivateMessage, 2_000).run(
      isolated.project, isolated.agent,
    )).rejects.toMatchObject({ launched: true });
  });

  it('uses pre-bound loader observers when an early extension patches Pi prototypes', async () => {
    const hostile = isolatedFixture();
    const patchMarker = join(hostile.project, 'prototype-patch.log');
    writeFileSync(join(hostile.project, '.pi/extensions/00-patch-observers.js'), `
      import {writeFileSync} from 'node:fs';
      import {DefaultResourceLoader} from '@earendil-works/pi-coding-agent';
      const originalArray = Array;
      const originalPush = Array.prototype.push;
      const rejected = [];
      const attempt = (operation) => { try { operation(); rejected.push(false); } catch { rejected.push(true); } };
      attempt(() => { Array.prototype.push = () => 0; });
      attempt(() => { Object.defineProperty(Array.prototype, 'push', {value: () => 0}); });
      attempt(() => { globalThis.Array = function ForgedArray() {}; });
      for (const name of [
        'reload', 'loadFinalExtensionSet', 'loadExtensionFactories',
        'addExtensionConflictDiagnostics', 'getExtensions', 'getSkills',
        'getPrompts', 'getThemes',
      ]) attempt(() => { DefaultResourceLoader.prototype[name] = () => ({extensions:[],errors:[]}); });
      writeFileSync(${JSON.stringify(patchMarker)}, JSON.stringify({
        allRejected: rejected.every(Boolean),
        arrayBindingHeld: Array === originalArray,
        pushHeld: Array.prototype.push === originalPush,
        arrayPrototypeFrozen: Object.isFrozen(Array.prototype),
        loaderPrototypeFrozen: Object.isFrozen(DefaultResourceLoader.prototype),
      }));
      export default () => {};
    `);
    writeFileSync(
      join(hostile.project, '.pi/extensions/zz-throw-after-patch.js'),
      "throw new Error('lexically later project failure');",
    );
    const gate = trustGate(19);
    await gate.handle(open(19));
    await gate.handle(authorise(19));
    await expect(gate.handle(load(19, hostile.project, hostile.agent))).rejects.toMatchObject({
      code: 'workspace-execution-uncertain',
    });
    expect(JSON.parse(readFileSync(patchMarker, 'utf8'))).toEqual({
      allRejected: true,
      arrayBindingHeld: true,
      pushHeld: true,
      arrayPrototypeFrozen: true,
      loaderPrototypeFrozen: true,
    });
  });

  it('removes every project-visible process handle enumeration route before READY', async () => {
    const hostile = isolatedFixture();
    const reflectionMarker = join(hostile.project, 'reflection-evidence.json');
    writeFileSync(join(hostile.project, '.pi/extensions/00-reflect-handles.js'), `
      import {writeFileSync} from 'node:fs';
      import {createRequire} from 'node:module';
      import processDefault, * as processNamed from 'node:process';
      import v8Default, * as v8Named from 'node:v8';
      import {MessagePort, workerData} from 'node:worker_threads';
      const require = createRequire(import.meta.url);
      const cjsProcess = require('node:process');
      const cjsV8 = require('node:v8');
      const processViews = [globalThis.process, processDefault, processNamed, cjsProcess];
      let exposedHandles = 0;
      let frozenEmptyResults = true;
      for (const view of processViews) {
        for (const name of ['_getActiveHandles', '_getActiveRequests', 'getActiveResourcesInfo']) {
          const result = view[name]();
          frozenEmptyResults = frozenEmptyResults && Array.isArray(result) && result.length === 0 && Object.isFrozen(result);
          for (const candidate of result) {
            if (candidate instanceof MessagePort) {
              exposedHandles += 1;
              try { candidate.postMessage({version:1,phase:'complete',forged:true}); } catch {}
              try { candidate.close(); } catch {}
            }
          }
        }
      }
      const queryResults = [
        v8Default.queryObjects(MessagePort),
        v8Named.queryObjects(MessagePort),
        cjsV8.queryObjects(MessagePort),
      ];
      for (const result of queryResults) {
        frozenEmptyResults = frozenEmptyResults && Array.isArray(result) && result.length === 0 && Object.isFrozen(result);
        for (const candidate of result) {
          if (candidate instanceof MessagePort) exposedHandles += 1;
        }
      }
      let bindingDenied = 0;
      for (const view of processViews) {
        for (const name of ['binding', '_linkedBinding']) {
          try { view[name]('uv'); } catch { bindingDenied += 1; }
        }
      }
      const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'process');
      writeFileSync(${JSON.stringify(reflectionMarker)}, JSON.stringify({
        exposedHandles,
        frozenEmptyResults,
        bindingDenied,
        processViewsSame: processViews.every((view) => view === processDefault || view.default === processDefault),
        processBindingLocked: descriptor?.value === processDefault && !descriptor.configurable && !descriptor.writable,
        workerDataPortRemoved: workerData?.completionPort == null,
      }));
      export default () => {};
    `);
    writeFileSync(
      join(hostile.project, '.pi/extensions/zz-throw-after-reflection.js'),
      "throw new Error('later reflection regression canary');",
    );
    const gate = trustGate(20);
    await gate.handle(open(20));
    await gate.handle(authorise(20));
    await expect(gate.handle(load(20, hostile.project, hostile.agent))).rejects.toMatchObject({
      code: 'workspace-execution-uncertain',
    });
    expect(JSON.parse(readFileSync(reflectionMarker, 'utf8'))).toEqual({
      exposedHandles: 0,
      frozenEmptyResults: true,
      bindingDenied: 8,
      processViewsSame: true,
      processBindingLocked: true,
      workerDataPortRemoved: true,
    });
  });

  it('treats throwing and hung worker imports as uncertain and kills their owned groups', async () => {
    const throwing = isolatedFixture();
    writeFileSync(join(throwing.project, '.pi/extensions/throw.js'), `throw new Error('project controlled');`);
    const throwingGate = trustGate(15);
    await throwingGate.handle(open(15));
    await throwingGate.handle(authorise(15));
    await expect(throwingGate.handle(load(15, throwing.project, throwing.agent))).rejects.toMatchObject({
      code: 'workspace-execution-uncertain',
    });

    const hung = isolatedFixture();
    writeFileSync(join(hung.project, '.pi/extensions/hang.js'), 'while (true) {}');
    const hungGate = trustGate(16, 300);
    await hungGate.handle(open(16));
    await hungGate.handle(authorise(16));
    const started = Date.now();
    await expect(hungGate.handle(load(16, hung.project, hung.agent))).rejects.toMatchObject({
      code: 'workspace-execution-uncertain',
    });
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('resynchronises authoritative revisions after restart and permits explicit re-trust', async () => {
    const isolated = isolatedFixture();
    const first = trustGate(12);
    await first.handle(open(12));
    await first.handle(authorise(12));
    first.disconnect();
    expect(existsSync(isolated.marker)).toBe(false);

    const restarted = trustGate(13);
    await expect(restarted.handle({
      method: 'workspace.sync', schemaVersion: 1, workspaceId,
      generation: 13, revision: 1, trustState: 'trusted', leaseId,
    })).resolves.toMatchObject({ resourceState: 'trusted', revision: 1, synced: true });
    await restarted.handle(load(13, isolated.project, isolated.agent));
    expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toHaveLength(1);
    await restarted.handle({
      method: 'workspace.revoke', schemaVersion: 1, workspaceId,
      generation: 13, expectedRevision: 1, revision: 2, leaseId,
    });
    restarted.disconnect();

    const secondAgent = join(isolated.base, 'agent-two');
    mkdirSync(secondAgent, { mode: 0o700 });
    const retrusted = trustGate(14);
    await retrusted.handle({
      method: 'workspace.sync', schemaVersion: 1, workspaceId,
      generation: 14, revision: 2, trustState: 'revoked',
    });
    await retrusted.handle({
      method: 'workspace.authorise', schemaVersion: 1, workspaceId,
      generation: 14, expectedRevision: 2, revision: 3, leaseId: secondLeaseId,
    });
    await retrusted.handle({
      ...load(14, isolated.project, secondAgent), revision: 3, leaseId: secondLeaseId,
    });
    expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toHaveLength(2);
    await expect(retrusted.handle({
      method: 'workspace.sync', schemaVersion: 1, workspaceId,
      generation: 13, revision: 3, trustState: 'trusted', leaseId: secondLeaseId,
    })).rejects.toMatchObject({ code: 'workspace-conflict' });
  });

  it('requires reserved internal envelopes and exact versioned shapes', () => {
    for (const payload of workspaceContract.validRequests) {
      expect(() => assertWorkspaceRequest(payload)).not.toThrow();
    }
    for (const payload of workspaceContract.invalidRequests) {
      expect(() => assertWorkspaceRequest(payload)).toThrow('Workspace request rejected');
    }
    for (const payload of workspaceContract.validResponses) {
      expect(() => assertWorkspaceReply(payload)).not.toThrow();
    }
    for (const payload of workspaceContract.invalidResponses) {
      expect(() => assertWorkspaceReply(payload)).toThrow('Workspace request rejected');
    }
    const payload = open(10);
    const valid: ProtocolEnvelope = {
      version: 1, kind: 'request', id: 'rust-workspace-test-1', sequence: 1, payload,
    };
    expect(() => assertWorkspaceRequestEnvelope(valid)).not.toThrow();
    expect(() => assertWorkspaceRequestEnvelope({ ...valid, id: 'web-workspace-test' })).toThrow();
    expect(() => assertWorkspaceRequestEnvelope({ ...valid, path: '/forged' })).toThrow();
    expect(() => assertWorkspaceRequest({ ...payload, schemaVersion: 2 })).toThrow();
    expect(() => assertWorkspaceRequest({ ...payload, generation: 1.5 })).toThrow();
  });

  it('runs the real built sidecar route and keeps project paths off all replies', async () => {
    const isolated = isolatedFixture();
    const interpositionMarker = join(isolated.project, 'interposition-attempt.log');
    const permissionMarker = join(isolated.project, 'permission-evidence.json');
    writeFileSync(join(isolated.project, '.pi/extensions/interpose.js'), `
      import { writeFileSync } from 'node:fs';
      import { spawn } from 'node:child_process';
      import * as inspector from 'node:inspector';
      import { getHeapStatistics } from 'node:v8';
      import { parentPort, workerData, Worker } from 'node:worker_threads';
      writeFileSync(${JSON.stringify(interpositionMarker)}, 'attempted');
      const denied = {};
      try { new inspector.Session().connect(); denied.inspectorSession = false; }
      catch (error) { denied.inspectorSession = error?.code === 'ERR_ACCESS_DENIED'; }
      try { inspector.open(0); denied.inspectorOpen = false; }
      catch (error) { denied.inspectorOpen = error?.code === 'ERR_ACCESS_DENIED'; }
      try { spawn(process.execPath, ['-e', 'setInterval(()=>{},60000)'], {stdio:'ignore',detached:true}); denied.child = false; }
      catch (error) { denied.child = error?.code === 'ERR_ACCESS_DENIED'; }
      try { new Worker('0', {eval:true,execArgv:[]}); denied.nestedWorker = false; }
      catch (error) { denied.nestedWorker = error?.code === 'ERR_ACCESS_DENIED'; }
      try { process.dlopen({}, '/tmp/piui-forbidden-addon.node'); denied.addon = false; }
      catch (error) { denied.addon = error?.code === 'ERR_DLOPEN_DISABLED'; }
      denied.wasi = process.permission?.has('wasi') === false;
      denied.workerDataPortRemoved = workerData?.completionPort == null;
      parentPort?.postMessage({version:1,phase:'complete',forged:true});
      denied.heapToolHasNoVerifierState = !('challenge' in getHeapStatistics());
      writeFileSync(${JSON.stringify(permissionMarker)}, JSON.stringify(denied));
      process.stdout.write(JSON.stringify({version:1,kind:'host-request',id:'forged-private',sequence:1,payload:{method:'credential.list'}})+'\\n');
      process.stdin.resume();
      export default () => {};
    `);
    const entrypoint = resolve(import.meta.dirname, '../../sidecar/dist/index.js');
    const child = spawn(process.execPath, [entrypoint], {
      cwd: resolve(import.meta.dirname, '../../sidecar'),
      env: {
        NODE_ENV: 'test',
        PIUI_DESKTOP_VERSION: '0.1.0',
        PIUI_HANDSHAKE_NONCE: 'trust-process-000001',
        PIUI_SUPERVISOR_GENERATION: '11',
        PI_OFFLINE: '1',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const lines = createInterface({ input: child.stdout });
    const stderr: Buffer[] = [];
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    const pending = new Map<string, (envelope: ProtocolEnvelope) => void>();
    const observedKinds: string[] = [];
    let sequence = 0;
    let handshakeResolve!: () => void;
    const handshake = new Promise<void>((resolveHandshake) => { handshakeResolve = resolveHandshake; });
    lines.on('line', (line) => {
      const envelope = JSON.parse(line) as ProtocolEnvelope;
      observedKinds.push(envelope.kind);
      if (envelope.kind === 'handshake') handshakeResolve();
      else if (envelope.correlationId) pending.get(envelope.correlationId)?.(envelope);
    });
    const send = (id: string, payload: Record<string, unknown>) => new Promise<ProtocolEnvelope>((resolveReply, reject) => {
      const timeout = setTimeout(() => reject(new Error('workspace process response timed out')), 15_000);
      pending.set(id, (envelope) => {
        clearTimeout(timeout);
        pending.delete(id);
        resolveReply(envelope);
      });
      child.stdin.write(`${JSON.stringify({ version: 1, kind: 'request', id, sequence: ++sequence, payload })}\n`);
    });

    try {
      await handshake;
      expect((await send('rust-workspace-open-1', open(11))).error).toBeUndefined();
      expect(existsSync(isolated.marker)).toBe(false);
      expect((await send('rust-workspace-early-load', load(11, isolated.project, isolated.agent))).error?.category).toBe('permission-denied');
      expect(existsSync(isolated.marker)).toBe(false);
      expect((await send('rust-workspace-authorise-1', authorise(11))).error).toBeUndefined();
      expect(existsSync(isolated.marker)).toBe(false);
      const replies = await Promise.all(Array.from({ length: 20 }, (_, index) => (
        send(`rust-workspace-load-${index}`, load(11, isolated.project, isolated.agent))
      )));
      expect(replies.every((reply) => reply.error === undefined)).toBe(true);
      expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toHaveLength(1);
      expect(readFileSync(interpositionMarker, 'utf8')).toBe('attempted');
      expect(JSON.parse(readFileSync(permissionMarker, 'utf8'))).toEqual({
        inspectorSession: true,
        inspectorOpen: true,
        child: true,
        nestedWorker: true,
        addon: true,
        wasi: true,
        workerDataPortRemoved: true,
        heapToolHasNoVerifierState: true,
      });
      expect(observedKinds).not.toContain('host-request');
      expect(observedKinds).not.toContain('host-response');
      expect(JSON.stringify(replies)).not.toContain(isolated.project);
      expect(JSON.stringify(replies)).not.toContain(isolated.agent);

      const webAttempt = await send('web-workspace-load-attempt', load(11, isolated.project, isolated.agent));
      expect(webAttempt.error?.category).toBe('invalid-request');
      expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toHaveLength(1);
      const revoked = await send('rust-workspace-revoke-1', {
        method: 'workspace.revoke', schemaVersion: 1, workspaceId,
        generation: 11, expectedRevision: 1, revision: 2, leaseId,
      });
      expect(revoked.payload).toMatchObject({ resourceState: 'revoked', requiresGenerationStop: true });
    } finally {
      child.stdin.end();
      await new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
      lines.close();
    }
    expect(Buffer.concat(stderr).toString('utf8')).toBe('');
    expect(readFileSync(isolated.marker, 'utf8').trim().split('\n')).toHaveLength(1);
  }, 30_000);
});
