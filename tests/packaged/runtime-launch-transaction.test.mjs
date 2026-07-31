import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  chmod,
  lstat,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  A27ForcedCleanupCompleteError,
  A27RuntimeProcessLedger,
  createA27RuntimeIsolate,
  launchA27Runtime,
  terminateFailedRuntime,
} from '../../scripts/run-packaged-lifecycle-probe.mjs';
import {
  A28ForcedCleanupCompleteError,
  createA28RuntimeIsolate,
  launchA28NegativeRuntime,
} from '../../scripts/run-packaged-accessibility-probe.mjs';

const nonce = 'a'.repeat(64);
const activation = Object.freeze({ nonce, port: 53_421 });
const bundle = Object.freeze({
  appPath: '/Applications/PIUI.app',
  hostPath: '/Applications/PIUI.app/Contents/MacOS/piui',
  nodePath: '/Applications/PIUI.app/Contents/MacOS/piui-node',
});

function error(message) {
  return new Error(message);
}

function waitForChildExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return once(child, 'exit').then(() => undefined);
}

function a27LaunchDependencies(failingStage, events) {
  let nextFd = 40;
  const stage = (name, value) => {
    events.push(name);
    if (failingStage === name) throw error(`${name} failed`);
    return value;
  };
  const child = { pid: failingStage === 'pid' ? 1 : 43_210 };
  const descriptor = { closed: false, fd: 39 };
  const ledger = {
    groups: new Set([43_210]),
    async terminate() {
      return stage('ledger-terminate', { forced: false });
    },
  };
  return {
    assertLockContended: () => stage('lock-contention', true),
    assertLockDescriptor: () => stage('lock-descriptor', true),
    closeLog(fd) {
      events.push(`close-fd:${fd}`);
      if (failingStage === `close-fd:${fd}`) throw error(`close-fd:${fd} failed`);
    },
    closeOwnershipDescriptor(value) {
      events.push('close-lock-fd');
      value.closed = true;
    },
    compileHelper: async () => stage('compile', '/tmp/reopen-helper'),
    createIsolate: async () => stage('isolate', '/tmp/piui-a27-injected'),
    createLedger: () => stage('ledger', ledger),
    createNetworkPolicy: () => stage('network-policy', () => 0),
    initialiseProcessLedger: async () => stage('ledger-initialise', undefined),
    makeOwnershipDescriptor: () => stage('lock-fd', descriptor),
    openLog: () => stage(nextFd === 40 ? 'stdout-fd' : 'stderr-fd', nextFd++),
    removeTree: async () => stage('remove', undefined),
    spawnProcess: () => stage('spawn', child),
    terminateGroups: async () => stage('terminate', undefined),
    waitForListener: async () => stage('listener', undefined),
    waitForSpawn: async () => stage('spawn-confirm', undefined),
  };
}

function a28LaunchDependencies(failingStage, events) {
  let nextFd = 50;
  const stage = (name, value) => {
    events.push(name);
    if (failingStage === name) throw error(`${name} failed`);
    return value;
  };
  const child = { pid: failingStage === 'pid' ? 1 : 43_220 };
  const ledger = {
    groups: new Set([43_220]),
    async terminate() {
      return stage('ledger-terminate', { forced: false });
    },
  };
  return {
    closeLog(fd) {
      events.push(`close-fd:${fd}`);
    },
    createIsolate: async () => stage('isolate', '/tmp/piui-a28-injected'),
    createLedger: () => stage('ledger', ledger),
    initialiseLedger: async () => stage('ledger-initialise', undefined),
    openLog: () => stage(nextFd === 50 ? 'stdout-fd' : 'stderr-fd', nextFd++),
    removeTree: async () => stage('remove', undefined),
    spawnProcess: () => stage('spawn', child),
    terminateGroups: async () => stage('terminate', undefined),
    waitForSpawn: async () => stage('spawn-confirm', undefined),
  };
}

function isolateDependencies(failingStage, events, requested) {
  return {
    chmodPath: async () => {
      events.push('chmod');
      if (failingStage === 'chmod') throw error('chmod failed');
    },
    makeDirectory: async () => {
      events.push('mkdir');
      if (failingStage === 'mkdir') throw error('mkdir failed');
    },
    makeTemporaryDirectory: async () => requested,
    removeTree: async () => {
      events.push('remove');
      if (failingStage === 'remove') throw error('remove failed');
    },
    resolveRealPath: async () => requested,
  };
}

test('A.27 and A.28 remove a partially constructed isolate after chmod or mkdir fails', async () => {
  for (const [createIsolate, prefix] of [
    [(dependencies) => createA27RuntimeIsolate(dependencies), 'a27'],
    [(dependencies) => createA28RuntimeIsolate('piui-a28-test-', dependencies), 'a28'],
  ]) {
    for (const failingStage of ['chmod', 'mkdir']) {
      const events = [];
      const requested = `/tmp/${prefix}-injected-isolate`;
      await assert.rejects(
        createIsolate(isolateDependencies(failingStage, events, requested)),
        new RegExp(`${failingStage} failed`, 'u'),
      );
      assert.equal(events.at(-1), 'remove');
    }
  }
});

test('isolate setup preserves its primary and removal failures', async () => {
  const events = [];
  const dependencies = isolateDependencies(
    'remove',
    events,
    '/tmp/a28-injected-isolate',
  );
  dependencies.makeDirectory = async () => {
    events.push('mkdir');
    throw error('mkdir failed before cleanup');
  };
  await assert.rejects(
    createA28RuntimeIsolate('piui-a28-test-', dependencies),
    (caught) => {
      assert.equal(caught instanceof AggregateError, true);
      assert.deepEqual(caught.errors.map(({ message }) => message), [
        'mkdir failed before cleanup',
        'remove failed',
      ]);
      return true;
    },
  );
});

test('A.27 launch rolls back every guarded setup stage and closes each opened log FD', async () => {
  for (const failingStage of [
    'compile',
    'lock-fd',
    'stdout-fd',
    'stderr-fd',
    'spawn',
    'spawn-confirm',
    'pid',
    'network-policy',
    'ledger',
    'ledger-initialise',
    'listener',
    'lock-descriptor',
    'lock-contention',
  ]) {
    const events = [];
    await assert.rejects(
      launchA27Runtime(bundle, activation, undefined, a27LaunchDependencies(failingStage, events)),
      new RegExp(`${failingStage === 'pid' ? 'packaged lifecycle probe rejected' : `${failingStage} failed`}`, 'iu'),
    );
    if (events.includes('stderr-fd')) assert.equal(events.includes('close-fd:40'), true);
    if (events.includes('spawn')) assert.equal(events.includes('close-fd:41'), true);
    assert.equal(
      events.includes('terminate'),
      ['spawn-confirm', 'network-policy', 'ledger'].includes(failingStage),
    );
    if (['spawn-confirm', 'pid', 'network-policy', 'ledger'].includes(failingStage)) {
      assert.equal(events.includes('remove'), false);
    } else {
      assert.equal(events.at(-1), 'remove');
    }
  }
});

test('A.28 launch rolls back both FD opens, spawn confirmation and ledger setup', async () => {
  for (const failingStage of [
    'stdout-fd',
    'stderr-fd',
    'spawn',
    'spawn-confirm',
    'pid',
    'ledger',
    'ledger-initialise',
  ]) {
    const events = [];
    await assert.rejects(
      launchA28NegativeRuntime(
        bundle,
        undefined,
        undefined,
        a28LaunchDependencies(failingStage, events),
      ),
      new RegExp(`${failingStage === 'pid' ? 'accessibility probe rejected' : `${failingStage} failed`}`, 'iu'),
    );
    if (events.includes('stderr-fd')) assert.equal(events.includes('close-fd:50'), true);
    if (events.includes('spawn')) assert.equal(events.includes('close-fd:51'), true);
    assert.equal(
      events.includes('terminate'),
      ['spawn-confirm', 'ledger'].includes(failingStage),
    );
    if (['spawn-confirm', 'pid', 'ledger'].includes(failingStage)) {
      assert.equal(events.includes('remove'), false);
    } else {
      assert.equal(events.at(-1), 'remove');
    }
  }
});

test('launch preserves cleanup failures and retains the isolate when group ownership is uncertain', async () => {
  const events = [];
  const dependencies = a27LaunchDependencies('listener', events);
  dependencies.createLedger = () => ({
    groups: new Set([43_210]),
    async sample() {
      return Object.freeze([{ pid: 43_210 }]);
    },
    async terminate() {
      throw error('identity cleanup failed');
    },
  });
  dependencies.terminateGroups = async () => {
    events.push('terminate');
    throw error('emergency containment failed');
  };
  await assert.rejects(
    launchA27Runtime(bundle, activation, undefined, dependencies),
    (caught) => {
      assert.equal(caught instanceof AggregateError, true);
      assert.deepEqual(caught.errors.map(({ message }) => message), [
        'listener failed',
        'identity cleanup failed',
        'emergency containment failed',
      ]);
      return true;
    },
  );
  assert.equal(events.includes('remove'), false);

  const a28Events = [];
  const a28Dependencies = a28LaunchDependencies('ledger-initialise', a28Events);
  a28Dependencies.createLedger = () => ({
    groups: new Set([43_220]),
    async terminate() {
      const ambiguity = error('A.28 process identity is ambiguous');
      ambiguity.code = 'PIUI_PROCESS_GROUP_IDENTITY_AMBIGUOUS';
      throw ambiguity;
    },
  });
  a28Dependencies.terminateGroups = async () => {
    a28Events.push('terminate');
    throw error('must not signal an ambiguous group');
  };
  await assert.rejects(
    launchA28NegativeRuntime(bundle, undefined, undefined, a28Dependencies),
    (caught) => {
      assert.equal(caught instanceof AggregateError, true);
      assert.deepEqual(caught.errors.map(({ message }) => message), [
        'ledger-initialise failed',
        'A.28 process identity is ambiguous',
      ]);
      return true;
    },
  );
  assert.equal(a28Events.includes('remove'), false);
  assert.equal(a28Events.includes('terminate'), false);
});

test('normal and typed forced ledger completion never re-signal a numeric process group', async () => {
  for (const forced of [false, true]) {
    const a27Events = [];
    const a27Dependencies = a27LaunchDependencies('listener', a27Events);
    a27Dependencies.createLedger = () => ({
      groups: new Set([43_210]),
      async terminate() {
        a27Events.push('ledger-terminate');
        if (forced) throw new A27ForcedCleanupCompleteError(error('forced'));
        return { forced: false };
      },
    });
    a27Dependencies.terminateGroups = async () => {
      a27Events.push('emergency-terminate');
      throw error('numeric terminator must not run');
    };
    await assert.rejects(
      launchA27Runtime(bundle, activation, undefined, a27Dependencies),
      /listener failed/u,
    );
    assert.equal(a27Events.includes('emergency-terminate'), false);
    assert.equal(a27Events.at(-1), 'remove');

    const a28Events = [];
    const a28Dependencies = a28LaunchDependencies('ledger-initialise', a28Events);
    a28Dependencies.createLedger = () => ({
      groups: new Set([43_220]),
      async terminate() {
        a28Events.push('ledger-terminate');
        if (forced) throw new A28ForcedCleanupCompleteError(error('forced'));
        return { forced: false };
      },
    });
    a28Dependencies.terminateGroups = async () => {
      a28Events.push('emergency-terminate');
      throw error('numeric terminator must not run');
    };
    await assert.rejects(
      launchA28NegativeRuntime(bundle, undefined, undefined, a28Dependencies),
      /ledger-initialise failed/u,
    );
    assert.equal(a28Events.includes('emergency-terminate'), false);
    assert.equal(a28Events.at(-1), 'remove');
  }
});

test('verified empty identity observation authorises removal without numeric re-signalling', async () => {
  const events = [];
  const dependencies = a27LaunchDependencies('listener', events);
  dependencies.createLedger = () => ({
    groups: new Set([43_210]),
    async sample() {
      events.push('verified-empty');
      return Object.freeze([]);
    },
    async terminate() {
      events.push('ledger-terminate');
      throw error('post-cleanup policy failure');
    },
  });
  dependencies.terminateGroups = async () => {
    events.push('emergency-terminate');
    throw error('numeric terminator must not run');
  };
  await assert.rejects(
    launchA27Runtime(bundle, activation, undefined, dependencies),
    (caught) => {
      assert.equal(caught instanceof AggregateError, true);
      assert.deepEqual(caught.errors.map(({ message }) => message), [
        'listener failed',
        'post-cleanup policy failure',
      ]);
      return true;
    },
  );
  assert.equal(events.includes('verified-empty'), true);
  assert.equal(events.includes('emergency-terminate'), false);
  assert.equal(events.at(-1), 'remove');

  const a28Events = [];
  const a28Dependencies = a28LaunchDependencies('ledger-initialise', a28Events);
  a28Dependencies.createLedger = () => ({
    groups: new Set([43_220]),
    async sample() {
      a28Events.push('verified-empty');
      return Object.freeze([]);
    },
    async terminate() {
      a28Events.push('ledger-terminate');
      throw error('A.28 post-cleanup policy failure');
    },
  });
  a28Dependencies.terminateGroups = async () => {
    a28Events.push('emergency-terminate');
    throw error('numeric terminator must not run');
  };
  await assert.rejects(
    launchA28NegativeRuntime(bundle, undefined, undefined, a28Dependencies),
    (caught) => {
      assert.equal(caught instanceof AggregateError, true);
      assert.deepEqual(caught.errors.map(({ message }) => message), [
        'ledger-initialise failed',
        'A.28 post-cleanup policy failure',
      ]);
      return true;
    },
  );
  assert.equal(a28Events.includes('verified-empty'), true);
  assert.equal(a28Events.includes('emergency-terminate'), false);
  assert.equal(a28Events.at(-1), 'remove');
});

test('real ProcessLedger forces SIGKILL, proves exact absence and leaves an unrelated group alive', async () => {
  const requested = await mkdtemp(resolve(tmpdir(), 'piui-a27-stubborn-child-'));
  await chmod(requested, 0o700);
  const isolate = await realpath(requested);
  const stdoutPath = resolve(isolate, 'stdout.log');
  const stderrPath = resolve(isolate, 'stderr.log');
  await Promise.all([
    writeFile(stdoutPath, '', { flag: 'wx', mode: 0o600 }),
    writeFile(stderrPath, '', { flag: 'wx', mode: 0o600 }),
  ]);
  const child = spawn(process.execPath, [
    '--eval',
    "process.on('SIGTERM', () => {}); process.stdout.write('ready\\n'); setInterval(() => {}, 1000);",
  ], {
    detached: true,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const unrelated = spawn(process.execPath, [
    '--eval',
    "process.on('SIGTERM', () => {}); process.stdout.write('unrelated-ready\\n'); setInterval(() => {}, 1000);",
  ], {
    detached: true,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  try {
    await Promise.all([
      once(child.stdout, 'data', { signal: AbortSignal.timeout(2_000) }),
      once(unrelated.stdout, 'data', { signal: AbortSignal.timeout(2_000) }),
    ]);
    const ledger = new A27RuntimeProcessLedger({
      hostPath: process.execPath,
      networkChecker: () => 0,
      nodePath: process.execPath,
    });
    await ledger.initialise(child.pid);
    const runtime = {
      childPid: child.pid,
      isolate,
      ledger,
      removed: false,
      stderrPath,
      stdoutPath,
    };
    await terminateFailedRuntime(runtime);
    if (child.exitCode === null && child.signalCode === null) {
      await once(child, 'exit', { signal: AbortSignal.timeout(2_000) });
    }
    assert.equal(child.signalCode, 'SIGKILL');
    assert.deepEqual(await ledger.sample(), []);
    assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' });
    assert.throws(() => process.kill(-child.pid, 0), { code: 'ESRCH' });
    assert.doesNotThrow(() => process.kill(unrelated.pid, 0));
    assert.doesNotThrow(() => process.kill(-unrelated.pid, 0));
    assert.equal(runtime.removed, true);
    await assert.rejects(lstat(isolate), { code: 'ENOENT' });
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch (caught) {
        if (caught?.code !== 'ESRCH') throw caught;
      }
    }
    await waitForChildExit(child);
    if (unrelated.exitCode === null && unrelated.signalCode === null) {
      try {
        process.kill(-unrelated.pid, 'SIGKILL');
      } catch (caught) {
        if (caught?.code !== 'ESRCH') throw caught;
      }
    }
    await waitForChildExit(unrelated);
    await rm(isolate, { recursive: true, force: true });
  }
});
