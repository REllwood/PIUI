import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  openSync,
} from 'node:fs';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import test from 'node:test';
import {
  authoriseAuthenticatedNodeSandboxProfile,
  configureAuthenticatedNodeSpawn,
  createAuthenticatedNodeGuardedProductionSandboxProfile,
  runOwnedCommand,
} from '../../scripts/a21-gate-support.mjs';
import { snapshotArchitectureSource } from '../../scripts/architecture-source-snapshot.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from '../../scripts/authenticated-node-spawn.mjs';
import { a28WdioSandbox } from '../../scripts/run-packaged-accessibility-probe.mjs';
import { credentialCleanupSandbox } from '../../scripts/run-packaged-credential-probe.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const scenario = process.env.PIUI_AUTHENTICATED_NODE_SCENARIO;
const suppliedNode = process.env.PIUI_AUTHENTICATED_NODE_TEST_PATH;
const pinnedNodeArchive = resolve(
  repositoryRoot,
  '.cache/node-runtime/node-v22.23.1-darwin-arm64.tar.gz',
);
const pinnedNodeArchiveMember = 'node-v22.23.1-darwin-arm64/bin/node';

async function provisionPinnedTestNode(t) {
  const privateTemporaryRoot = await realpath('/private/tmp');
  const fixture = await realpath(
    await mkdtemp(resolve(privateTemporaryRoot, 'piui-authenticated-node-fixture.')),
  );
  t.after(async () => rm(fixture, { force: false, recursive: true }));
  const nodePath = resolve(fixture, 'node');
  const descriptor = openSync(
    nodePath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    0o500,
  );
  let extraction;
  try {
    extraction = spawnSync(
      '/usr/bin/bsdtar',
      ['-xOf', pinnedNodeArchive, pinnedNodeArchiveMember],
      {
        cwd: fixture,
        env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
        stdio: ['ignore', descriptor, 'pipe'],
        timeout: 30_000,
      },
    );
  } finally {
    closeSync(descriptor);
  }
  assert.equal(
    extraction.status,
    0,
    extraction.stderr?.toString('utf8') ?? 'Pinned Node extraction failed',
  );
  assert.equal(extraction.signal, null);
  await chmod(nodePath, 0o500);
  return nodePath;
}

async function configuration(nodePath) {
  return createAuthenticatedNodeSpawnConfiguration({
    nodePath,
    snapshot: await snapshotArchitectureSource(repositoryRoot),
    sourceRoot: repositoryRoot,
  });
}

function sandboxProfile(
  nodePath,
  buildIsolate,
  { allowFork = true, allowSignal = true } = {},
) {
  return `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (deny mach-lookup
    (global-name "com.apple.securityd")
    (global-name "com.apple.SecurityServer"))
  ${allowFork ? '(allow process-fork)' : ''}
  ${allowSignal ? '(allow signal (target same-sandbox))' : ''}
  (allow process-info* (target same-sandbox))
  (allow dynamic-code-generation)
  (allow sysctl-read)
  (allow process-exec (literal "${nodePath}"))
  (allow file-read-metadata file-test-existence (subpath "/"))
  (allow file-read* file-test-existence file-map-executable
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/private/etc/ssl/openssl.cnf")
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib")
    (literal "${nodePath}")
    (subpath "${buildIsolate}"))
  (allow file-write* file-link (subpath "${buildIsolate}"))`;
}

function sandboxPolicy(nodePath, buildIsolate) {
  return Object.freeze({
    executableFiles: Object.freeze([nodePath]),
    executableRoots: Object.freeze([]),
    kind: 'deny-network',
    metadataFiles: Object.freeze([]),
    metadataRoots: Object.freeze(['/']),
    readableFiles: Object.freeze([
      '/dev/null',
      '/dev/random',
      '/dev/urandom',
      '/private/etc/ssl/openssl.cnf',
      nodePath,
    ]),
    readableRoots: Object.freeze([
      '/Library/Apple/System/Library',
      '/System/Library',
      '/usr/lib',
      buildIsolate,
    ]),
    writableFiles: Object.freeze([]),
    writableRoots: Object.freeze([buildIsolate]),
  });
}

async function waitForMarker(path) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      if (await readFile(path, 'utf8') === 'ready\n') return;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await sleep(10);
  }
  throw new Error(`Timed out waiting for authenticated launcher marker: ${path}`);
}

async function runScenario() {
  assert.ok(suppliedNode);
  const nodePath = await realpath(suppliedNode);
  const buildIsolate = await realpath(
    await mkdtemp(resolve(tmpdir(), 'piui-authenticated-node-spawn.')),
  );
  await chmod(buildIsolate, 0o700);
  try {
    if (scenario === 'happy-path') {
      const accepted = await configuration(nodePath);
      configureAuthenticatedNodeSpawn(accepted);
      const capabilityPath = resolve(buildIsolate, 'capability.txt');
      await writeFile(capabilityPath, 'held-capability\n', { flag: 'wx', mode: 0o400 });
      const descriptor = openSync(capabilityPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const result = await runOwnedCommand({
          args: [
            '-e',
            "const fs=require('node:fs'); process.stdout.write(process.version+'\\n'+fs.readFileSync(Number(process.env.HELD_FD)));",
          ],
          command: nodePath,
          cwd: buildIsolate,
          env: {
            HELD_FD: String(descriptor),
            LANG: 'en_AU.UTF-8',
            LC_ALL: 'en_AU.UTF-8',
            PATH: '/usr/bin:/bin',
          },
          inheritedFds: [descriptor],
          label: 'Authenticated Node happy-path probe',
          timeoutMs: 30_000,
        });
        assert.equal(result.status, 0);
        assert.equal(result.signal, null);
        assert.equal(result.stderr.length, 0);
        assert.equal(result.stdout.toString('utf8'), 'v22.23.1\nheld-capability\n');
      } finally {
        closeSync(descriptor);
      }
      return;
    }

    if (scenario === 'sandboxed-path') {
      const accepted = await configuration(nodePath);
      configureAuthenticatedNodeSpawn(accepted);
      const profile = sandboxProfile(nodePath, buildIsolate);
      authoriseAuthenticatedNodeSandboxProfile({
        command: nodePath,
        policy: sandboxPolicy(nodePath, buildIsolate),
        profile,
      });
      const result = await runOwnedCommand({
        args: [
          '-e',
          "const fs=require('node:fs'); let denial='missed'; try{fs.readFileSync('/etc/hosts')}catch(error){denial=error.code}; process.stdout.write(process.version+'\\n'+denial+'\\n');",
        ],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        label: 'Authenticated sandboxed Node probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(
        result.status,
        0,
        `Authenticated sandboxed Node failed: ${result.stderr.toString('utf8')}`,
      );
      assert.equal(result.signal, null);
      assert.equal(result.stderr.length, 0);
      assert.equal(result.stdout.toString('utf8'), 'v22.23.1\nEPERM\n');
      const forkedPath = resolve(buildIsolate, 'forked-node-child.cjs');
      await writeFile(
        forkedPath,
        [
          "const preloads = process.execArgv.filter((value) => value.startsWith('--import=data:'));",
          "if (!process.send) process.exit(2);",
          "process.send({ preloads: preloads.length }, () => process.disconnect());",
          '',
        ].join('\n'),
        { flag: 'wx', mode: 0o400 },
      );
      const forked = await runOwnedCommand({
        args: [
          '-e',
          [
            "const { fork } = require('node:child_process');",
            'let received = false;',
            `const child = fork(${JSON.stringify(forkedPath)}, [], { stdio: ['inherit', 'inherit', 'inherit', 'ipc'] });`,
            "child.once('message', ({ preloads }) => { received = true; process.stdout.write(`forked-preloads=${preloads}\\n`); });",
            "child.once('error', (error) => { throw error; });",
            "child.once('exit', (code) => { if (!received || code !== 0) process.exitCode = 1; });",
          ].join(''),
        ],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        label: 'Authenticated forked-Node preload lifetime probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(
        forked.status,
        0,
        `Authenticated forked Node failed: ${forked.stderr.toString('utf8')}`,
      );
      assert.equal(forked.signal, null);
      assert.equal(forked.stderr.length, 0);
      assert.equal(forked.stdout.toString('utf8'), 'forked-preloads=0\n');
      await assert.rejects(
        runOwnedCommand({
          args: ['-p', profile, nodePath, '--version'],
          command: '/usr/bin/sandbox-exec',
          cwd: buildIsolate,
          env: { PATH: '/usr/bin:/bin' },
          label: 'Embedded authenticated Node rejection probe',
          timeoutMs: 30_000,
        }),
        /embedded behind an unrecognised command/u,
      );
      return;
    }

    if (scenario === 'sandboxed-no-fork-environment') {
      configureAuthenticatedNodeSpawn(await configuration(nodePath));
      const profile = sandboxProfile(nodePath, buildIsolate, {
        allowFork: false,
        allowSignal: false,
      });
      assert.doesNotMatch(profile, /\(allow signal/u);
      const policy = sandboxPolicy(nodePath, buildIsolate);
      authoriseAuthenticatedNodeSandboxProfile({
        command: nodePath,
        policy,
        profile,
      });
      const mixedIntersectionRoot = '/private/tmp/piui-authenticated-node-mixed-intersection';
      const readableOnlyRoot = '/private/tmp/piui-authenticated-node-readable-only';
      const writableOnlyRoot = '/private/tmp/piui-authenticated-node-writable-only';
      const mixedPolicy = Object.freeze({
        ...policy,
        readableRoots: Object.freeze([
          ...policy.readableRoots,
          mixedIntersectionRoot,
          readableOnlyRoot,
        ]),
        writableRoots: Object.freeze([
          ...policy.writableRoots,
          mixedIntersectionRoot,
          writableOnlyRoot,
        ]),
      });
      const profileWithMixedReadWrite = (path) => (
        `${profile}\n  (allow file-read* file-write* (subpath "${path}"))`
      );
      authoriseAuthenticatedNodeSandboxProfile({
        command: nodePath,
        policy: mixedPolicy,
        profile: profileWithMixedReadWrite(mixedIntersectionRoot),
      });
      for (const nonIntersectingRoot of [readableOnlyRoot, writableOnlyRoot]) {
        assert.throws(
          () => authoriseAuthenticatedNodeSandboxProfile({
            command: nodePath,
            policy: mixedPolicy,
            profile: profileWithMixedReadWrite(nonIntersectingRoot),
          }),
          /Authenticated Node sandbox profile is invalid/u,
        );
      }
      const injectedKeys = [
        'BUNDLE_GEMFILE',
        'DYLD_INSERT_LIBRARIES',
        'GEM_HOME',
        'NODE_OPTIONS',
        'NODE_PATH',
        'NODE_REPL_EXTERNAL_MODULE',
        'NODE_V8_COVERAGE',
        'OPENSSL_CONF',
        'SSL_CERT_FILE',
        'UV_THREADPOOL_SIZE',
        'RUBYLIB',
        'RUBYOPT',
      ];
      const result = await runOwnedCommand({
        args: [
          '-e',
          `const keys=${JSON.stringify(injectedKeys)}; process.stdout.write(JSON.stringify(keys.filter((key)=>Object.hasOwn(process.env,key)))+'\\n');`,
        ],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          BUNDLE_GEMFILE: '/definitely/not/a/gemfile',
          DYLD_INSERT_LIBRARIES: '/definitely/not/a/library.dylib',
          GEM_HOME: '/definitely/not/a/gem/home',
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          NODE_OPTIONS: '--definitely-not-a-node-option',
          NODE_PATH: '/definitely/not/a/node/path',
          NODE_REPL_EXTERNAL_MODULE: '/definitely/not/a/repl/module',
          NODE_V8_COVERAGE: '/definitely/not/a/coverage/root',
          OPENSSL_CONF: '/definitely/not/an/openssl/config',
          PATH: '/usr/bin:/bin',
          RUBYLIB: '/definitely/not/a/ruby/library',
          RUBYOPT: '--definitely-not-a-ruby-option',
          SSL_CERT_FILE: '/definitely/not/a/certificate/file',
          UV_THREADPOOL_SIZE: '999',
        },
        label: 'Authenticated no-fork environment scrub probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(result.status, 0);
      assert.equal(result.signal, null);
      assert.equal(result.stderr.length, 0);
      assert.equal(result.stdout.toString('utf8'), '[]\n');
      assert.throws(
        () => authoriseAuthenticatedNodeSandboxProfile({
          command: nodePath,
          policy: sandboxPolicy(nodePath, buildIsolate),
          profile: profile.replace('(deny network*)', '(allow network*)'),
        }),
        /Authenticated Node sandbox profile is invalid/u,
      );
      assert.throws(
        () => authoriseAuthenticatedNodeSandboxProfile({
          command: nodePath,
          policy: sandboxPolicy(nodePath, buildIsolate),
          profile: `${profile}\n  (allow file-read* (subpath "/"))`,
        }),
        /Authenticated Node sandbox profile is invalid/u,
      );
      await assert.rejects(
        runOwnedCommand({
          args: ['--version'],
          command: nodePath,
          cwd: buildIsolate,
          env: { PATH: '/usr/bin:/bin' },
          label: 'Malformed authenticated sandbox profile probe',
          sandboxProfile: profile.replace('(deny network*)', '(allow network*)'),
          timeoutMs: 30_000,
        }),
        /Authenticated Node sandbox profile was not authorised/u,
      );
      for (const argumentsList of [
        ['--env-file=/definitely/not/an/env'],
        ['--experimental-config-file=/definitely/not/a/config'],
        ['--openssl-config=/definitely/not/a/config'],
        ['--snapshot-blob=/definitely/not/a/snapshot'],
        ['--test'],
        ['--eval', "process.stdout.write('unexpected\\n')"],
        ['-p', 'process.version'],
      ]) {
        await assert.rejects(
          runOwnedCommand({
            args: argumentsList,
            command: nodePath,
            cwd: buildIsolate,
            env: { PATH: '/usr/bin:/bin' },
            label: 'Authenticated pre-script option rejection probe',
            sandboxProfile: profile,
            timeoutMs: 30_000,
          }),
          /Authenticated Node arguments are invalid/u,
        );
      }
      const preloadMarker = resolve(buildIsolate, 'preload-ran.marker');
      const preload = resolve(buildIsolate, 'hostile-preload.cjs');
      await writeFile(
        preload,
        `require('node:fs').writeFileSync(${JSON.stringify(preloadMarker)}, 'ran\\n'); process.kill=()=>true;\n`,
        { flag: 'wx', mode: 0o400 },
      );
      await assert.rejects(
        runOwnedCommand({
          args: ['--require', preload, '-e', "process.stdout.write('unexpected\\n');"],
          command: nodePath,
          cwd: buildIsolate,
          env: { PATH: '/usr/bin:/bin' },
          label: 'Authenticated pre-require rejection probe',
          sandboxProfile: profile,
          timeoutMs: 30_000,
        }),
        /Authenticated Node arguments are invalid/u,
      );
      await assert.rejects(readFile(preloadMarker), /ENOENT/u);
      return;
    }

    if (scenario === 'sandboxed-handshake-stress') {
      configureAuthenticatedNodeSpawn(await configuration(nodePath));
      const profile = sandboxProfile(nodePath, buildIsolate, {
        allowFork: false,
        allowSignal: false,
      });
      assert.doesNotMatch(profile, /\(allow signal/u);
      authoriseAuthenticatedNodeSandboxProfile({
        command: nodePath,
        policy: sandboxPolicy(nodePath, buildIsolate),
        profile,
      });
      for (let index = 0; index < 24; index += 1) {
        const expected = `authenticated-handshake-${index}\n`;
        const result = await runOwnedCommand({
          args: ['-e', `process.stdout.write(${JSON.stringify(expected)});`],
          command: nodePath,
          cwd: buildIsolate,
          env: {
            LANG: 'en_AU.UTF-8',
            LC_ALL: 'en_AU.UTF-8',
            PATH: '/usr/bin:/bin',
          },
          label: `Authenticated stop-handshake stress probe ${index + 1}`,
          sandboxProfile: profile,
          timeoutMs: 30_000,
        });
        assert.equal(
          result.status,
          0,
          `Authenticated stop-handshake probe ${index + 1} failed: ${result.stderr.toString('utf8')}`,
        );
        assert.equal(result.signal, null);
        assert.equal(result.stderr.length, 0);
        assert.equal(result.stdout.toString('utf8'), expected);
      }
      const workerPath = resolve(buildIsolate, 'file-backed-worker.cjs');
      await writeFile(
        workerPath,
        [
          "const { parentPort } = require('node:worker_threads');",
          "const inheritedPreloads = process.execArgv.filter((value) => value.startsWith('--import=data:'));",
          "if (parentPort) parentPort.postMessage(inheritedPreloads.length);",
          '',
        ].join('\n'),
        { flag: 'wx', mode: 0o400 },
      );
      const workerResult = await runOwnedCommand({
        args: [
          '-e',
          [
            "const { Worker } = require('node:worker_threads');",
            "const mainPreloads = process.execArgv.filter((value) => value.startsWith('--import=data:'));",
            "if (mainPreloads.length !== 0) throw new Error('authenticated preload remained in main execArgv');",
            `const worker = new Worker(${JSON.stringify(workerPath)});`,
            "worker.once('message', (workerPreloads) => process.stdout.write(`main=${mainPreloads.length} worker=${workerPreloads}\\n`));",
            "worker.once('error', (error) => { throw error; });",
          ].join(''),
        ],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        label: 'Authenticated file-backed Worker preload probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(
        workerResult.status,
        0,
        `Authenticated file-backed Worker failed: ${workerResult.stderr.toString('utf8')}`,
      );
      assert.equal(workerResult.signal, null);
      assert.equal(workerResult.stderr.length, 0);
      assert.equal(workerResult.stdout.toString('utf8'), 'main=0 worker=0\n');

      const stopStartedAt = Date.now();
      const unexpectedStop = await runOwnedCommand({
        args: [
          '-e',
          "process.stdout.write(`${process.pid}\\n`); setImmediate(() => process.kill(process.pid, 'SIGSTOP'));",
        ],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        label: 'Authenticated post-handshake stop rejection probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.notEqual(unexpectedStop.status, 0);
      assert.equal(unexpectedStop.signal, null);
      assert.ok(Date.now() - stopStartedAt < 10_000);
      assert.match(
        unexpectedStop.stderr.toString('utf8'),
        /Authenticated Node launcher rejected/u,
      );
      const stoppedPid = Number(unexpectedStop.stdout.toString('utf8').trim());
      assert.ok(Number.isSafeInteger(stoppedPid) && stoppedPid >= 2);
      assert.throws(
        () => process.kill(stoppedPid, 0),
        (error) => error?.code === 'ESRCH',
      );
      return;
    }

    if (scenario === 'a28-loopback-profile') {
      configureAuthenticatedNodeSpawn(await configuration(nodePath));
      const bundle = Object.freeze({
        appPath: resolve(buildIsolate, 'automation-twin.app'),
        hostPath: resolve(buildIsolate, 'automation-twin.app/Contents/MacOS/PIUI'),
        nodePath: resolve(buildIsolate, 'automation-twin.app/Contents/Resources/sidecar/node'),
      });
      const port = 54_321;
      const profile = a28WdioSandbox({
        bundle,
        controlRoot: resolve(buildIsolate, 'control'),
        evidenceRoot: resolve(buildIsolate, 'human-evidence'),
        port,
        repositoryRoot,
        runRoot: buildIsolate,
        runnerPath: nodePath,
      });
      const policy = Object.freeze({
        expectedProfileSha256: createHash('sha256').update(profile).digest('hex'),
        hostPath: bundle.hostPath,
        kind: 'a28-loopback',
        nodePath: bundle.nodePath,
        port,
        runnerPath: nodePath,
      });
      authoriseAuthenticatedNodeSandboxProfile({ command: nodePath, policy, profile });
      const broadenedNetworkProfile = profile.replace(
        new RegExp(
          `\\(allow network-outbound \\(remote tcp4? "(?:localhost|127\\.0\\.0\\.1):${port}"\\)\\)`,
          'u',
        ),
        '(allow network-outbound (remote tcp "*:*"))',
      );
      assert.notEqual(broadenedNetworkProfile, profile);
      for (const changed of [
        `${profile}\n  (allow default)`,
        `${profile}\n  (allow file-read* (subpath "/"))`,
        broadenedNetworkProfile,
      ]) {
        assert.throws(
          () => authoriseAuthenticatedNodeSandboxProfile({
            command: nodePath,
            policy,
            profile: changed,
          }),
          /Authenticated Node sandbox profile authorisation is invalid/u,
        );
      }
      const result = await runOwnedCommand({
        args: ['-e', "process.stdout.write('a28-authenticated\\n');"],
        command: nodePath,
        cwd: repositoryRoot,
        env: {
          HOME: buildIsolate,
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
          TMPDIR: `${buildIsolate}/`,
        },
        label: 'Authenticated A.28 loopback-only Node probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(
        result.status,
        0,
        `A.28 authenticated runner failed: ${result.stderr.toString('utf8')}`,
      );
      assert.equal(result.signal, null);
      assert.equal(result.stderr.length, 0);
      assert.equal(result.stdout.toString('utf8'), 'a28-authenticated\n');
      return;
    }

    if (scenario === 'guarded-production-profile') {
      configureAuthenticatedNodeSpawn(await configuration(nodePath));
      const profile = createAuthenticatedNodeGuardedProductionSandboxProfile({
        command: nodePath,
        executableFiles: [nodePath],
        executableRoots: [],
        readableFiles: [
          '/dev/null',
          '/dev/random',
          '/dev/urandom',
          nodePath,
        ],
        readableRoots: [
          '/Library/Apple/System/Library',
          '/System/Library',
          '/usr/lib',
          buildIsolate,
        ],
        writableFiles: [],
        writableRoots: [buildIsolate],
      });
      assert.doesNotMatch(profile, /\(allow default\)/u);
      const keychain = resolve(
        process.env.HOME ?? '/Users/invalid',
        'Library/Keychains/login.keychain-db',
      );
      const script = `
        const fs = require('node:fs');
        const cp = require('node:child_process');
        const net = require('node:net');
        const denied = {};
        for (const [key, path] of [['ambient','/etc/hosts'],['keychain',${JSON.stringify(keychain)}]]) {
          try { fs.readFileSync(path); denied[key] = 'missed'; } catch (error) { denied[key] = error.code; }
        }
        const executable = cp.spawnSync('/usr/bin/curl', ['--version']);
        denied.executable = executable.error?.code ?? 'missed';
        const server = net.createServer();
        server.once('error', (error) => {
          denied.loopback = error.code;
          fs.writeFileSync(${JSON.stringify(resolve(buildIsolate, 'guarded.marker'))}, 'allowed\\n');
          process.stdout.write(JSON.stringify(denied) + '\\n');
        });
        server.listen(0, '127.0.0.1');
      `;
      const result = await runOwnedCommand({
        args: ['-e', script],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          HOME: buildIsolate,
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
          TMPDIR: `${buildIsolate}/`,
        },
        label: 'Authenticated guarded-production Node probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(
        result.status,
        0,
        `Guarded-production Node failed: ${result.stderr.toString('utf8')}`,
      );
      assert.equal(result.signal, null);
      assert.equal(result.stderr.length, 0);
      assert.deepEqual(JSON.parse(result.stdout.toString('utf8')), {
        ambient: 'EPERM',
        executable: 'EPERM',
        keychain: 'EPERM',
        loopback: 'EPERM',
      });
      assert.equal(await readFile(resolve(buildIsolate, 'guarded.marker'), 'utf8'), 'allowed\n');

      const readOnlyProfile = createAuthenticatedNodeGuardedProductionSandboxProfile({
        command: nodePath,
        executableFiles: [nodePath],
        executableRoots: [],
        readableFiles: [
          '/dev/null',
          '/dev/random',
          '/dev/urandom',
          nodePath,
        ],
        readableRoots: [
          '/Library/Apple/System/Library',
          '/System/Library',
          '/usr/lib',
          buildIsolate,
        ],
        writableFiles: [],
        writableRoots: [],
      });
      assert.doesNotMatch(readOnlyProfile, /\(allow[^\n)]*(?:file-write|file-link)/u);
      const deniedWritePath = resolve(buildIsolate, 'guarded-denied.marker');
      const deniedWrite = await runOwnedCommand({
        args: [
          '-e',
          `const fs=require('node:fs'); try{fs.writeFileSync(${JSON.stringify(deniedWritePath)},'unexpected\\n');process.stdout.write('missed\\n')}catch(error){process.stdout.write(String(error.code)+'\\n')}`,
        ],
        command: nodePath,
        cwd: buildIsolate,
        env: {
          HOME: buildIsolate,
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
          TMPDIR: `${buildIsolate}/`,
        },
        label: 'Authenticated guarded-production empty-write probe',
        sandboxProfile: readOnlyProfile,
        timeoutMs: 30_000,
      });
      assert.equal(
        deniedWrite.status,
        0,
        `Guarded-production empty-write probe failed: ${deniedWrite.stderr.toString('utf8')}`,
      );
      assert.equal(deniedWrite.signal, null);
      assert.equal(deniedWrite.stderr.length, 0);
      assert.equal(deniedWrite.stdout.toString('utf8'), 'EPERM\n');
      await assert.rejects(readFile(deniedWritePath), /ENOENT/u);
      return;
    }

    if (scenario === 'multiple-paths') {
      const secondParent = resolve(buildIsolate, 'second-node');
      await mkdir(secondParent, { mode: 0o700 });
      const secondNode = resolve(secondParent, 'node');
      await copyFile(nodePath, secondNode, constants.COPYFILE_EXCL);
      await chmod(secondNode, 0o500);
      configureAuthenticatedNodeSpawn(await configuration(nodePath));
      configureAuthenticatedNodeSpawn(await configuration(secondNode));
      for (const command of [nodePath, secondNode]) {
        const result = await runOwnedCommand({
          args: ['--version'],
          command,
          cwd: buildIsolate,
          env: {
            LANG: 'en_AU.UTF-8',
            LC_ALL: 'en_AU.UTF-8',
            PATH: '/usr/bin:/bin',
          },
          label: 'Multiple authenticated Node path probe',
          timeoutMs: 30_000,
        });
        assert.equal(result.status, 0);
        assert.equal(result.stdout.toString('utf8'), 'v22.23.1\n');
        assert.equal(result.stderr.length, 0);
      }

      const indirectLaunches = [
        {
          args: ['node', '--version'],
          command: '/usr/bin/env',
          env: { PATH: resolve(nodePath, '..') },
          label: 'Indirect env registered-Node rejection probe',
        },
        {
          args: ['-c', '"$AUTHENTICATED_NODE" --version'],
          command: '/bin/sh',
          env: {
            AUTHENTICATED_NODE: nodePath,
            PATH: '/usr/bin:/bin',
          },
          label: 'Indirect shell registered-Node rejection probe',
        },
      ];
      for (const launch of indirectLaunches) {
        const result = await runOwnedCommand({
          ...launch,
          cwd: buildIsolate,
          timeoutMs: 30_000,
        });
        assert.notEqual(result.status, 0, `${launch.label} unexpectedly succeeded`);
        assert.equal(result.signal, null);
        assert.equal(result.stdout.length, 0);
        assert.match(result.stderr.toString('utf8'), /Operation not permitted/u);
      }

      assert.ok(nodePath.startsWith('/private/tmp/'));
      const tmpAlias = nodePath.replace(/^\/private\/tmp\//u, '/tmp/');
      await assert.rejects(
        runOwnedCommand({
          args: ['--version'],
          command: tmpAlias,
          cwd: buildIsolate,
          env: { PATH: '/usr/bin:/bin' },
          label: 'Authenticated Node /tmp alias rejection probe',
          timeoutMs: 30_000,
        }),
        /Authenticated Node command used a non-canonical path/u,
      );
      return;
    }

    if (scenario === 'explicit-sandbox-flattening') {
      configureAuthenticatedNodeSpawn(await configuration(nodePath));
      const permissiveProfile = `(version 1)
  (allow default)`;
      const direct = await runOwnedCommand({
        args: ['-p', permissiveProfile, '/usr/bin/true'],
        command: '/usr/bin/sandbox-exec',
        cwd: buildIsolate,
        env: { PATH: '/usr/bin:/bin' },
        label: 'Flattened explicit sandbox probe',
        timeoutMs: 30_000,
      });
      assert.equal(direct.status, 0, direct.stderr.toString('utf8'));
      assert.equal(direct.signal, null);
      assert.equal(direct.stderr.length, 0);

      const regexProfile = `${permissiveProfile}
  (deny file-write* (regex #"^/private/tmp/piui-[A-Za-z0-9_]+$"))`;
      const regexResult = await runOwnedCommand({
        args: ['-p', regexProfile, '/usr/bin/true'],
        command: '/usr/bin/sandbox-exec',
        cwd: buildIsolate,
        env: { PATH: '/usr/bin:/bin' },
        label: 'Flattened explicit sandbox regex probe',
        timeoutMs: 30_000,
      });
      assert.equal(regexResult.status, 0, regexResult.stderr.toString('utf8'));
      assert.equal(regexResult.signal, null);
      assert.equal(regexResult.stderr.length, 0);

      const credentialProfileResult = await runOwnedCommand({
        args: ['-p', credentialCleanupSandbox('/usr/bin/true'), '/usr/bin/true'],
        command: '/usr/bin/sandbox-exec',
        cwd: buildIsolate,
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
        label: 'Flattened credential cleanup sandbox profile probe',
        timeoutMs: 30_000,
      });
      assert.equal(
        credentialProfileResult.status,
        0,
        credentialProfileResult.stderr.toString('utf8'),
      );
      assert.equal(credentialProfileResult.signal, null);
      assert.equal(credentialProfileResult.stderr.length, 0);

      const deniedMarker = resolve(buildIsolate, 'inner-profile-denied.marker');
      const restrictiveProfile = `${permissiveProfile}
  (deny file-write* (literal "${deniedMarker}"))`;
      const restricted = await runOwnedCommand({
        args: [
          '-p',
          restrictiveProfile,
          '/bin/sh',
          '-c',
          'printf denied > "$DENIED_MARKER"',
        ],
        command: '/usr/bin/sandbox-exec',
        cwd: buildIsolate,
        env: { DENIED_MARKER: deniedMarker, PATH: '/usr/bin:/bin' },
        label: 'Flattened inner restriction probe',
        timeoutMs: 30_000,
      });
      assert.notEqual(restricted.status, 0);
      assert.equal(restricted.signal, null);
      await assert.rejects(readFile(deniedMarker), /ENOENT/u);

      const indirectNode = await runOwnedCommand({
        args: [
          '-p',
          permissiveProfile,
          '/bin/sh',
          '-c',
          '"$AUTHENTICATED_NODE" --version',
        ],
        command: '/usr/bin/sandbox-exec',
        cwd: buildIsolate,
        env: { AUTHENTICATED_NODE: nodePath, PATH: '/usr/bin:/bin' },
        label: 'Flattened registered-Node denial probe',
        timeoutMs: 30_000,
      });
      assert.notEqual(indirectNode.status, 0);
      assert.equal(indirectNode.signal, null);
      assert.match(indirectNode.stderr.toString('utf8'), /Operation not permitted/u);

      await assert.rejects(
        runOwnedCommand({
          args: ['-p', permissiveProfile, '/usr/bin/sandbox-exec', '-p', permissiveProfile, '/usr/bin/true'],
          command: '/usr/bin/sandbox-exec',
          cwd: buildIsolate,
          env: { PATH: '/usr/bin:/bin' },
          label: 'Recursive explicit sandbox rejection probe',
          timeoutMs: 30_000,
        }),
        /Explicit sandbox invocation is invalid/u,
      );
      return;
    }

    if (scenario === 'source-path-swap') {
      const sourceParent = resolve(buildIsolate, 'source');
      await mkdir(sourceParent, { mode: 0o700 });
      const privateNode = resolve(sourceParent, 'node');
      await copyFile(nodePath, privateNode, constants.COPYFILE_EXCL);
      await chmod(privateNode, 0o500);
      const accepted = await configuration(privateNode);
      configureAuthenticatedNodeSpawn(accepted);
      await rename(privateNode, resolve(sourceParent, 'node-held'));
      await copyFile(nodePath, privateNode, constants.COPYFILE_EXCL);
      await chmod(privateNode, 0o500);
      await assert.rejects(
        runOwnedCommand({
          args: ['--version'],
          command: privateNode,
          cwd: buildIsolate,
          env: {
            LANG: 'en_AU.UTF-8',
            LC_ALL: 'en_AU.UTF-8',
            PATH: '/usr/bin:/bin',
          },
          label: 'Authenticated Node source-swap probe',
          timeoutMs: 30_000,
        }),
        /Authenticated Node spawn lease changed/u,
      );
      return;
    }

    if (scenario === 'registration-refresh') {
      const sourceParent = resolve(buildIsolate, 'refresh-source');
      await mkdir(sourceParent, { mode: 0o700 });
      const privateNode = resolve(sourceParent, 'node');
      await copyFile(nodePath, privateNode, constants.COPYFILE_EXCL);
      await chmod(privateNode, 0o500);
      const accepted = await configuration(privateNode);
      configureAuthenticatedNodeSpawn(accepted);
      const profile = sandboxProfile(privateNode, buildIsolate);
      const policy = sandboxPolicy(privateNode, buildIsolate);
      authoriseAuthenticatedNodeSandboxProfile({
        command: privateNode,
        policy,
        profile,
      });
      await writeFile(resolve(sourceParent, 'closure-marker'), 'sealed\n', {
        flag: 'wx',
        mode: 0o400,
      });
      configureAuthenticatedNodeSpawn(accepted);
      await assert.rejects(
        runOwnedCommand({
          args: ['--version'],
          command: privateNode,
          cwd: buildIsolate,
          env: { PATH: '/usr/bin:/bin' },
          label: 'Stale authenticated Node sandbox authorisation probe',
          sandboxProfile: profile,
          timeoutMs: 30_000,
        }),
        /Authenticated Node sandbox profile was not authorised/u,
      );
      authoriseAuthenticatedNodeSandboxProfile({
        command: privateNode,
        policy,
        profile,
      });
      const result = await runOwnedCommand({
        args: ['-e', "process.stdout.write(process.version+'\\n');"],
        command: privateNode,
        cwd: buildIsolate,
        env: { PATH: '/usr/bin:/bin' },
        label: 'Authenticated Node registration refresh probe',
        sandboxProfile: profile,
        timeoutMs: 30_000,
      });
      assert.equal(
        result.status,
        0,
        `Registration-refresh sandbox probe failed: ${result.stderr.toString('utf8')}`,
      );
      assert.equal(result.stdout.toString('utf8'), 'v22.23.1\n');

      await rename(privateNode, resolve(sourceParent, 'node-held'));
      await copyFile(nodePath, privateNode, constants.COPYFILE_EXCL);
      await chmod(privateNode, 0o500);
      const replacementConfiguration = await configuration(privateNode);
      assert.throws(
        () => configureAuthenticatedNodeSpawn(replacementConfiguration),
        /already installed for another identity/u,
      );
      return;
    }

    if (scenario === 'source-parent-swap') {
      const sourceParent = resolve(buildIsolate, 'source-parent');
      await mkdir(sourceParent, { mode: 0o700 });
      const privateNode = resolve(sourceParent, 'node');
      await copyFile(nodePath, privateNode, constants.COPYFILE_EXCL);
      await chmod(privateNode, 0o500);
      const accepted = await configuration(privateNode);
      configureAuthenticatedNodeSpawn(accepted);
      await rename(sourceParent, resolve(buildIsolate, 'held-source-parent'));
      await mkdir(sourceParent, { mode: 0o700 });
      await copyFile(nodePath, privateNode, constants.COPYFILE_EXCL);
      await chmod(privateNode, 0o500);
      await assert.rejects(
        runOwnedCommand({
          args: ['--version'],
          command: privateNode,
          cwd: buildIsolate,
          env: {
            LANG: 'en_AU.UTF-8',
            LC_ALL: 'en_AU.UTF-8',
            PATH: '/usr/bin:/bin',
          },
          label: 'Authenticated Node source-parent-swap probe',
          timeoutMs: 30_000,
        }),
        /Authenticated Node spawn lease changed/u,
      );
      return;
    }

    if (scenario === 'live-vnode-grandparent-aba') {
      const activeTree = resolve(buildIsolate, 'active-tree');
      const heldTree = resolve(buildIsolate, 'held-tree');
      const decoyTree = resolve(buildIsolate, 'decoy-tree');
      const usedDecoyTree = resolve(buildIsolate, 'used-decoy-tree');
      for (const tree of [activeTree, decoyTree]) {
        await mkdir(resolve(tree, 'bin'), { recursive: true, mode: 0o700 });
        await copyFile(nodePath, resolve(tree, 'bin/node'), constants.COPYFILE_EXCL);
        await chmod(resolve(tree, 'bin/node'), 0o500);
      }
      const privateNode = resolve(activeTree, 'bin/node');
      const beforeSpawnMarker = resolve(buildIsolate, 'before-spawn.marker');
      const afterSpawnMarker = resolve(buildIsolate, 'after-spawn.marker');
      const launcherRoot = resolve(buildIsolate, 'launcher-source');
      await mkdir(resolve(launcherRoot, 'scripts'), { recursive: true, mode: 0o700 });
      const productionLauncher = await readFile(
        resolve(repositoryRoot, 'scripts/authenticated-node-launcher.rb'),
        'utf8',
      );
      const beforeSpawnNeedle = '  end\n  leases.call\n  if input.fetch(:sandbox_profile)';
      const afterSpawnNeedle = [
        '  initial_status = wait_for_suspended_child(child_pid, handshake_deadline)',
        '  reject unless initial_status.stopsig.zero?',
        '  leases.call',
      ].join('\n');
      assert.equal(productionLauncher.split(beforeSpawnNeedle).length - 1, 1);
      assert.equal(productionLauncher.split(afterSpawnNeedle).length - 1, 1);
      const testLauncher = productionLauncher
        .replace(
          beforeSpawnNeedle,
          `  end\n  leases.call\n  File.write(${JSON.stringify(beforeSpawnMarker)}, "ready\\n")\n  sleep 1\n  if input.fetch(:sandbox_profile)`,
        )
        .replace(
          afterSpawnNeedle,
          `  initial_status = wait_for_suspended_child(child_pid, handshake_deadline)\n  reject unless initial_status.stopsig.zero?\n  File.write(${JSON.stringify(afterSpawnMarker)}, "ready\\n")\n  sleep 1\n  leases.call`,
        );
      const launcherPath = resolve(launcherRoot, 'scripts/authenticated-node-launcher.rb');
      await writeFile(launcherPath, testLauncher, { flag: 'wx', mode: 0o400 });
      const launcherBytes = Buffer.from(testLauncher, 'utf8');
      configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
        nodePath: privateNode,
        snapshot: {
          inventory: [{
            executable: false,
            path: 'scripts/authenticated-node-launcher.rb',
            sha256: createHash('sha256').update(launcherBytes).digest('hex'),
            size: launcherBytes.length,
          }],
        },
        sourceRoot: launcherRoot,
      }));

      const launch = runOwnedCommand({
        args: ['-e', "process.stdout.write('unexpected\\n');"],
        command: privateNode,
        cwd: buildIsolate,
        env: { PATH: '/usr/bin:/bin' },
        label: 'Authenticated Node live-vnode grandparent ABA probe',
        timeoutMs: 30_000,
      });
      await waitForMarker(beforeSpawnMarker);
      await rename(activeTree, heldTree);
      await rename(decoyTree, activeTree);
      await waitForMarker(afterSpawnMarker);
      await rename(activeTree, usedDecoyTree);
      await rename(heldTree, activeTree);
      const result = await launch;
      assert.notEqual(result.status, 0);
      assert.equal(result.signal, null);
      assert.equal(result.stdout.length, 0);
      assert.match(result.stderr.toString('utf8'), /Authenticated Node launcher rejected/u);
      return;
    }

    if (scenario === 'launcher-source-swap') {
      const accepted = await configuration(nodePath);
      assert.throws(
        () => configureAuthenticatedNodeSpawn({
          ...accepted,
          launcherSource: `${accepted.launcherSource}\n`,
        }),
        /Authenticated Node spawn configuration is invalid/u,
      );
      configureAuthenticatedNodeSpawn(accepted);
      const changedLauncherSource = `${accepted.launcherSource}\n`;
      assert.throws(
        () => configureAuthenticatedNodeSpawn({
          ...accepted,
          launcherSha256: createHash('sha256').update(changedLauncherSource).digest('hex'),
          launcherSource: changedLauncherSource,
        }),
        /Authenticated Node spawn path was already installed for another configuration/u,
      );
      return;
    }

    assert.fail(`Unexpected scenario: ${scenario}`);
  } finally {
    await rm(buildIsolate, { force: false, recursive: true });
  }
}

if (scenario) {
  await runScenario();
} else {
  test('authenticated Node launch uses a held live identity and preserves explicit descriptors', async (t) => {
    const authenticatedNodeTestPath = suppliedNode ?? await provisionPinnedTestNode(t);
    for (const childScenario of [
      'happy-path',
      'sandboxed-path',
      'sandboxed-no-fork-environment',
      'sandboxed-handshake-stress',
      'a28-loopback-profile',
      'guarded-production-profile',
      'multiple-paths',
      'explicit-sandbox-flattening',
      'registration-refresh',
      'source-path-swap',
      'source-parent-swap',
      'live-vnode-grandparent-aba',
      'launcher-source-swap',
    ]) {
      const result = spawnSync(process.execPath, [import.meta.filename], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          PIUI_AUTHENTICATED_NODE_SCENARIO: childScenario,
          PIUI_AUTHENTICATED_NODE_TEST_PATH: authenticatedNodeTestPath,
        },
        timeout: 120_000,
      });
      assert.equal(
        result.status,
        0,
        `${childScenario} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
      );
      assert.equal(result.signal, null);
      assert.equal(result.stderr, '');
    }
  });

  test('launcher source is passed as held bytes rather than executed through its pathname', async () => {
    const [supportSource, launcherSource] = await Promise.all([
      readFile(resolve(repositoryRoot, 'scripts/a21-gate-support.mjs'), 'utf8'),
      readFile(resolve(repositoryRoot, 'scripts/authenticated-node-launcher.rb'), 'utf8'),
    ]);
    assert.match(supportSource, /'-e',\s*configuration\.launcherSource/u);
    assert.doesNotMatch(supportSource, /authenticated-node-launcher\.rb['"`]/u);
    assert.match(launcherSource, /POSIX_SPAWN_START_SUSPENDED/u);
    assert.match(launcherSource, /SecCodeCopyGuestWithAttributes/u);
    assert.match(launcherSource, /proc_pidpath/u);
    assert.match(launcherSource, /proc_pidinfo/u);
    assert.match(launcherSource, /mapped_dev == expected_dev && mapped_ino == expected_ino/u);
    assert.match(launcherSource, /AUTHENTICATED_HANDSHAKE_MARKER/u);
    assert.match(launcherSource, /AUTHENTICATED_HANDSHAKE_ENVIRONMENT/u);
    assert.match(launcherSource, /import\{isMainThread\}from'node:worker_threads'/u);
    assert.match(launcherSource, /if\(!isMainThread\)process\.exit\(125\)/u);
    assert.match(launcherSource, /process\.execArgv\.shift\(\)/u);
    assert.match(launcherSource, /SecureRandom\.hex\(32\)/u);
    assert.match(launcherSource, /handshake_reader, handshake_writer = IO\.pipe/u);
    assert.match(launcherSource, /reader\.read_nonblock/u);
    assert.match(launcherSource, /handshake_deadline = Process\.clock_gettime/u);
    assert.match(launcherSource, /wait_for_suspended_child\(child_pid, handshake_deadline\)/u);
    assert.match(launcherSource, /Process\.waitpid2\(pid, Process::WUNTRACED\)/u);
    assert.match(supportSource, /authenticatedNodeArgumentsAreValid/u);
    assert.match(launcherSource, /valid_node_arguments/u);
    assert.doesNotMatch(launcherSource, /File::CREAT \| File::EXCL/u);
  });

  test('Ruby launcher requires live sandbox denials and preserves authorised profile bytes', async () => {
    const launcherSource = await readFile(
      resolve(repositoryRoot, 'scripts/authenticated-node-launcher.rb'),
      'utf8',
    );
    assert.match(
      launcherSource,
      /result = check\.call\(pid, operation_pointer, filter, value_pointer\)\n    reject unless result\.positive\?/u,
    );
    const exactProfileHelper = [
      'def sandbox_profile_for(profile, node_path)',
      '  escaped_node = seatbelt_literal(node_path)',
      '  reject unless profile.include?("(literal \\"#{escaped_node}\\")")',
      '  profile',
      'end',
    ].join('\n');
    assert.ok(launcherSource.includes(exactProfileHelper));
    assert.match(
      launcherSource,
      /sandbox_handshake_preload\(handshake_descriptor, handshake_nonce\)/u,
    );
    const profileHashCheck = launcherSource.indexOf(
      'Digest::SHA256.hexdigest(sandbox_profile) == sandbox_sha256',
    );
    const profileLaunch = launcherSource.indexOf(
      'sandbox_handshake_preload(handshake_descriptor, handshake_nonce),',
    );
    assert.notEqual(profileHashCheck, -1);
    assert.notEqual(profileLaunch, -1);
    assert.ok(profileHashCheck < profileLaunch);
  });
}
