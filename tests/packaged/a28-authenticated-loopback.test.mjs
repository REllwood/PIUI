import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  mkdtemp,
  realpath,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  authoriseAuthenticatedNodeSandboxProfile,
  configureAuthenticatedNodeSpawn,
  runOwnedCommand,
} from '../../scripts/a21-gate-support.mjs';
import { snapshotArchitectureSource } from '../../scripts/architecture-source-snapshot.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from '../../scripts/authenticated-node-spawn.mjs';
import { a28WdioSandbox } from '../../scripts/run-packaged-accessibility-probe.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const suppliedNode = process.env.PIUI_AUTHENTICATED_NODE_TEST_PATH;

test('authenticated A.28 runner permits only its exact IPv4 loopback port', {
  skip: process.platform !== 'darwin' || !suppliedNode
    ? 'Authenticated macOS Node witness is unavailable'
    : false,
  timeout: 120_000,
}, async (t) => {
  const nodePath = await realpath(suppliedNode);
  const runRoot = await realpath(await mkdtemp(resolve(tmpdir(), 'piui-a28-loopback.')));
  await chmod(runRoot, 0o700);
  t.after(async () => rm(runRoot, { force: true, recursive: true }));

  configureAuthenticatedNodeSpawn(await createAuthenticatedNodeSpawnConfiguration({
    nodePath,
    snapshot: await snapshotArchitectureSource(repositoryRoot),
    sourceRoot: repositoryRoot,
  }));
  const port = 54_321;
  const bundle = Object.freeze({
    appPath: resolve(runRoot, 'automation-twin.app'),
    hostPath: resolve(runRoot, 'automation-twin.app/Contents/MacOS/PIUI'),
    nodePath: resolve(runRoot, 'automation-twin.app/Contents/Resources/sidecar/node'),
  });
  const profile = a28WdioSandbox({
    bundle,
    controlRoot: resolve(runRoot, 'control'),
    evidenceRoot: resolve(runRoot, 'human-evidence'),
    port,
    repositoryRoot,
    runRoot,
    runnerPath: nodePath,
  });
  authoriseAuthenticatedNodeSandboxProfile({
    command: nodePath,
    policy: Object.freeze({
      expectedProfileSha256: createHash('sha256').update(profile).digest('hex'),
      hostPath: bundle.hostPath,
      kind: 'a28-loopback',
      nodePath: bundle.nodePath,
      port,
      runnerPath: nodePath,
    }),
    profile,
  });

  const source = `
    const net = require('node:net');
    const port = ${port};
    const attempt = (options) => new Promise((resolveAttempt) => {
      const socket = net.createConnection(options);
      const finish = (value) => {
        socket.removeAllListeners();
        socket.destroy();
        resolveAttempt(value);
      };
      socket.setTimeout(2000, () => finish('timeout'));
      socket.once('connect', () => finish('connected'));
      socket.once('error', (error) => finish(error.code));
    });
    const bind = (host, selectedPort) => new Promise((resolveBind) => {
      const candidate = net.createServer();
      candidate.once('error', (error) => resolveBind(error.code));
      candidate.listen({ exclusive: true, host, port: selectedPort }, () => {
        candidate.close(() => resolveBind('bound'));
      });
    });
    const server = net.createServer((socket) => socket.end());
    server.once('error', (error) => {
      process.stderr.write(String(error.code) + '\\n');
      process.exitCode = 1;
    });
    server.listen({ exclusive: true, host: '127.0.0.1', port }, async () => {
      const evidence = {
        exact: await attempt({ family: 4, host: '127.0.0.1', port }),
        ipv6: await attempt({ family: 6, host: '::1', port }),
        nonLoopback: await attempt({ family: 4, host: '203.0.113.1', port }),
        offPortBind: await bind('127.0.0.1', port + 1),
        offPortConnect: await attempt({ family: 4, host: '127.0.0.1', port: port + 1 }),
      };
      server.close(() => process.stdout.write(JSON.stringify(evidence) + '\\n'));
    });
  `;
  const result = await runOwnedCommand({
    args: ['-e', source],
    command: nodePath,
    cwd: runRoot,
    env: {
      HOME: runRoot,
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
      TMPDIR: `${runRoot}/`,
    },
    label: 'Authenticated A.28 exact IPv4 loopback witness',
    sandboxProfile: profile,
    timeoutMs: 30_000,
  });
  assert.equal(result.status, 0, result.stderr.toString('utf8'));
  assert.equal(result.signal, null);
  assert.equal(result.stderr.length, 0);
  const evidence = JSON.parse(result.stdout.toString('utf8'));
  assert.equal(evidence.exact, 'connected');
  for (const key of ['ipv6', 'nonLoopback', 'offPortBind', 'offPortConnect']) {
    assert.ok(
      ['EACCES', 'EPERM'].includes(evidence[key]),
      `${key} was not denied: ${evidence[key]}`,
    );
  }
});
