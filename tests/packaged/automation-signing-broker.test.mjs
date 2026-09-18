import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  awaitAutomationSigningBrokerResponse,
  publishAutomationSigningBrokerRequest,
  requestAutomationHostSigning,
  runAutomationSigningBrokerChild,
  startAutomationSigningBroker,
} from '../../scripts/automation-signing-broker.mjs';
import {
  configureAuthenticatedNodeSpawn,
  createAuthenticatedNodeAutomationSigningBrokerSandboxProfile,
  runOwnedCommand,
} from '../../scripts/a21-gate-support.mjs';
import {
  automationHostSigningPolicy,
  automationSigningKeychainPath,
} from '../../scripts/automation-host-signing.mjs';
import { createAuthenticatedNodeSpawnConfiguration } from '../../scripts/authenticated-node-spawn.mjs';
import { canonicalArchitectureJson, sha256Bytes } from '../../scripts/architecture-gate-schema.mjs';
import { snapshotArchitectureSource } from '../../scripts/architecture-source-snapshot.mjs';
import {
  APPLE_TOOLCHAIN_PATHS,
  appleToolchainBuildEnvironment,
  captureAppleToolchainAuthority,
  releaseAppleToolchainAuthority,
  revalidateAppleToolchainAuthority,
} from '../../scripts/apple-toolchain-trust.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const brokerScript = resolve(repositoryRoot, 'scripts/automation-signing-broker.mjs');
const suppliedNode = process.env.PIUI_AUTHENTICATED_NODE_TEST_PATH;

function digest(label) {
  return createHash('sha256').update(label).digest('hex');
}

function evidenceFor(bytes) {
  const executableSha256 = sha256Bytes(bytes);
  const codeDirectorySha256 = digest('code-directory');
  const requirementsSha256 = digest('requirements');
  const cmsSha256 = digest('cms');
  return Object.freeze({
    bundleIdentifier: automationHostSigningPolicy.bundleIdentifier,
    cdHash: codeDirectorySha256.slice(0, 40),
    certificateSha1: automationHostSigningPolicy.certificateSha1,
    certificateSha256: automationHostSigningPolicy.certificateSha256,
    cmsBytes: 64,
    cmsSha256,
    codeDirectoryFlags: 0,
    codeDirectorySha256,
    designatedRequirement: automationHostSigningPolicy.designatedRequirement,
    entitlements: 'none',
    executableBytes: bytes.length,
    executableSha256,
    nonCmsSignatureSha256: digest('non-cms'),
    requirementsSha256,
    schemaVersion: 1,
    signature: 'apple-development',
    signatureContainerBytes: 300,
    signatureSlots: Object.freeze([
      Object.freeze({ sha256: codeDirectorySha256, size: 32, slot: 0 }),
      Object.freeze({ sha256: requirementsSha256, size: 136, slot: 2 }),
      Object.freeze({ sha256: cmsSha256, size: 64, slot: 0x10000 }),
    ]),
    teamIdentifier: automationHostSigningPolicy.teamIdentifier,
  });
}

async function fixture(label = 'broker') {
  const temporary = await realpath(tmpdir());
  const root = await realpath(await mkdtemp(resolve(temporary, `piui-${label}.`)));
  await chmod(root, 0o700);
  const controlRoot = resolve(root, 'control');
  const verificationRoot = resolve(controlRoot, 'verification');
  await mkdir(controlRoot, { mode: 0o700 });
  await mkdir(verificationRoot, { mode: 0o700 });
  const hostPath = resolve(root, 'host');
  const unsignedBytes = Buffer.alloc(512, 0x31);
  const signedBytes = Buffer.alloc(512, 0x73);
  await writeFile(hostPath, unsignedBytes, { flag: 'wx', mode: 0o700 });
  await chmod(hostPath, 0o700);
  const hostState = await stat(hostPath, { bigint: true });
  const nonce = digest(`nonce:${label}`);
  const host = Object.freeze({
    dev: hostState.dev.toString(),
    ino: hostState.ino.toString(),
    mode: Number(hostState.mode & 0o7777n),
    size: Number(hostState.size),
    unsignedSha256: sha256Bytes(unsignedBytes),
  });
  const request = Object.freeze({
    host,
    hostPath,
    nonce,
    schemaVersion: 1,
    type: 'automation-signing-request',
  });
  const contract = Object.freeze({
    nonce,
    request,
    requestPath: resolve(controlRoot, `request-${nonce}.json`),
    responsePath: resolve(controlRoot, `response-${nonce}.json`),
    schemaVersion: 1,
  });
  const configuration = Object.freeze({
    controlRoot,
    host,
    hostPath,
    nonce,
    requestTimeoutMs: 5_000,
    verificationRoot,
  });
  const replaceHost = async () => {
    const oldPath = resolve(root, 'held-unsigned-host');
    await rename(hostPath, oldPath);
    await writeFile(hostPath, signedBytes, { flag: 'wx', mode: host.mode });
    await chmod(hostPath, host.mode);
    await unlink(oldPath);
  };
  return Object.freeze({
    configuration,
    contract,
    controlRoot,
    hostPath,
    nonce,
    replaceHost,
    root,
    signedBytes,
    unsignedBytes,
    verificationRoot,
  });
}

function fakeDependencies(item, overrides = {}) {
  return Object.freeze({
    applySignature: async () => item.replaceHost(),
    authenticateAuthority: async () => Object.freeze({ test: true }),
    inspectHost: async () => evidenceFor(item.signedBytes),
    ...overrides,
  });
}

async function runFixtureTransaction(item, dependencies = fakeDependencies(item)) {
  const running = runAutomationSigningBrokerChild(item.configuration, dependencies);
  const settled = running.then(
    (value) => Object.freeze({ value }),
    (error) => Object.freeze({ error }),
  );
  await publishAutomationSigningBrokerRequest(item.contract);
  const outcome = await settled;
  if (outcome.error) throw outcome.error;
  return outcome.value;
}

test('one-use broker consumes one canonical request and publishes one bound response', async () => {
  const item = await fixture('broker-happy');
  try {
    const response = await runFixtureTransaction(item);
    assert.equal(response.nonce, item.nonce);
    assert.equal(response.hostPath, item.hostPath);
    assert.equal(response.requestSha256, sha256Bytes(Buffer.from(
      `${canonicalArchitectureJson(item.contract.request)}\n`,
    )));
    assert.equal(response.signedHost.sha256, sha256Bytes(item.signedBytes));
    assert.deepEqual((await readFile(item.contract.requestPath, 'utf8')),
      `${canonicalArchitectureJson(item.contract.request)}\n`);
    assert.deepEqual((await readFile(item.contract.responsePath, 'utf8')),
      `${canonicalArchitectureJson(response)}\n`);
    assert.ok(await stat(resolve(item.controlRoot, `consumed-${item.nonce}.json`)));
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('broker rejects request replay and a second broker for the consumed nonce', async () => {
  const item = await fixture('broker-replay');
  try {
    await runFixtureTransaction(item);
    await assert.rejects(
      publishAutomationSigningBrokerRequest(item.contract),
    );
    await assert.rejects(
      runAutomationSigningBrokerChild(item.configuration, fakeDependencies(item)),
      /Automation signing broker rejected/u,
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('broker rejects a second host path or unsigned hash in the request', async () => {
  const item = await fixture('broker-request-swap');
  try {
    const wrongRequest = Object.freeze({
      ...item.contract.request,
      hostPath: resolve(item.root, 'other-host'),
      host: Object.freeze({
        ...item.contract.request.host,
        unsignedSha256: digest('wrong-host'),
      }),
    });
    const wrongContract = Object.freeze({ ...item.contract, request: wrongRequest });
    const running = runAutomationSigningBrokerChild(
      item.configuration,
      fakeDependencies(item),
    ).then(
      (value) => Object.freeze({ value }),
      (error) => Object.freeze({ error }),
    );
    await publishAutomationSigningBrokerRequest(wrongContract);
    const outcome = await running;
    assert.match(outcome.error?.message ?? '', /Automation signing broker rejected/u);
    await assert.rejects(stat(item.contract.responsePath), { code: 'ENOENT' });
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('broker rejects request pathname replacement after exclusive consumption', async () => {
  const item = await fixture('broker-request-aba');
  try {
    const replaced = resolve(item.controlRoot, 'replaced-request.json');
    const dependencies = fakeDependencies(item, {
      authenticateAuthority: async () => {
        await rename(item.contract.requestPath, replaced);
        await writeFile(item.contract.requestPath, `${canonicalArchitectureJson(item.contract.request)}\n`, {
          flag: 'wx',
          mode: 0o600,
        });
        return Object.freeze({ test: true });
      },
    });
    await assert.rejects(
      runFixtureTransaction(item, dependencies),
      /Automation signing broker rejected/u,
    );
    await assert.rejects(stat(item.contract.responsePath), { code: 'ENOENT' });
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('broker rejects host pathname replacement after binding its unsigned descriptor', async () => {
  const item = await fixture('broker-host-aba');
  try {
    const dependencies = fakeDependencies(item, {
      authenticateAuthority: async () => {
        await item.replaceHost();
        return Object.freeze({ test: true });
      },
    });
    await assert.rejects(
      runFixtureTransaction(item, dependencies),
      /Automation signing broker rejected/u,
    );
    await assert.rejects(stat(item.contract.responsePath), { code: 'ENOENT' });
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

async function authenticatedConfiguration(nodePath) {
  return createAuthenticatedNodeSpawnConfiguration({
    nodePath,
    snapshot: await snapshotArchitectureSource(repositoryRoot),
    sourceRoot: repositoryRoot,
  });
}

test('broker sandbox is instance-bound and rejects unauthorised profile mutation', {
  skip: !suppliedNode && 'PIUI_AUTHENTICATED_NODE_TEST_PATH is unavailable',
}, async () => {
  const item = await fixture('broker-profile');
  try {
    const nodePath = await realpath(suppliedNode);
    const nodeConfiguration = await authenticatedConfiguration(nodePath);
    configureAuthenticatedNodeSpawn(nodeConfiguration);
    const profile = createAuthenticatedNodeAutomationSigningBrokerSandboxProfile({
      brokerScript,
      command: nodePath,
      controlRoot: item.controlRoot,
      hostPath: item.hostPath,
      keychainPath: automationSigningKeychainPath(),
      nonce: item.nonce,
      verificationRoot: item.verificationRoot,
    });
    for (const expected of [
      item.contract.requestPath,
      item.contract.responsePath,
      resolve(item.controlRoot, `consumed-${item.nonce}.json`),
      automationSigningKeychainPath(),
      '/usr/bin/codesign',
      '/usr/bin/security',
    ]) assert.ok(profile.includes(expected));
    assert.equal((profile.match(/\(allow mach-lookup/gu) ?? []).length, 1);
    assert.equal((profile.match(/\(deny network\*\)/gu) ?? []).length, 1);
    const result = await runOwnedCommand({
      args: ['-e', "process.stdout.write('broker-profile-ok\\n')"],
      command: nodePath,
      cwd: '/',
      env: {
        HOME: process.env.HOME,
        LANG: 'en_AU.UTF-8',
        LC_ALL: 'en_AU.UTF-8',
        PATH: '/usr/bin:/bin',
      },
      label: 'Automation-signing broker sandbox profile probe',
      sandboxProfile: profile,
      timeoutMs: 30_000,
    });
    assert.equal(result.status, 0, result.stderr.toString('utf8'));
    assert.equal(result.stderr.length, 0);
    assert.equal(result.stdout.toString('utf8'), 'broker-profile-ok\n');
    await assert.rejects(
      runOwnedCommand({
        args: ['-e', "process.stdout.write('unexpected\\n')"],
        command: nodePath,
        cwd: '/',
        env: {
          HOME: process.env.HOME,
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        label: 'Mutated automation-signing broker sandbox probe',
        sandboxProfile: `${profile}\n(allow default)`,
        timeoutMs: 30_000,
      }),
      /sandbox profile was not authorised/u,
    );

    for (const mutated of [
      profile.replace(
        '(global-name "com.apple.trustd.agent")',
        '(global-name "com.apple.coreservices.appleevents")',
      ),
      profile.replace(
        '(literal "/usr/bin/codesign")',
        '(literal "/bin/sh")\n    (literal "/usr/bin/codesign")',
      ),
    ]) {
      const ruby = spawnSync('/usr/bin/ruby', [
        '--disable-gems',
        '-e',
        nodeConfiguration.launcherSource,
        '--',
        nodeConfiguration.node.path,
        nodeConfiguration.node.dev,
        nodeConfiguration.node.ino,
        String(nodeConfiguration.node.size),
        nodeConfiguration.node.sha256,
        '',
        '--sandbox-profile',
        sha256Bytes(Buffer.from(mutated)),
        Buffer.from(mutated).toString('base64'),
        '--sandbox-policy',
        `automation-signing-broker:${item.nonce}`,
        '--node-args',
        '-e',
        '',
      ], {
        cwd: '/',
        encoding: 'utf8',
        env: {
          HOME: process.env.HOME,
          LANG: 'en_AU.UTF-8',
          LC_ALL: 'en_AU.UTF-8',
          PATH: '/usr/bin:/bin',
        },
        maxBuffer: 256 * 1024,
        timeout: 30_000,
      });
      assert.notEqual(ruby.status, 0);
    }
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test('authenticated sibling broker signs and independently inspects one real host', {
  skip: process.platform !== 'darwin'
    || !suppliedNode
    || process.env.PIUI_RUN_LIVE_AUTOMATION_SIGNING_BROKER !== '1'
    ? 'Explicit authenticated macOS broker witness was not requested'
    : false,
  timeout: 120_000,
}, async () => {
  const item = await fixture('broker-live');
  try {
    const authority = captureAppleToolchainAuthority();
    let compile;
    try {
      compile = spawnSync(APPLE_TOOLCHAIN_PATHS.clang, [
        '--no-default-config',
        '-arch', 'arm64',
        '-isysroot', APPLE_TOOLCHAIN_PATHS.sdk,
        '-x', 'c',
        '-',
        '-o', item.hostPath,
      ], {
        encoding: 'utf8',
        env: {
          ...appleToolchainBuildEnvironment(),
          LANG: 'C',
          LC_ALL: 'C',
          PATH: `${APPLE_TOOLCHAIN_PATHS.bin}:/usr/bin:/bin`,
        },
        input: 'int main(void) { return 0; }\n',
        maxBuffer: 256 * 1024,
        timeout: 30_000,
      });
      revalidateAppleToolchainAuthority(authority);
    } finally {
      releaseAppleToolchainAuthority(authority);
    }
    assert.equal(compile.status, 0, compile.stderr);
    await chmod(item.hostPath, 0o700);
    const nodePath = await realpath(suppliedNode);
    configureAuthenticatedNodeSpawn(await authenticatedConfiguration(nodePath));
    const session = await startAutomationSigningBroker({
      command: nodePath,
      controlRoot: item.controlRoot,
      hostPath: item.hostPath,
      nonce: digest('live-broker-nonce'),
      requestTimeoutMs: 60_000,
      timeoutMs: 90_000,
    });
    const response = await requestAutomationHostSigning(session);
    assert.equal(response.state, 'signed');
    assert.equal(response.signingEvidence.certificateSha1,
      automationHostSigningPolicy.certificateSha1);
    assert.equal(response.signingEvidence.executableSha256, response.signedHost.sha256);
    await assert.rejects(
      requestAutomationHostSigning(session),
      /already consumed/u,
    );
    assert.deepEqual(
      await awaitAutomationSigningBrokerResponse(session),
      response,
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});
