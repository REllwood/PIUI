import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, openSync } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  buildSandboxFor,
  preparePinnedNodeTool,
} from '../../scripts/package-spike.mjs';
import {
  architectureCacheEntryPath,
  architectureToolchainPins,
} from '../../scripts/architecture-toolchain-trust.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sortPaths = (values) => [...new Set(values)].sort((left, right) => (
  Buffer.from(left).compare(Buffer.from(right))
));

test('formal package and guarded-production profiles use canonical bsdtar only', async () => {
  for (const name of [
    'build-production.mjs',
    'fetch-node-runtime.mjs',
    'package-spike.mjs',
  ]) {
    const source = await readFile(resolve(repositoryRoot, 'scripts', name), 'utf8');
    assert.match(source, /['"]\/usr\/bin\/bsdtar['"]/u);
    assert.doesNotMatch(source, /['"]\/usr\/bin\/tar['"]/u);
  }

  const fetchSource = await readFile(
    resolve(repositoryRoot, 'scripts/fetch-node-runtime.mjs'),
    'utf8',
  );
  const packageRecord = JSON.parse(await readFile(resolve(repositoryRoot, 'package.json'), 'utf8'));
  assert.equal(
    packageRecord.scripts['test:packaged:inspection'],
    'node scripts/provision-node-runtime.mjs && node --test tests/packaged/*.test.mjs',
  );
  const packageSpikeSource = await readFile(
    resolve(repositoryRoot, 'scripts/package-spike.mjs'),
    'utf8',
  );
  assert.match(
    packageSpikeSource,
    /const source = architectureCacheEntryPath\(architectureToolchainPins\.node\)/u,
  );
  assert.doesNotMatch(
    packageSpikeSource,
    /resolve\(repositoryRoot, '\.cache\/node-runtime'/u,
  );
  const nodeProvisionerSource = await readFile(
    resolve(repositoryRoot, 'scripts/provision-node-runtime.mjs'),
    'utf8',
  );
  const architectureProvisionerSource = await readFile(
    resolve(repositoryRoot, 'scripts/provision-architecture-toolchain.mjs'),
    'utf8',
  );
  assert.match(
    nodeProvisionerSource,
    /provisionNodeArchitectureArchive\(\)/u,
  );
  assert.match(
    nodeProvisionerSource,
    /async function isDirectInvocation\(\)[\s\S]+return await realpath\(process\.argv\[1\]\) === await realpath\(provisionerPath\);[\s\S]+const directlyInvoked = await isDirectInvocation\(\);[\s\S]+if \(directlyInvoked\) await runNodeRuntimeProvisioner\(\);/u,
  );
  assert.doesNotMatch(architectureProvisionerSource, /process\.umask\(/u);
  assert.match(
    architectureProvisionerSource,
    /const deadlineSignal = AbortSignal\.timeout\(DOWNLOAD_DEADLINE_MS\);[\s\S]+request\([\s\S]+deadlineSignal[\s\S]+for await \(const chunk of response\)/u,
  );
  assert.match(
    architectureProvisionerSource,
    /while \(offset < chunk\.length\)[\s\S]+handle\.write\([\s\S]+position \+ offset[\s\S]+offset \+= bytesWritten/u,
  );
  assert.match(
    architectureProvisionerSource,
    /constants\.O_RDWR \| constants\.O_CREAT \| constants\.O_EXCL \| constants\.O_NOFOLLOW/u,
  );
  assert.match(
    architectureProvisionerSource,
    /authenticateHeldTemporary\([\s\S]+await link\(temporary, destination\)[\s\S]+sameFileIdentity\(authenticated, heldAfterPublication\)/u,
  );
  assert.doesNotMatch(fetchSource, /response\.arrayBuffer\(\)/u);
  assert.doesNotMatch(fetchSource, /writeFile\(archive/u);
  assert.match(fetchSource, /AbortSignal\.timeout\(DOWNLOAD_TIMEOUT_MS\)/u);
  assert.match(
    fetchSource,
    /constants\.O_RDWR \| constants\.O_CREAT \| constants\.O_EXCL \| constants\.O_NOFOLLOW/u,
  );
  assert.match(
    fetchSource,
    /const promotedSha256 = descriptorSha256\(descriptor, bytes\.length\);[\s\S]+!sameState\(promoted, verified\)[\s\S]+!sameState\(verified, verifiedPath\)/u,
  );
  for (const diagnostic of [
    'Disk quota exceeded',
    'No space left on device',
    'Operation not permitted',
    'Permission denied',
  ]) {
    assert.equal(fetchSource.includes(diagnostic), true);
  }
});

test('provisioner modules are import-safe and preserve the importer umask', async () => {
  const before = process.umask();
  const architectureModule = await import(
    new URL('../../scripts/provision-architecture-toolchain.mjs', import.meta.url),
  );
  const nodeModule = await import(
    new URL('../../scripts/provision-node-runtime.mjs', import.meta.url),
  );
  assert.equal(process.umask(), before);
  assert.equal(typeof architectureModule.provisionNodeArchitectureArchive, 'function');
  assert.equal(typeof nodeModule.runNodeRuntimeProvisioner, 'function');

  const importedPath = new URL('../../scripts/provision-node-runtime.mjs', import.meta.url).href;
  const importProbe = spawnSync(process.execPath, [
    '--input-type=module',
    '--eval',
    `process.argv[1] = '/private/tmp/piui-missing-provisioner-entry';
const before = process.umask();
await import(${JSON.stringify(importedPath)});
process.stdout.write(process.umask() === before ? 'unchanged\\n' : 'changed\\n');`,
  ], {
    encoding: 'utf8',
    maxBuffer: 1 * 1_048_576,
  });
  assert.equal(importProbe.status, 0, importProbe.stderr);
  assert.equal(importProbe.signal, null);
  assert.equal(importProbe.stdout, 'unchanged\n');
  assert.equal(importProbe.stderr, '');
});

test('downloads, publishes, and provisions pinned Node while preserving the generated inode', async (t) => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    t.skip('arm64 macOS sandbox-exec is required');
    return;
  }

  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(join(canonicalTemporaryRoot, 'piui-node-provisioning-test.'));
  const sourceRoot = resolve(root, 'source');
  const scriptsRoot = resolve(sourceRoot, 'scripts');
  const cacheParent = resolve(sourceRoot, '.cache');
  const cacheRoot = resolve(cacheParent, 'node-runtime');
  const tauriRoot = resolve(sourceRoot, 'src-tauri');
  const binariesRoot = resolve(tauriRoot, 'binaries');
  const home = resolve(root, 'home');
  const temporary = resolve(root, 'tmp');
  const mutableDirectories = [
    root,
    sourceRoot,
    scriptsRoot,
    cacheParent,
    cacheRoot,
    tauriRoot,
    binariesRoot,
    home,
    temporary,
  ];
  t.after(async () => {
    for (const path of mutableDirectories) {
      try {
        await chmod(path, 0o700);
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
    await rm(root, { force: true, recursive: true });
  });

  for (const path of [scriptsRoot, cacheRoot, binariesRoot, home, temporary]) {
    await mkdir(path, { mode: 0o700, recursive: true });
  }
  for (const name of [
    'architecture-gate-schema.mjs',
    'architecture-toolchain-trust.mjs',
    'fetch-node-runtime.mjs',
    'node-checksums.json',
  ]) {
    const destination = resolve(scriptsRoot, name);
    await copyFile(resolve(repositoryRoot, 'scripts', name), destination);
    await chmod(destination, 0o400);
  }

  const pin = architectureToolchainPins.node;
  const archive = resolve(cacheRoot, pin.filename);
  const archiveFixture = architectureCacheEntryPath(pin);
  const downloadPreload = resolve(scriptsRoot, 'node-download-preload.mjs');
  await writeFile(downloadPreload, `
import { readFile } from 'node:fs/promises';

const source = process.env.PIUI_NODE_DOWNLOAD_FIXTURE;
if (!source) throw new Error('Node download fixture is absent');
const bytes = await readFile(source);
globalThis.fetch = async (url, options = {}) => {
  if (url !== '${pin.url}'
    || options.redirect !== 'error'
    || !(options.signal instanceof AbortSignal)) {
    throw new Error('Node download request contract changed');
  }
  return {
    body: new ReadableStream({
      start(controller) {
        const chunkBytes = 64 * 1_048_576;
        for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
          controller.enqueue(bytes.subarray(offset, Math.min(offset + chunkBytes, bytes.length)));
        }
        controller.close();
      },
    }),
    headers: {
      get(name) {
        return name.toLowerCase() === 'content-length' ? String(bytes.length) : null;
      },
    },
    ok: true,
    status: 200,
  };
};
`, { mode: 0o400 });
  const output = resolve(binariesRoot, 'piui-node-aarch64-apple-darwin');
  await writeFile(output, Buffer.alloc(0), { mode: 0o600 });
  const outputBefore = await lstat(output, { bigint: true });

  const canonicalTar = '/usr/bin/bsdtar';
  const tarState = await lstat(canonicalTar);
  assert.equal(await realpath(canonicalTar), canonicalTar);
  assert.equal(tarState.isFile() && !tarState.isSymbolicLink(), true);
  assert.equal(tarState.uid, 0);
  assert.equal(tarState.mode & 0o022, 0);

  const pinnedNode = await preparePinnedNodeTool(root);
  for (const path of [scriptsRoot, cacheParent, tauriRoot, binariesRoot]) {
    await chmod(path, 0o500);
  }
  const writableRoots = sortPaths([cacheRoot, home, temporary]);
  const profile = buildSandboxFor({
    authenticatedCommand: pinnedNode.node,
    executableFiles: sortPaths([canonicalTar, pinnedNode.node]),
    executableRoots: [],
    readableFiles: sortPaths([
      archiveFixture,
      canonicalTar,
      '/dev/null',
      '/dev/random',
      '/dev/urandom',
      '/dev/zero',
      '/private/etc/localtime',
      '/private/var/select/sh',
      ...pinnedNode.nodeRuntimeFiles,
    ]),
    readableRoots: sortPaths([
      sourceRoot,
      dirname(pinnedNode.node),
      '/Library/Apple/System/Library',
      '/System/Library',
      '/private/var/db/timezone',
      '/usr/lib',
      '/usr/share/zoneinfo',
      ...writableRoots,
    ]),
    writableFiles: sortPaths([output, ...writableRoots]),
    writableRoots,
  });
  assert.match(profile, /\(literal "\/usr\/bin\/bsdtar"\)/u);
  assert.doesNotMatch(profile, /\/usr\/bin\/tar/u);

  const sandboxArguments = [
    pinnedNode.node,
    '--import',
    downloadPreload,
    resolve(scriptsRoot, 'fetch-node-runtime.mjs'),
    '--held-output-fd',
  ];
  const environment = {
    CFFIXED_USER_HOME: home,
    HOME: home,
    LANG: 'en_AU.UTF-8',
    LC_ALL: 'en_AU.UTF-8',
    PATH: `${dirname(pinnedNode.node)}:/usr/bin:/bin:/usr/sbin:/sbin`,
    PIUI_NODE_DOWNLOAD_FIXTURE: archiveFixture,
    TMPDIR: `${temporary}/`,
  };

  const outputDescriptor = openSync(
    output,
    constants.O_RDWR | constants.O_NOFOLLOW,
  );
  assert.ok(outputDescriptor >= 3 && outputDescriptor <= 255);
  const childStdio = Array.from(
    { length: outputDescriptor + 1 },
    (_, descriptor) => (descriptor === 0 ? 'ignore' : descriptor < 3 ? 'pipe' : 'ignore'),
  );
  childStdio[outputDescriptor] = outputDescriptor;
  const deniedProfile = buildSandboxFor({
    authenticatedCommand: pinnedNode.node,
    executableFiles: sortPaths([pinnedNode.node]),
    executableRoots: [],
    readableFiles: sortPaths([
      archiveFixture,
      canonicalTar,
      '/dev/null',
      '/dev/random',
      '/dev/urandom',
      '/dev/zero',
      '/private/etc/localtime',
      '/private/var/select/sh',
      ...pinnedNode.nodeRuntimeFiles,
    ]),
    readableRoots: sortPaths([
      sourceRoot,
      dirname(pinnedNode.node),
      '/Library/Apple/System/Library',
      '/System/Library',
      '/private/var/db/timezone',
      '/usr/lib',
      '/usr/share/zoneinfo',
      ...writableRoots,
    ]),
    writableFiles: sortPaths([output, ...writableRoots]),
    writableRoots,
  });
  let result;
  try {
    const denied = spawnSync('/usr/bin/sandbox-exec', [
      '-p',
      deniedProfile,
      ...sandboxArguments,
      String(outputDescriptor),
    ], {
      cwd: sourceRoot,
      encoding: 'utf8',
      env: environment,
      maxBuffer: 1 * 1_048_576,
      stdio: childStdio,
    });
    assert.equal(denied.status, 1);
    assert.equal(denied.signal, null);
    assert.match(denied.stderr, /Node archive extraction failed \(sandbox-denial\)/u);
    assert.doesNotMatch(denied.stderr, /subprocess-failure/u);

    const publishedArchive = await lstat(archive, { bigint: true });
    assert.equal(publishedArchive.isFile() && !publishedArchive.isSymbolicLink(), true);
    assert.equal(publishedArchive.nlink, 1n);
    assert.equal(publishedArchive.size, BigInt(pin.maxBytes));
    assert.equal(publishedArchive.mode & 0o777n, 0o600n);
    assert.equal(
      createHash('sha256').update(await readFile(archive)).digest('hex'),
      pin.digest,
    );

    result = spawnSync('/usr/bin/sandbox-exec', [
      '-p',
      profile,
      ...sandboxArguments,
      String(outputDescriptor),
    ], {
      cwd: sourceRoot,
      encoding: 'utf8',
      env: {
        ...environment,
        PIUI_NODE_OFFLINE: '1',
      },
      maxBuffer: 1 * 1_048_576,
      stdio: childStdio,
    });
  } finally {
    closeSync(outputDescriptor);
  }
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, '');
  assert.equal(
    result.stdout,
    `Bundled official Node v22.23.1 (${pin.digest}; executable ${pin.executableSha256})\n`,
  );

  const outputAfter = await lstat(output, { bigint: true });
  assert.equal(outputAfter.dev, outputBefore.dev);
  assert.equal(outputAfter.ino, outputBefore.ino);
  assert.equal(outputAfter.nlink, 1n);
  assert.equal(outputAfter.size, 112_928_848n);
  assert.equal(outputAfter.mode & 0o777n, 0o755n);
  assert.equal(
    createHash('sha256').update(await readFile(output)).digest('hex'),
    pin.executableSha256,
  );
  assert.deepEqual(await readdir(cacheRoot), [pin.filename]);
  assert.deepEqual(await readdir(binariesRoot), ['piui-node-aarch64-apple-darwin']);
});
