import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import { canonicalArchitectureJson } from '../../scripts/architecture-gate-schema.mjs';
import {
  assertAuthenticatedToolchainReceipt,
  assertAuthenticatedToolchainClosureCounts,
  authenticatePinnedRegularSystemInput,
  authenticateSystemOpenSslConfig,
  architectureArchiveDestination,
  authenticatedToolchainPaths,
  createAuthenticatedToolchainContextSha256,
  noForkToolSandbox,
  pnpmStoreSandbox,
  systemOpenSslConfigPin,
} from '../../scripts/architecture-toolchain-prepare.mjs';
import {
  architectureToolchainPins,
  architectureToolchainPinsSha256,
  pinnedNpmDuplicateExceptionsSha256,
  pinnedNpmLegacyPaxExceptionsSha256,
} from '../../scripts/architecture-toolchain-trust.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const systemOpenSslConfig = Object.freeze({
  ctimeNs: '1700000000000000000',
  dev: '16777233',
  gid: systemOpenSslConfigPin.gid,
  ino: '140860839',
  mode: systemOpenSslConfigPin.mode,
  mtimeNs: '1700000000000000001',
  nlink: systemOpenSslConfigPin.nlink,
  path: systemOpenSslConfigPin.path,
  sha256: systemOpenSslConfigPin.sha256,
  size: systemOpenSslConfigPin.size,
  type: systemOpenSslConfigPin.type,
  uid: systemOpenSslConfigPin.uid,
});
const witness = Object.freeze({
  cargoArchives: 520,
  cargoLockSha256: sha('cargo-lock'),
  npmArchives: 868,
  pnpmLocksSha256: Object.freeze([sha('root-lock'), sha('sidecar-lock')]),
  systemOpenSslConfig,
});

test('authenticated toolchain paths expose the exact pinned target objcopy helper', () => {
  const isolateRoot = '/private/tmp/piui-authenticated-toolchain-fixture';
  const paths = authenticatedToolchainPaths(isolateRoot);
  assert.equal(
    paths.rustObjcopy,
    `${isolateRoot}/authenticated-toolchain/rust-toolchain/lib/rustlib/`
      + 'aarch64-apple-darwin/bin/rust-objcopy',
  );
  assert.equal(paths.rustObjcopy.startsWith(`${paths.rustToolchain}/`), true);
});

function receiptFixture() {
  return {
    cargoArchives: witness.cargoArchives,
    cargoLockSha256: witness.cargoLockSha256,
    nodeArchiveSha256: architectureToolchainPins.node.digest,
    nodeExecutableSha256: architectureToolchainPins.node.executableSha256,
    npmArchives: witness.npmArchives,
    pnpmArchiveSha512: architectureToolchainPins.pnpm.digest,
    pnpmLocksSha256: [...witness.pnpmLocksSha256],
    pnpmValidationDuplicateExceptionsSha256: pinnedNpmDuplicateExceptionsSha256,
    pnpmValidationLegacyPaxExceptionsSha256: pinnedNpmLegacyPaxExceptionsSha256,
    rustChannelManifestSha256: architectureToolchainPins.rustChannel.manifestSha256,
    rustComponentsSha256: architectureToolchainPins.rust.map((item) => item.digest),
    schemaVersion: 1,
    systemOpenSslConfig,
    target: 'aarch64-apple-darwin',
    toolchainPinsSha256: architectureToolchainPinsSha256,
  };
}

function receiptBytes(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

function mutate(value) {
  if (typeof value === 'number') return value + 1;
  if (Array.isArray(value)) {
    const changed = [...value];
    changed[0] = sha(`mutated-${changed[0]}`);
    return changed;
  }
  if (value && typeof value === 'object') {
    return { ...value, ctimeNs: String(BigInt(value.ctimeNs) + 1n) };
  }
  return value === 'aarch64-apple-darwin'
    ? 'x86_64-apple-darwin'
    : `${value.slice(0, -1)}${value.endsWith('0') ? '1' : '0'}`;
}

test('authenticated toolchain receipt accepts only the exact complete pin object', () => {
  const receipt = receiptFixture();
  assert.deepEqual(
    assertAuthenticatedToolchainReceipt(receiptBytes(receipt), witness),
    receipt,
  );

  for (const key of Object.keys(receipt)) {
    const missing = receiptFixture();
    delete missing[key];
    assert.throws(
      () => assertAuthenticatedToolchainReceipt(receiptBytes(missing), witness),
      /exact closure pins/u,
      `missing ${key}`,
    );

    const changed = receiptFixture();
    changed[key] = mutate(changed[key]);
    assert.throws(
      () => assertAuthenticatedToolchainReceipt(receiptBytes(changed), witness),
      /exact closure pins/u,
      `changed ${key}`,
    );
  }

  assert.throws(
    () => assertAuthenticatedToolchainReceipt(receiptBytes({
      ...receipt,
      unexpected: true,
    }), witness),
    /exact closure pins/u,
  );
});

test('authenticated toolchain context binds receipt, complete inventory and metadata lease', () => {
  const receiptSha256 = sha('receipt');
  const input = Object.freeze({
    entries: 42,
    inventorySha256: sha('inventory'),
    leaseSha256: sha('lease'),
  });
  const baseline = createAuthenticatedToolchainContextSha256(
    receiptSha256,
    input,
    systemOpenSslConfig,
  );
  for (const changed of [
    { ...input, entries: input.entries + 1 },
    { ...input, inventorySha256: sha('changed-inventory') },
    { ...input, leaseSha256: sha('changed-lease') },
  ]) {
    assert.notEqual(
      createAuthenticatedToolchainContextSha256(
        receiptSha256,
        changed,
        systemOpenSslConfig,
      ),
      baseline,
    );
  }
  assert.notEqual(
    createAuthenticatedToolchainContextSha256(
      sha('changed-receipt'),
      input,
      systemOpenSslConfig,
    ),
    baseline,
  );
  assert.notEqual(
    createAuthenticatedToolchainContextSha256(receiptSha256, input, {
      ...systemOpenSslConfig,
      ctimeNs: String(BigInt(systemOpenSslConfig.ctimeNs) + 1n),
    }),
    baseline,
  );
  assert.throws(
    () => createAuthenticatedToolchainContextSha256(receiptSha256, {
      ...input,
      unexpected: true,
    }, systemOpenSslConfig),
    /input witness is invalid/u,
  );
});

test('authenticated toolchain validation closes aggregate and unique lock counts', () => {
  const exact = Object.freeze({
    cargoArchives: 520,
    npmArchives: 868,
    npmLockRecords: 1_005,
  });
  assert.deepEqual(assertAuthenticatedToolchainClosureCounts(exact), exact);
  for (const key of Object.keys(exact)) {
    assert.throws(
      () => assertAuthenticatedToolchainClosureCounts({
        ...exact,
        [key]: exact[key] - 1,
      }),
      /frozen lock counts are not exact/u,
      `changed ${key}`,
    );
  }
  assert.throws(
    () => assertAuthenticatedToolchainReceipt(receiptBytes(receiptFixture()), {
      ...witness,
      npmArchives: 846,
    }),
    /receipt witness is invalid/u,
  );
  const { systemOpenSslConfig: omitted, ...missingSystemOpenSslConfig } = witness;
  assert.ok(omitted);
  assert.throws(
    () => assertAuthenticatedToolchainReceipt(
      receiptBytes(receiptFixture()),
      missingSystemOpenSslConfig,
    ),
    /receipt witness is invalid/u,
  );
});

function fixturePin(bytes, overrides = {}) {
  return Object.freeze({
    gid: typeof process.getgid === 'function' ? process.getgid() : 0,
    mode: 0o644,
    nlink: 1,
    sha256: sha(bytes),
    size: bytes.length,
    type: 'regular-file',
    uid: typeof process.getuid === 'function' ? process.getuid() : 0,
    ...overrides,
  });
}

test('system OpenSSL input authentication rejects byte, mode, owner, link and swap attacks', async (t) => {
  const root = await mkdtemp(resolve(await realpath(tmpdir()), 'piui-system-input.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const trustedBytes = Buffer.from('trusted-input\n', 'utf8');
  const pin = fixturePin(trustedBytes);

  const acceptedPath = resolve(root, 'accepted.cnf');
  await writeFile(acceptedPath, trustedBytes, { flag: 'wx', mode: 0o644 });
  const accepted = await authenticatePinnedRegularSystemInput({ path: acceptedPath, pin });
  assert.equal(accepted.path, acceptedPath);
  assert.equal(accepted.sha256, pin.sha256);

  const wrongBytesPath = resolve(root, 'wrong-bytes.cnf');
  await writeFile(wrongBytesPath, Buffer.from('hostile-input\n'), { flag: 'wx', mode: 0o644 });
  await assert.rejects(
    authenticatePinnedRegularSystemInput({ path: wrongBytesPath, pin }),
    /bytes are invalid/u,
  );

  const wrongModePath = resolve(root, 'wrong-mode.cnf');
  await writeFile(wrongModePath, trustedBytes, { flag: 'wx', mode: 0o644 });
  await chmod(wrongModePath, 0o600);
  await assert.rejects(
    authenticatePinnedRegularSystemInput({ path: wrongModePath, pin }),
    /identity is invalid/u,
  );

  const wrongOwnerPath = resolve(root, 'wrong-owner.cnf');
  await writeFile(wrongOwnerPath, trustedBytes, { flag: 'wx', mode: 0o644 });
  await assert.rejects(
    authenticatePinnedRegularSystemInput({
      path: wrongOwnerPath,
      pin: fixturePin(trustedBytes, { uid: pin.uid + 1 }),
    }),
    /identity is invalid/u,
  );

  const hardLinkPath = resolve(root, 'hard-link.cnf');
  await writeFile(hardLinkPath, trustedBytes, { flag: 'wx', mode: 0o644 });
  await link(hardLinkPath, resolve(root, 'hard-link-alias.cnf'));
  await assert.rejects(
    authenticatePinnedRegularSystemInput({ path: hardLinkPath, pin }),
    /identity is invalid/u,
  );

  const linkTarget = resolve(root, 'link-target.cnf');
  const symbolicLinkPath = resolve(root, 'symbolic-link.cnf');
  await writeFile(linkTarget, trustedBytes, { flag: 'wx', mode: 0o644 });
  await symlink(linkTarget, symbolicLinkPath);
  await assert.rejects(
    authenticatePinnedRegularSystemInput({ path: symbolicLinkPath, pin }),
  );

  const swapPath = resolve(root, 'swap.cnf');
  await writeFile(swapPath, trustedBytes, { flag: 'wx', mode: 0o644 });
  await assert.rejects(
    authenticatePinnedRegularSystemInput({
      path: swapPath,
      pin,
      testHook: async () => {
        await rename(swapPath, resolve(root, 'swap-held.cnf'));
        await writeFile(swapPath, trustedBytes, { flag: 'wx', mode: 0o644 });
      },
    }),
    /changed during authentication/u,
  );

  const host = await authenticateSystemOpenSslConfig();
  assert.equal(host.path, systemOpenSslConfigPin.path);
  assert.equal(host.sha256, systemOpenSslConfigPin.sha256);
});

test('no-fork tool sandbox exposes only the exact authenticated OpenSSL config path', () => {
  const profile = noForkToolSandbox({
    cargoBin: '/private/tmp/piui-no-fork/rust/bin',
    closureRoot: '/private/tmp/piui-no-fork/closure',
    node: '/private/tmp/piui-no-fork/node',
    systemOpenSslConfig,
  });
  assert.match(profile, /\(literal "\/private\/etc\/ssl\/openssl\.cnf"\)/u);
  assert.doesNotMatch(profile, /\(subpath "\/private\/etc/u);
  assert.doesNotMatch(profile, /\(allow file-write/u);
  assert.match(profile, /\(deny network\*\)/u);
  assert.match(profile, /\(deny process-fork\)/u);
  assert.doesNotMatch(profile, /\(allow signal/u);
});

test('no-fork tool probes retain one finite load-tolerant deadline', async () => {
  const source = await readFile(
    new URL('../../scripts/architecture-toolchain-prepare.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /const NO_FORK_TOOL_PROBE_TIMEOUT_MS = 120_000;/u);
  assert.equal(
    (source.match(/timeoutM?s?: NO_FORK_TOOL_PROBE_TIMEOUT_MS/gu) ?? []).length,
    3,
  );
});

test('private archive names preserve pnpm tarball detection without weakening other namespaces', () => {
  const root = '/private/tmp/piui-toolchain-fixture/authenticated-toolchain';
  assert.equal(
    architectureArchiveDestination(root, { digest: 'a'.repeat(128), kind: 'npm' }),
    `${root}/npm-archives/${'a'.repeat(128)}.tgz`,
  );
  assert.equal(
    architectureArchiveDestination(root, { digest: 'b'.repeat(64), kind: 'cargo' }),
    `${root}/crate-archives/${'b'.repeat(64)}.archive`,
  );
  assert.equal(
    architectureArchiveDestination(root, { digest: 'c'.repeat(64), kind: 'node' }),
    `${root}/pinned-archives/${'c'.repeat(64)}.archive`,
  );
});

test('pnpm store sandbox can resolve its exact cwd without granting cwd writes', () => {
  const working = '/private/tmp/piui-toolchain-fixture/pnpm-store-control';
  const profile = pnpmStoreSandbox({
    archives: '/private/tmp/piui-toolchain-fixture/npm-archives',
    home: `${working}/home`,
    node: '/private/tmp/piui-toolchain-fixture/node',
    pnpmRoot: '/private/tmp/piui-toolchain-fixture/pnpm',
    store: '/private/tmp/piui-toolchain-fixture/store',
    temporary: `${working}/tmp`,
    working,
  });
  assert.match(profile, new RegExp(`\\(subpath "${working}"\\)`, 'u'));
  const writeAuthority = profile.slice(profile.indexOf('(allow file-write*'));
  assert.doesNotMatch(
    writeAuthority,
    new RegExp(`\\(subpath "${working}"\\)`, 'u'),
  );
  assert.match(writeAuthority, new RegExp(`\\(subpath "${working}/home"\\)`, 'u'));
  assert.match(writeAuthority, new RegExp(`\\(subpath "${working}/tmp"\\)`, 'u'));
  assert.match(profile, /\(deny network\*\)/u);
  assert.match(profile, /\(deny process-fork\)/u);
  assert.doesNotMatch(profile, /\(allow signal/u);
});
