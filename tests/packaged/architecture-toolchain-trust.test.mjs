import assert from 'node:assert/strict';
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  rm,
  writeFile,
} from 'node:fs/promises';
import { chmodSync, renameSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';
import {
  architectureCacheEntryPath,
  parsePnpmLocks,
  pinnedNpmDuplicateExceptions,
  pinnedNpmDuplicateExceptionsSha256,
  pinnedNpmLegacyPaxExceptions,
  pinnedNpmLegacyPaxExceptionsSha256,
  processTrustedGzipTar,
} from '../../scripts/architecture-toolchain-trust.mjs';

const duplicateTableSha256 = 'd9d4d393f2dcf8b4aa65204a9a407af82fad2eeb6e037088c334cf3ac907c04f';
const legacyPaxTableSha256 = '4cba4ed3cef1c952a284a2ebe0df9c7b359812ea4a7a775fab305c65a523f19b';

function octal(value, width) {
  return `${value.toString(8).padStart(width - 1, '0')}\0`;
}

function tarRecord({
  bytes = Buffer.from('fixture\n', 'utf8'),
  gid = 0,
  mode = 0o644,
  mtime = 499_162_500,
  name,
  type = '0',
  uid = 0,
  uidBytes,
}) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  header.write(octal(mode, 8), 100, 8, 'ascii');
  if (uidBytes) uidBytes.copy(header, 108);
  else header.write(octal(uid, 8), 108, 8, 'ascii');
  header.write(octal(gid, 8), 116, 8, 'ascii');
  header.write(octal(bytes.length, 12), 124, 12, 'ascii');
  header.write(octal(mtime, 12), 136, 12, 'ascii');
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return Buffer.concat([
    header,
    bytes,
    Buffer.alloc(Math.ceil(bytes.length / 512) * 512 - bytes.length),
  ]);
}

function base256(value, width) {
  const bytes = Buffer.alloc(width);
  let remaining = BigInt(value);
  for (let index = width - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n || (bytes[0] & 0x40) !== 0) throw new Error('Fixture base-256 value is out of range');
  bytes[0] |= 0x80;
  return bytes;
}

function paxRecord(key, value) {
  const body = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(body) + 1;
  while (true) {
    const candidate = `${length}${body}`;
    const actual = Buffer.byteLength(candidate);
    if (actual === length) return candidate;
    length = actual;
  }
}

function paxPayload(fields) {
  return Buffer.from(fields.map(([key, value]) => paxRecord(key, value)).join(''), 'utf8');
}

function gzipTar(records) {
  return gzipSync(Buffer.concat([...records, Buffer.alloc(1_024)]), { level: 9, mtime: 0 });
}

async function privateFixture(t, name, bytes) {
  const root = await mkdtemp(resolve(tmpdir(), 'piui-toolchain-trust.'));
  t.after(async () => rm(root, { force: true, recursive: true }));
  const path = resolve(root, name);
  await writeFile(path, bytes, { flag: 'wx', mode: 0o400 });
  return { path, root };
}

test('duplicate-entry exception table is closed, sorted and bound to the frozen locks', async () => {
  assert.equal(pinnedNpmDuplicateExceptions.length, 10);
  assert.equal(pinnedNpmDuplicateExceptionsSha256, duplicateTableSha256);
  assert.equal(pinnedNpmLegacyPaxExceptions.length, 1);
  assert.equal(pinnedNpmLegacyPaxExceptionsSha256, legacyPaxTableSha256);
  assert.deepEqual(
    pinnedNpmDuplicateExceptions.map((entry) => entry.archiveSha512),
    pinnedNpmDuplicateExceptions.map((entry) => entry.archiveSha512).toSorted(),
  );
  assert.equal(new Set(pinnedNpmDuplicateExceptions.map((entry) => entry.archiveSha512)).size, 10);
  assert.equal(
    pinnedNpmDuplicateExceptions.some(
      (entry) => entry.package === 'data-uri-to-buffer' && entry.version === '4.0.1',
    ),
    false,
  );
  const locks = await parsePnpmLocks(resolve(import.meta.dirname, '../..'));
  for (const exception of pinnedNpmDuplicateExceptions) {
    assert.equal(
      locks.some((entry) => entry.name === exception.package
        && entry.version === exception.version
        && entry.digest === exception.archiveSha512),
      true,
    );
  }
});

test('all ten exact upstream duplicate pairs validate only without extraction', async (t) => {
  const missing = [];
  for (const exception of pinnedNpmDuplicateExceptions) {
    try {
      await lstat(architectureCacheEntryPath({ algorithm: 'sha512', digest: exception.archiveSha512 }));
    } catch (error) {
      if (error?.code === 'ENOENT') missing.push(exception.archiveSha512);
      else throw error;
    }
  }
  if (missing.length > 0) {
    t.skip('Provisioned architecture cache is not present');
    return;
  }
  for (const exception of pinnedNpmDuplicateExceptions) {
    const path = architectureCacheEntryPath({ algorithm: 'sha512', digest: exception.archiveSha512 });
    const inspected = await processTrustedGzipTar(path, {
      label: `${exception.package}@${exception.version}`,
      maxExpandedBytes: 64 * 1_048_576,
      pinnedDuplicateArchiveSha512: exception.archiveSha512,
      singleTopLevel: true,
    });
    assert.equal(inspected.topLevel, 'package');
    await assert.rejects(
      processTrustedGzipTar(path, {
        destination: resolve(tmpdir(), 'must-not-be-created'),
        label: `${exception.package}@${exception.version}`,
        mapEntry: () => false,
        maxExpandedBytes: 64 * 1_048_576,
        pinnedDuplicateArchiveSha512: exception.archiveSha512,
      }),
      /validation-only duplicate exception/u,
    );
  }
});

test('all 847 frozen npm archives pass the repeatable cache-backed validation walk', async (t) => {
  const locks = await parsePnpmLocks(resolve(import.meta.dirname, '../..'));
  const missing = [];
  for (const archive of locks) {
    try {
      await lstat(architectureCacheEntryPath(archive));
    } catch (error) {
      if (error?.code === 'ENOENT') missing.push(archive.digest);
      else throw error;
    }
  }
  if (missing.length > 0) {
    t.skip('Provisioned architecture cache is not present');
    return;
  }
  const exceptions = new Map(
    pinnedNpmDuplicateExceptions.map((entry) => [entry.archiveSha512, entry]),
  );
  const legacyPaxExceptions = new Map(
    pinnedNpmLegacyPaxExceptions.map((entry) => [entry.archiveSha512, entry]),
  );
  for (const archive of locks) {
    const exception = exceptions.get(archive.digest);
    const legacyPaxException = legacyPaxExceptions.get(archive.digest);
    await processTrustedGzipTar(architectureCacheEntryPath(archive), {
      label: `${archive.name}@${archive.version}`,
      maxEntries: 100_000,
      maxExpandedBytes: 512 * 1_048_576,
      pinnedDuplicateArchiveSha512: exception?.archiveSha512,
      pinnedLegacyPaxArchiveSha512: legacyPaxException?.archiveSha512,
      singleTopLevel: true,
    });
  }
  assert.equal(locks.length, 847);
});

test('generic dot paths and forged opt-in archives remain rejected', async (t) => {
  const exception = pinnedNpmDuplicateExceptions[0];
  const payload = Buffer.alloc(exception.size, 0x61);
  const forged = gzipTar([
    tarRecord({ bytes: payload, name: exception.firstName }),
    tarRecord({ bytes: payload, name: exception.secondName }),
  ]);
  const { path } = await privateFixture(t, 'forged.tgz', forged);
  await assert.rejects(
    processTrustedGzipTar(path, { maxExpandedBytes: 16 * 1_048_576 }),
    /escaping archive path/u,
  );
  await assert.rejects(
    processTrustedGzipTar(path, {
      maxExpandedBytes: 16 * 1_048_576,
      pinnedDuplicateArchiveSha512: exception.archiveSha512,
    }),
    /payload bytes changed|exact pin-scoped duplicate exception/u,
  );
});

test('duplicate exception rejects changed order, metadata and a third record', async (t) => {
  const exception = pinnedNpmDuplicateExceptions[0];
  const payload = Buffer.alloc(exception.size, 0x61);
  const variants = [
    gzipTar([
      tarRecord({ bytes: payload, name: exception.secondName }),
      tarRecord({ bytes: payload, name: exception.firstName }),
    ]),
    gzipTar([
      tarRecord({ bytes: payload, mode: 0o600, name: exception.firstName }),
      tarRecord({ bytes: payload, name: exception.secondName }),
    ]),
    gzipTar([
      tarRecord({ bytes: payload, name: exception.firstName }),
      tarRecord({ bytes: payload, name: exception.secondName }),
      tarRecord({ bytes: payload, name: exception.secondName }),
    ]),
  ];
  for (const [index, bytes] of variants.entries()) {
    const { path } = await privateFixture(t, `variant-${index}.tgz`, bytes);
    await assert.rejects(
      processTrustedGzipTar(path, {
        maxExpandedBytes: 32 * 1_048_576,
        pinnedDuplicateArchiveSha512: exception.archiveSha512,
      }),
      /pin-scoped duplicate exception|payload bytes changed/u,
    );
  }
});

test('archive lease rejects writable, multiply-linked and path-ABA inputs', async (t) => {
  const ordinary = gzipTar([tarRecord({ name: 'package/index.js' })]);
  const writable = await privateFixture(t, 'writable.tgz', ordinary);
  await chmod(writable.path, 0o660);
  await assert.rejects(processTrustedGzipTar(writable.path), /unique regular archive/u);

  const linked = await privateFixture(t, 'linked.tgz', ordinary);
  await link(linked.path, resolve(linked.root, 'second-link.tgz'));
  await assert.rejects(processTrustedGzipTar(linked.path), /unique regular archive/u);

  const aba = await privateFixture(t, 'aba.tgz', ordinary);
  const replacement = resolve(aba.root, 'replacement.tgz');
  await writeFile(replacement, ordinary, { flag: 'wx', mode: 0o400 });
  let swapped = false;
  await assert.rejects(
    processTrustedGzipTar(aba.path, {
      mapEntry: () => {
        if (!swapped) {
          swapped = true;
          renameSync(aba.path, resolve(aba.root, 'held-original.tgz'));
          renameSync(replacement, aba.path);
          chmodSync(aba.path, 0o400);
          writeFileSync(resolve(aba.root, 'swap-observed'), 'yes\n', { flag: 'wx', mode: 0o400 });
        }
        return false;
      },
    }),
    /identity changed during streaming inspection/u,
  );
  assert.equal(swapped, true);
});

test('PAX overrides are bounded and cannot introduce extraction semantics', async (t) => {
  const payload = Buffer.from('fixture\n', 'utf8');
  const variants = [
    paxPayload([
      ['path', `package/${'a'.repeat(1_020)}`],
      ['size', String(payload.length)],
    ]),
    paxPayload([
      ['NODETAR.package.description', 'a'.repeat(1_025)],
      ['path', 'package/index.js'],
      ['size', String(payload.length)],
    ]),
    paxPayload([
      ['linkpath', '../../outside'],
      ['path', 'package/index.js'],
      ['size', String(payload.length)],
    ]),
    paxPayload([
      ['gid', '2'],
      ['path', 'package/index.js'],
      ['size', String(payload.length)],
      ['uid', '1'],
    ]),
  ];
  for (const [index, pax] of variants.entries()) {
    const archive = gzipTar([
      tarRecord({ bytes: pax, name: 'PaxHeader/package/index.js', type: 'x' }),
      tarRecord({ bytes: payload, name: 'package/index.js' }),
    ]);
    const { path } = await privateFixture(t, `hostile-pax-${index}.tgz`, archive);
    await assert.rejects(
      processTrustedGzipTar(path, { maxExpandedBytes: 4 * 1_048_576 }),
      /PAX|unsafe archive path/u,
    );
  }
});

test('base-256 tar numbers are accepted only for the exact validation-only legacy pin', async (t) => {
  const generic = await privateFixture(t, 'base256-generic.tgz', gzipTar([
    tarRecord({ name: 'package/index.js', uidBytes: base256(2_805_947, 8) }),
  ]));
  await assert.rejects(
    processTrustedGzipTar(generic.path, { singleTopLevel: true }),
    /base-256 tar number outside its exact pin/u,
  );

  const negative = Buffer.alloc(8, 0xff);
  const unsafe = Buffer.alloc(8, 0xff);
  unsafe[0] = 0x80;
  for (const [index, uidBytes] of [negative, unsafe].entries()) {
    const fixture = await privateFixture(t, `base256-hostile-${index}.tgz`, gzipTar([
      tarRecord({ name: 'package/index.js', uidBytes }),
    ]));
    await assert.rejects(
      processTrustedGzipTar(fixture.path),
      /negative base-256|unsafe base-256/u,
    );
  }
});

function splitTarRecords(bytes) {
  const records = [];
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const size = Number.parseInt(header.subarray(124, 136).toString('ascii').replace(/\0.*$/su, '').trim(), 8);
    const length = 512 + Math.ceil(size / 512) * 512;
    records.push(Buffer.from(bytes.subarray(offset, offset + length)));
    offset += length;
  }
  return records;
}

function refreshTarChecksum(record) {
  record.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of record.subarray(0, 512)) checksum += byte;
  record.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
}

test('legacy PAX exception rejects reordered, extra, missing and changed records', async (t) => {
  const exception = pinnedNpmLegacyPaxExceptions[0];
  const cachePath = architectureCacheEntryPath({
    algorithm: 'sha512',
    digest: exception.archiveSha512,
  });
  try {
    await lstat(cachePath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      t.skip('Provisioned architecture cache is not present');
      return;
    }
    throw error;
  }
  const compressed = await readFile(cachePath);
  const records = splitTarRecords(gunzipSync(compressed));
  assert.equal(records.length, exception.archiveEntries);
  const changedHeader = records.map((record) => Buffer.from(record));
  base256(2_805_948, 8).copy(changedHeader[0], 108);
  refreshTarChecksum(changedHeader[0]);
  const changedPayload = records.map((record) => Buffer.from(record));
  changedPayload[0][512] ^= 0x01;
  const variants = [
    [records[1], records[0], ...records.slice(2)],
    [...records, records[0]],
    records.slice(1),
    changedHeader,
    changedPayload,
  ];
  for (const [index, variant] of variants.entries()) {
    const bytes = gzipSync(Buffer.concat([...variant, Buffer.alloc(1_024)]), { level: 9, mtime: 0 });
    const fixture = await privateFixture(t, `legacy-pax-hostile-${index}.tgz`, bytes);
    await assert.rejects(
      processTrustedGzipTar(fixture.path, {
        maxExpandedBytes: 4 * 1_048_576,
        pinnedLegacyPaxArchiveSha512: exception.archiveSha512,
      }),
      /legacy PAX|exact pin/u,
    );
  }
  await assert.rejects(
    processTrustedGzipTar(cachePath, {
      destination: resolve(tmpdir(), 'legacy-pax-must-not-extract'),
      mapEntry: () => false,
      pinnedLegacyPaxArchiveSha512: exception.archiveSha512,
    }),
    /validation-only legacy PAX exception/u,
  );
});
