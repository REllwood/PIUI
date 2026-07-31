import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, readdir, realpath } from 'node:fs/promises';
import { basename, dirname, posix, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';

export const SIDECAR_ROOT = 'Contents/Resources/resources/sidecar';
export const SIDECAR_MANIFEST = `${SIDECAR_ROOT}/manifest.json`;
export const HOST_PATH = 'Contents/MacOS/piui';
export const NODE_PATH = 'Contents/MacOS/piui-node';
const INFO_PATH = 'Contents/Info.plist';
const FORBIDDEN_NAMES = /^(?:\.env(?:\..*)?|\.npmrc|\.netrc|\.git-credentials|auth\.json|credentials\.json|id_(?:rsa|ecdsa|ed25519)|.*\.(?:p12|pfx|pem|key|mobileprovision))$/i;
const SECRET_TEXT = /(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+|\b(?:apple|github|npm|updater|openai|anthropic|aws|azure|google)[_-]+(?:api[_-]?key|token|password|secret|private[_-]?key)\s*[=:]\s*[^\s"']+)/i;
const MACHO_64_LE_BYTES = 0xcffaedfe;
const UNSUPPORTED_THIN_MACHO_MAGICS = new Set([
  0xcefaedfe, // 32-bit little-endian
  0xfeedface, // 32-bit big-endian
  0xfeedfacf, // 64-bit big-endian
]);
const FAT_MAGICS = new Set([0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]);
const CPU_TYPE_ARM64 = 0x0100000c;
const LC_CODE_SIGNATURE = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSMAGIC_BLOBWRAPPER = 0xfade0b01;
const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_SIGNATURESLOT = 0x10000;
const CS_ADHOC = 0x2;

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function safeRelative(root, path) {
  const value = relative(root, path);
  if (!value || value === '..' || value.startsWith(`..${sep}`) || resolve(root, value) !== path) {
    throw new Error(`Bundle path escaped its root: ${value || '.'}`);
  }
  return value.split(sep).join('/');
}

function assertModeAndAcl(path, label, item) {
  if ((item.mode & 0o6000) !== 0) throw new Error(`set-id mode forbidden in bundle: ${label}`);
  if ((item.mode & 0o022) !== 0) throw new Error(`group/world writable bundle entry: ${label}`);
  const acl = spawnSync('/bin/ls', ['-lde', path], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (acl.status !== 0) throw new Error(`Could not inspect ACL for ${label}`);
  if ((acl.stdout.split('\n')[0] ?? '').split(/\s+/)[0]?.endsWith('+')) throw new Error(`ACL forbidden in bundle: ${label}`);
}

function inspectXattrs(path, label) {
  const listed = spawnSync('/usr/bin/xattr', [path], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (listed.status !== 0) throw new Error(`Could not inspect extended attributes for ${label}`);
  const names = listed.stdout.split(/\r?\n/).filter(Boolean).sort();
  if (names.some((name) => name !== 'com.apple.provenance')) {
    throw new Error(`Extended attributes/resource forks forbidden in bundle: ${label}`);
  }
  if (!names.length) return null;
  const value = spawnSync('/usr/bin/xattr', ['-px', 'com.apple.provenance', path], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (value.status !== 0 || !/^(?:[0-9a-fA-F]{2}\s*)+$/.test(value.stdout)) {
    throw new Error(`Could not read provenance attribute for ${label}`);
  }
  return value.stdout.replace(/\s+/g, '').toLowerCase();
}

export async function inventoryBundle(appPath) {
  const requested = resolve(appPath);
  const requestedStat = await lstat(requested);
  if (requestedStat.isSymbolicLink() || !requestedStat.isDirectory()) throw new Error('Bundle root must be a real directory, not a symlink');
  const root = await realpath(requested);
  const canonicalStat = await lstat(root);
  if (canonicalStat.dev !== requestedStat.dev || canonicalStat.ino !== requestedStat.ino) throw new Error('Bundle root identity changed during canonicalisation');
  assertModeAndAcl(root, '.', canonicalStat);
  const rootProvenance = inspectXattrs(root, '.');
  const entries = [];
  async function visit(directory) {
    const directoryBefore = await lstat(directory);
    const directoryHandle = await open(
      directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const openedDirectory = await directoryHandle.stat();
    if (!openedDirectory.isDirectory()
      || openedDirectory.dev !== directoryBefore.dev
      || openedDirectory.ino !== directoryBefore.ino) {
      await directoryHandle.close();
      throw new Error('Bundle directory changed before traversal');
    }
    try {
      const children = await readdir(directory, { withFileTypes: true });
      children.sort((a, b) => Buffer.from(a.name).compare(Buffer.from(b.name)));
      for (const child of children) {
        const path = resolve(directory, child.name);
        const rel = safeRelative(root, path);
        const item = await lstat(path);
        if (item.isSymbolicLink()) throw new Error(`Symlink forbidden in bundle: ${rel}`);
        if (!item.isFile() && !item.isDirectory()) throw new Error(`Special file forbidden in bundle: ${rel}`);
        assertModeAndAcl(path, rel, item);
        const provenance = inspectXattrs(path, rel);
        if (item.isDirectory()) {
          entries.push({ path: `${rel}/`, kind: 'directory', mode: item.mode & 0o777, bytes: 0, sha256: null, provenance, dev: item.dev, ino: item.ino });
          await visit(path);
        } else {
          if (item.nlink !== 1) throw new Error(`Hard-linked file forbidden in bundle: ${rel}`);
          const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
          try {
            const opened = await handle.stat();
            if (!opened.isFile() || opened.nlink !== 1
              || opened.dev !== item.dev || opened.ino !== item.ino
              || opened.size !== item.size || opened.mode !== item.mode) {
              throw new Error(`Bundle file changed before inspection: ${rel}`);
            }
            const bytes = await handle.readFile();
            const after = await handle.stat();
            const pathAfter = await lstat(path);
            if (after.dev !== opened.dev || after.ino !== opened.ino
              || after.size !== opened.size || after.mode !== opened.mode
              || pathAfter.isSymbolicLink() || pathAfter.dev !== opened.dev
              || pathAfter.ino !== opened.ino || pathAfter.size !== opened.size
              || pathAfter.mode !== opened.mode || bytes.length !== opened.size) {
              throw new Error(`Bundle file changed while inspected: ${rel}`);
            }
            entries.push({ path: rel, kind: 'file', mode: item.mode & 0o777, bytes: bytes.length, sha256: sha256(bytes), provenance, dev: item.dev, ino: item.ino });
          } finally {
            await handle.close();
          }
        }
      }
      const directoryAfter = await directoryHandle.stat();
      const directoryPathAfter = await lstat(directory);
      if (directoryAfter.dev !== openedDirectory.dev
        || directoryAfter.ino !== openedDirectory.ino
        || directoryAfter.mode !== openedDirectory.mode
        || directoryPathAfter.isSymbolicLink()
        || directoryPathAfter.dev !== openedDirectory.dev
        || directoryPathAfter.ino !== openedDirectory.ino
        || directoryPathAfter.mode !== openedDirectory.mode) {
        throw new Error('Bundle directory changed during traversal');
      }
    } finally {
      await directoryHandle.close();
    }
  }
  await visit(root);
  const rootAfter = await lstat(root);
  if (rootAfter.isSymbolicLink() || rootAfter.dev !== canonicalStat.dev
    || rootAfter.ino !== canonicalStat.ino || rootAfter.mode !== canonicalStat.mode) {
    throw new Error('Bundle root changed during inventory');
  }
  entries.sort((a, b) => Buffer.from(a.path).compare(Buffer.from(b.path)));
  const fingerprintEntries = entries.map(({ dev: _dev, ino: _ino, ...entry }) => entry);
  return {
    root,
    rootIdentity: Object.freeze({ dev: canonicalStat.dev, ino: canonicalStat.ino }),
    entries,
    rootProvenance,
    fingerprint: sha256(Buffer.from(JSON.stringify({ rootProvenance, entries: fingerprintEntries }))),
  };
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) throw new Error(`${label} fields are not exact`);
}

export function parseStrictManifest(bytes, expectedNode = '22.23.1', expectedPi = '0.82.0') {
  let manifest;
  try { manifest = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('Sidecar manifest is not valid JSON'); }
  exactKeys(manifest, ['closure', 'files', 'node', 'piSdk'], 'Sidecar manifest');
  if (manifest.node !== expectedNode || manifest.piSdk !== expectedPi || manifest.closure !== 'isolated-v1' || !Array.isArray(manifest.files)) {
    throw new Error('Sidecar manifest pins/schema do not match the architecture gate');
  }
  const seen = new Set();
  let previous;
  for (const entry of manifest.files) {
    exactKeys(entry, ['bytes', 'path', 'sha256'], 'Sidecar manifest file');
    if (typeof entry.path !== 'string' || entry.path.includes('\\') || entry.path.startsWith('/') || posix.normalize(entry.path) !== entry.path || entry.path === '.' || entry.path.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error('Manifest contains non-canonical path');
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error('Manifest contains invalid file metadata');
    if (entry.path === 'manifest.json' || seen.has(entry.path)) throw new Error('Manifest contains duplicate/reserved path');
    if (previous !== undefined && Buffer.from(previous).compare(Buffer.from(entry.path)) >= 0) throw new Error('Manifest paths are not strictly byte-sorted');
    seen.add(entry.path);
    previous = entry.path;
  }
  return Object.freeze({ ...manifest, files: Object.freeze(manifest.files.map((entry) => Object.freeze({ ...entry }))) });
}

export async function captureStageAnchors({ sidecarRoot, nodePath, expectedNode, expectedPi }) {
  const manifestPath = resolve(sidecarRoot, 'manifest.json');
  const manifestBytes = await readFile(manifestPath);
  const manifest = parseStrictManifest(manifestBytes, expectedNode, expectedPi);
  const actual = [];
  async function walk(directory) {
    for (const name of (await readdir(directory)).sort((a, b) => Buffer.from(a).compare(Buffer.from(b)))) {
      const path = resolve(directory, name);
      const item = await lstat(path);
      if (item.isSymbolicLink() || (!item.isFile() && !item.isDirectory())) throw new Error('Staging anchor contains unsafe entry');
      if (item.isDirectory()) await walk(path);
      else actual.push(safeRelative(sidecarRoot, path));
    }
  }
  await walk(sidecarRoot);
  const expected = ['manifest.json', ...manifest.files.map((entry) => entry.path)].sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  actual.sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('Staged sidecar file set does not equal its manifest');
  for (const entry of manifest.files) {
    const bytes = await readFile(resolve(sidecarRoot, entry.path));
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) throw new Error('Staged sidecar manifest hash mismatch');
  }
  const nodeBytes = await readFile(nodePath);
  return Object.freeze({ manifestBytes, manifestSha256: sha256(manifestBytes), manifest, nodeSha256: sha256(nodeBytes), nodeBytes: nodeBytes.length });
}

function machoMagic(bytes) {
  if (bytes.length < 4) return null;
  const be = bytes.readUInt32BE(0);
  if (FAT_MAGICS.has(be)) return 'fat';
  if (UNSUPPORTED_THIN_MACHO_MAGICS.has(be)) return 'unsupported-thin';
  return be === MACHO_64_LE_BYTES ? 'thin64-le' : null;
}

export function inspectMachOBytes(bytes) {
  const magic = machoMagic(bytes);
  if (magic === null) return null;
  if (magic === 'fat') throw new Error('Universal/fat Mach-O forbidden in arm64-only bundle');
  if (magic === 'unsupported-thin') throw new Error('Unsupported 32-bit or byte-swapped Mach-O forbidden in arm64-only bundle');
  if (bytes.length < 32 || bytes.readUInt32LE(4) !== CPU_TYPE_ARM64) throw new Error('Non-arm64 Mach-O forbidden in bundle');
  const commands = bytes.readUInt32LE(16);
  const commandsBytes = bytes.readUInt32LE(20);
  if (commands > 4096 || commandsBytes > bytes.length - 32) throw new Error('Malformed Mach-O load commands');
  let cursor = 32;
  let signature;
  for (let index = 0; index < commands; index += 1) {
    if (cursor + 8 > bytes.length) throw new Error('Truncated Mach-O command');
    const command = bytes.readUInt32LE(cursor);
    const size = bytes.readUInt32LE(cursor + 4);
    if (size < 8 || cursor + size > 32 + commandsBytes) throw new Error('Malformed Mach-O command size');
    if (command === LC_CODE_SIGNATURE) {
      if (signature) throw new Error('Duplicate Mach-O code-signature command');
      if (size < 16) throw new Error('Malformed Mach-O code-signature command');
      signature = { offset: bytes.readUInt32LE(cursor + 8), size: bytes.readUInt32LE(cursor + 12) };
    }
    cursor += size;
  }
  if (!signature) return Object.freeze({ architecture: 'arm64', signature: 'none', cms: false, adhoc: false });
  if (signature.size < 8 || signature.offset + signature.size > bytes.length) throw new Error('Mach-O signature lies outside file');
  let blob = bytes.subarray(signature.offset, signature.offset + signature.size);
  let cms = false;
  let adhoc = false;
  const inspectBlob = (offset, slot) => {
    if (offset + 8 > blob.length) throw new Error('Malformed code-signature blob');
    const magicValue = blob.readUInt32BE(offset);
    const length = blob.readUInt32BE(offset + 4);
    if (length < 8 || offset + length > blob.length) throw new Error('Code-signature blob outside superblob');
    if (slot === CSSLOT_SIGNATURESLOT) {
      if (magicValue !== CSMAGIC_BLOBWRAPPER) {
        throw new Error('Malformed CMS signature wrapper');
      }
      // `codesign --sign -` emits the canonical empty eight-byte wrapper for
      // an ad-hoc signature. Only bytes beyond that header are CMS material.
      cms ||= length > 8;
    }
    if (slot === CSSLOT_CODEDIRECTORY || magicValue === CSMAGIC_CODEDIRECTORY) {
      if (length < 16 || magicValue !== CSMAGIC_CODEDIRECTORY) throw new Error('Malformed CodeDirectory');
      adhoc ||= (blob.readUInt32BE(offset + 12) & CS_ADHOC) !== 0;
    }
  };
  if (blob.readUInt32BE(0) === CSMAGIC_EMBEDDED_SIGNATURE) {
    const length = blob.readUInt32BE(4);
    const count = blob.readUInt32BE(8);
    if (length < 12 || length > blob.length || count > 256 || 12 + count * 8 > length) throw new Error('Malformed signature superblob');
    blob = blob.subarray(0, length);
    for (let index = 0; index < count; index += 1) inspectBlob(blob.readUInt32BE(16 + index * 8), blob.readUInt32BE(12 + index * 8));
  } else {
    inspectBlob(0, CSSLOT_CODEDIRECTORY);
  }
  if (!adhoc && !cms) throw new Error('Unclassified Mach-O signature state');
  return Object.freeze({ architecture: 'arm64', signature: cms ? 'cms' : 'adhoc', cms, adhoc });
}

function expectedDirectories(files) {
  const directories = new Set();
  for (const file of files) {
    let parent = posix.dirname(file);
    while (parent !== '.') { directories.add(`${parent}/`); parent = posix.dirname(parent); }
  }
  return [...directories].sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
}

function identityFromEntry(entry) {
  return Object.freeze({ dev: entry.dev, ino: entry.ino, bytes: entry.bytes, sha256: entry.sha256 });
}

function sidecarFingerprint(entries) {
  const identity = entries
    .filter((entry) => entry.path === `${SIDECAR_ROOT}/`
      || entry.path.startsWith(`${SIDECAR_ROOT}/`))
    .map(({ dev: _dev, ino: _ino, provenance: _provenance, ...entry }) => entry);
  return sha256(Buffer.from(JSON.stringify(identity)));
}

export async function inspectBundle({ appPath, sourceRoot, anchors, forbiddenValues = [], expectedNode = '22.23.1', expectedPi = '0.82.0' }) {
  if (!anchors) throw new Error('Independent staging anchors are required');
  const inventory = await inventoryBundle(appPath);
  const files = inventory.entries.filter((entry) => entry.kind === 'file');
  const filePaths = files.map((entry) => entry.path);
  const manifestEntry = files.find((entry) => entry.path === SIDECAR_MANIFEST);
  if (!manifestEntry || files.filter((entry) => entry.path.endsWith('/manifest.json')).length !== 1) throw new Error('Canonical sidecar manifest missing or ambiguous');
  const manifestBytes = await readFile(resolve(inventory.root, SIDECAR_MANIFEST));
  if (sha256(manifestBytes) !== anchors.manifestSha256 || !manifestBytes.equals(anchors.manifestBytes)) throw new Error('Bundled manifest differs from independently captured staging anchor');
  const manifest = parseStrictManifest(manifestBytes, expectedNode, expectedPi);
  const sidecarFiles = files.filter((entry) => entry.path.startsWith(`${SIDECAR_ROOT}/`)).map((entry) => entry.path.slice(SIDECAR_ROOT.length + 1)).sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  const expectedSidecar = ['manifest.json', ...manifest.files.map((entry) => entry.path)].sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  if (JSON.stringify(sidecarFiles) !== JSON.stringify(expectedSidecar)) throw new Error('Bundled sidecar contains missing or extra files');
  for (const expected of manifest.files) {
    const entry = files.find((candidate) => candidate.path === `${SIDECAR_ROOT}/${expected.path}`);
    if (!entry || entry.bytes !== expected.bytes || entry.sha256 !== expected.sha256) throw new Error('Bundled sidecar file differs from anchored manifest');
  }
  const allowedFiles = [INFO_PATH, HOST_PATH, NODE_PATH, SIDECAR_MANIFEST, ...manifest.files.map((entry) => `${SIDECAR_ROOT}/${entry.path}`)].sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  const sortedFiles = [...filePaths].sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  if (JSON.stringify(sortedFiles) !== JSON.stringify(allowedFiles)) throw new Error('Bundle contains a file outside the explicit layout');
  const actualDirectories = inventory.entries.filter((entry) => entry.kind === 'directory').map((entry) => entry.path).sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  if (JSON.stringify(actualDirectories) !== JSON.stringify(expectedDirectories(allowedFiles))) throw new Error('Bundle contains a directory outside the explicit layout');

  const executables = files.filter((entry) => (entry.mode & 0o111) !== 0).map((entry) => entry.path);
  if (JSON.stringify(executables.sort()) !== JSON.stringify([HOST_PATH, NODE_PATH].sort())) throw new Error('Unexpected executable set');
  const hostEntry = files.find((entry) => entry.path === HOST_PATH);
  const nodeEntry = files.find((entry) => entry.path === NODE_PATH);
  if (!hostEntry || !nodeEntry || nodeEntry.sha256 !== anchors.nodeSha256 || nodeEntry.bytes !== anchors.nodeBytes) throw new Error('Bundled Node differs from independently captured anchor');

  const signatureStates = {};
  for (const entry of files) {
    const bytes = await readFile(resolve(inventory.root, entry.path));
    let state;
    try {
      state = inspectMachOBytes(bytes);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`${detail}: ${entry.path}`);
    }
    if (state) signatureStates[entry.path] = state;
    if (FORBIDDEN_NAMES.test(basename(entry.path))) throw new Error(`Secret-bearing filename in bundle: ${entry.path}`);
    const binaryText = bytes.toString('latin1');
    // Credential syntax is meaningful only in text. Mach-O and other opaque
    // files are governed by the exact layout plus independent hash/signature
    // policy and may contain benign protocol strings such as auth headers.
    if (!bytes.includes(0) && SECRET_TEXT.test(bytes.toString('utf8'))) {
      throw new Error(`Credential-shaped text in bundle: ${entry.path}`);
    }
    if (/http:\/\/(?:127\.0\.0\.1|localhost):1420/i.test(binaryText)) throw new Error('Development endpoint in bundle');
    for (const value of [sourceRoot, ...forbiddenValues]) if (typeof value === 'string' && value.length >= 12 && binaryText.includes(value)) throw new Error('Private machine/environment value entered bundle');
  }
  const hostSignature = signatureStates[HOST_PATH];
  const nodeSignature = signatureStates[NODE_PATH];
  if (!hostSignature || hostSignature.cms || (hostSignature.signature !== 'none' && !hostSignature.adhoc)) throw new Error('Local host has identity-bearing or invalid signature state');
  if (!nodeSignature) throw new Error('Bundled Node is not Mach-O');
  for (const [path, state] of Object.entries(signatureStates)) if (path !== NODE_PATH && state.cms) throw new Error('Only hash-pinned upstream Node may carry CMS signature material');

  const capabilityPath = resolve(sourceRoot, 'src-tauri/capabilities/default.json');
  const configPath = resolve(sourceRoot, 'src-tauri/tauri.conf.json');
  const capability = JSON.parse(await readFile(capabilityPath, 'utf8'));
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  if (JSON.stringify(capability.permissions) !== JSON.stringify(['core:default'])) throw new Error('Unexpected Tauri capability permissions');
  if (config.bundle?.macOS?.signingIdentity !== undefined) throw new Error('Signing identity must remain unset');
  if (JSON.stringify(config.bundle?.externalBin) !== JSON.stringify(['binaries/piui-node']) || JSON.stringify(config.bundle?.resources) !== JSON.stringify(['resources/sidecar'])) throw new Error('Unexpected bundle resource configuration');

  const hostPath = resolve(inventory.root, HOST_PATH);
  const nodePath = resolve(inventory.root, NODE_PATH);
  // The exact Node bytes are already bound to the independently captured
  // staging anchor and its frozen version. Executing the mutable bundle path
  // here would add a post-inventory pathname race without adding evidence.
  const nodeVersion = `v${expectedNode}`;
  return Object.freeze({ appPath: inventory.root, hostPath, nodePath, nodeVersion, piVersion: manifest.piSdk, fingerprint: inventory.fingerprint, entries: inventory.entries.length, files: files.length, sidecarFiles: manifest.files.length, hostSignature: hostSignature.signature, nodeSignature: nodeSignature.signature, machoFiles: Object.keys(signatureStates).length, hostIdentity: identityFromEntry(hostEntry), nodeIdentity: identityFromEntry(nodeEntry), nodeSha256: nodeEntry.sha256, sidecarSha256: sidecarFingerprint(inventory.entries), sourceConfigSha256: sha256(await readFile(configPath)), sourceCapabilitySha256: sha256(await readFile(capabilityPath)) });
}

export async function revalidateBundle(bundle) {
  const current = await inventoryBundle(bundle.appPath);
  if (current.fingerprint !== bundle.fingerprint) throw new Error('Accepted bundle mutated after inspection');
  for (const [path, expected] of [[HOST_PATH, bundle.hostIdentity], [NODE_PATH, bundle.nodeIdentity]]) {
    const entry = current.entries.find((candidate) => candidate.path === path && candidate.kind === 'file');
    if (!entry || entry.dev !== expected.dev || entry.ino !== expected.ino || entry.bytes !== expected.bytes || entry.sha256 !== expected.sha256) throw new Error('Executed bundle identity changed');
  }
  return current.fingerprint;
}
