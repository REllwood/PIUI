import { constants as fsConstants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import {
  basename,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { platform } from 'node:os';
import {
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';

export const ARCHITECTURE_SOURCE_SCHEMA_VERSION = 2;

const MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_SOURCE_TOTAL_BYTES = 256 * 1024 * 1024;
const ACL_INSPECTION_BATCH_SIZE = 128;
const ARCHITECTURE_SOURCE_DIGEST_DOMAIN = Buffer.from(
  'PIUI architecture source snapshot v2\0',
  'utf8',
);
const A29_PLAN_PATH = '.forge/PLAN.md';
const A29_PLAN_HEADING = Buffer.from(
  '### A.29 — Record and enforce the architecture gate decision\n',
  'utf8',
);
const A29_PLAN_UNCHECKED = Buffer.from('- [ ] done\n', 'utf8');
const A29_PLAN_CHECKED = Buffer.from('- [x] done\n', 'utf8');
const PLAN_H2_PREFIX = Buffer.from('\n## ', 'utf8');
const PLAN_H3_PREFIX = Buffer.from('\n### ', 'utf8');

const SOURCE_DIRECTORIES = Object.freeze(new Set([
  'docs',
  'packages',
  'public',
  'scripts',
  'sidecar',
  'src',
  'src-tauri',
  'tests',
]));

const EXCLUDED_ROOT_DIRECTORIES = Object.freeze(new Set([
  '.build',
  '.cache',
  '.claude',
  '.git',
  '.idea',
  '.pi-subagents',
  '.vscode',
  'coverage',
  'dist',
  'graphify-out',
  'node_modules',
  'playwright-report',
  'reports',
  'test-results',
]));

const EXCLUDED_DIRECTORY_NAMES = Object.freeze(new Set([
  '.cache',
  '.idea',
  '.vscode',
  'coverage',
  'dist',
  'node_modules',
  'playwright-report',
  'target',
  'test-results',
]));

const FORGE_CONTROL_FILES = Object.freeze([
  '.forge/ARCHITECTURE-GATE.md',
  '.forge/FORGE.md',
  '.forge/PLAN.md',
  '.forge/SPEC.md',
  '.forge/UI-DESIGN.md',
]);

const REQUIRED_SOURCE_FILES = Object.freeze([
  ...FORGE_CONTROL_FILES,
  'pnpm-lock.yaml',
  'src-tauri/Cargo.lock',
]);

const EXACT_EXCLUDED_PREFIXES = Object.freeze([
  'src-tauri/binaries/',
  'src-tauri/gen/',
  'src-tauri/resources/sidecar/',
]);

const EXACT_INCLUDED_GENERATED_PLACEHOLDERS = Object.freeze(new Set([
  'src-tauri/binaries/.gitkeep',
]));

function reject(message = 'Architecture source snapshot rejected') {
  throw new Error(message);
}

function comparePathBytes(left, right) {
  return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'));
}

function bufferOccurrences(bytes, needle, start = 0, end = bytes.length) {
  const occurrences = [];
  let offset = start;
  while (offset <= end - needle.length) {
    const index = bytes.indexOf(needle, offset);
    if (index < 0 || index + needle.length > end) break;
    occurrences.push(index);
    offset = index + 1;
  }
  return occurrences;
}

// A.29's checkbox is post-record ceremony, not gate authority. Ambiguous PLAN
// structure falls back to hashing the original bytes so the exception cannot
// extend beyond the one exact state byte.
function canonicalArchitectureSourceBytes(path, bytes) {
  if (path !== A29_PLAN_PATH) return bytes;

  const headings = bufferOccurrences(bytes, A29_PLAN_HEADING);
  if (headings.length !== 1
    || (headings[0] !== 0 && bytes[headings[0] - 1] !== 0x0a)) return bytes;

  const sectionStart = headings[0] + A29_PLAN_HEADING.length;
  const followingHeadings = [
    bytes.indexOf(PLAN_H2_PREFIX, sectionStart),
    bytes.indexOf(PLAN_H3_PREFIX, sectionStart),
  ].filter((index) => index >= 0);
  const sectionEnd = followingHeadings.length > 0
    ? Math.min(...followingHeadings)
    : bytes.length;
  const completionLines = [
    ...bufferOccurrences(bytes, A29_PLAN_UNCHECKED, sectionStart, sectionEnd),
    ...bufferOccurrences(bytes, A29_PLAN_CHECKED, sectionStart, sectionEnd),
  ].filter((index) => index === 0 || bytes[index - 1] === 0x0a);
  if (completionLines.length !== 1
    || completionLines[0] + A29_PLAN_UNCHECKED.length !== sectionEnd) return bytes;

  const canonical = Buffer.from(bytes);
  canonical[completionLines[0] + 3] = 0x20;
  return canonical;
}

function normaliseRelativePath(value) {
  const path = value.split(sep).join('/');
  if (!path
    || path === '.'
    || path.startsWith('../')
    || path.includes('/../')
    || path.includes('\\')
    || /[\0-\x1f\x7f]/u.test(path)) reject();
  return path;
}

function isGeneratedFile(path) {
  const name = basename(path);
  return name === '.DS_Store'
    || name === 'Thumbs.db'
    || name.endsWith('.log')
    || name.endsWith('.swp')
    || name.endsWith('.swo')
    || name.endsWith('~');
}

function isExcludedPath(path) {
  if (EXACT_INCLUDED_GENERATED_PLACEHOLDERS.has(path)) return false;
  return EXACT_EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function assertNonSecretPath(path) {
  const name = basename(path).toLowerCase();
  const forbiddenEnvironment = name === '.env'
    || (name.startsWith('.env.') && name !== '.env.example');
  const forbiddenPrivateKey = [
    'id_dsa',
    'id_ecdsa',
    'id_ed25519',
    'id_rsa',
  ].includes(name)
    || name.endsWith('.key')
    || name.endsWith('.p12')
    || name.endsWith('.pem')
    || name.endsWith('.pfx');
  const forbiddenCredentialFile = [
    'credentials.json',
    'service-account.json',
  ].includes(name);
  if (forbiddenEnvironment || forbiddenPrivateKey || forbiddenCredentialFile) {
    reject(`Architecture source contains a secret-shaped file: ${path}`);
  }
}

function sameFileState(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.uid === after.uid
    && before.gid === after.gid
    && before.nlink === after.nlink
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs;
}

function assertTrustedState(state, type, label) {
  const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
  const expectedType = type === 'file' ? state.isFile() : state.isDirectory();
  if (expectedUid === null
    || !expectedType
    || state.isSymbolicLink()
    || state.uid !== expectedUid
    || (state.mode & 0o022n) !== 0n) {
    reject(`Architecture source ${label} is not owner-controlled and non-writable by group or world`);
  }
}

function recordObservation(observations, absolutePath, label, path, state, type) {
  assertTrustedState(state, type, label);
  observations.push(Object.freeze({ absolutePath, label, path, state, type }));
}

async function assertStableObservations(observations) {
  const leaseEntries = [];
  for (const observation of observations) {
    const current = await lstat(observation.absolutePath, { bigint: true });
    assertTrustedState(current, observation.type, observation.label);
    if (!sameFileState(observation.state, current)) {
      reject(`Architecture source ${observation.label} changed during inspection`);
    }
    leaseEntries.push(Object.freeze({
      ctimeNs: current.ctimeNs.toString(10),
      dev: current.dev.toString(10),
      gid: current.gid.toString(10),
      ino: current.ino.toString(10),
      kind: observation.type,
      mode: current.mode.toString(10),
      mtimeNs: current.mtimeNs.toString(10),
      nlink: current.nlink.toString(10),
      path: observation.path,
      size: current.size.toString(10),
      uid: current.uid.toString(10),
    }));
  }
  leaseEntries.sort((left, right) => comparePathBytes(left.path, right.path));
  return Object.freeze(leaseEntries);
}

export function architectureSourceAclListingHasExtendedAcl(listing, expectedEntries) {
  if (typeof listing !== 'string'
    || !Number.isSafeInteger(expectedEntries)
    || expectedEntries < 1) reject();
  const primaryLines = listing.split('\n').filter((line) => (
    /^[bcdlps-][rwxStTs-]{9}(?:[@+]?)\s/u.test(line)
  ));
  if (primaryLines.length !== expectedEntries) reject('Architecture source ACL inspection was incomplete');
  return primaryLines.some((line) => /^[bcdlps-][rwxStTs-]{9}\+/u.test(line))
    || listing.split('\n').some((line) => /^\s+\d+:/u.test(line));
}

function assertNoExtendedAcl(absolutePaths) {
  for (let index = 0; index < absolutePaths.length; index += ACL_INSPECTION_BATCH_SIZE) {
    const paths = absolutePaths.slice(index, index + ACL_INSPECTION_BATCH_SIZE);
    const args = platform() === 'darwin'
      ? ['-lde', '--', ...paths]
      : ['-ld', '--', ...paths];
    const result = spawnSync('/bin/ls', args, {
      encoding: 'utf8',
      maxBuffer: 4 * 1_048_576,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (result.status !== 0 || result.signal !== null || result.stderr !== '') {
      reject('Architecture source ACL inspection failed');
    }
    if (architectureSourceAclListingHasExtendedAcl(result.stdout, paths.length)) {
      reject('Architecture source must not contain extended ACL entries');
    }
  }
}

async function inspectFile(root, rootRealPath, path, observations) {
  assertNonSecretPath(path);
  const absolutePath = join(root, ...path.split('/'));
  const resolvedPath = await realpath(absolutePath);
  if (resolvedPath !== rootRealPath
    && !resolvedPath.startsWith(`${rootRealPath}${sep}`)) reject();

  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await open(absolutePath, flags);
  try {
    const before = await handle.stat({ bigint: true });
    assertTrustedState(before, 'file', `file ${path}`);
    if (before.nlink !== 1n) {
      reject(`Architecture source must contain only single-link regular files: ${path}`);
    }
    if (before.size < 0n
      || before.size > BigInt(MAX_SOURCE_FILE_BYTES)) {
      reject(`Architecture source file exceeds its bounded size: ${path}`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(absolutePath, { bigint: true });
    if (BigInt(bytes.length) !== before.size
      || !sameFileState(before, after)
      || pathAfter.isSymbolicLink()
      || !sameFileState(after, pathAfter)) {
      reject(`Architecture source changed while it was being inspected: ${path}`);
    }
    recordObservation(observations, absolutePath, `file ${path}`, path, after, 'file');
    return Object.freeze({
      executable: (before.mode & 0o111n) !== 0n,
      path,
      sha256: sha256Bytes(canonicalArchitectureSourceBytes(path, bytes)),
      size: bytes.length,
    });
  } finally {
    await handle.close();
  }
}

async function collectDirectory(root, directory, output, observations) {
  const absoluteDirectory = join(root, ...directory.split('/'));
  const directoryState = await lstat(absoluteDirectory, { bigint: true });
  recordObservation(
    observations,
    absoluteDirectory,
    `directory ${directory}`,
    `${directory}/`,
    directoryState,
    'directory',
  );
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });
  entries.sort((left, right) => comparePathBytes(left.name, right.name));

  for (const entry of entries) {
    const path = normaliseRelativePath(`${directory}/${entry.name}`);
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRECTORY_NAMES.has(entry.name) || isExcludedPath(`${path}/`)) continue;
      await collectDirectory(root, path, output, observations);
      continue;
    }
    if (isGeneratedFile(path) || isExcludedPath(path)) continue;
    if (!entry.isFile()) {
      reject(`Architecture source contains an unsupported entry: ${path}`);
    }
    output.push(path);
  }
  const directoryAfter = await lstat(absoluteDirectory, { bigint: true });
  if (!sameFileState(directoryState, directoryAfter)) {
    reject(`Architecture source directory ${directory} changed during inspection`);
  }
}

async function collectSourcePaths(root, observations) {
  const output = [];
  const entries = await readdir(root, { withFileTypes: true });
  entries.sort((left, right) => comparePathBytes(left.name, right.name));
  for (const entry of entries) {
    if (entry.name === '.forge') continue;
    if (entry.isDirectory()) {
      if (EXCLUDED_ROOT_DIRECTORIES.has(entry.name)) continue;
      if (!SOURCE_DIRECTORIES.has(entry.name)) {
        reject(`Architecture source contains an unclassified root directory: ${entry.name}`);
      }
      await collectDirectory(root, entry.name, output, observations);
      continue;
    }
    if (isGeneratedFile(entry.name)) continue;
    if (!entry.isFile()) {
      reject(`Architecture source contains an unsupported root entry: ${entry.name}`);
    }
    output.push(normaliseRelativePath(entry.name));
  }

  const forgeState = await lstat(join(root, '.forge'), { bigint: true });
  recordObservation(
    observations,
    join(root, '.forge'),
    'directory .forge',
    '.forge/',
    forgeState,
    'directory',
  );
  for (const path of FORGE_CONTROL_FILES) {
    const state = await lstat(join(root, ...path.split('/')), { bigint: true });
    if (!state.isFile() || state.isSymbolicLink()) reject();
    output.push(path);
  }
  return output.sort(comparePathBytes);
}

function findRequiredFile(files, path) {
  const file = files.find((candidate) => candidate.path === path);
  if (!file) reject(`Architecture source is missing required file: ${path}`);
  return file;
}

export async function snapshotArchitectureSource(rootPath) {
  if (typeof rootPath !== 'string' || !rootPath || !isAbsolute(rootPath)) reject();
  const root = resolve(rootPath);
  const rootState = await lstat(root, { bigint: true });
  const observations = [];
  recordObservation(observations, root, 'root directory', '.', rootState, 'directory');
  const rootRealPath = await realpath(root);
  const paths = await collectSourcePaths(root, observations);
  if (new Set(paths).size !== paths.length) reject();

  const files = [];
  let totalBytes = 0;
  for (const path of paths) {
    const file = await inspectFile(root, rootRealPath, path, observations);
    totalBytes += file.size;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_SOURCE_TOTAL_BYTES) {
      reject('Architecture source exceeds its bounded total size');
    }
    files.push(file);
  }
  for (const path of REQUIRED_SOURCE_FILES) findRequiredFile(files, path);
  assertNoExtendedAcl(observations.map(({ absolutePath }) => absolutePath));
  const leaseEntries = await assertStableObservations(observations);

  const inventoryBytes = Buffer.from(`${canonicalArchitectureJson({
    files,
    schemaVersion: ARCHITECTURE_SOURCE_SCHEMA_VERSION,
  })}\n`, 'utf8');
  const inventorySha256 = sha256Bytes(inventoryBytes);
  const digest = sha256Bytes(Buffer.concat([
    ARCHITECTURE_SOURCE_DIGEST_DOMAIN,
    inventoryBytes,
  ]));
  const source = Object.freeze({
    cargoLockSha256: findRequiredFile(files, 'src-tauri/Cargo.lock').sha256,
    digest,
    forgeSha256: findRequiredFile(files, '.forge/FORGE.md').sha256,
    inventorySha256,
    packageLockSha256: findRequiredFile(files, 'pnpm-lock.yaml').sha256,
    planSha256: findRequiredFile(files, '.forge/PLAN.md').sha256,
    specSha256: findRequiredFile(files, '.forge/SPEC.md').sha256,
  });
  const leaseBytes = Buffer.from(`${canonicalArchitectureJson({
    entries: leaseEntries,
    schemaVersion: 1,
  })}\n`, 'utf8');
  const lease = Object.freeze({
    entries: leaseEntries.length,
    sha256: sha256Bytes(Buffer.concat([
      Buffer.from('PIUI architecture source lease v1\0', 'utf8'),
      leaseBytes,
    ])),
  });
  return Object.freeze({
    inventory: Object.freeze(files),
    inventoryBytes,
    lease,
    leaseBytes,
    source,
  });
}

export function equalArchitectureSourceLease(left, right) {
  return Boolean(left
    && right
    && Buffer.isBuffer(left.leaseBytes)
    && Buffer.isBuffer(right.leaseBytes)
    && left.leaseBytes.equals(right.leaseBytes)
    && canonicalArchitectureJson(left.lease) === canonicalArchitectureJson(right.lease));
}
