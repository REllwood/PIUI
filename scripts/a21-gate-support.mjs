import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
} from 'node:fs';
import { lstat, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const TRUSTED_INVOCATION_ARGV_MAX_BYTES = 2 * 1_048_576;
const PROCESS_OBSERVATION_AMBIENT_ROWS_MAX_BYTES = 7 * TRUSTED_INVOCATION_ARGV_MAX_BYTES;
// One process-table row can contain the complete accepted trusted invocation.
// Reserve seven further full-invocation budgets for concurrent and ambient
// rows; a larger table is never parsed as a partial identity observation.
export const PROCESS_OBSERVATION_MAX_BUFFER_BYTES = TRUSTED_INVOCATION_ARGV_MAX_BYTES
  + PROCESS_OBSERVATION_AMBIENT_ROWS_MAX_BYTES;

export function identityKey(row) {
  // PPID is deliberately excluded because an otherwise identical live process
  // is reparented when its leader exits.
  return `${row.pid}:${row.pgid}:${row.start}:${row.command}`;
}

export function parseProcessRows(text) {
  return text.split('\n').map((line) => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.{24})\s+(.*)$/);
    return match ? {
      pid: Number(match[1]),
      ppid: Number(match[2]),
      pgid: Number(match[3]),
      state: match[4],
      start: match[5],
      command: match[6],
    } : null;
  }).filter(Boolean);
}

export function descendantsOf(seedPids, rows) {
  const result = [];
  const parents = [...new Set(seedPids)];
  for (let index = 0; index < parents.length; index += 1) {
    for (const row of rows) {
      if (row.ppid === parents[index] && !result.some((candidate) => identityKey(candidate) === identityKey(row))) {
        result.push(row);
        parents.push(row.pid);
      }
    }
  }
  return result;
}

export function buildSignalPlan({ ledger, rows, ownedGroups }) {
  const ledgerKeys = new Set([...ledger.values()].map(identityKey));
  const exact = rows.filter((row) => ledgerKeys.has(identityKey(row)));
  const anchoredGroups = new Set(exact.map((row) => row.pgid).filter((pgid) => ownedGroups.has(pgid)));
  const currentOwnedGroupIds = new Set(rows.map((row) => row.pgid).filter((pgid) => ownedGroups.has(pgid)));
  const ambiguousGroups = [...currentOwnedGroupIds].filter((pgid) => !anchoredGroups.has(pgid)).sort((a, b) => a - b);
  // All members of a currently identity-anchored group are ours. A historical
  // PGID with no current exact-identity anchor is ambiguous (the old group may
  // have become empty and the number reused), so callers must fail without
  // signalling it.
  const owned = rows.filter((row) => exact.includes(row) || anchoredGroups.has(row.pgid));
  return Object.freeze({
    rows: Object.freeze(owned),
    groups: Object.freeze([...anchoredGroups].sort((a, b) => a - b)),
    ambiguousGroups: Object.freeze(ambiguousGroups),
    pids: Object.freeze([...new Set(owned.map((row) => row.pid))].sort((a, b) => a - b)),
  });
}

export class ProcessGroupIdentityAmbiguityError extends Error {
  constructor(groups) {
    super('Owned process-group identity became ambiguous before cleanup');
    this.name = 'ProcessGroupIdentityAmbiguityError';
    this.code = 'PIUI_PROCESS_GROUP_IDENTITY_AMBIGUOUS';
    this.ambiguousGroups = Object.freeze([...groups]);
  }
}

export class ProcessLedger {
  constructor({
    hostPath,
    nodePath,
    observer = observeProcesses,
    executableResolver = executableForPid,
    networkChecker = assertNoNetwork,
  }) {
    this.hostPath = hostPath;
    this.nodePath = nodePath;
    this.observer = observer;
    this.executableResolver = executableResolver;
    this.networkChecker = networkChecker;
    this.entries = new Map();
    this.groups = new Set();
    this.rootPid = undefined;
  }

  async initialise(rootPid) {
    this.rootPid = rootPid;
    const rows = await this.observer();
    const root = rows.find((row) => row.pid === rootPid);
    if (!root) throw new Error('Packaged root process identity unavailable');
    const executable = this.executableResolver(rootPid);
    if (executable !== this.hostPath) throw new Error('Packaged root executable identity mismatch');
    this.add({ ...root, executable });
  }

  add(row) {
    const key = identityKey(row);
    const existingPid = [...this.entries.values()].find((entry) => entry.pid === row.pid && identityKey(entry) !== key);
    if (existingPid) return false;
    this.entries.set(key, Object.freeze({ ...row }));
    this.groups.add(row.pgid);
    return true;
  }

  async sample() {
    const rows = await this.observer();
    const liveEntries = [...this.entries.values()].filter((entry) => rows.some((row) => identityKey(row) === identityKey(entry)));
    const descendants = descendantsOf([this.rootPid, ...liveEntries.map((entry) => entry.pid)], rows);
    const candidates = rows.filter((row) => (
      row.pid === this.rootPid
      || descendants.includes(row)
      || this.entries.has(identityKey(row))
    ));
    let candidateFailure;
    for (const row of candidates) {
      let executable;
      try {
        executable = this.executableResolver(row.pid);
      } catch (error) {
        // A short-lived process can exit between ps and lsof. Accept only
        // demonstrable disappearance of the exact observed identity; a still
        // live identity with an unreadable executable remains fail-closed.
        const refreshed = await this.observer();
        if (!refreshed.some((candidate) => identityKey(candidate) === identityKey(row))) continue;
        throw error;
      }
      if (![this.hostPath, this.nodePath].includes(executable)) {
        candidateFailure ??= new Error('Unexpected packaged descendant executable');
        continue;
      }
      this.add({ ...row, executable });
    }
    // Bind every accepted candidate observed in this snapshot before
    // reporting an unexpected descendant process. The unexpected row is not
    // adopted; group cleanup may still terminate descendants of an owned group.
    if (candidateFailure) throw candidateFailure;
    const current = rows.filter((row) => this.entries.has(identityKey(row)));
    const live = [];
    for (const row of current) {
      const entry = this.entries.get(identityKey(row));
      let executable;
      try {
        executable = this.executableResolver(row.pid);
      } catch (error) {
        const refreshed = await this.observer();
        if (!refreshed.some((candidate) => identityKey(candidate) === identityKey(row))) continue;
        throw error;
      }
      if (executable !== entry.executable) throw new Error('Packaged process executable identity changed');
      this.networkChecker(row.pid);
      live.push(entry);
    }
    return Object.freeze(live);
  }

  hasLiveHostAndNode(live) {
    return this.hasLiveHost(live)
      && live.some((entry) => entry.executable === this.nodePath);
  }

  hasLiveHost(live) {
    return live.some((entry) => entry.executable === this.hostPath);
  }

  async terminate() {
    let discoveryFailure;
    try {
      // A sidecar may enter its own process group after the caller's last
      // observation. Bind that exact PID/start/command/executable identity
      // before constructing any signal plan.
      await this.sample();
    } catch (error) {
      // Continue cleaning identities that were bound before the failure, then
      // report the original observation/policy defect after cleanup.
      discoveryFailure = error;
    }
    let forced = false;
    let rows = await this.observer();
    let plan = buildSignalPlan({ ledger: this.entries, rows, ownedGroups: this.groups });
    for (const group of plan.groups) {
      rows = await this.observer();
      const refreshed = buildSignalPlan({ ledger: this.entries, rows, ownedGroups: this.groups });
      // Signal only a group that remains identity-anchored at this exact
      // observation. A target that became unanchored is not signalled; the
      // bounded observation phase below waits for it to disappear and fails
      // closed if it survives. This also permits a leader that became a zombie
      // between snapshots to be reaped naturally.
      if (refreshed.groups.includes(group)) signalGroup(group, 'SIGTERM');
    }
    for (const pid of plan.pids.filter((pid) => !plan.rows.some((row) => plan.groups.includes(row.pgid) && row.pid === pid))) signalPidIfExact(pid, this.entries, rows, 'SIGTERM');
    if (!plan.rows.length && plan.ambiguousGroups.length) {
      throw new ProcessGroupIdentityAmbiguityError(plan.ambiguousGroups);
    }
    let deadline = Date.now() + 8_000;
    while (Date.now() < deadline) {
      await sleep(100);
      rows = await this.observer();
      plan = buildSignalPlan({ ledger: this.entries, rows, ownedGroups: this.groups });
      // A signalled group can briefly retain an unanchored exiting member.
      // Treat it as clean only after both owned rows and ambiguous retained
      // groups disappear; never signal an ambiguous identity.
      if (!plan.rows.length) {
        if (plan.ambiguousGroups.length) {
          throw new ProcessGroupIdentityAmbiguityError(plan.ambiguousGroups);
        }
        if (discoveryFailure) throw discoveryFailure;
        return { forced };
      }
    }
    forced = true;
    for (const group of plan.groups) {
      rows = await this.observer();
      const refreshed = buildSignalPlan({ ledger: this.entries, rows, ownedGroups: this.groups });
      // Never force-signal a group that is no longer identity-anchored. It
      // remains visible as ambiguous and therefore cannot be reported clean.
      if (refreshed.groups.includes(group)) signalGroup(group, 'SIGKILL');
    }
    for (const row of plan.rows.filter((row) => !plan.groups.includes(row.pgid))) signalPidIfExact(row.pid, this.entries, rows, 'SIGKILL');
    deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      await sleep(100);
      rows = await this.observer();
      plan = buildSignalPlan({ ledger: this.entries, rows, ownedGroups: this.groups });
      if (!plan.rows.length) {
        if (plan.ambiguousGroups.length) {
          throw new ProcessGroupIdentityAmbiguityError(plan.ambiguousGroups);
        }
        throw new Error('Packaged runtime required forced cleanup');
      }
    }
    throw new Error('Owned packaged process survived cleanup');
  }
}

const authenticatedNodeSpawns = new Map();
const authenticatedNodeSandboxProfiles = new Map();
let authenticatedNodeRegistrationEpoch = 0;

const SANDBOX_PROFILE_MAX_DEPTH = 64;
const SANDBOX_PROFILE_MAX_NODES = 32_768;

const A28_ALLOWED_MACH_SERVICES = new Set([
  'com.apple.CARenderServer',
  'com.apple.CoreDisplay.Notification',
  'com.apple.CoreDisplay.master',
  'com.apple.WebKit.GPU',
  'com.apple.WebKit.Networking',
  'com.apple.WebKit.WebContent',
  'com.apple.WebKit.WebContent.EnhancedSecurity',
  'com.apple.appsleep',
  'com.apple.dock.fullscreen',
  'com.apple.dock.server',
  'com.apple.fonts',
  'com.apple.lsd.mapdb',
  'com.apple.window_proxies',
  'com.apple.windowserver.active',
]);

function parseSandboxProfile(profile) {
  let offset = 0;
  let nodes = 0;
  const countNode = () => {
    nodes += 1;
    if (nodes > SANDBOX_PROFILE_MAX_NODES) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
  };
  const skipWhitespace = () => {
    while (offset < profile.length && /\s/u.test(profile[offset])) offset += 1;
  };
  const parseValue = (depth = 0) => {
    if (depth > SANDBOX_PROFILE_MAX_DEPTH) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    countNode();
    skipWhitespace();
    if (profile[offset] === '(') {
      offset += 1;
      const values = [];
      while (true) {
        skipWhitespace();
        if (offset >= profile.length) throw new Error('Authenticated Node sandbox profile is invalid');
        if (profile[offset] === ')') {
          offset += 1;
          if (values.length === 0) throw new Error('Authenticated Node sandbox profile is invalid');
          return Object.freeze(values);
        }
        values.push(parseValue(depth + 1));
      }
    }
    if (profile[offset] === ')') throw new Error('Authenticated Node sandbox profile is invalid');
    if (profile[offset] === '#' && profile[offset + 1] === '"') {
      offset += 2;
      let value = '';
      while (offset < profile.length) {
        const character = profile[offset];
        offset += 1;
        if (character === '"') return Object.freeze({ kind: 'regex', value });
        if (character === '\\') {
          if (offset >= profile.length) throw new Error('Authenticated Node sandbox profile is invalid');
          value += `\\${profile[offset]}`;
          offset += 1;
        } else {
          if (character === '\n' || character === '\r' || character === '\0') {
            throw new Error('Authenticated Node sandbox profile is invalid');
          }
          value += character;
        }
      }
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    if (profile[offset] === '"') {
      offset += 1;
      let value = '';
      while (offset < profile.length) {
        const character = profile[offset];
        offset += 1;
        if (character === '"') return Object.freeze({ kind: 'string', value });
        if (character === '\\') {
          if (offset >= profile.length) throw new Error('Authenticated Node sandbox profile is invalid');
          value += profile[offset];
          offset += 1;
        } else {
          if (character === '\n' || character === '\r' || character === '\0') {
            throw new Error('Authenticated Node sandbox profile is invalid');
          }
          value += character;
        }
      }
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    const start = offset;
    while (offset < profile.length && !/[\s()]/u.test(profile[offset])) offset += 1;
    if (start === offset) throw new Error('Authenticated Node sandbox profile is invalid');
    const value = profile.slice(start, offset);
    if (!/^[A-Za-z0-9*._:+\/-]+$/u.test(value)) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    return Object.freeze({ kind: 'atom', value });
  };
  const forms = [];
  while (true) {
    skipWhitespace();
    if (offset === profile.length) break;
    forms.push(parseValue());
  }
  return Object.freeze(forms);
}

function sandboxAtom(value, expected) {
  return !Array.isArray(value) && value?.kind === 'atom' && value.value === expected;
}

function sandboxString(value) {
  return !Array.isArray(value) && value?.kind === 'string' ? value.value : undefined;
}

function sandboxFormHead(form, expected) {
  return Array.isArray(form) && sandboxAtom(form[0], expected);
}

function exactSandboxForm(form, atoms) {
  return Array.isArray(form)
    && form.length === atoms.length
    && atoms.every((atom, index) => sandboxAtom(form[index], atom));
}

function assertAbsoluteSandboxPath(path) {
  if (typeof path !== 'string'
    || !path.startsWith('/')
    || path.length > 4_096
    || /[\0\r\n]/u.test(path)
    || path.includes('/../')
    || path.includes('/./')
    || path.endsWith('/..')
    || path.endsWith('/.')
    || path.includes('//')) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
}

function assertSandboxPathFilters(filters) {
  if (filters.length === 0) throw new Error('Authenticated Node sandbox profile is invalid');
  for (const filter of filters) {
    if ((!sandboxFormHead(filter, 'literal') && !sandboxFormHead(filter, 'subpath'))
      || filter.length !== 2) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    assertAbsoluteSandboxPath(sandboxString(filter[1]));
  }
}

function sandboxPathFilterKey(filter) {
  return `${filter[0].value}:${sandboxString(filter[1])}`;
}

function assertPermittedSandboxPathFilters(filters, permitted) {
  assertSandboxPathFilters(filters);
  if (filters.some((filter) => !permitted.has(sandboxPathFilterKey(filter)))) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
}

function assertSandboxTargets(filters, permitted) {
  if (filters.length === 0) throw new Error('Authenticated Node sandbox profile is invalid');
  for (const filter of filters) {
    if (!sandboxFormHead(filter, 'target')
      || filter.length !== 2
      || !permitted.has(filter[1]?.value)
      || filter[1]?.kind !== 'atom') {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
  }
}

function validateA28MachLookup(form, processPath, policy) {
  if (form.length < 3 || processPath !== policy.hostPath) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
  for (const filter of form.slice(2)) {
    const kind = filter?.[0]?.value;
    const service = sandboxString(filter?.[1]);
    if (!Array.isArray(filter)
      || filter.length !== 2
      || !['global-name', 'xpc-service-name'].includes(kind)
      || !A28_ALLOWED_MACH_SERVICES.has(service)) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
  }
}

function validateA28Extension(form, operation, processPath, policy) {
  const expected = {
    'generic-issue-extension': ['extension-class', 'com.apple.webkit.mach-bootstrap'],
    'iokit-issue-extension': ['extension-class', 'com.apple.webkit.extension.iokit'],
    'mach-issue-extension': ['extension-class', 'com.apple.webkit.extension.mach'],
  }[operation];
  if (processPath !== policy.hostPath
    || form.length !== 3
    || !sandboxFormHead(form[2], expected[0])
    || form[2].length !== 2
    || sandboxString(form[2][1]) !== expected[1]) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
}

function validateA28Iokit(form, operation, processPath, policy) {
  const expected = {
    'iokit-get-properties': Object.freeze([
      Object.freeze(['iokit-registry-entry-class', Object.freeze(['IOAccelerator', 'IOFramebuffer', 'IOSurfaceRoot'])]),
    ]),
    'iokit-open-service': Object.freeze([
      Object.freeze(['iokit-registry-entry-class', Object.freeze(['IOAccelerator', 'IOFramebuffer', 'IOSurfaceRoot'])]),
    ]),
    'iokit-open-user-client': Object.freeze([
      Object.freeze(['iokit-connection', Object.freeze(['IOAccelerator'])]),
      Object.freeze(['iokit-user-client-class', Object.freeze([
        'AGXDeviceUserClient',
        'IOAccelerationUserClient',
        'IOFramebufferSharedUserClient',
        'IOSurfaceAcceleratorClient',
        'IOSurfaceRootUserClient',
        'IOSurfaceSendRight',
      ])]),
    ]),
  }[operation];
  if (processPath !== policy.hostPath || form.length !== expected.length + 2) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
  expected.forEach(([filterName, values], index) => {
    const filter = form[index + 2];
    if (!sandboxFormHead(filter, filterName)
      || filter.length !== values.length + 1
      || values.some((value, valueIndex) => sandboxString(filter[valueIndex + 1]) !== value)) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
  });
}

function validateSandboxAllow(form, policy, processPath) {
  if (form.length < 2) throw new Error('Authenticated Node sandbox profile is invalid');
  const operations = [];
  let index = 1;
  while (index < form.length && !Array.isArray(form[index])) {
    if (form[index]?.kind !== 'atom') throw new Error('Authenticated Node sandbox profile is invalid');
    operations.push(form[index].value);
    index += 1;
  }
  if (operations.length === 0) throw new Error('Authenticated Node sandbox profile is invalid');
  const filters = form.slice(index);
  const fileOperations = new Set([
    'file-link',
    'file-map-executable',
    'file-read*',
    'file-read-metadata',
    'file-test-existence',
    'file-write*',
    'file-write-data',
  ]);
  if (operations.every((operation) => fileOperations.has(operation))) {
    if (policy.kind === 'deny-network') {
      const writes = operations.some((operation) => (
        operation === 'file-link'
        || operation === 'file-write*'
        || operation === 'file-write-data'
      ));
      const reads = operations.some((operation) => (
        operation === 'file-map-executable' || operation === 'file-read*'
      ));
      const permitted = writes && reads
        ? new Set([...policy.writablePaths].filter((path) => policy.readablePaths.has(path)))
        : writes
          ? policy.writablePaths
          : reads
            ? policy.readablePaths
            : policy.metadataPaths;
      assertPermittedSandboxPathFilters(filters, permitted);
    } else {
      assertSandboxPathFilters(filters);
    }
    return;
  }
  if (operations.length !== 1) throw new Error('Authenticated Node sandbox profile is invalid');
  const operation = operations[0];
  if (operation === 'process-exec') {
    if (policy.kind === 'deny-network') {
      assertPermittedSandboxPathFilters(filters, policy.executablePaths);
    } else {
      assertSandboxPathFilters(filters);
      const permitted = new Set([policy.hostPath, policy.nodePath, policy.runnerPath]);
      for (const filter of filters) {
        if (!sandboxFormHead(filter, 'literal') || !permitted.has(sandboxString(filter[1]))) {
          throw new Error('Authenticated Node sandbox profile is invalid');
        }
      }
    }
    return;
  }
  if (operation === 'process-fork') {
    if (filters.length !== 0) throw new Error('Authenticated Node sandbox profile is invalid');
    return;
  }
  if (operation === 'signal') {
    assertSandboxTargets(filters, new Set(['self', 'children', 'same-sandbox']));
    return;
  }
  if (operation === 'process-info*') {
    assertSandboxTargets(filters, new Set(['self', 'children', 'same-sandbox']));
    return;
  }
  if (operation === 'dynamic-code-generation' || operation === 'sysctl-read') {
    if (filters.length !== 0) throw new Error('Authenticated Node sandbox profile is invalid');
    return;
  }
  if (operation === 'mach-lookup' && policy.kind === 'a28-loopback') {
    validateA28MachLookup(form, processPath, policy);
    return;
  }
  if (['generic-issue-extension', 'iokit-issue-extension', 'mach-issue-extension'].includes(operation)
    && policy.kind === 'a28-loopback') {
    validateA28Extension(form, operation, processPath, policy);
    return;
  }
  if (['iokit-get-properties', 'iokit-open-service', 'iokit-open-user-client'].includes(operation)
    && policy.kind === 'a28-loopback') {
    validateA28Iokit(form, operation, processPath, policy);
    return;
  }
  if (['network-inbound', 'network-outbound'].includes(operation)
    && policy.kind === 'a28-loopback'
    && processPath === undefined
    && filters.length === 1) {
    const direction = operation === 'network-inbound' ? 'local' : 'remote';
    const filter = filters[0];
    if (!sandboxFormHead(filter, direction)
      || filter.length !== 3
      || !sandboxAtom(filter[1], 'tcp4')
      || sandboxString(filter[2]) !== `localhost:${policy.port}`) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    return;
  }
  throw new Error('Authenticated Node sandbox profile is invalid');
}

function normaliseSandboxPermissionPaths(policy, key, filterName) {
  const values = policy[key];
  if (!Array.isArray(values)
    || values.length > 16_384
    || new Set(values).size !== values.length) {
    throw new Error('Authenticated Node sandbox profile authorisation is invalid');
  }
  return values.map((path) => {
    assertAbsoluteSandboxPath(path);
    return `${filterName}:${path}`;
  });
}

function normaliseDenyNetworkPolicy(policy) {
  const expectedKeys = [
    'executableFiles',
    'executableRoots',
    'kind',
    'metadataFiles',
    'metadataRoots',
    'readableFiles',
    'readableRoots',
    'writableFiles',
    'writableRoots',
  ];
  if (Object.keys(policy).sort().join(',') !== expectedKeys.join(',')) {
    throw new Error('Authenticated Node sandbox profile authorisation is invalid');
  }
  const paths = (prefix) => new Set([
    ...normaliseSandboxPermissionPaths(policy, `${prefix}Files`, 'literal'),
    ...normaliseSandboxPermissionPaths(policy, `${prefix}Roots`, 'subpath'),
  ]);
  return Object.freeze({
    executablePaths: paths('executable'),
    kind: 'deny-network',
    metadataPaths: paths('metadata'),
    readablePaths: paths('readable'),
    writablePaths: paths('writable'),
  });
}

function validateSandboxProfile(profile, policy) {
  const forms = parseSandboxProfile(profile);
  if (forms.length < 5
    || forms.filter((form) => exactSandboxForm(form, ['version', '1'])).length !== 1
    || forms.filter((form) => exactSandboxForm(form, ['deny', 'default'])).length !== 1
    || forms.filter((form) => exactSandboxForm(form, ['deny', 'network*'])).length !== 1
    || forms.filter((form) => exactSandboxForm(form, ['deny', 'appleevent-send'])).length !== 1
    || forms.filter((form) => sandboxFormHead(form, 'import')).some((form) => (
      form.length !== 2 || sandboxString(form[1]) !== 'dyld-support.sb'
    ))) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
  let inbound = 0;
  let outbound = 0;
  const validateForm = (form, processPath) => {
    if (!Array.isArray(form) || form.length < 1 || form[0]?.kind !== 'atom') {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
    const head = form[0].value;
    if (head === 'allow') {
      validateSandboxAllow(form, policy, processPath);
      if (sandboxAtom(form[1], 'network-inbound')) inbound += 1;
      if (sandboxAtom(form[1], 'network-outbound')) outbound += 1;
      return;
    }
    if (head === 'with-filter') {
      const filter = form[1];
      const filteredPath = sandboxString(filter?.[1]);
      if (!sandboxFormHead(filter, 'process-path') || filter.length !== 2) {
        throw new Error('Authenticated Node sandbox profile is invalid');
      }
      assertAbsoluteSandboxPath(filteredPath);
      const permittedProcessFilter = policy.kind === 'a28-loopback'
        ? new Set(['/usr/bin/sandbox-exec', policy.hostPath, policy.nodePath, policy.runnerPath])
          .has(filteredPath)
        : policy.kind === 'deny-network' && filteredPath === '/usr/bin/sandbox-exec';
      if (!permittedProcessFilter || form.length < 3) {
        throw new Error('Authenticated Node sandbox profile is invalid');
      }
      form.slice(2).forEach((child) => validateForm(child, filteredPath));
      return;
    }
    if (!['version', 'deny', 'import'].includes(head)) {
      throw new Error('Authenticated Node sandbox profile is invalid');
    }
  };
  forms.forEach((form) => validateForm(form, undefined));
  if ((policy.kind === 'deny-network' && (inbound !== 0 || outbound !== 0))
    || (policy.kind === 'a28-loopback' && (inbound !== 1 || outbound !== 1))) {
    throw new Error('Authenticated Node sandbox profile is invalid');
  }
  if (policy.kind === 'deny-network') {
    const requiredMachDeny = forms.some((form) => (
      sandboxFormHead(form, 'deny')
      && sandboxAtom(form[1], 'mach-lookup')
      && form.length === 4
      && sandboxFormHead(form[2], 'global-name')
      && sandboxString(form[2][1]) === 'com.apple.securityd'
      && sandboxFormHead(form[3], 'global-name')
      && sandboxString(form[3][1]) === 'com.apple.SecurityServer'
    ));
    if (!requiredMachDeny) throw new Error('Authenticated Node sandbox profile is invalid');
  }
}

export function authoriseAuthenticatedNodeSandboxProfile({
  command,
  policy,
  profile,
}) {
  const configuration = authenticatedNodeSpawns.get(command);
  const policyKeys = policy && typeof policy === 'object' && !Array.isArray(policy)
    ? Object.keys(policy).sort().join(',')
    : '';
  if (!configuration
    || typeof profile !== 'string'
    || Buffer.byteLength(profile, 'utf8') < 256
    || Buffer.byteLength(profile, 'utf8') > 512 * 1024
    || /[\0\r]/u.test(profile)
    || (policy?.kind === 'a28-loopback'
      && policyKeys !== 'expectedProfileSha256,hostPath,kind,nodePath,port,runnerPath')
    || !['deny-network', 'a28-loopback'].includes(policy?.kind)) {
    throw new Error('Authenticated Node sandbox profile authorisation is invalid');
  }
  const acceptedPolicy = policy.kind === 'deny-network'
    ? normaliseDenyNetworkPolicy(policy)
    : policy;
  if (acceptedPolicy.kind === 'a28-loopback') {
    for (const path of [acceptedPolicy.hostPath, acceptedPolicy.nodePath, acceptedPolicy.runnerPath]) {
      assertAbsoluteSandboxPath(path);
    }
    if (acceptedPolicy.runnerPath !== command
      || typeof acceptedPolicy.expectedProfileSha256 !== 'string'
      || !/^[0-9a-f]{64}$/u.test(acceptedPolicy.expectedProfileSha256)
      || createHash('sha256').update(profile).digest('hex')
        !== acceptedPolicy.expectedProfileSha256
      || !Number.isSafeInteger(acceptedPolicy.port)
      || acceptedPolicy.port < 49_152
      || acceptedPolicy.port > 65_535) {
      throw new Error('Authenticated Node sandbox profile authorisation is invalid');
    }
  }
  validateSandboxProfile(profile, acceptedPolicy);
  assertAuthenticatedNodeSpawnLease(configuration);
  const sha256 = createHash('sha256').update(profile).digest('hex');
  authenticatedNodeSandboxProfiles.set(`${command}:${sha256}`, Object.freeze({
    dev: configuration.node.dev,
    epoch: configuration.registrationEpoch,
    ino: configuration.node.ino,
    kind: acceptedPolicy.kind,
    port: acceptedPolicy.kind === 'a28-loopback' ? acceptedPolicy.port : undefined,
  }));
  return sha256;
}

function normaliseGeneratedSandboxPaths(values, label) {
  if (!Array.isArray(values)
    || values.length > 16_384
    || values.some((path) => typeof path !== 'string')
    || new Set(values).size !== values.length) {
    throw new Error(`Authenticated Node orchestration ${label} is invalid`);
  }
  for (const path of values) assertAbsoluteSandboxPath(path);
  return Object.freeze([...values].sort((left, right) => (
    Buffer.from(left).compare(Buffer.from(right))
  )));
}

export function createAuthenticatedNodeGuardedProductionSandboxProfile(configuration) {
  const expectedKeys = [
    'command',
    'executableFiles',
    'executableRoots',
    'readableFiles',
    'readableRoots',
    'writableFiles',
    'writableRoots',
  ];
  if (!configuration
    || typeof configuration !== 'object'
    || Array.isArray(configuration)
    || Object.keys(configuration).sort().join(',') !== expectedKeys.join(',')) {
    throw new Error('Authenticated guarded-production sandbox configuration is invalid');
  }
  const node = authenticatedNodeSpawns.get(configuration.command);
  if (!node) throw new Error('Authenticated guarded-production command is not registered');
  const executableFiles = normaliseGeneratedSandboxPaths(
    configuration.executableFiles,
    'executable files',
  );
  const executableRoots = normaliseGeneratedSandboxPaths(
    configuration.executableRoots,
    'executable roots',
  );
  const readableFiles = normaliseGeneratedSandboxPaths(
    configuration.readableFiles,
    'readable files',
  );
  const readableRoots = normaliseGeneratedSandboxPaths(
    configuration.readableRoots,
    'readable roots',
  );
  const writableFiles = normaliseGeneratedSandboxPaths(
    configuration.writableFiles,
    'writable files',
  );
  const writableRoots = normaliseGeneratedSandboxPaths(
    configuration.writableRoots,
    'writable roots',
  );
  if (!executableFiles.includes(configuration.command)
    || !readableFiles.includes(configuration.command)
    || executableRoots.some((path) => (
      configuration.command === path || configuration.command.startsWith(`${path}/`)
    ))
    || writableFiles.includes(configuration.command)
    || writableRoots.some((path) => (
      configuration.command === path || configuration.command.startsWith(`${path}/`)
    ))) {
    throw new Error('Authenticated guarded-production command permissions are invalid');
  }
  const seatbelt = (path) => path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  const filters = (files, roots) => [
    ...files.map((path) => `(literal "${seatbelt(path)}")`),
    ...roots.map((path) => `(subpath "${seatbelt(path)}")`),
  ].join(' ');
  const ordinaryExecutableFiles = executableFiles.filter(
    (path) => path !== configuration.command,
  );
  const ordinaryProcessExec = ordinaryExecutableFiles.length > 0 || executableRoots.length > 0
    ? `\n  (allow process-exec ${filters(ordinaryExecutableFiles, executableRoots)})`
    : '';
  const writes = writableFiles.length > 0 || writableRoots.length > 0
    ? `\n  (allow file-write* file-link ${filters(writableFiles, writableRoots)})`
    : '';
  const profile = `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (deny mach-lookup
    (global-name "com.apple.securityd")
    (global-name "com.apple.SecurityServer"))
  (allow process-fork)
  (allow signal (target same-sandbox))
  (allow process-info* (target same-sandbox))
  (allow dynamic-code-generation)
  (allow sysctl-read)
  (with-filter (process-path "/usr/bin/sandbox-exec")
    (allow process-exec (literal "${seatbelt(configuration.command)}")))${ordinaryProcessExec}
  (allow file-read-metadata file-test-existence (subpath "/"))
  (allow file-read* file-test-existence file-map-executable ${filters(readableFiles, readableRoots)})${writes}`;
  if (Buffer.byteLength(profile, 'utf8') < 256
    || Buffer.byteLength(profile, 'utf8') > 512 * 1024) {
    throw new Error('Authenticated guarded-production sandbox profile is invalid');
  }
  assertAuthenticatedNodeSpawnLease(node);
  const sha256 = createHash('sha256').update(profile).digest('hex');
  authenticatedNodeSandboxProfiles.set(`${configuration.command}:${sha256}`, Object.freeze({
    dev: node.node.dev,
    epoch: node.registrationEpoch,
    ino: node.node.ino,
    kind: 'guarded-production',
    marker: 'guarded-production',
    port: undefined,
  }));
  return profile;
}

/**
 * Create and authorise the only authenticated-Node sandbox shape which may
 * reach the local Apple Development signing authority. Every mutable protocol
 * path is derived from the broker instance nonce; callers cannot add arbitrary
 * readable, writable or executable roots to this capability.
 */
export function createAuthenticatedNodeAutomationSigningBrokerSandboxProfile(configuration) {
  const expectedKeys = [
    'brokerScript',
    'command',
    'controlRoot',
    'hostPath',
    'keychainPath',
    'nonce',
    'signingPolicyPath',
    'verificationRoot',
  ];
  if (!configuration
    || typeof configuration !== 'object'
    || Array.isArray(configuration)
    || Object.keys(configuration).sort().join(',') !== expectedKeys.join(',')) {
    throw new Error('Authenticated automation-signing broker sandbox configuration is invalid');
  }
  const node = authenticatedNodeSpawns.get(configuration.command);
  if (!node) throw new Error('Authenticated automation-signing broker command is not registered');
  for (const path of [
    configuration.brokerScript,
    configuration.command,
    configuration.controlRoot,
    configuration.hostPath,
    configuration.keychainPath,
    configuration.signingPolicyPath,
    configuration.verificationRoot,
  ]) assertAbsoluteSandboxPath(path);
  if (configuration.brokerScript !== resolve(dirname(configuration.brokerScript), 'automation-signing-broker.mjs')
    || configuration.keychainPath !== resolve(homedir(), 'Library/Keychains/login.keychain-db')
    || configuration.verificationRoot !== resolve(configuration.controlRoot, 'verification')
    || !/^[0-9a-f]{64}$/u.test(configuration.nonce)) {
    throw new Error('Authenticated automation-signing broker sandbox boundary is invalid');
  }
  const brokerModules = Object.freeze([
    configuration.brokerScript,
    resolve(dirname(configuration.brokerScript), 'architecture-gate-schema.mjs'),
    resolve(dirname(configuration.brokerScript), 'automation-host-signing.mjs'),
  ]);
  const assertSafeFile = (path, exactMode) => {
    const state = lstatSync(path, { bigint: true });
    if (!state.isFile()
      || state.isSymbolicLink()
      || state.nlink !== 1n
      || state.uid !== BigInt(process.getuid())
      || (exactMode === undefined
        ? (state.mode & 0o022n) !== 0n
        : (state.mode & 0o7777n) !== BigInt(exactMode))
      || realpathSync(path) !== path) {
      throw new Error('Authenticated automation-signing broker file boundary is unsafe');
    }
  };
  const assertPrivateDirectory = (path) => {
    const state = lstatSync(path, { bigint: true });
    if (!state.isDirectory()
      || state.isSymbolicLink()
      || state.uid !== BigInt(process.getuid())
      || (state.mode & 0o7777n) !== 0o700n
      || realpathSync(path) !== path) {
      throw new Error('Authenticated automation-signing broker directory boundary is unsafe');
    }
  };
  brokerModules.forEach((path) => assertSafeFile(path));
  assertSafeFile(configuration.keychainPath);
  assertSafeFile(configuration.signingPolicyPath);
  const hostState = lstatSync(configuration.hostPath, { bigint: true });
  if (!hostState.isFile()
    || hostState.isSymbolicLink()
    || hostState.nlink !== 1n
    || hostState.uid !== BigInt(process.getuid())
    || ![0o500n, 0o700n].includes(hostState.mode & 0o7777n)
    || realpathSync(configuration.hostPath) !== configuration.hostPath) {
    throw new Error('Authenticated automation-signing broker host boundary is unsafe');
  }
  assertPrivateDirectory(configuration.controlRoot);
  assertPrivateDirectory(configuration.verificationRoot);

  const requestPath = resolve(configuration.controlRoot, `request-${configuration.nonce}.json`);
  const consumedPath = resolve(configuration.controlRoot, `consumed-${configuration.nonce}.json`);
  const responsePath = resolve(configuration.controlRoot, `response-${configuration.nonce}.json`);
  const temporaryHostPath = `${configuration.hostPath}.cstemp`;
  const seatbelt = (path) => path.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  const literal = (path) => `(literal "${seatbelt(path)}")`;
  const ancestors = (paths) => {
    const result = new Set(['/']);
    for (const path of paths) {
      const spellings = path.startsWith('/private/var/')
        ? [path, path.slice('/private'.length)]
        : [path];
      for (const spelling of spellings) {
        for (let current = dirname(spelling);; current = dirname(current)) {
          result.add(current);
          if (current === dirname(current)) break;
        }
      }
    }
    return [...result].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  };
  const keychainAncestors = ancestors([configuration.keychainPath]);
  const readableFiles = [
    '/dev/null',
    '/dev/random',
    '/dev/urandom',
    '/private/etc/localtime',
    '/private/etc/ssl/openssl.cnf',
    '/usr/bin/codesign',
    '/usr/bin/security',
    configuration.command,
    configuration.controlRoot,
    configuration.hostPath,
    configuration.keychainPath,
    configuration.signingPolicyPath,
    configuration.verificationRoot,
    requestPath,
    consumedPath,
    responsePath,
    temporaryHostPath,
    ...brokerModules,
  ].filter((path, index, values) => values.indexOf(path) === index);
  const profile = `(version 1)
  (deny default)
  (import "dyld-support.sb")
  (deny network*)
  (deny appleevent-send)
  (allow mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.trustd.agent"))
  (allow process-fork)
  (allow signal (target children) (target same-sandbox))
  (allow process-info* (target children) (target same-sandbox))
  (allow dynamic-code-generation)
  (allow sysctl-read)
  (allow system-fsctl)
  (allow process-exec
    ${literal(configuration.command)}
    ${literal('/usr/bin/codesign')}
    ${literal('/usr/bin/security')})
  (allow file-read-metadata file-test-existence (subpath "/"))
  (allow file-read* file-test-existence file-map-executable
    ${keychainAncestors.map(literal).join('\n    ')}
    ${readableFiles.map(literal).join('\n    ')}
    (subpath "/Library/Apple/System/Library")
    (subpath "/System/Library")
    (subpath "/usr/lib"))
  (allow file-write* file-link
    ${literal(consumedPath)}
    ${literal(responsePath)}
    ${literal(configuration.hostPath)}
    ${literal(temporaryHostPath)}
    (subpath "${seatbelt(configuration.verificationRoot)}"))`;
  if (Buffer.byteLength(profile, 'utf8') < 256
    || Buffer.byteLength(profile, 'utf8') > 512 * 1024) {
    throw new Error('Authenticated automation-signing broker sandbox profile is invalid');
  }
  assertAuthenticatedNodeSpawnLease(node);
  const sha256 = createHash('sha256').update(profile).digest('hex');
  authenticatedNodeSandboxProfiles.set(`${configuration.command}:${sha256}`, Object.freeze({
    dev: node.node.dev,
    epoch: node.registrationEpoch,
    ino: node.node.ino,
    kind: 'automation-signing-broker',
    marker: `automation-signing-broker:${configuration.nonce}`,
    port: undefined,
  }));
  return profile;
}

function sameAuthenticatedNodeState(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function assertAuthenticatedNodeSpawnLease(configuration) {
  const node = fstatSync(configuration.nodeFd, { bigint: true });
  const nodePath = lstatSync(configuration.node.path, { bigint: true });
  const parent = fstatSync(configuration.nodeParentFd, { bigint: true });
  const parentPath = lstatSync(configuration.nodeParent, { bigint: true });
  if (!node.isFile()
    || node.isSymbolicLink()
    || node.nlink !== 1n
    || node.uid !== BigInt(process.getuid())
    || (node.mode & 0o777n) !== 0o500n
    || node.dev.toString() !== configuration.node.dev
    || node.ino.toString() !== configuration.node.ino
    || node.size !== BigInt(configuration.node.size)
    || nodePath.isSymbolicLink()
    || !sameAuthenticatedNodeState(node, nodePath)
    || realpathSync(configuration.node.path) !== configuration.node.path
    || !parent.isDirectory()
    || parent.isSymbolicLink()
    || parent.uid !== BigInt(process.getuid())
    || (parent.mode & 0o022n) !== 0n
    || parentPath.isSymbolicLink()
    || !sameAuthenticatedNodeState(parent, configuration.nodeParentState)
    || !sameAuthenticatedNodeState(parent, parentPath)
    || realpathSync(configuration.nodeParent) !== configuration.nodeParent) {
    throw new Error('Authenticated Node spawn lease changed');
  }
}

export function configureAuthenticatedNodeSpawn(configuration) {
  const node = configuration?.node;
  if (!configuration
    || typeof configuration !== 'object'
    || Array.isArray(configuration)
    || Object.keys(configuration).sort().join(',')
      !== 'launcherSha256,launcherSource,node,rubyPath,schemaVersion'
    || !node
    || typeof node !== 'object'
    || Array.isArray(node)
    || Object.keys(node).sort().join(',') !== 'dev,ino,path,sha256,size'
    || configuration.schemaVersion !== 1
    || configuration.rubyPath !== '/usr/bin/ruby'
    || typeof configuration.launcherSource !== 'string'
    || configuration.launcherSource.length < 8_192
    || configuration.launcherSource.length > 128 * 1_024
    || !configuration.launcherSource.startsWith('#!/usr/bin/ruby --disable-gems\n')
    || /\0/u.test(configuration.launcherSource)
    || typeof configuration.launcherSha256 !== 'string'
    || !/^[0-9a-f]{64}$/u.test(configuration.launcherSha256)
    || createHash('sha256').update(configuration.launcherSource).digest('hex')
      !== configuration.launcherSha256
    || typeof node.path !== 'string'
    || resolve(node.path) !== node.path
    || typeof node.dev !== 'string'
    || !/^(?:0|[1-9][0-9]*)$/u.test(node.dev)
    || typeof node.ino !== 'string'
    || !/^[1-9][0-9]*$/u.test(node.ino)
    || node.size !== 112_928_848
    || node.sha256 !== '2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d') {
    throw new Error('Authenticated Node spawn configuration is invalid');
  }
  const prior = authenticatedNodeSpawns.get(node.path);
  if (prior && (prior.node.dev !== node.dev || prior.node.ino !== node.ino)) {
    throw new Error('Authenticated Node spawn path was already installed for another identity');
  }
  if (prior) {
    if (prior.launcherSha256 !== configuration.launcherSha256
      || prior.launcherSource !== configuration.launcherSource
      || prior.rubyPath !== configuration.rubyPath
      || prior.schemaVersion !== configuration.schemaVersion
      || Object.keys(node).some((key) => prior.node[key] !== node[key])) {
      throw new Error('Authenticated Node spawn path was already installed for another configuration');
    }
  }
  let nodeFd;
  let nodeParentFd;
  try {
    nodeFd = openSync(node.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const nodeParent = dirname(node.path);
    nodeParentFd = openSync(
      nodeParent,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_DIRECTORY ?? 0),
    );
    const nodeParentState = fstatSync(nodeParentFd, { bigint: true });
    const accepted = {
      launcherSha256: configuration.launcherSha256,
      launcherSource: configuration.launcherSource,
      node: Object.freeze({ ...node }),
      nodeFd,
      nodeParent,
      nodeParentFd,
      nodeParentState,
      registrationEpoch: authenticatedNodeRegistrationEpoch + 1,
      rubyPath: configuration.rubyPath,
      schemaVersion: 1,
    };
    assertAuthenticatedNodeSpawnLease(accepted);
    authenticatedNodeSpawns.set(node.path, Object.freeze(accepted));
    authenticatedNodeRegistrationEpoch = accepted.registrationEpoch;
    if (prior) {
      closeSync(prior.nodeFd);
      closeSync(prior.nodeParentFd);
    }
  } catch (error) {
    if (nodeFd !== undefined) closeSync(nodeFd);
    if (nodeParentFd !== undefined) closeSync(nodeParentFd);
    throw error;
  }
}

function authenticatedSandboxProfile(command, profile, configuration) {
  if (profile === undefined) return undefined;
  if (typeof profile !== 'string') {
    throw new Error('Authenticated Node sandbox profile was not authorised');
  }
  const sha256 = createHash('sha256').update(profile).digest('hex');
  const authorisation = authenticatedNodeSandboxProfiles.get(`${command}:${sha256}`);
  if (!authorisation
    || authorisation.dev !== configuration.node.dev
    || authorisation.epoch !== configuration.registrationEpoch
    || authorisation.ino !== configuration.node.ino) {
    throw new Error('Authenticated Node sandbox profile was not authorised');
  }
  return Object.freeze({
    kind: authorisation.kind,
    marker: authorisation.marker,
    port: authorisation.port,
    profile,
  });
}

function registeredNodeDenialRules() {
  const paths = [...authenticatedNodeSpawns.keys()].sort((left, right) => (
    Buffer.from(left).compare(Buffer.from(right))
  ));
  const literals = paths.map((path) => (
    `(literal "${path.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}")`
  )).join(' ');
  return `(deny process-exec ${literals})
  (deny file-read-data file-map-executable ${literals})
  (deny file-link ${literals})`;
}

function registeredNodeDenialProfile() {
  return `(version 1)
  (allow default)
  ${registeredNodeDenialRules()}`;
}

function composeExplicitSandboxProfile(profile) {
  if (typeof profile !== 'string'
    || Buffer.byteLength(profile, 'utf8') < 16
    || Buffer.byteLength(profile, 'utf8') > 512 * 1_024
    || /[\0\r]/u.test(profile)) {
    throw new Error('Explicit sandbox profile is invalid');
  }
  const forms = parseSandboxProfile(profile);
  const versionForms = forms.filter((form) => sandboxFormHead(form, 'version'));
  if (forms.length < 2
    || !exactSandboxForm(forms[0], ['version', '1'])
    || versionForms.length !== 1) {
    throw new Error('Explicit sandbox profile is invalid');
  }
  return `${profile}${profile.endsWith('\n') ? '' : '\n'}${registeredNodeDenialRules()}`;
}

function explicitSandboxInvocation(args, env) {
  if (!env || typeof env !== 'object' || Array.isArray(env)
    || !Array.isArray(args)
    || args.length < 3
    || args.length > 8_192
    || args.some((argument) => (
      typeof argument !== 'string'
      || Buffer.byteLength(argument, 'utf8') > 512 * 1_024
      || /\0/u.test(argument)
    ))
    || args.reduce((bytes, argument) => bytes + Buffer.byteLength(argument, 'utf8'), 0)
      > TRUSTED_INVOCATION_ARGV_MAX_BYTES
    || args[0] !== '-p') {
    throw new Error('Explicit sandbox invocation is invalid');
  }
  const targetIndex = args[2] === '--' ? 3 : 2;
  const target = args[targetIndex];
  let canonicalTarget;
  try {
    canonicalTarget = typeof target === 'string' && target.startsWith('/')
      ? realpathSync(target)
      : undefined;
  } catch {
    canonicalTarget = undefined;
  }
  if (!canonicalTarget
    || canonicalTarget !== target
    || canonicalTarget === '/usr/bin/sandbox-exec') {
    throw new Error('Explicit sandbox invocation is invalid');
  }
  if (authenticatedNodeSpawns.has(canonicalTarget)) {
    throw new Error('Authenticated Node executable was embedded behind an unrecognised command');
  }
  return Object.freeze({
    args: Object.freeze([
      '-p',
      composeExplicitSandboxProfile(args[1]),
      '--',
      ...args.slice(targetIndex),
    ]),
    command: '/usr/bin/sandbox-exec',
    env,
  });
}

function authenticatedNodeScriptEntry(argument) {
  if (typeof argument !== 'string'
    || argument.length === 0
    || argument.startsWith('-')
    || argument.endsWith('/')) return false;
  if (argument.startsWith('/')) return resolve(argument) === argument;
  const components = argument.split('/');
  return argument.startsWith('scripts/')
    && components.every((component) => component !== '' && component !== '.' && component !== '..');
}

function authenticatedNodeArgumentsAreValid(args) {
  if (args.length === 1 && args[0] === '--version') return true;
  if (args.length === 2 && args[0] === '-e') return args[1].length > 0;
  return args.length > 0 && authenticatedNodeScriptEntry(args[0]);
}

function authenticatedNodeInvocation(command, args, env, inheritedFds, sandboxProfile) {
  const configuration = authenticatedNodeSpawns.get(command);
  if (!configuration) {
    let canonicalCommand;
    if (typeof command === 'string' && command.startsWith('/')) {
      try {
        canonicalCommand = realpathSync(command);
      } catch {
        canonicalCommand = undefined;
      }
    }
    if (canonicalCommand && authenticatedNodeSpawns.has(canonicalCommand)) {
      throw new Error('Authenticated Node command used a non-canonical path');
    }
    const embeddedAuthenticatedNode = [...authenticatedNodeSpawns.keys()].find((path) => (
      args.includes(path)
    ));
    if (embeddedAuthenticatedNode) {
      throw new Error('Authenticated Node executable was embedded behind an unrecognised command');
    }
    if (authenticatedNodeSpawns.size === 0
      && command === process.execPath
      && process.env.PIUI_ARCHITECTURE_BOOTSTRAP_FD !== undefined) {
      throw new Error('Authenticated Node spawn configuration is required');
    }
    if (sandboxProfile !== undefined) {
      throw new Error('Authenticated Node sandbox requires an authenticated Node command');
    }
    if (authenticatedNodeSpawns.size > 0) {
      if (command === '/usr/bin/sandbox-exec') {
        return explicitSandboxInvocation(args, env);
      }
      return Object.freeze({
        args: Object.freeze(['-p', registeredNodeDenialProfile(), '--', command, ...args]),
        command: '/usr/bin/sandbox-exec',
        env,
      });
    }
    return Object.freeze({ args, command, env });
  }
  if (!env || typeof env !== 'object' || Array.isArray(env)) {
    throw new Error('Authenticated Node spawn requires an explicit environment');
  }
  if (!Array.isArray(args)
    || args.length > 8_192
    || args.some((argument) => (
      typeof argument !== 'string'
      || Buffer.byteLength(argument, 'utf8') > 256 * 1_024
      || /\0/u.test(argument)
    ))
    || args.reduce((bytes, argument) => bytes + Buffer.byteLength(argument, 'utf8'), 0)
      > TRUSTED_INVOCATION_ARGV_MAX_BYTES
    || !authenticatedNodeArgumentsAreValid(args)) {
    throw new Error('Authenticated Node arguments are invalid');
  }
  const scrubbedEnvironment = Object.fromEntries(Object.entries(env).filter(([key]) => (
    !/^(?:RUBY|GEM|BUNDLE|DYLD_|LD_|NODE_(?!ENV$)|OPENSSL_CONF$|SSL_CERT_(?:FILE|DIR)$|UV_THREADPOOL_SIZE$)/u.test(key)
  )));
  const node = configuration.node;
  const acceptedSandboxProfile = authenticatedSandboxProfile(
    command,
    sandboxProfile,
    configuration,
  );
  assertAuthenticatedNodeSpawnLease(configuration);
  return Object.freeze({
    args: Object.freeze([
      '--disable-gems',
      '-e',
      configuration.launcherSource,
      '--',
      node.path,
      node.dev,
      node.ino,
      String(node.size),
      node.sha256,
      inheritedFds.join(','),
      '--sandbox-profile',
      acceptedSandboxProfile === undefined
        ? '-'
        : createHash('sha256').update(acceptedSandboxProfile.profile).digest('hex'),
      acceptedSandboxProfile === undefined
        ? '-'
        : Buffer.from(acceptedSandboxProfile.profile, 'utf8').toString('base64'),
      '--sandbox-policy',
      acceptedSandboxProfile === undefined
        ? '-'
        : acceptedSandboxProfile.marker
          ? acceptedSandboxProfile.marker
        : acceptedSandboxProfile.kind === 'a28-loopback'
          ? `a28-loopback:${acceptedSandboxProfile.port}`
          : acceptedSandboxProfile.kind,
      '--node-args',
      ...args,
    ]),
    command: configuration.rubyPath,
    env: scrubbedEnvironment,
  });
}

function signalGroup(group, signal) {
  try { process.kill(-group, signal); } catch (error) { if (error?.code !== 'ESRCH') throw error; }
}

function groupExists(group) {
  try { process.kill(-group, 0); return true; }
  catch (error) { if (error?.code === 'ESRCH') return false; if (error?.code === 'EPERM') return true; throw error; }
}

async function terminateRecordedGroupsWithoutObservation(groups) {
  const ownedGroups = [...new Set(groups)].filter((group) => Number.isSafeInteger(group) && group > 1);
  for (const group of ownedGroups) if (groupExists(group)) signalGroup(group, 'SIGTERM');
  let deadline = Date.now() + 2_000;
  while (Date.now() < deadline && ownedGroups.some(groupExists)) await sleep(25);
  for (const group of ownedGroups) if (groupExists(group)) signalGroup(group, 'SIGKILL');
  deadline = Date.now() + 2_000;
  while (Date.now() < deadline && ownedGroups.some(groupExists)) await sleep(25);
  if (ownedGroups.some(groupExists)) throw new Error('Owned command group survived emergency cleanup');
}

export async function terminateRecordedProcessGroupsWithoutObservation(groups) {
  await terminateRecordedGroupsWithoutObservation(groups);
}

export function isProcessObservationFailure(error) {
  return [
    'Process observation failed',
    'Process executable observation failed',
    'Process executable path unavailable',
  ].includes(error instanceof Error ? error.message : '');
}

export function waitForChildSpawn(child) {
  return new Promise((resolveSpawn, rejectSpawn) => {
    child.once('spawn', resolveSpawn);
    child.once('error', rejectSpawn);
  });
}

function signalPidIfExact(pid, ledger, rows, signal) {
  const row = rows.find((candidate) => candidate.pid === pid);
  const entry = row ? ledger.get(identityKey(row)) : undefined;
  if (!row || !entry) return;
  // Revalidate the executable immediately before signalling. Together with
  // parent/group/start/command identity this refuses same-PID replacement.
  if (executableForPid(pid) !== entry.executable) return;
  try { process.kill(pid, signal); } catch (error) { if (error?.code !== 'ESRCH') throw error; }
}

export function observeProcesses(processRunner = spawnSync) {
  let result;
  try {
    result = processRunner(
      '/bin/ps',
      ['-ww', '-axo', 'pid=,ppid=,pgid=,state=,lstart=,command='],
      {
        encoding: 'utf8',
        env: { PATH: '/usr/bin:/bin' },
        maxBuffer: PROCESS_OBSERVATION_MAX_BUFFER_BYTES,
      },
    );
  } catch {
    throw new Error('Process observation failed');
  }
  if (result?.error !== undefined
    || result?.status !== 0
    || typeof result?.stdout !== 'string'
    || Buffer.byteLength(result.stdout, 'utf8') > PROCESS_OBSERVATION_MAX_BUFFER_BYTES) {
    throw new Error('Process observation failed');
  }
  return parseProcessRows(result.stdout);
}

export function executableForPid(pid) {
  const result = spawnSync('/usr/sbin/lsof', ['-a', '-p', String(pid), '-d', 'txt', '-Fn'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (result.status !== 0) throw new Error('Process executable observation failed');
  const path = result.stdout.split('\n').find((line) => line.startsWith('n'))?.slice(1);
  if (!path) throw new Error('Process executable path unavailable');
  return path;
}

export function assertNoNetwork(pid) {
  const result = spawnSync('/usr/sbin/lsof', ['-nP', '-a', '-p', String(pid), '-i'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (result.stdout.trim()) throw new Error('Packaged runtime opened a network descriptor');
  if (![0, 1].includes(result.status)) throw new Error('Network observation failed');
}

function assertLockFile(item) {
  if (!item.isFile() || item.isSymbolicLink() || item.nlink !== 1
    || (item.mode & 0o077) !== 0
    || (typeof process.getuid === 'function' && item.uid !== process.getuid())) {
    throw new Error('Architecture-gate lock file is unsafe');
  }
}

/**
 * Hold a BSD advisory lock on one persistent inode. The descriptor is opened
 * no-follow and passed to lockf's descriptor mode, so acquisition has no
 * owner-file publication window. A crashed owner releases the kernel lock;
 * no contender ever renames, unlinks or stale-reclaims the pathname.
 */
export async function acquireOwnedLock(lockPath, { timeoutMs = 0, label = 'A.21 package gate lock' } = {}) {
  const parent = dirname(lockPath);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const parentItem = await lstat(parent);
  if (!parentItem.isDirectory() || parentItem.isSymbolicLink() || (parentItem.mode & 0o022) !== 0
    || (typeof process.getuid === 'function' && parentItem.uid !== process.getuid())) {
    throw new Error(`${label} parent is unsafe`);
  }

  let fd;
  try {
    fd = openSync(lockPath, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    fchmodSync(fd, 0o600);
    const opened = fstatSync(fd);
    assertLockFile(opened);
    const seconds = Math.max(0, Math.ceil(timeoutMs / 1_000));
    const result = spawnSync('/usr/bin/lockf', ['-s', '-t', String(seconds), '3'], {
      env: { PATH: '/usr/bin:/bin' },
      stdio: ['ignore', 'ignore', 'ignore', fd],
    });
    if (result.status !== 0) {
      throw new Error(timeoutMs > 0 ? `${label} acquisition timed out` : `${label} is already held`);
    }
    const pathItem = await lstat(lockPath);
    if (pathItem.dev !== opened.dev || pathItem.ino !== opened.ino) {
      throw new Error(`${label} pathname identity changed during acquisition`);
    }
    return { lockPath, fd, dev: opened.dev, ino: opened.ino, released: false };
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    throw error;
  }
}

export async function releaseOwnedLock(lock) {
  if (!lock || lock.released) throw new Error('Architecture-gate lock is not held');
  let failure;
  try {
    const descriptor = fstatSync(lock.fd);
    const pathItem = await lstat(lock.lockPath);
    if (descriptor.dev !== lock.dev || descriptor.ino !== lock.ino
      || pathItem.dev !== lock.dev || pathItem.ino !== lock.ino) {
      throw new Error('Architecture-gate lock pathname identity changed before release');
    }
  } catch (error) {
    failure = error;
  } finally {
    closeSync(lock.fd);
    lock.released = true;
  }
  if (failure) throw failure;
}

function ownedCommandProcessKey(row) {
  // PGID, PPID and argv are mutable across setsid(2), reparenting and exec.
  // PID plus the kernel-reported process start is the stable ps identity; an
  // executable path is retained separately and rechecked before signalling.
  return `${row.pid}:${row.start}`;
}

class OwnedCommandLedger {
  constructor(rootPid, observer = observeProcesses) {
    this.rootPid = rootPid;
    this.observer = observer;
    this.rootBound = false;
    this.rootDiscoveryOpen = true;
    this.processes = new Map();
    this.identities = new Map();
    this.groups = new Set();
  }

  async executableWhileExact(row) {
    try {
      return executableForPid(row.pid);
    } catch (error) {
      const refreshed = await this.observer();
      const current = refreshed.find((candidate) => ownedCommandProcessKey(candidate) === ownedCommandProcessKey(row));
      if (!current || current.state?.startsWith('Z')) return undefined;
      throw error;
    }
  }

  record(row, executable) {
    const key = ownedCommandProcessKey(row);
    let processEntry = this.processes.get(key);
    if (!processEntry) {
      processEntry = { pid: row.pid, start: row.start, lastCommand: row.command, executables: new Set(), groups: new Set() };
      this.processes.set(key, processEntry);
    }
    processEntry.lastCommand = row.command;
    processEntry.executables.add(executable);
    processEntry.groups.add(row.pgid);
    this.groups.add(row.pgid);
    const identity = `${key}:${executable}`;
    if (!this.identities.has(identity)) this.identities.set(identity, Object.freeze({ ...row, executable }));
  }

  async sample() {
    const rows = await this.observer();
    const liveRecorded = rows.filter((row) => this.processes.has(ownedCommandProcessKey(row)));
    let roots = liveRecorded.map((row) => row.pid);
    if (!this.rootBound && this.rootDiscoveryOpen && Number.isSafeInteger(this.rootPid)) {
      const root = rows.find((row) => row.pid === this.rootPid);
      if (root) roots = [root.pid, ...roots];
    }
    const descendants = descendantsOf(roots, rows);
    // The spawn creates this PGID. Sampling it before the root is bound closes
    // the ordinary leader-exits-before-first-ps race without ever signalling
    // by PGID alone: every member still receives an executable-bound identity.
    const initialGroup = this.rootDiscoveryOpen
      ? rows.filter((row) => row.pgid === this.rootPid)
      : [];
    const candidates = rows.filter((row) => roots.includes(row.pid) || descendants.includes(row) || initialGroup.includes(row));
    for (const row of candidates) {
      const key = ownedCommandProcessKey(row);
      const existing = this.processes.get(key);
      let executable;
      if (!existing || existing.lastCommand !== row.command) {
        executable = await this.executableWhileExact(row);
        if (!executable) continue;
      } else {
        executable = [...existing.executables].at(-1);
      }
      this.record(row, executable);
      if (row.pid === this.rootPid) this.rootBound = true;
    }
    return rows;
  }

  closeRootDiscovery() {
    this.rootDiscoveryOpen = false;
  }

  async exactLive(rows = this.observer()) {
    const observed = await rows;
    const exact = [];
    const unverifiable = [];
    for (const row of observed) {
      const processEntry = this.processes.get(ownedCommandProcessKey(row));
      if (!processEntry) continue;
      let executable;
      try {
        executable = executableForPid(row.pid);
      } catch (error) {
        const refreshed = await this.observer();
        const current = refreshed.find((candidate) => ownedCommandProcessKey(candidate) === ownedCommandProcessKey(row));
        if (!current || current.state?.startsWith('Z')) continue;
        unverifiable.push(row);
        continue;
      }
      if (processEntry.executables.has(executable)) exact.push({ row, processEntry, executable });
      else unverifiable.push(row);
    }
    return { exact, unverifiable };
  }

  async signalExactPid(target, signal) {
    const rows = await this.observer();
    const current = rows.find((row) => ownedCommandProcessKey(row) === ownedCommandProcessKey(target.row));
    if (!current) return;
    const processEntry = this.processes.get(ownedCommandProcessKey(current));
    if (!processEntry) return;
    let executable;
    try { executable = executableForPid(current.pid); } catch { return; }
    if (!processEntry.executables.has(executable)) return;
    try { process.kill(current.pid, signal); } catch (error) { if (error?.code !== 'ESRCH') throw error; }
  }

  async signalLive(signal) {
    await this.sample();
    const rows = await this.observer();
    const live = await this.exactLive(rows);
    const exactKeys = new Set(live.exact.map(({ row }) => ownedCommandProcessKey(row)));
    const anchoredGroups = new Set(live.exact.map(({ row }) => row.pgid));
    const safeGroups = new Set();
    for (const { row } of live.exact) {
      const members = rows.filter((candidate) => candidate.pgid === row.pgid);
      if (members.length && members.every((member) => exactKeys.has(ownedCommandProcessKey(member)))) safeGroups.add(row.pgid);
    }
    for (const group of [...safeGroups].sort((a, b) => a - b)) {
      const refreshedRows = await this.observer();
      const refreshed = await this.exactLive(refreshedRows);
      const refreshedKeys = new Set(refreshed.exact.map(({ row }) => ownedCommandProcessKey(row)));
      const members = refreshedRows.filter((row) => row.pgid === group);
      if (members.length && members.every((row) => refreshedKeys.has(ownedCommandProcessKey(row)))) signalGroup(group, signal);
    }
    for (const target of live.exact.filter(({ row }) => !safeGroups.has(row.pgid))) {
      await this.signalExactPid(target, signal);
    }
    const ambiguousGroups = [...this.groups].filter((group) => {
      const members = rows.filter((row) => row.pgid === group);
      return members.length > 0 && (!anchoredGroups.has(group)
        || members.some((row) => !exactKeys.has(ownedCommandProcessKey(row))));
    });
    return { ...live, ambiguousGroups };
  }

  async terminate() {
    let forced = false;
    let live = await this.signalLive('SIGTERM');
    const hasLive = () => live.exact.length > 0 || live.unverifiable.length > 0 || live.ambiguousGroups.length > 0;
    const hadRecordedSurvivor = hasLive();
    let deadline = Date.now() + 5_000;
    while (Date.now() < deadline) {
      if (!hasLive()) return { forced, hadRecordedSurvivor };
      await sleep(50);
      live = await this.signalLive('SIGTERM');
    }
    forced = true;
    deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      live = await this.signalLive('SIGKILL');
      if (!hasLive()) return { forced, hadRecordedSurvivor };
      await sleep(50);
    }
    throw new Error('Owned command identity survived cleanup');
  }
}

/**
 * Run one trusted architecture-gate command with a sampled descendant ledger.
 * Recorded PID/start/executable identities remain attributable after observed
 * reparenting, exec and process-group/session changes. This is not a claim of
 * gapless containment against a descendant that forks and disappears wholly
 * between process-table samples.
 */
export async function runOwnedCommand({
  command,
  args = [],
  cwd,
  env,
  timeoutMs,
  maxOutputBytes = 64 * 1024 * 1024,
  input,
  inheritedFds = [],
  signal,
  label = 'Architecture-gate command',
  observer = observeProcesses,
  stderrObserver,
  sandboxProfile,
}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error(`${label} has no valid deadline`);
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw new Error(`${label} has no valid output bound`);
  }
  if (signal?.aborted) throw new Error(`${label} was cut off by its parent`);
  if (input !== undefined && !Buffer.isBuffer(input)) {
    throw new Error(`${label} input must be a mutable buffer`);
  }
  if (stderrObserver !== undefined && typeof stderrObserver !== 'function') {
    throw new Error(`${label} stderr observer is invalid`);
  }
  if (!Array.isArray(inheritedFds)
    || inheritedFds.length > 8
    || inheritedFds.some((fd) => !Number.isSafeInteger(fd) || fd < 3 || fd > 255)
    || new Set(inheritedFds).size !== inheritedFds.length) {
    throw new Error(`${label} inherited descriptors are invalid`);
  }
  const stdio = Array.from(
    { length: Math.max(3, ...inheritedFds.map((fd) => fd + 1)) },
    (_, fd) => (fd === 0 ? (input === undefined ? 'ignore' : 'pipe') : fd < 3 ? 'pipe' : 'ignore'),
  );
  for (const fd of inheritedFds) stdio[fd] = fd;
  const invocation = authenticatedNodeInvocation(
    command,
    args,
    env,
    inheritedFds,
    sandboxProfile,
  );
  const child = spawn(invocation.command, invocation.args, {
    cwd,
    env: invocation.env,
    detached: true,
    stdio,
  });
  if (input !== undefined) {
    child.stdin.on('error', () => undefined);
    child.stdin.end(input);
  }
  const stdout = [];
  const stderr = [];
  let outputBytes = 0;
  let outputFailure;
  let triggerOutputFailure;
  const outputFailed = new Promise((resolveFailure) => { triggerOutputFailure = resolveFailure; });
  let stdoutCollector;
  let stderrCollector;
  const stopOutputCollection = () => {
    for (const [stream, collector] of [
      [child.stdout, stdoutCollector],
      [child.stderr, stderrCollector],
    ]) {
      if (collector) stream.removeListener('data', collector);
      stream.pause();
      stream.destroy();
    }
  };
  const collect = (target, chunkObserver) => (chunk) => {
    if (outputFailure) return;
    const remaining = maxOutputBytes - outputBytes;
    if (chunk.length > remaining) {
      if (remaining > 0) target.push(Buffer.from(chunk.subarray(0, remaining)));
      outputBytes = maxOutputBytes;
      outputFailure = new Error(`${label} exceeded its output bound`);
      triggerOutputFailure('output');
      stopOutputCollection();
      return;
    }
    outputBytes += chunk.length;
    const retained = Buffer.from(chunk);
    target.push(retained);
    if (chunkObserver) {
      try {
        chunkObserver(Buffer.from(retained));
      } catch (error) {
        outputFailure = error instanceof Error
          ? error
          : new Error(`${label} stderr observer rejected output`);
        triggerOutputFailure('output');
        stopOutputCollection();
      }
    }
  };
  stdoutCollector = collect(stdout);
  stderrCollector = collect(stderr, stderrObserver);
  child.stdout.on('data', stdoutCollector);
  child.stderr.on('data', stderrCollector);

  let abortListener;
  const aborted = new Promise((resolveAbort) => {
    abortListener = () => resolveAbort('abort');
    signal?.addEventListener('abort', abortListener, { once: true });
  });
  let timeout;
  const timedOut = new Promise((resolveTimeout) => {
    timeout = setTimeout(() => resolveTimeout('timeout'), timeoutMs);
    timeout.unref?.();
  });
  const exited = new Promise((resolveExit) => {
    child.once('error', (error) => resolveExit({ type: 'spawn-error', error }));
    child.once('close', (status, childSignal) => resolveExit({ type: 'exit', status, signal: childSignal }));
  });
  const ledger = new OwnedCommandLedger(child.pid, observer);
  const sampleWithRetry = async () => {
    let lastError;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try { return await ledger.sample(); }
      catch (error) {
        lastError = error;
        if (attempt < 2) await sleep(10);
      }
    }
    throw lastError;
  };
  let stopSampling = false;
  let samplingFailure;
  let reportSamplingFailure;
  const samplingFailed = new Promise((resolveFailure) => { reportSamplingFailure = resolveFailure; });
  const sampler = (async () => {
    while (!stopSampling) {
      await sampleWithRetry();
      await sleep(20);
    }
  })().catch((error) => {
    samplingFailure = error;
    reportSamplingFailure({ type: 'sampling-error', error });
  });

  const outcome = await Promise.race([exited, timedOut, aborted, outputFailed, samplingFailed]);
  clearTimeout(timeout);
  signal?.removeEventListener('abort', abortListener);
  stopSampling = true;
  await sampler;
  let finalSamplingFailure;
  try { await sampleWithRetry(); } catch (error) { finalSamplingFailure = error; }
  ledger.closeRootDiscovery();
  let cleanup;
  if (samplingFailure || finalSamplingFailure) {
    const emergencyGroups = [child.pid, ...ledger.groups];
    try { cleanup = await ledger.terminate(); }
    catch { await terminateRecordedGroupsWithoutObservation(emergencyGroups); }
    if (emergencyGroups.some(groupExists)) await terminateRecordedGroupsWithoutObservation(emergencyGroups);
    throw new Error(`${label} descendant identity observation failed`);
  }
  cleanup = await ledger.terminate();
  if (typeof outcome === 'string' || outcome.type === 'spawn-error' || outcome.type === 'sampling-error') {
    if (outcome === 'timeout') throw new Error(`${label} exceeded its deadline`);
    if (outcome === 'abort') throw new Error(`${label} was cut off by its parent`);
    if (outcome === 'output') throw outputFailure;
    if (outcome?.type === 'sampling-error') throw new Error(`${label} descendant identity observation failed`);
    throw new Error(`${label} could not be started`);
  }
  if (cleanup.hadRecordedSurvivor) throw new Error(`${label} left a recorded descendant survivor`);
  return Object.freeze({
    status: outcome.status,
    signal: outcome.signal,
    stdout: Buffer.concat(stdout),
    stderr: Buffer.concat(stderr),
    forcedCleanup: cleanup?.forced === true,
  });
}

export function installParentCutoffs() {
  const controller = new AbortController();
  const handlers = new Map();
  for (const signalName of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    const handler = () => controller.abort(new Error(`Architecture gate received ${signalName}`));
    handlers.set(signalName, handler);
    process.on(signalName, handler);
  }
  return Object.freeze({
    signal: controller.signal,
    dispose() {
      for (const [signalName, handler] of handlers) process.removeListener(signalName, handler);
    },
  });
}
