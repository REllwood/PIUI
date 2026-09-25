import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  link,
  mkdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import {
  AUTOMATION_SIGNING_NOT_CONFIGURED,
  AUTOMATION_SIGNING_POLICY_ENVIRONMENT,
  automationSigningPolicyPath,
  parseAutomationSigningPolicy,
  readAutomationSigningPolicy,
} from '../../scripts/architecture-gate-schema.mjs';
import {
  FIXTURE_AUTOMATION_SIGNING_POLICY,
  privatePolicyDirectory,
  writeAutomationSigningPolicyFile,
} from './helpers/automation-signing-policy.mjs';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const notConfigured = /Automation signing identity not configured/u;
const invalid = /Automation signing policy is invalid/u;
const unsafe = /Automation signing policy file is unsafe/u;

function policyDirectory(t, label) {
  const directory = privatePolicyDirectory(label);
  t.after(async () => rm(directory, { force: true, recursive: true }));
  return directory;
}

test('resolves the default policy path under the account home and honours an absolute override', () => {
  assert.equal(
    automationSigningPolicyPath({}, '/Users/example'),
    '/Users/example/Library/Application Support/PIUI/automation-signing-policy.json',
  );
  assert.equal(
    automationSigningPolicyPath({ [AUTOMATION_SIGNING_POLICY_ENVIRONMENT]: '' }, '/Users/example'),
    '/Users/example/Library/Application Support/PIUI/automation-signing-policy.json',
  );
  assert.equal(
    automationSigningPolicyPath(
      { [AUTOMATION_SIGNING_POLICY_ENVIRONMENT]: '/private/policy/signing.json' },
      '/Users/example',
    ),
    '/private/policy/signing.json',
  );
  for (const configured of ['relative/policy.json', '/private/policy/../signing.json', '/private/\npolicy.json']) {
    assert.throws(
      () => automationSigningPolicyPath({ [AUTOMATION_SIGNING_POLICY_ENVIRONMENT]: configured }, '/Users/example'),
      /must be an absolute, normalised path/u,
    );
  }
  assert.throws(() => automationSigningPolicyPath({}, 'relative-home'), /home directory is invalid/u);
});

test('a missing policy fails closed as not configured', (t) => {
  const directory = policyDirectory(t, 'signing-policy-missing');
  const path = join(directory, 'automation-signing-policy.json');
  assert.throws(() => readAutomationSigningPolicy(path), (error) => {
    assert.equal(error.code, AUTOMATION_SIGNING_NOT_CONFIGURED);
    assert.match(error.message, notConfigured);
    assert.ok(error.message.includes(path));
    return true;
  });
  assert.throws(() => readAutomationSigningPolicy('relative.json'), /policy path is invalid/u);
});

test('a valid owner-only policy is parsed into one frozen exact pin', (t) => {
  const directory = policyDirectory(t, 'signing-policy-valid');
  const path = writeAutomationSigningPolicyFile(directory);
  const policy = readAutomationSigningPolicy(path);
  assert.deepEqual(policy, FIXTURE_AUTOMATION_SIGNING_POLICY);
  assert.ok(Object.isFrozen(policy));

  const readable = policyDirectory(t, 'signing-policy-readable');
  assert.deepEqual(
    readAutomationSigningPolicy(writeAutomationSigningPolicyFile(readable, undefined, 0o644)),
    FIXTURE_AUTOMATION_SIGNING_POLICY,
  );
});

test('malformed policies are rejected without echoing their content', (t) => {
  const base = FIXTURE_AUTOMATION_SIGNING_POLICY;
  const { requirementsBytes: _requirementsBytes, ...missingKey } = base;
  const otherTeam = 'anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = "ZZZZ000003"';
  const values = [
    '{"schemaVersion":1',
    '[]',
    'null',
    missingKey,
    { ...base, extra: true },
    { ...base, schemaVersion: 2 },
    { ...base, bundleIdentifier: 'au.com.piui.desktop' },
    { ...base, certificateCommonName: 'Developer ID Application: Example (ZZZZ000001)' },
    { ...base, certificateCommonName: 'Apple Development: quoted " name (ZZZZ000001)' },
    { ...base, certificateCommonName: 'Apple Development: line\nbreak (ZZZZ000001)' },
    { ...base, certificateCommonName: 'Apple Development: missing identifier' },
    { ...base, certificateSha1: base.certificateSha1.toLowerCase().replace('1', 'a') },
    { ...base, certificateSha1: '0'.repeat(39) },
    { ...base, certificateSha256: 'A'.repeat(64) },
    { ...base, certificateSha256: 1 },
    { ...base, teamIdentifier: 'zzzz000002' },
    { ...base, designatedRequirement: otherTeam },
    { ...base, designatedRequirement: `${base.designatedRequirement} or anchor apple` },
    { ...base, requirementsBytes: 137 },
    { ...base, requirementsBytes: '136' },
  ];
  for (const [index, value] of values.entries()) {
    const directory = policyDirectory(t, `signing-policy-malformed-${index}`);
    const path = writeAutomationSigningPolicyFile(directory, value);
    assert.throws(() => readAutomationSigningPolicy(path), (error) => {
      assert.match(error.message, invalid);
      assert.doesNotMatch(error.message, /ZZZZ|0000000000/u);
      return true;
    }, `malformed case ${index}`);
  }
  assert.throws(() => parseAutomationSigningPolicy(Object.create(null)), invalid);
});

test('links, shared-writable files and shared-writable parents are refused', async (t) => {
  const groupWritable = policyDirectory(t, 'signing-policy-group');
  assert.throws(
    () => readAutomationSigningPolicy(writeAutomationSigningPolicyFile(groupWritable, undefined, 0o620)),
    unsafe,
  );
  const worldWritable = policyDirectory(t, 'signing-policy-world');
  assert.throws(
    () => readAutomationSigningPolicy(writeAutomationSigningPolicyFile(worldWritable, undefined, 0o602)),
    unsafe,
  );

  const linked = policyDirectory(t, 'signing-policy-symlink');
  const target = writeAutomationSigningPolicyFile(policyDirectory(t, 'signing-policy-target'));
  const symbolic = join(linked, 'automation-signing-policy.json');
  await symlink(target, symbolic);
  assert.throws(() => readAutomationSigningPolicy(symbolic), unsafe);

  const hardLinked = policyDirectory(t, 'signing-policy-hardlink');
  const original = writeAutomationSigningPolicyFile(hardLinked);
  await link(original, join(hardLinked, 'second-name.json'));
  assert.throws(() => readAutomationSigningPolicy(original), unsafe);

  const sharedParent = policyDirectory(t, 'signing-policy-parent');
  const inner = join(sharedParent, 'shared');
  await mkdir(inner, { mode: 0o700 });
  const shared = writeAutomationSigningPolicyFile(inner);
  await chmod(inner, 0o770);
  assert.throws(() => readAutomationSigningPolicy(shared), unsafe);

  const directoryPolicy = policyDirectory(t, 'signing-policy-directory');
  const notFile = join(directoryPolicy, 'automation-signing-policy.json');
  await mkdir(notFile, { mode: 0o700 });
  assert.throws(() => readAutomationSigningPolicy(notFile), unsafe);

  const oversized = policyDirectory(t, 'signing-policy-oversized');
  const large = join(oversized, 'automation-signing-policy.json');
  await writeFile(large, `${JSON.stringify(FIXTURE_AUTOMATION_SIGNING_POLICY)}${' '.repeat(16_384)}\n`, {
    mode: 0o600,
  });
  assert.throws(() => readAutomationSigningPolicy(large), unsafe);
});

function runWithPolicy(path, source) {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: {
      HOME: process.env.HOME,
      LANG: 'en_AU.UTF-8',
      LC_ALL: 'en_AU.UTF-8',
      PATH: '/usr/bin:/bin',
      [AUTOMATION_SIGNING_POLICY_ENVIRONMENT]: path,
    },
    maxBuffer: 256 * 1024,
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('every consumer of the real signer fails closed when the identity is not configured', (t) => {
  const directory = policyDirectory(t, 'signing-policy-consumers');
  const missing = join(directory, 'automation-signing-policy.json');
  const module = (path) => JSON.stringify(pathToFileURL(resolve(repositoryRoot, path)).href);
  const outcomes = runWithPolicy(missing, `
    const schema = await import(${module('scripts/architecture-gate-schema.mjs')});
    const signing = await import(${module('scripts/automation-host-signing.mjs')});
    const broker = await import(${module('scripts/automation-signing-broker.mjs')});
    const fixtures = await import(${module('tests/packaged/architecture-proof-fixtures.mjs')});
    const outcome = async (action) => {
      try {
        await action();
        return 'accepted';
      } catch (error) {
        return error.message;
      }
    };
    const { record } = fixtures.architectureMeasuredDelta('automation-twin', {
      baseFingerprint: 'a'.repeat(64),
      twinFingerprint: 'b'.repeat(64),
    });
    process.stdout.write(JSON.stringify({
      authenticate: await outcome(() => signing.authenticateAutomationSigningAuthority()),
      broker: await outcome(() => broker.startAutomationSigningBroker({
        command: '/usr/bin/true',
        controlRoot: '/private/piui-unconfigured/control',
        hostPath: '/private/piui-unconfigured/host',
      })),
      evidence: await outcome(() => signing.assertAutomationHostSigningEvidence({})),
      inspect: await outcome(() => signing.inspectAppleDevelopmentHost('/private/piui-unconfigured/host')),
      policy: await outcome(() => schema.automationSigningPolicy()),
      record: await outcome(() => schema.assertMeasuredTwinDeltaRecord(record, 'automation-twin')),
      signingArguments: await outcome(() => signing.automationSigningArguments(
        '/private/piui-unconfigured/host',
        signing.automationSigningKeychainPath(),
      )),
    }));
  `);
  for (const [consumer, message] of Object.entries(outcomes)) {
    assert.match(message, notConfigured, consumer);
  }
});

test('an injected policy file reaches child processes through the environment', (t) => {
  const directory = policyDirectory(t, 'signing-policy-child');
  const path = writeAutomationSigningPolicyFile(directory);
  const schema = JSON.stringify(
    pathToFileURL(resolve(repositoryRoot, 'scripts/architecture-gate-schema.mjs')).href,
  );
  const policy = runWithPolicy(path, `
    const { automationSigningPolicy } = await import(${schema});
    process.stdout.write(JSON.stringify(automationSigningPolicy()));
  `);
  assert.deepEqual(policy, FIXTURE_AUTOMATION_SIGNING_POLICY);
});
