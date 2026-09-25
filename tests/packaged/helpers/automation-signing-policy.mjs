import {
  chmodSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AUTOMATION_SIGNING_NOT_CONFIGURED,
  AUTOMATION_SIGNING_POLICY_ENVIRONMENT,
  automationSigningPolicy,
} from '../../../scripts/architecture-gate-schema.mjs';

// Committed placeholder identity. It names no real certificate or team, so
// fixtures signed "by" it can never verify against a real Keychain.
export const FIXTURE_AUTOMATION_SIGNING_POLICY = Object.freeze({
  bundleIdentifier: 'au.com.piui.desktop.architecture-test',
  certificateCommonName: 'Apple Development: automation-signer@example.invalid (ZZZZ000001)',
  certificateSha1: '0000000000000000000000000000000000000001',
  certificateSha256: '0000000000000000000000000000000000000000000000000000000000000001',
  designatedRequirement: 'anchor apple generic and identifier "au.com.piui.desktop.architecture-test" and certificate leaf[subject.OU] = "ZZZZ000002"',
  requirementsBytes: 136,
  schemaVersion: 1,
  teamIdentifier: 'ZZZZ000002',
});

export function privatePolicyDirectory(label = 'signing-policy') {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), `piui-${label}.`)));
  chmodSync(directory, 0o700);
  return directory;
}

export function writeAutomationSigningPolicyFile(
  directory,
  value = FIXTURE_AUTOMATION_SIGNING_POLICY,
  mode = 0o600,
) {
  const path = join(directory, 'automation-signing-policy.json');
  const bytes = typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`;
  writeFileSync(path, bytes, { flag: 'wx', mode });
  chmodSync(path, mode);
  return path;
}

/**
 * Point this test process (and any child that inherits its environment) at
 * the placeholder identity through the same loader production uses. Call it
 * before anything resolves the process-wide policy.
 */
export function useFixtureAutomationSigningPolicy() {
  const directory = privatePolicyDirectory();
  const path = writeAutomationSigningPolicyFile(directory);
  process.env[AUTOMATION_SIGNING_POLICY_ENVIRONMENT] = path;
  process.once('exit', () => rmSync(directory, { force: true, recursive: true }));
  return path;
}

/**
 * Live signing tests need the owner's real pin. Without it they are skipped
 * with the loader's own reason rather than failing on a placeholder.
 */
export function realAutomationSigningSkipReason() {
  try {
    automationSigningPolicy();
    return false;
  } catch (error) {
    if (error?.code === AUTOMATION_SIGNING_NOT_CONFIGURED) return error.message;
    throw error;
  }
}
