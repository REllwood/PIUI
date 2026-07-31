import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CanaryScanError, scanSecretCanary } from '../../../scripts/scan-secret-canary.mjs';

const workspace = mkdtempSync(join(tmpdir(), 'piui-a23-acl-probe-'));
const canary = Buffer.from('PIUI_A23_ACL_CANARY_00000001', 'ascii');
try {
  chmodSync(workspace, 0o700);
  const root = join(workspace, 'scan-root');
  mkdirSync(root, { mode: 0o700 });
  const capture = join(root, 'capture.bin');
  writeFileSync(capture, canary, { mode: 0o600 });
  const acl = spawnSync('/bin/chmod', ['+a', 'everyone allow read', root], { stdio: 'ignore' });
  if (acl.status !== 0) throw new Error('fixture');
  try {
    await scanSecretCanary({
      workspace,
      roots: [root],
      authorised: [{ path: capture, count: 1 }],
      canary,
    });
    throw new Error('accepted');
  } catch (error) {
    if (!(error instanceof CanaryScanError)) throw error;
  }
} catch {
  process.exitCode = 1;
} finally {
  canary.fill(0);
  rmSync(workspace, { recursive: true, force: true });
}
