import { chmodSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CANARY_SCAN_TEST_HOOK,
  scanSecretCanary,
} from '../../../scripts/scan-secret-canary.mjs';

const fixture = realpathSync(mkdtempSync(join(tmpdir(), `piui-a23-parent-death-fixture-${process.pid}-`)));
chmodSync(fixture, 0o700);
const root = join(fixture, 'scan-root');
mkdirSync(root, { mode: 0o700 });
const capture = join(root, 'capture.bin');
const canary = Buffer.from('PIUI_A23_PARENT_DEATH_CANARY_01', 'ascii');
writeFileSync(capture, canary, { mode: 0o600 });

await scanSecretCanary({
  workspace: fixture,
  roots: [root],
  authorised: [{ path: capture, count: 1 }],
  canary,
  [CANARY_SCAN_TEST_HOOK]: async (phase) => {
    if (phase === 'roots-held') {
      process.stdout.write('READY\n');
      await new Promise(() => undefined);
    }
  },
});
