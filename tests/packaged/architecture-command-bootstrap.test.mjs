import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '../..');
const bootstrap = '/usr/bin/env -i PATH=/usr/bin:/bin LANG=en_AU.UTF-8 LC_ALL=en_AU.UTF-8 /usr/bin/ruby --disable-gems scripts/architecture-bootstrap.rb';

test('all package, record and production commands enter the scrubbed authenticated bootstrap', async () => {
  const [packageBytes, bootstrapSource, bootstrapContract, packageRunner, buildRunner, recordRunner] =
    await Promise.all([
      readFile(resolve(root, 'package.json'), 'utf8'),
      readFile(resolve(root, 'scripts/architecture-bootstrap.rb'), 'utf8'),
      readFile(resolve(root, 'scripts/architecture-bootstrap-contract.mjs'), 'utf8'),
      readFile(resolve(root, 'scripts/package-spike.mjs'), 'utf8'),
      readFile(resolve(root, 'scripts/build-production.mjs'), 'utf8'),
      readFile(resolve(root, 'scripts/record-architecture-gate.mjs'), 'utf8'),
    ]);
  const scripts = JSON.parse(packageBytes).scripts;
  const expected = {
    'spike:package:inspect': `${bootstrap} package`,
    'spike:packaged:sdk': `${bootstrap} package --authoritative-a22`,
    'spike:packaged:credentials': `${bootstrap} package --authoritative-a23`,
    'spike:packaged:trust': `${bootstrap} package --authoritative-a24`,
    'spike:packaged:approvals': `${bootstrap} package --authoritative-a25`,
    'spike:packaged:markdown': `${bootstrap} package --authoritative-a26`,
    'spike:packaged:lifecycle': `${bootstrap} package --authoritative-a27`,
    'spike:packaged:accessibility': `${bootstrap} package --authoritative-a28`,
    'gate:architecture:record': `${bootstrap} record`,
    'tauri:build:production': `${bootstrap} build`,
  };
  assert.deepEqual(
    Object.fromEntries(Object.keys(expected).map((key) => [key, scripts[key]])),
    expected,
  );
  assert.match(bootstrapSource, /reject\('Architecture bootstrap requires a scrubbed environment'\)/u);
  assert.match(bootstrapSource, /reject\('Architecture bootstrap PATH is not exact'\)/u);
  assert.match(
    bootstrapSource,
    /mode == 'package' && ARGV == \['--authoritative-a28'\]/u,
  );
  assert.match(bootstrapSource, /POSIX_SPAWN_START_SUSPENDED/u);
  assert.match(bootstrapSource, /SecCodeCopyGuestWithAttributes/u);
  assert.match(bootstrapSource, /cleanup_bootstrap_private_root/u);
  assert.match(bootstrapSource, /receipt_reader = File\.open\(receipt_path, File::RDONLY/u);
  assert.match(bootstrapSource, /receipt_writer\.close/u);
  assert.match(bootstrapContract, /assertReadOnlyDescriptor\(fd\)/u);
  assert.match(packageRunner, /assertArchitectureBootstrap\(/u);
  assert.match(buildRunner, /assertArchitectureBootstrap\(/u);
  assert.match(recordRunner, /assertArchitectureBootstrap\(/u);
});
