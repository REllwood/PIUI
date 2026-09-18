#!/usr/bin/env node
/**
 * Provenance for tests/fixtures/pi-sessions/active-branch-v3.jsonl.
 *
 * This script creates every session line through Pi 0.82's package-root public
 * SessionManager APIs in a temporary directory, then byte-copies the completed
 * file to a new destination. It deliberately refuses to open or overwrite an
 * existing repository fixture. Generated Pi entry IDs/timestamps vary; contract
 * assertions are therefore relational rather than golden-ID based.
 */
import { constants, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { SessionManager } from '@earendil-works/pi-coding-agent';

const destination = resolve(
  process.argv[2] ?? 'tests/fixtures/pi-sessions/active-branch-v3.jsonl',
);
if (existsSync(destination)) {
  throw new Error('Refusing to open or overwrite an existing Pi session fixture');
}

const root = mkdtempSync(join(tmpdir(), 'piui-a19-fixture-'));
const sessionDirectory = join(root, 'sessions');
mkdirSync(sessionDirectory, { mode: 0o700 });

const usage = Object.freeze({
  input: 1,
  output: 1,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 2,
  cost: Object.freeze({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 }),
});
const assistant = (text, timestamp) => Object.freeze({
  role: 'assistant',
  content: Object.freeze([Object.freeze({ type: 'text', text })]),
  api: 'fixture-api',
  provider: 'fixture-provider',
  model: 'fixture-model',
  usage,
  stopReason: 'stop',
  timestamp,
});

try {
  const manager = SessionManager.create(
    '/tmp',
    sessionDirectory,
    { id: 'piui-a19-active-branch-v3' },
  );
  manager.appendThinkingLevelChange('off');
  manager.appendCustomEntry('piui.a19.fixture-provenance', Object.freeze({
    schemaVersion: 1,
    state: 'generated-by-public-sdk',
  }));
  manager.appendMessage(Object.freeze({
    role: 'user', content: 'root request', timestamp: 1_700_000_000_000,
  }));
  const selectedAssistant = manager.appendMessage(assistant(
    'selected earlier assistant response',
    1_700_000_001_000,
  ));
  manager.appendMessage(Object.freeze({
    role: 'user', content: 'abandoned branch request', timestamp: 1_700_000_002_000,
  }));
  manager.appendMessage(assistant('abandoned branch response', 1_700_000_003_000));
  manager.branch(selectedAssistant);
  manager.appendMessage(Object.freeze({
    role: 'user', content: 'active branch request', timestamp: 1_700_000_004_000,
  }));
  manager.appendMessage(assistant('active branch response', 1_700_000_005_000));

  const generated = manager.getSessionFile();
  if (!generated || !existsSync(generated)) throw new Error('Pi did not persist the fixture');
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(generated, destination, constants.COPYFILE_EXCL);
} finally {
  rmSync(root, { recursive: true, force: true });
}
