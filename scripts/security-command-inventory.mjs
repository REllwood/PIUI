import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const sourcePath = resolve(root, 'src-tauri/src/lib.rs');
const outputPath = resolve(root, 'docs/architecture/command-inventory.md');

function commandOwner(command) {
  if (/^(present_credential|credential_)/u.test(command)) return ['Rust credential repository', 'Native sheet, permission checks, opaque references and secret canaries'];
  if (command.startsWith('approval_')) return ['Rust approval domain', 'Immutable IDs, legal transitions, risk-owned scopes and replay rejection'];
  if (command.startsWith('workspace_')) return ['Rust workspace registry', 'Native capability, canonical identity, revision and trust-before-load'];
  if (/^(sidecar_|bridge_|stream_|cancel_stream)/u.test(command)) return ['Rust supervisor and protocol projector', 'Frame limits, public-operation mapping, generation and process ownership'];
  if (command.startsWith('product_')) return ['Rust bridge and public Pi adapter', 'Typed request validation, session generation and adapter contracts'];
  if (/^(open_|attachment_|close_|window_|notification_|menu_)/u.test(command)) return ['Rust platform adapter', 'Closed request type, capability or disclosed-target validation'];
  if (/^(app_|diagnostics_|update_|host_)/u.test(command)) return ['Rust application domain', 'Versioned data, redaction, bounded output and disabled-safe configuration'];
  if (/^a2[3678]_/u.test(command)) return ['Architecture-test feature only', 'Frozen test activation, exact nonce/mode and controlled twin evidence'];
  return ['Rust command boundary', 'Typed deserialisation and registered-command regression tests'];
}

function extractCommands(source) {
  const blocks = [...source.matchAll(/tauri::generate_handler!\[([\s\S]*?)\n\s*\];/gu)];
  if (blocks.length < 1) throw new Error('Tauri handler inventory unavailable');
  const commands = new Set();
  for (const block of blocks) {
    for (const line of block[1].split('\n')) {
      if (line.includes('#[cfg(')) continue;
      const match = line.trim().match(/(?:^|::)([a-z][a-z0-9_]*)\s*,?\s*$/u);
      if (match) commands.add(match[1]);
    }
  }
  return [...commands].sort((left, right) => left.localeCompare(right, 'en-AU'));
}

function render(commands) {
  const rows = commands.map((command) => {
    const [owner, controls] = commandOwner(command);
    return `| \`${command}\` | ${owner} | ${controls} |`;
  });
  return [
    '# Native command inventory',
    '',
    'This file is generated from every `tauri::generate_handler!` block. `pnpm security:threat-model` rejects drift. Test-feature commands are included because controlled packaged twins compile them even though ordinary production activation does not.',
    '',
    '| Command | Authority owner | Validation and evidence class |',
    '| --- | --- | --- |',
    ...rows,
    '',
    `Registered command count: ${commands.length}.`,
    '',
  ].join('\n');
}

const expected = render(extractCommands(await readFile(sourcePath, 'utf8')));
if (process.argv.includes('--check')) {
  const actual = await readFile(outputPath, 'utf8').catch(() => '');
  if (actual !== expected) throw new Error('Native command inventory is stale');
  process.stdout.write('Native command inventory: current\n');
} else {
  await writeFile(outputPath, expected, 'utf8');
  process.stdout.write('Native command inventory: generated\n');
}
