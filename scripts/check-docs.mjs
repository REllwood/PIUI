import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const files = [
  'README.md',
  'CHANGELOG.md',
  'docs/PRIVACY.md',
  'docs/SECURITY.md',
  'docs/TROUBLESHOOTING.md',
  'docs/UPDATES.md',
  'docs/RELEASING.md',
  'docs/architecture/README.md',
  'docs/architecture/data-flow.md',
  'docs/architecture/command-inventory.md',
  'docs/testing/README.md',
  'docs/testing/MANUAL-ACCESSIBILITY.md',
];

const contents = new Map();
for (const file of files) contents.set(file, await readFile(resolve(root, file), 'utf8'));

const unsupportedClaims = [
  /public updates? (?:are|is) enabled/iu,
  /(?:is|has been) notarised/iu,
  /Developer ID signed(?: release)? is available/iu,
  /VoiceOver (?:passed|certified)/iu,
];
for (const [file, text] of contents) {
  if (!text.endsWith('\n')) throw new Error(`${file}: final newline missing`);
  for (const claim of unsupportedClaims) {
    if (claim.test(text)) throw new Error(`${file}: unsupported release claim`);
  }
  for (const match of text.matchAll(/\[[^\]]+\]\(([^)]+)\)/gu)) {
    const target = match[1].split('#')[0];
    if (!target || /^(?:https?:|mailto:)/u.test(target)) continue;
    await readFile(resolve(root, dirname(file), decodeURI(target))).catch(() => {
      throw new Error(`${file}: broken link ${target}`);
    });
  }
}

const australianChecks = [
  [/\bbehavior\b/iu, 'behaviour'],
  [/\bcolor\b/iu, 'colour'],
  [/\blicense\b/iu, 'licence'],
  [/\bauthorization\b/iu, 'authorisation'],
  [/\binitialization\b/iu, 'initialisation'],
];
for (const [file, text] of contents) {
  for (const [american, preferred] of australianChecks) {
    if (american.test(text)) throw new Error(`${file}: use Australian English “${preferred}”`);
  }
}

const readme = contents.get('README.md') ?? '';
for (const command of ['pnpm verify:static', 'pnpm release:verify', 'pnpm release:local']) {
  if (!readme.includes(command)) throw new Error(`README.md: missing ${command}`);
}
const releasing = contents.get('docs/RELEASING.md') ?? '';
for (const gate of ['Developer ID', 'notarisation', 'updater', 'hosting']) {
  if (!releasing.includes(gate)) throw new Error(`docs/RELEASING.md: missing ${gate} gate`);
}

process.stdout.write(`Documentation: ${files.length} files checked\n`);
