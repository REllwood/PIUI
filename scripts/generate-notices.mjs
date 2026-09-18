import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { assertReviewedLicences, collectReleaseDependencies } from './release-dependencies.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'src-tauri/resources/THIRD-PARTY-NOTICES.txt');
const components = collectReleaseDependencies();
assertReviewedLicences(components);
const lines = [
  'PIUI THIRD-PARTY NOTICES',
  '',
  'This deterministic inventory covers production JavaScript and Rust dependencies.',
  'Refer to each upstream project for its complete licence text and attribution terms.',
  '',
  ...components.flatMap((component) => [
    `${component.name} ${component.version} [${component.ecosystem}]`,
    `Licence: ${component.license}`,
    ...(component.homepage ? [`Upstream: ${component.homepage}`] : []),
    '',
  ]),
];
await mkdir(resolve(root, 'src-tauri/resources'), { recursive: true });
await writeFile(output, `${lines.join('\n').trimEnd()}\n`, 'utf8');
process.stdout.write(`Generated notices for ${components.length} release components.\n`);
