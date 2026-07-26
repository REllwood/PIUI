import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isForbiddenDocumentationPath } from './sidecar-closure-policy.mjs';
import {
  prepareCandidateForRename,
  renamePreparedCandidate,
} from './sidecar-publication-policy.mjs';

const extensionlessDocumentationNames = [
  'README',
  'CHANGELOG-v2',
  'HISTORY_2024',
  'CONTRIBUTING notes',
  'CODE_OF_CONDUCT',
  'SECURITY',
];
const rejected = [
  'docs/guide.js',
  'node_modules/@scope/package/EXAMPLES/demo.js',
  'node_modules/proper-lockfile/node_modules/retry/example/README.md',
  'node_modules/outer/node_modules/@nested/package/Tests/canary.js',
  'node_modules/package/opslevel.yaml',
  'node_modules/package/runtime-notes.mdx',
  ...extensionlessDocumentationNames.flatMap((name) => [
    `node_modules/package/${name}`,
    `node_modules/package/${name}.md`,
  ]),
];
for (const path of rejected) {
  assert.equal(isForbiddenDocumentationPath(path), true, `expected policy rejection: ${path}`);
}

const runtimePrefixNames = [
  'README',
  'CHANGELOG',
  'HISTORY',
  'CONTRIBUTING',
  'CODE_OF_CONDUCT',
  'SECURITY',
];
const accepted = [
  'dist/pi/trust-loader-project-thread.js',
  'node_modules/proper-lockfile/node_modules/retry/index.js',
  'node_modules/@scope/package/dist/runtime.js',
  'node_modules/package/documentation/runtime.json',
  'node_modules/package/example-runtime.js',
  'node_modules/package/package.json',
  'node_modules/package/LICENSE.md',
  'node_modules/package/NOTICE.rst',
  'node_modules/package/CHANGELOG.txt',
  'node_modules/@earendil-works/pi-coding-agent/dist/utils/changelog.js',
  'node_modules/yaml/dist/doc/directives.js',
  'node_modules/yaml/dist/doc/Document.js',
  'node_modules/package/dist/test/runtime.js',
  'node_modules/@scope/package/lib/examples/runtime.json',
  'node_modules/@earendil-works/pi-coding-agent/dist/modes/interactive/theme/dark.json',
  ...runtimePrefixNames.flatMap((name) => [
    `node_modules/package/${name}.js`,
    `node_modules/package/${name}.json`,
  ]),
];
for (const path of accepted) {
  assert.equal(isForbiddenDocumentationPath(path), false, `expected runtime acceptance: ${path}`);
}

const stageSource = readFileSync(new URL('./stage-sidecar.mjs', import.meta.url), 'utf8');
const publicationSource = readFileSync(new URL('./sidecar-publication-policy.mjs', import.meta.url), 'utf8');
assert.match(stageSource, /manifestPath[\s\S]*await prepareCandidateForRename\(prepared\);/);
assert.match(stageSource, /function makeTreeOwnerWritable\(path\) \{\s+const result = spawnSync\('chmod', \['-R', 'u\+w', path\]/);
assert.match(stageSource, /async function cleanTreeBestEffort\(path\) \{\s+spawnSync\('chmod', \['-R', 'u\+w', path\]/);
assert.match(stageSource, /failed-publish[\s\S]*rename\(retired, output\)[\s\S]*sealPublishedOutput\(output\)/);
assert.match(publicationSource, /chmod\(path, isRoot \? 0o755 : 0o555\)/);
assert.match(publicationSource, /rename\(prepared, output\)[\s\S]*sealPublishedOutput\(output\)/);
assert.match(publicationSource, /chmod\(path, 0o555\)[\s\S]*verifyNoFinderMetadata\(path\)/);
assert.doesNotMatch(stageSource, /chmod\(output, 0o755\)/);

const disposable = await mkdtemp(join(tmpdir(), 'piui-closure-rename-'));
try {
  const prepared = join(disposable, 'prepared');
  const output = join(disposable, 'output');
  const nested = join(prepared, 'node_modules', 'yaml', 'dist', 'doc');
  await mkdir(nested, { recursive: true });
  await writeFile(join(nested, 'directives.js'), 'export {};\n');
  await writeFile(join(prepared, '.DS_Store'), 'root-race');
  await writeFile(join(nested, '.DS_Store'), 'nested-race');
  await prepareCandidateForRename(prepared);
  assert.equal((await stat(prepared)).mode & 0o777, 0o755, 'candidate root must remain renameable');
  assert.equal((await stat(nested)).mode & 0o777, 0o555, 'candidate descendants must be sealed');
  await renamePreparedCandidate(prepared, output);
  assert.equal((await stat(output)).mode & 0o777, 0o555, 'published root must be sealed');
  assert.equal((await stat(join(output, 'node_modules', 'yaml', 'dist', 'doc'))).mode & 0o777, 0o555);
  assert.equal(readFileSync(join(output, 'node_modules', 'yaml', 'dist', 'doc', 'directives.js'), 'utf8'), 'export {};\n');
  assert.equal(spawnSync('find', [output, '-name', '.DS_Store', '-print'], { encoding: 'utf8' }).stdout, '');
} finally {
  spawnSync('chmod', ['-R', 'u+w', disposable], { stdio: 'ignore' });
  await rm(disposable, { recursive: true, force: true });
}

console.log(`Sidecar closure policy accepted: ${rejected.length} rejected, ${accepted.length} runtime and real sealed-rename cases`);
