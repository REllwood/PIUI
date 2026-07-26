import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isForbiddenDocumentationPath } from './sidecar-closure-policy.mjs';

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
assert.match(stageSource, /manifestPath[\s\S]*await sealDirectories\(prepared\);/);
assert.match(stageSource, /await chmod\(path, 0o555\);/);
assert.match(stageSource, /function makeTreeOwnerWritable\(path\) \{\s+const result = spawnSync\('chmod', \['-R', 'u\+w', path\]/);
assert.match(stageSource, /async function cleanTreeBestEffort\(path\) \{\s+spawnSync\('chmod', \['-R', 'u\+w', path\]/);
assert.match(stageSource, /async function sealDirectories\(path\)[\s\S]*rm\(resolve\(path, '\.DS_Store'\)[\s\S]*chmod\(path, 0o555\)/);
assert.doesNotMatch(stageSource, /chmod\(output, 0o755\)/);

console.log(`Sidecar closure policy accepted: ${rejected.length} rejected, ${accepted.length} runtime and sealed-publish cases`);
