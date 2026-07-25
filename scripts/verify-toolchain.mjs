import { existsSync, readFileSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const pinnedNode = '22.23.1';
const supportedNode = { major: 22, minimumMinor: 19 };
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bundledPath = resolve(root, 'src-tauri/binaries/piui-node-aarch64-apple-darwin');
const [major, minor] = process.versions.node.split('.').map(Number);
const problems = [];

if (platform() !== 'darwin') problems.push(`unsupported host platform ${platform()}; expected darwin`);
if (arch() !== 'arm64') problems.push(`unsupported host architecture ${arch()}; expected arm64`);
if (major !== supportedNode.major || minor < supportedNode.minimumMinor) {
  problems.push(`unsupported host Node ${process.versions.node}; expected >=22.19.0 <23`);
}

let bundled = { prepared: false, expected: `v${pinnedNode}` };
if (existsSync(bundledPath)) {
  const actual = execFileSync(bundledPath, ['--version'], { encoding: 'utf8' }).trim();
  bundled = { prepared: true, expected: `v${pinnedNode}`, actual };
  if (actual !== bundled.expected) problems.push(`bundled Node ${actual}; expected ${bundled.expected}`);
}

const packageJson = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const report = {
  status: problems.length === 0 ? 'supported' : 'unsupported',
  host: {
    platform: platform(),
    architecture: arch(),
    macOSKernel: release(),
    node: process.versions.node,
    pnpmPin: packageJson.packageManager
  },
  bundledRuntime: bundled,
  pins: {
    node: pinnedNode,
    tauri: '2.11.5',
    react: packageJson.dependencies.react,
    vite: packageJson.devDependencies.vite,
    tailwind: packageJson.devDependencies.tailwindcss,
    reactAriaComponents: packageJson.dependencies['react-aria-components'],
    piSdk: packageJson.dependencies['@earendil-works/pi-coding-agent']
  }
};
console.log(JSON.stringify(report, null, 2));
if (problems.length) {
  for (const problem of problems) console.error(`toolchain: ${problem}`);
  process.exit(1);
}
