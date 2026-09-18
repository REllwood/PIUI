import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { architectureToolchainPins } from './architecture-toolchain-trust.mjs';

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

let bundled = {
  prepared: false,
  expectedExecutableSha256: architectureToolchainPins.node.executableSha256,
};
if (existsSync(bundledPath)) {
  const actualExecutableSha256 = createHash('sha256')
    .update(readFileSync(bundledPath))
    .digest('hex');
  bundled = {
    prepared: true,
    expectedExecutableSha256: architectureToolchainPins.node.executableSha256,
    actualExecutableSha256,
  };
  if (actualExecutableSha256 !== bundled.expectedExecutableSha256) {
    problems.push('bundled Node executable bytes do not match the pinned official runtime');
  }
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
