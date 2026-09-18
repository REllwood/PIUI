import { realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { provisionNodeArchitectureArchive } from './provision-architecture-toolchain.mjs';

const provisionerPath = fileURLToPath(import.meta.url);

export async function runNodeRuntimeProvisioner() {
  if (process.argv.length !== 2) {
    throw new Error('Node runtime provisioner accepts no arguments');
  }

  process.stderr.write('[working] Provisioning the authenticated Node archive\n');
  const status = await provisionNodeArchitectureArchive();
  process.stdout.write(`Authenticated Node archive ready (${status})\n`);
}

async function isDirectInvocation() {
  if (typeof process.argv[1] !== 'string') return false;
  try {
    return await realpath(process.argv[1]) === await realpath(provisionerPath);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return false;
    throw error;
  }
}

const directlyInvoked = await isDirectInvocation();
if (directlyInvoked) await runNodeRuntimeProvisioner();
