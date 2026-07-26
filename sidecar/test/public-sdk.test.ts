import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ModelRuntime } from '@earendil-works/pi-coding-agent';
import type { ProtocolEnvelope } from '@piui/protocol';
import { describe, expect, it } from 'vitest';
import { HostRequestClient } from '../src/bridge/host-requests';
import { SidecarRouter } from '../src/bridge/router';
import { PiCredentialStore } from '../src/credentials/store-proxy';
import {
  assertPublicSdk,
  publicSdkMetadata,
  REQUIRED_PUBLIC_CAPABILITIES,
  type PublicCredentialStore,
} from '../src/pi/public-sdk';

const credentialMethods = ['read', 'list', 'modify', 'delete'] as const satisfies readonly (keyof PublicCredentialStore)[];

function allFiles(path: string): string[] {
  return readdirSync(path).flatMap((entry) => {
    const target = join(path, entry);
    return statSync(target).isDirectory() ? allFiles(target) : [target];
  });
}

function sourceFiles(path: string): string[] {
  return allFiles(path).filter((target) => target.endsWith('.ts'));
}

describe('public Pi SDK adapter', () => {
  it('loads the exact pinned package-root SDK and required probes', () => {
    expect(assertPublicSdk).not.toThrow();
    const metadata = publicSdkMetadata();
    expect(metadata.piVersion).toBe('0.82.0');
    expect(metadata.nodeVersion).toMatch(/^22\./);
    expect(Object.values(REQUIRED_PUBLIC_CAPABILITIES).every(Boolean)).toBe(true);
    expect(credentialMethods).toEqual(['read', 'list', 'modify', 'delete']);
  });

  it('derives the credential-store contract from the public root model options', () => {
    const source = readFileSync(resolve(import.meta.dirname, '../src/pi/public-sdk.ts'), 'utf8');
    expect(source).toContain("type CreateModelRuntimeOptions,");
    expect(source).toContain("NonNullable<CreateModelRuntimeOptions['credentials']>");
  });

  it('injects the proxy into public ModelRuntime without creating default auth.json', async () => {
    const isolatedDirectory = mkdtempSync(join(tmpdir(), 'piui-public-sdk-'));
    const priorAgentDirectory = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = isolatedDirectory;
    const requests: ProtocolEnvelope[] = [];
    let sequence = 1;
    let client!: HostRequestClient;
    client = new HostRequestClient({
      router: new SidecarRouter(),
      write: (request) => {
        requests.push(request);
        queueMicrotask(() => {
          const method = request.payload.method;
          const payload = method === 'credential.list'
            ? { entries: [] }
            : method === 'credential.get'
              ? { found: false }
              : method === 'credential.set'
                ? { stored: true }
                : { removed: true };
          client.consume({
            version: 1,
            kind: 'host-response',
            id: `public-sdk-host-${sequence}`,
            correlationId: request.id,
            sequence: sequence++,
            payload,
          });
        });
      },
    });
    const proxy = new PiCredentialStore(client);

    try {
      const runtime = await ModelRuntime.create({
        credentials: proxy,
        modelsPath: null,
        allowModelNetwork: false,
      });
      expect(runtime).toBeInstanceOf(ModelRuntime);
      expect(requests.some((request) => request.payload.method === 'credential.list')).toBe(true);
      expect(existsSync(join(isolatedDirectory, 'auth.json'))).toBe(false);
      expect(
        allFiles(isolatedDirectory).some((path) => path.endsWith('auth.json')),
      ).toBe(false);
    } finally {
      client.disconnect();
      if (priorAgentDirectory === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = priorAgentDirectory;
      rmSync(isolatedDirectory, { recursive: true, force: true });
    }
  });

  it('contains no Pi deep import', () => {
    const source = sourceFiles(resolve(import.meta.dirname, '../src')).map((file) => readFileSync(file, 'utf8')).join('\n');
    expect(source).not.toMatch(/@earendil-works\/pi-coding-agent\//);
    expect(source.match(/from ['"]@earendil-works\/pi-coding-agent['"]/g)).toHaveLength(1);
  });
});
