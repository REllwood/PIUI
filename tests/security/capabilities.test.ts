import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../..');

function sourceFiles(directory: string): string[] {
  const result: string[] = [];
  for (const name of readdirSync(directory)) {
    const path = resolve(directory, name);
    const state = statSync(path);
    if (state.isDirectory()) result.push(...sourceFiles(path));
    else if (/\.(?:ts|tsx)$/u.test(name)) result.push(path);
  }
  return result;
}

function invokedCommands(): Set<string> {
  const commands = new Set<string>();
  for (const path of sourceFiles(resolve(root, 'src'))) {
    const source = readFileSync(path, 'utf8');
    for (const match of source.matchAll(
      /\binvoke(?:<[\s\S]{0,800}?>)?\s*\(\s*(['"])([a-z0-9_]+)\1/gu,
    )) {
      if (match[2]) commands.add(match[2]);
    }
  }
  return commands;
}

function registeredCommands(): Set<string> {
  const source = readFileSync(resolve(root, 'src-tauri/src/lib.rs'), 'utf8');
  const handlers = [...source.matchAll(/tauri::generate_handler!\[([\s\S]*?)\n\s*\];/gu)];
  if (handlers.length === 0) throw new Error('Tauri command handler inventory was not found');
  return new Set(
    handlers
      .flatMap((match) => (match[1] ?? '').split('\n'))
      .map((line) => line.trim())
      .filter((line) => line.endsWith(','))
      .map((line) => line.slice(0, -1).split('::').at(-1) ?? ''),
  );
}

describe('Tauri authority boundary', () => {
  it('registers every WebView invoke and exposes no unregistered fallback', () => {
    const registered = registeredCommands();
    const invoked = invokedCommands();
    expect(invoked.size).toBeGreaterThan(30);
    expect([...invoked].filter((command) => !registered.has(command))).toEqual([]);
    expect(registered).not.toContain('shell_execute');
    expect(registered).not.toContain('read_arbitrary_file');
    expect(registered).not.toContain('http_request');
  });

  it('keeps the sole production window on core-only capability permissions', () => {
    const capability = JSON.parse(
      readFileSync(resolve(root, 'src-tauri/capabilities/default.json'), 'utf8'),
    ) as { windows: string[]; permissions: string[] };
    expect(capability.windows).toEqual(['main']);
    expect(capability.permissions).toEqual(['core:default']);
    expect(JSON.stringify(capability)).not.toMatch(/shell|filesystem|fs:|http|process/iu);
  });

  it('uses the exact restrictive production CSP without ambient remote authority', () => {
    const config = JSON.parse(
      readFileSync(resolve(root, 'src-tauri/tauri.conf.json'), 'utf8'),
    ) as {
      app: { withGlobalTauri: boolean; security: { csp: string }; windows: unknown[] };
    };
    const csp = config.app.security.csp;
    expect(config.app.withGlobalTauri).toBe(false);
    expect(config.app.windows).toHaveLength(1);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain('connect-src ipc: http://ipc.localhost');
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toMatch(/https?:\/\/\*/u);
    expect(csp).not.toContain('file:');
    expect(csp).not.toContain('data:');
    expect(csp).not.toContain('blob:');
  });
});
