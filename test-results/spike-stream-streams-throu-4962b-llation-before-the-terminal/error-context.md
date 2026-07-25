# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: spike-stream.spec.ts >> streams through Rust and acknowledges cancellation before the terminal
- Location: tests/e2e/spike-stream.spec.ts:20:1

# Error details

```
Error: Command failed: cargo build --manifest-path /Users/rhysellwood/Documents/Code/PIUI/src-tauri/Cargo.toml --bin stream-harness
   Compiling piui v0.1.0 (/Users/rhysellwood/Documents/Code/PIUI/src-tauri)
error: failed to run custom build command for `piui v0.1.0 (/Users/rhysellwood/Documents/Code/PIUI/src-tauri)`

Caused by:
  process didn't exit successfully: `/Users/rhysellwood/Documents/Code/PIUI/src-tauri/target/debug/build/piui-f37501ed5d158ce6/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=TAURI_CONFIG
  cargo:rustc-check-cfg=cfg(desktop)
  cargo:rustc-cfg=desktop
  cargo:rustc-check-cfg=cfg(mobile)
  cargo:rerun-if-changed=/Users/rhysellwood/Documents/Code/PIUI/src-tauri/tauri.conf.json
  cargo:rustc-env=TAURI_ANDROID_PACKAGE_NAME_APP_NAME=desktop
  cargo:rustc-env=TAURI_ANDROID_PACKAGE_NAME_PREFIX=au_com_piui
  cargo:rustc-check-cfg=cfg(dev)
  cargo:rustc-cfg=dev
  cargo:PERMISSION_FILES_PATH=/Users/rhysellwood/Documents/Code/PIUI/src-tauri/target/debug/build/piui-b636bc6eff3988d3/out/app-manifest/__app__-permission-files
  cargo:rerun-if-changed=capabilities
  cargo:rerun-if-env-changed=REMOVE_UNUSED_COMMANDS
  cargo:rustc-env=TAURI_ENV_TARGET_TRIPLE=aarch64-apple-darwin
  cargo:rerun-if-changed=binaries/piui-node-aarch64-apple-darwin
  cargo:rerun-if-changed=resources/sidecar/.DS_Store
  cargo:rerun-if-changed=resources/sidecar/dist/bridge/handshake.js
  Permission denied (os error 13)

```

# Test source

```ts
  1   | import { expect, test } from '@playwright/test';
  2   | import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
  3   | import { createInterface } from 'node:readline';
  4   | import { resolve } from 'node:path';
  5   | 
  6   | type Envelope = {
  7   |   kind: string;
  8   |   id: string;
  9   |   correlationId?: string;
  10  |   sequence: number;
  11  |   payload: Record<string, unknown>;
  12  | };
  13  | 
  14  | const projectRoot = resolve(import.meta.dirname, '../..');
  15  | const cargoManifest = resolve(projectRoot, 'src-tauri/Cargo.toml');
  16  | const harness = resolve(projectRoot, 'src-tauri/target/debug/stream-harness');
  17  | 
  18  | test.setTimeout(45_000);
  19  | 
  20  | test('streams through Rust and acknowledges cancellation before the terminal', async ({ page }) => {
> 21  |   execFileSync(
      |   ^ Error: Command failed: cargo build --manifest-path /Users/rhysellwood/Documents/Code/PIUI/src-tauri/Cargo.toml --bin stream-harness
  22  |     'cargo',
  23  |     ['build', '--manifest-path', cargoManifest, '--bin', 'stream-harness'],
  24  |     { cwd: projectRoot, stdio: 'pipe' },
  25  |   );
  26  |   // Stage after compiling: staging rewrites bundle resources, which should not
  27  |   // force an otherwise unchanged Rust harness to rebuild on every browser run.
  28  |   execFileSync('pnpm', ['stage:sidecar'], { cwd: projectRoot, stdio: 'pipe' });
  29  |   const child = spawn(harness, [], {
  30  |     cwd: projectRoot,
  31  |     env: { PATH: process.env.PATH ?? '' },
  32  |     stdio: ['pipe', 'pipe', 'pipe'],
  33  |   });
  34  |   const stderr: string[] = [];
  35  |   child.stderr.setEncoding('utf8');
  36  |   child.stderr.on('data', (chunk: string) => stderr.push(chunk));
  37  | 
  38  |   const lines = createInterface({ input: child.stdout });
  39  |   const received: Envelope[] = [];
  40  |   let acknowledgementAt = 0;
  41  |   let acknowledgementResolve: ((accepted: boolean) => void) | undefined;
  42  |   const acknowledgement = new Promise<boolean>((resolveAcknowledgement) => {
  43  |     acknowledgementResolve = resolveAcknowledgement;
  44  |   });
  45  |   let terminalResolve: (() => void) | undefined;
  46  |   const terminal = new Promise<void>((resolveTerminal) => {
  47  |     terminalResolve = resolveTerminal;
  48  |   });
  49  |   let browserDelivery = Promise.resolve();
  50  |   lines.on('line', (line) => {
  51  |     const envelope = JSON.parse(line) as Envelope;
  52  |     received.push(envelope);
  53  |     if (envelope.kind === 'ack') {
  54  |       acknowledgementAt = Date.now();
  55  |       acknowledgementResolve?.(envelope.payload.accepted === true);
  56  |     }
  57  |     if (envelope.kind === 'event' && envelope.payload.terminal) {
  58  |       terminalResolve?.();
  59  |     }
  60  |     browserDelivery = browserDelivery.then(() =>
  61  |       page.evaluate((payload) => {
  62  |         window.dispatchEvent(new CustomEvent('piui-bridge-envelope', { detail: payload }));
  63  |       }, envelope),
  64  |     );
  65  |   });
  66  | 
  67  |   const write = (envelope: Envelope) => {
  68  |     child.stdin.write(`${JSON.stringify(envelope)}\n`);
  69  |   };
  70  |   await page.exposeFunction('__piuiStart', write);
  71  |   await page.exposeFunction('__piuiCancel', write);
  72  |   await page.exposeFunction('__piuiSend', write);
  73  |   await page.addInitScript(() => {
  74  |     const exposed = window as unknown as {
  75  |       __piuiStart: (envelope: Envelope) => Promise<void>;
  76  |       __piuiCancel: (envelope: Envelope) => Promise<void>;
  77  |       __piuiSend: (envelope: Envelope) => Promise<void>;
  78  |       __PIUI_STREAM_HARNESS__: {
  79  |         start: (envelope: Envelope) => Promise<void>;
  80  |         cancel: (envelope: Envelope) => Promise<void>;
  81  |         send: (envelope: Envelope) => Promise<void>;
  82  |       };
  83  |     };
  84  |     exposed.__PIUI_STREAM_HARNESS__ = {
  85  |       start: (envelope) => exposed.__piuiStart(envelope),
  86  |       cancel: (envelope) => exposed.__piuiCancel(envelope),
  87  |       send: (envelope) => exposed.__piuiSend(envelope),
  88  |     };
  89  |   });
  90  | 
  91  |   try {
  92  |     await page.goto('/?spike=stream');
  93  |     const output = page.getByTestId('stream-output');
  94  |     await expect(output).toContainText('Planning', { timeout: 3_000 });
  95  | 
  96  |     const started = Date.now();
  97  |     await page.getByRole('button', { name: 'Stop' }).click();
  98  |     await expect.poll(() => acknowledgement).toBe(true);
  99  |     await expect(page.getByTestId('stream-terminal')).toHaveText('cancelled', {
  100 |       timeout: 1_000,
  101 |     });
  102 |     await terminal;
  103 |     expect(acknowledgementAt - started).toBeLessThan(1_000);
  104 |     expect(Date.now() - started).toBeLessThan(1_000);
  105 |     const ackIndex = received.findIndex((envelope) => envelope.kind === 'ack');
  106 |     const terminalIndex = received.findIndex(
  107 |       (envelope) => envelope.kind === 'event' && envelope.payload.terminal === 'cancelled',
  108 |     );
  109 |     expect(ackIndex).toBeGreaterThanOrEqual(0);
  110 |     expect(terminalIndex).toBeGreaterThan(ackIndex);
  111 | 
  112 |     const retained = await output.textContent();
  113 |     expect(retained).toBeTruthy();
  114 |     expect('Planning a safe local change…'.startsWith(retained ?? '')).toBe(true);
  115 |     expect(retained).not.toBe('Planning a safe local change…');
  116 |     expect(stderr.join('')).toBe('');
  117 |   } finally {
  118 |     await browserDelivery.catch(() => undefined);
  119 |     lines.close();
  120 |     child.stdin.end();
  121 |     await waitForExit(child);
```