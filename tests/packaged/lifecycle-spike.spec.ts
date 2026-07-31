import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  actionForLifecyclePhase,
  assertLifecycleSnapshot,
  type LifecyclePhase,
} from '../../src/architecture-gate/LifecycleProbe';
import {
  A27_EXPECTED_EVIDENCE,
  A27_NATIVE_EVIDENCE_KEYS,
  mergeLifecycleEvidence,
  parseLifecycleEvidence,
  parseNativeLifecycleEvidence,
} from '../../scripts/assert-process-cleanup.mjs';

function line(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

describe('A.27 packaged lifecycle contract', () => {
  it('resumes only after last-window close and exposes quit only after the fourth generation', () => {
    const phases: readonly LifecyclePhase[] = [
      'ready',
      'starting',
      'running',
      'preparing-approval',
      'approval-waiting',
      'forcing-sidecar-death',
      'recovering',
      'recovered',
      'restarting',
      'awaiting-close',
      'awaiting-reopen',
      'resuming',
      'ready-to-quit',
      'quitting',
      'failed',
    ];
    expect(phases.map(actionForLifecyclePhase)).toEqual([
      'run',
      'wait',
      'recover',
      'wait',
      'wait',
      'wait',
      'wait',
      'restart',
      'wait',
      'close',
      'resume',
      'resume',
      'quit',
      'wait',
      'failed',
    ]);
  });

  it('accepts only bounded exact WebView lifecycle snapshots', () => {
    const valid = {
      schemaVersion: 1,
      phase: 'recovering',
      busy: true,
      message: 'Detecting the failure and recovering the helper…',
    };
    expect(assertLifecycleSnapshot(valid)).toEqual(valid);
    for (const malformed of [
      null,
      [],
      { ...valid, phase: 'unknown' },
      { ...valid, busy: 'true' },
      { ...valid, sidecarPid: 1234 },
      { ...valid, message: '' },
      { ...valid, message: 'x'.repeat(161) },
    ]) {
      expect(() => assertLifecycleSnapshot(malformed)).toThrow('lifecycle-snapshot-rejected');
    }
  });

  it('combines strict native and external observations into the exact path-free report', () => {
    const native = Object.fromEntries(
      A27_NATIVE_EVIDENCE_KEYS.map((key) => [key, A27_EXPECTED_EVIDENCE[key]]),
    );
    const external = Object.fromEntries(
      Object.entries(A27_EXPECTED_EVIDENCE)
        .filter(([key]) => !A27_NATIVE_EVIDENCE_KEYS.includes(key)),
    );
    expect(parseNativeLifecycleEvidence(line(native))).toEqual(native);
    expect(mergeLifecycleEvidence(native, external)).toEqual(A27_EXPECTED_EVIDENCE);
    expect(parseLifecycleEvidence(line(A27_EXPECTED_EVIDENCE))).toEqual(A27_EXPECTED_EVIDENCE);
    expect(JSON.stringify(A27_EXPECTED_EVIDENCE)).not.toContain('/');
  });

  it('keeps a visible progress indicator and busy state through every asynchronous stage', async () => {
    const source = await readFile(
      new URL('../../src/architecture-gate/LifecycleProbe.tsx', import.meta.url),
      'utf8',
    );
    expect(source).toContain('aria-busy={snapshot.busy}');
    expect(source).toContain('<progress');
    expect(source).toContain('aria-label={snapshot.message}');
    expect(source).toContain('disabled={disabled}');
    expect(source).toContain('await nextPaint()');
    expect(source).toContain("current.phase === 'failed'");
    expect(source).not.toContain('sidecarPid');
    expect(source).not.toContain('approvalId');
    expect(source).not.toContain('decisionId');
  });

  it('uses a retained BSD flock on inherited FD3 and sets close-on-exec before sidecar start', async () => {
    const source = await readFile(
      new URL('../../src-tauri/src/commands/a27_lifecycle.rs', import.meta.url),
      'utf8',
    );
    expect(source).toContain('const A27_LOCK_DESCRIPTOR: RawFd = 3;');
    expect(source).toContain('libc::flock(descriptor, libc::LOCK_EX | libc::LOCK_NB)');
    expect(source).toContain('descriptor_flags | libc::FD_CLOEXEC');
    expect(source).toContain('_ownership_lock: Option<File>');
    expect(source.indexOf('acquire_inherited_lock(A27_LOCK_DESCRIPTOR)'))
      .toBeLessThan(source.indexOf('Ok(Self {'));
  });
});
