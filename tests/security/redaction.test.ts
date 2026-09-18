import { describe, expect, it } from 'vitest';
import { redactForDisplay, safeError } from '../../src/domain/errors';
import { SafeLogger } from '../../sidecar/src/diagnostics/logger';
import {
  redactDiagnostic,
  safeDiagnosticSnapshot,
} from '../../sidecar/src/pi/diagnostics';

const canaries = Object.freeze([
  'PIUI_AUTH_CANARY_1402',
  'PIUI_COOKIE_CANARY_5831',
  'PIUI_QUERY_CANARY_9917',
  'piuicanaryuser',
]);

const hostileDiagnostic =
  'Authorization: Bearer PIUI_AUTH_CANARY_1402; Cookie=session=PIUI_COOKIE_CANARY_5831; callback=https://example.test/return?code=PIUI_QUERY_CANARY_9917 /Users/piuicanaryuser/Documents/PIUI';

function expectCanariesAbsent(value: unknown) {
  const serialised = typeof value === 'string' ? value : JSON.stringify(value);
  for (const canary of canaries) expect(serialised).not.toContain(canary);
}

describe('safe diagnostics', () => {
  it('redacts headers, query values and home paths in both UI and sidecar projections', () => {
    const web = redactForDisplay(hostileDiagnostic);
    const sidecar = redactDiagnostic(hostileDiagnostic);
    expectCanariesAbsent(web);
    expectCanariesAbsent(sidecar);
    expect(web).toContain('[redacted]');
    expect(sidecar).toContain('[redacted]');
    expect(web).toContain('/Users/[home]');
  });

  it('removes secret-shaped structured fields while retaining recovery evidence', () => {
    const snapshot = safeDiagnosticSnapshot({
      code: 'provider-offline',
      accessToken: 'PIUI_AUTH_CANARY_1402',
      detail: hostileDiagnostic,
      retryable: true,
      nested: { secret: 'PIUI_COOKIE_CANARY_5831' },
    });
    expectCanariesAbsent(snapshot);
    expect(snapshot).toMatchObject({
      code: 'provider-offline',
      accessToken: '[redacted]',
      retryable: true,
      nested: '[unsupported value]',
    });
  });

  it('writes bounded single-line stderr records without raw protocol or credentials', () => {
    const lines: string[] = [];
    const logger = new SafeLogger((line) => lines.push(line));
    logger.log('error', 'provider-offline', `${hostileDiagnostic}\n${'x'.repeat(2_000)}`);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.length).toBeLessThanOrEqual(1_100);
    expect(lines[0]).not.toContain('\n');
    expect(lines[0]).toContain('provider-offline');
    expectCanariesAbsent(lines[0]);
  });

  it('maps unknown internal errors to stable Australian-English recovery copy', () => {
    const error = safeError('internal-provider-stack');
    expect(error.code).toBe('unknown');
    expect(error.message).not.toContain('internal-provider-stack');
    expect(error.recovery).toContain('Diagnostics');
  });
});
