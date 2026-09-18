import { describe, expect, it } from 'vitest';
import { TurnRegistry, normaliseTurnEvent } from '../../sidecar/src/pi/turns';

describe('turn registry and event projection', () => {
  it('acknowledges active cancellation and reports terminal races as too late', () => {
    const registry = new TurnRegistry();
    const parent = new AbortController();
    const request = {
      requestId: 'turn-1',
      sessionId: `session-${'a'.repeat(32)}`,
      generation: 1,
      text: 'Review this project',
      attachmentCapabilities: [],
      retryPrevious: false,
    };
    const active = registry.begin(request, parent.signal);
    expect(active.nextSequence()).toBe(1);
    expect(registry.stop('turn-1')).toBe('stopped');
    expect(active.controller.signal.aborted).toBe(true);
    registry.finish('turn-1', 'stopped');
    expect(registry.stop('turn-1')).toBe('too-late');
    expect(registry.stop('unknown')).toBe('unknown');
    expect(() => registry.begin(request, parent.signal)).toThrow('turn-request-duplicate');
  });

  it('bounds untrusted event fields and retains useful unknown progress', () => {
    expect(normaliseTurnEvent('turn-1', 1, null)).toMatchObject({
      type: 'failed',
      code: 'turn-event-invalid',
    });
    expect(
      normaliseTurnEvent('turn-1', 2, {
        type: 'tool_execution_start',
        toolName: 'read',
        toolCallId: '../invalid',
      }),
    ).toEqual({ requestId: 'turn-1', sequence: 2, type: 'tool', text: 'read' });
    expect(normaliseTurnEvent('turn-1', 3, { type: 'future-progress' }).type).toBe('started');
  });
});
