import { describe, expect, it } from 'vitest';
import { emptyProductSnapshot } from './fixtures';
import {
  canReconcileTranscript,
  preferredSessionModel,
  preferredSessionThinking,
} from './sessionContinuity';
import type { ProductSnapshot } from './types';

const providers = [
  { id: 'first', status: 'connected', models: [{ id: 'default' }] },
  { id: 'chosen', status: 'connected', models: [{ id: 'other' }, { id: 'preferred' }] },
];

describe('conversation continuity', () => {
  it('keeps the selected provider and model even when they are not first in the catalogue', () => {
    expect(
      preferredSessionModel(providers, [
        { key: 'model.provider', value: 'chosen' },
        { key: 'model.id', value: 'preferred' },
      ]),
    ).toEqual({ providerId: 'chosen', modelId: 'preferred' });
  });

  it('falls back only when the selected provider/model pair is unavailable', () => {
    const settings = [
      { key: 'model.provider', value: 'chosen' },
      { key: 'model.id', value: 'missing' },
    ];
    expect(preferredSessionModel(providers, settings)).toEqual({
      providerId: 'first',
      modelId: 'default',
    });
    expect(
      preferredSessionModel(
        [
          { id: 'empty', status: 'connected', models: [] },
          { id: 'chosen', status: 'not-connected', models: [{ id: 'missing' }] },
        ],
        settings,
      ),
    ).toBeNull();
  });

  it('preserves every thinking level supported by the current protocol and rejects unknown values', () => {
    for (const value of ['off', 'minimal', 'low', 'medium', 'high', 'xhigh']) {
      expect(preferredSessionThinking([{ key: 'reasoning.level', value }])).toBe(value);
    }
    expect(preferredSessionThinking([{ key: 'reasoning.level', value: 'invalid' }])).toBeNull();
    expect(preferredSessionThinking([])).toBeNull();
  });

  const current: ProductSnapshot = {
    ...emptyProductSnapshot,
    activeSessionId: 'session-a',
    sessions: [
      {
        id: 'session-a',
        generation: 2,
        title: 'Task',
        project: 'Project',
        updatedAt: 'Now',
        status: 'active',
        preview: '',
      },
    ],
    messages: [
      {
        id: 'response-a',
        role: 'assistant',
        author: 'Pi',
        timestamp: '',
        markdown: 'Visible reply',
        status: 'stable',
      },
    ],
    connection: 'ready',
    turnStatus: 'complete',
  };
  const completed = { sessionId: 'session-a', generation: 2, messages: current.messages };

  it('accepts the completed transcript while unrelated activity updates continue', () => {
    expect(canReconcileTranscript(completed, { ...current, activity: [] })).toBe(true);
  });

  it('rejects a late history response after a new turn, session replacement, or loss of connection', () => {
    expect(canReconcileTranscript(completed, { ...current, turnStatus: 'streaming' })).toBe(false);
    expect(canReconcileTranscript(completed, { ...current, messages: [...current.messages] })).toBe(
      false,
    );
    expect(canReconcileTranscript(completed, { ...current, activeSessionId: 'session-b' })).toBe(
      false,
    );
    expect(
      canReconcileTranscript(completed, {
        ...current,
        sessions: current.sessions.map((session) => ({ ...session, generation: 3 })),
      }),
    ).toBe(false);
    expect(canReconcileTranscript(completed, { ...current, connection: 'external-change' })).toBe(
      false,
    );
  });
});
