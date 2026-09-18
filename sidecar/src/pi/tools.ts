export type NormalisedToolEvent = Readonly<{
  category: 'file' | 'command' | 'search' | 'extension' | 'error';
  verb: string;
  target: string;
  impact: string;
  evidence: string;
}>;

export function normaliseToolEvent(value: unknown): NormalisedToolEvent {
  if (!value || typeof value !== 'object')
    return {
      category: 'error',
      verb: 'Reported',
      target: 'unsupported tool event',
      impact: 'No action was permitted.',
      evidence: 'Event shape was invalid.',
    };
  const event = value as Record<string, unknown>;
  const toolName = typeof event.toolName === 'string' ? event.toolName.toLowerCase() : 'unknown';
  const category =
    toolName.includes('read') || toolName.includes('write') || toolName.includes('edit')
      ? 'file'
      : toolName.includes('bash') || toolName.includes('command')
        ? 'command'
        : toolName.includes('find') || toolName.includes('grep') || toolName.includes('search')
          ? 'search'
          : toolName === 'unknown'
            ? 'error'
            : 'extension';
  const target =
    typeof event.target === 'string' ? event.target.slice(0, 512) : 'Target not supplied';
  return Object.freeze({
    category,
    verb:
      typeof event.verb === 'string'
        ? event.verb.slice(0, 80)
        : category === 'file'
          ? 'Accessing'
          : category === 'command'
            ? 'Running'
            : 'Using',
    target,
    impact:
      typeof event.impact === 'string'
        ? event.impact.slice(0, 1_024)
        : 'Review the exact action before approval.',
    evidence:
      typeof event.evidence === 'string'
        ? event.evidence.slice(0, 131_072)
        : 'No bounded evidence supplied.',
  });
}

export function mayRememberApproval(
  category: NormalisedToolEvent['category'],
  destructive: boolean,
  externalEffect: boolean,
): boolean {
  return !destructive && !externalEffect && (category === 'file' || category === 'search');
}
