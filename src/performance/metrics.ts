export type LocalPerformanceMetric = Readonly<{
  name: string;
  durationMs: number;
  startedAt: number;
}>;

const allowedNames = new Set([
  'app-bootstrap',
  'first-workspace-frame',
  'stream-commit',
  'cancel-acknowledgement',
  'transcript-anchor-restore',
]);

export function measureLocal(name: string, action: () => void): LocalPerformanceMetric {
  if (!allowedNames.has(name)) throw new Error('performance-metric-name-rejected');
  const startedAt = performance.now();
  action();
  return Object.freeze({ name, startedAt, durationMs: performance.now() - startedAt });
}

export async function measureLocalAsync(
  name: string,
  action: () => Promise<void>,
): Promise<LocalPerformanceMetric> {
  if (!allowedNames.has(name)) throw new Error('performance-metric-name-rejected');
  const startedAt = performance.now();
  await action();
  return Object.freeze({ name, startedAt, durationMs: performance.now() - startedAt });
}
