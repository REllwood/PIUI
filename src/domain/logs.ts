import { redactForDisplay } from './errors';

// Redact first, then filter: searching the raw text would reveal that a redacted
// value matched even though the value itself is never shown.
export function visibleLogLines(
  lines: readonly string[],
  query: string,
  severity: string,
): readonly string[] {
  const search = query.toLowerCase();
  return lines
    .map(redactForDisplay)
    .filter((line) => {
      const normalised = line.toLowerCase();
      return normalised.includes(search) && (severity === 'all' || normalised.includes(severity));
    });
}
