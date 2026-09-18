const secretPattern = /(?:authorization|api[_-]?key|cookie|set-cookie|token|secret|password|client[_-]?secret)\s*[:=]\s*[^,;\r\n]*/giu;
const bearerPattern = /\bbearer\s+[A-Za-z0-9._~+/=-]+/giu;
const homePattern = /\/Users\/[^/\s]+/gu;
const querySecretPattern = /([?&](?:code|state|token|key)=)[^&\s]+/giu;

export function redactDiagnostic(value: string): string {
  return value
    .replace(secretPattern, '[credential]=[redacted]')
    .replace(bearerPattern, 'Bearer [redacted]')
    .replace(homePattern, '/Users/[home]')
    .replace(querySecretPattern, '$1[redacted]')
    .slice(0, 131_072);
}

export function safeDiagnosticSnapshot(
  values: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values).slice(0, 256)) {
    if (/secret|token|credential|password|authorization/iu.test(key)) result[key] = '[redacted]';
    else if (typeof value === 'string') result[key] = redactDiagnostic(value);
    else if (typeof value === 'number' || typeof value === 'boolean' || value === null)
      result[key] = value;
    else result[key] = '[unsupported value]';
  }
  return Object.freeze(result);
}
