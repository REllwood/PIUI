import { redactDiagnostic } from '../pi/diagnostics.js';

export type LogLevel = 'info' | 'warning' | 'error';

export class SafeLogger {
  readonly #write: (line: string) => void;

  constructor(write: (line: string) => void = (line) => process.stderr.write(`${line}\n`)) {
    this.#write = write;
  }

  log(level: LogLevel, code: string, detail: string): void {
    if (!/^[a-z][a-z0-9-]{0,79}$/u.test(code)) throw new Error('diagnostic-code-invalid');
    const safe = redactDiagnostic(detail)
      .replace(/[\r\n]+/gu, ' ')
      .slice(0, 1_024);
    this.#write(`[piui-sidecar] ${level} ${code}${safe ? ` ${safe}` : ''}`);
  }
}
