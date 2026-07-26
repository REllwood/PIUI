import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const marker = fileURLToPath(new URL('../../import-marker.log', import.meta.url));
appendFileSync(marker, 'imported\n', { encoding: 'utf8', mode: 0o600 });

export default function probeExtension() {
  // Import-time execution is the A.16 canary; registration is intentionally inert.
}
