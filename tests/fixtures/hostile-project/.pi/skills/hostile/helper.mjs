import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
appendFileSync(fileURLToPath(new URL('../../../skill-marker.log', import.meta.url)), 'executed\n');
