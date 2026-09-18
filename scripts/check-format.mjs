import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const included = ['src', 'sidecar/src', 'packages/protocol/src', 'scripts'];
const extensions = new Set(['.ts', '.tsx', '.js', '.mjs', '.css', '.json', '.md']);
const failures = [];

function visit(directory) {
  for (const name of readdirSync(directory)) {
    const absolute = join(directory, name);
    const metadata = statSync(absolute);
    if (metadata.isDirectory()) visit(absolute);
    else if (extensions.has(extname(name))) {
      const value = readFileSync(absolute, 'utf8');
      const label = relative(root, absolute);
      if (!value.endsWith('\n')) failures.push(`${label}: missing final newline`);
      if (value.includes('\r')) failures.push(`${label}: CR characters are not permitted`);
      value.split('\n').forEach((line, index) => {
        if (/[ \t]+$/u.test(line)) failures.push(`${label}:${index + 1}: trailing whitespace`);
      });
    }
  }
}

for (const directory of included) visit(join(root, directory));
if (failures.length) {
  process.stderr.write(`${failures.slice(0, 100).join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('Repository text format checks passed.\n');
}
