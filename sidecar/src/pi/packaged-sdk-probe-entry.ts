import { runPackagedSdkProbe } from './packaged-sdk-probe.js';

try {
  const evidence = await runPackagedSdkProbe();
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} catch {
  process.stderr.write('A.22 packaged SDK probe failed.\n');
  process.exitCode = 1;
}
