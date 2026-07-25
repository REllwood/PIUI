export function crashFixture(): never {
  process.stderr.write('[piui-sidecar] deterministic crash fixture requested\n');
  process.exit(70);
}
