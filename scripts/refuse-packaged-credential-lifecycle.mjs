const report = Object.freeze({
  schemaVersion: 1,
  status: 'refused',
  reasonCode: 'explicit-isolated-keychain-authorisation-required',
  keychainMutated: false,
  nativeSheetLaunched: false,
});

process.stdout.write(`${JSON.stringify(report)}\n`);
process.exitCode = 1;
