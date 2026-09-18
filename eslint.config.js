// PIUI uses scripts/check-boundaries.mjs plus TypeScript's strict compiler as
// its dependency-free lint authority. This flat-config file records the same
// source inventory for editors that provide ESLint without changing the
// frozen dependency graph.
export default [
  {
    files: ['src/**/*.{ts,tsx}', 'sidecar/src/**/*.ts', 'packages/**/*.ts'],
    ignores: ['dist/**', 'target/**', 'node_modules/**'],
    linterOptions: { reportUnusedDisableDirectives: 'error' },
  },
];
