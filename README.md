# PIUI

PIUI is a local-first macOS desktop interface for the Pi coding-agent harness. It gives ordinary users a guided setup, a focused conversation workspace and clear review surfaces without requiring terminal knowledge. Advanced mode exposes providers, models, permissions, executable resources, sessions, diagnostics and logs.

The application is currently a local Apple Silicon release candidate, not a publicly signed distribution. Developer ID signing, Apple notarisation, public update hosting and updater-signing credentials are external release gates and are not supplied by this repository.

## Product principles

- Pi remains authoritative for Pi sessions, settings and supported provider behaviour.
- Provider secrets are owned by Rust and macOS Keychain; they are not ordinary React state or application-data fields.
- Project trust and tool approval are separate decisions.
- Trusted extensions and packages are executable code and may act outside PIUI-mediated tool approvals.
- PIUI does not contain telemetry and does not push, publish or alter GitHub remotes.
- Simple mode is the default; Advanced mode is deliberate and reversible.

## Local development

Requirements are Apple Silicon macOS 13 or newer, Apple Command Line Tools, Node.js 22 and pnpm 9. The release bundle carries its own pinned Node runtime; end users of a future signed build will not need the development toolchain.

```sh
pnpm install --frozen-lockfile
pnpm verify:static
pnpm dev
```

Use `pnpm tauri` for the native development shell. Every production boundary is also exercised through deterministic browser, Rust, sidecar and packaged tests.

## Local release verification

```sh
pnpm release:metadata
pnpm release:local
pnpm release:verify
```

Local release builds are non-destructive: each invocation preserves an earlier app in a new private directory beneath `.forge/evidence/local-release-builds` before writing the current candidate.

The full release matrix is intentionally demanding. It verifies static checks, protocol and Pi contracts, security, onboarding, browser journeys, visual and accessibility baselines, performance, Rust integration and the local arm64 package. It does not notarise, upload or publish anything.

PIUI is independently designed. No Tau code, assets, screenshots, branding or trade dress are included.
