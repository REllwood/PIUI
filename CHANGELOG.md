# Changelog

## Unreleased

- Fixed real Pi conversations end to end: new sessions start before Pi has written a session file, follow-ups can be queued during a turn, failed turns reach the interface immediately, and long agent turns are no longer cut off.
- Approvals now show exactly what will run or change, beside the decision buttons at every window size. The approval gate stays usable after resource toggles, in long sessions, alongside tool calls Pi rejects, and for larger edits, while still failing closed.
- A repository can no longer enable its own executable extensions or packages. That acknowledgement lives in PIUI-owned state and is bound to the code's content. Session commands require the project to still be trusted.
- Agent commands run with the user's real home folder and login `PATH`. Cmd-C, Cmd-V and the other editing shortcuts work through a standard Edit menu.
- Fixed interface issues:
  - The work summary said work was complete while tools were still running.
  - Code colours ignored the app theme.
  - Settings and the model picker disagreed on thinking levels.
  - "Replay product tour" re-ran all of onboarding.
  - The work trace did not keep the current step in view.
  - Change counts were not pluralised correctly.
  - Some onboarding steps were cramped.
- Replaced native confirmation prompts with accessible in-app dialogs, and explained error codes in plain English.
- Added the PIUI logo, app icon, in-app brand mark, README screenshots, demo GIFs and an animated architecture diagram.
- Local release builds reuse fixed output paths, the automation signing identity is read from a local file outside the repository, and probe code and test fixtures no longer ship in production builds.

## 0.1.0 — Local release candidate

- Added the local-first Tauri, React, Rust and pinned public Pi SDK architecture.
- Added guided onboarding with environment checks, consent-based credential import, subscription-first provider connection, project trust and a skippable tour.
- Added Simple conversation, streaming, follow-up queues, activity traces, approvals, diffs, safe undo and session operations.
- Added Advanced settings, provider/model controls, permissions, resources, sessions, environment, logs, diagnostics and disabled-safe updates.
- Added Rust-owned Keychain access, filesystem capabilities, process supervision, redaction, native menus and notifications.
- Added dark/light themes, compact reflow, accessible transcript mode, deterministic visual baselines and 10,000-message virtualisation.
- Added protocol, contract, security, browser, accessibility, performance, Rust and packaged architecture verification.
- Added conversation starters, drafts that follow each conversation, a model and thinking picker, a skills and prompts picker, command search, compact navigation and motion preferences to the Simple workspace.
- Fixed the onboarding brand mark, silent clipboard and link failures, stranded pre-conversation drafts, unbounded sidecar stream bookkeeping, and Pi model-catalogue paths that could write inside the sealed sidecar resources.

Public Developer ID signing, notarisation and update hosting remain external release gates.
