# A.28 packaged VoiceOver check

This is a human observation, not an automated conformance claim. Complete it only during `pnpm gate:architecture:record`, while the formal runner retains the exact packaged automation twin and its original `started.json` context. A standalone accessibility spike cannot produce authoritative A.28 evidence.

## Start the formal witness

1. From the repository root, run `pnpm gate:architecture:record`.
2. Grant Accessibility access to the terminal or Codex process that launches the bounded accessibility-tree helper. The helper calls `AXIsProcessTrusted()` without prompting. A missing grant blocks A.28 and cannot produce passing evidence.
3. Wait for the packaged application to prepare its deterministic fixture. The preparation button displays a visible loading indicator and spoken status.
4. Start VoiceOver before the runner constructs the challenge request.
5. Continue only when the application shows “Exact packaged twin retained” and the indeterminate “Waiting for human VoiceOver evidence” progress indicator.
6. Follow each `[working] A.28` instruction printed by the runner. Run only the already installed, managed root launcher shown by the runner. Repository JavaScript must not run as root and must not invoke an elevation tool.

The runner creates and retains an exclusive expected-context file under the active architecture-gate run. It independently binds the original gate context, frozen-source and toolchain anchors, full production and automation inventories, measured delta, host identity and the live authenticated WDIO runner. The root launcher independently inspects the live host, runner and VoiceOver processes before issuing a challenge.

The installed native witness opens after root prepares its challenge. Keep the formal command, packaged application, WDIO runner, VoiceOver and installed native witness running until the final comparison completes. Do not close or relaunch any of them, and do not attach to a similarly named or previous process.

## Checks to perform

Start VoiceOver with its normal keyboard controls. Keep Quick Nav and any speech customisation in the state you record for the whole four-part pass.

Complete these four combinations in the installed native witness’s exact order:

1. Dark appearance, Accessible transcript.
2. Dark appearance, Virtualised transcript.
3. Light appearance, Accessible transcript.
4. Light appearance, Virtualised transcript.

For each combination:

- Navigate from the transcript heading to the rendering controls and the transcript without a pointer.
- Confirm VoiceOver announces the transcript as one named list and announces each reached row with its speaker, text and position in the 100-row set.
- Move with Arrow Down and Arrow Up, then Home, End, Page Down and Page Up. Confirm the announced order follows row numbers with no duplicate or skipped logical position.
- Move to row 51, change appearance, and confirm the logical focused row remains 51.
- Change between Virtualised transcript and Accessible transcript, and confirm the logical focused row remains 51.
- In the virtualised view, continue beyond the initially rendered rows and confirm newly materialised rows are announced in order.
- In the accessible view, confirm all 100 rows are available in one ordered list.
- Confirm focus is visible in both appearances and is not hidden beneath the scroll viewport.
- Treat any crash, silent control, incorrect name, incorrect position, focus loss, trapping, duplicate announcement or unreadable focus treatment as a blocking defect. Record the defect in the installed witness and do not report that row as passing.

## Root checkpoints and biometric signing

For each row, the runner prints one exact root checkpoint reveal command. Run it only after the preceding row is complete. Root writes a reviewer-owned token file in the installed checkpoint-delivery directory. Copy that row’s token into the installed witness; do not copy a token between rows or sessions.

The installed witness enables rows only in order and validates every token against the immutable root commitment. When all four rows are complete, choose “Authenticate and sign witness”. A visible progress indicator remains active while Secure Enclave biometric authentication is pending.

After signing, run the exact managed verification command printed by the formal runner. Root validates and consumes the four reveal receipts, verifies the signed attestation and live identities, and publishes a root-owned 0444 receipt.

## Final comparison

The public root receipt is not sufficient by itself. Before WDIO release or process cleanup, the formal runner must open that receipt without following links, validate it with the installed policy, compare every gate-owned request field with its independently retained expected context, revalidate both bundle inventories and both live process identities, and write one exclusive comparison receipt.

Only that one-use comparison receipt can produce `gateContextCompared: true` and `humanWitnessed: true`. The expected-context file, challenge request and comparison receipt remain append-only evidence in the active architecture-gate run. If any retained pathname, inode, digest, process identity, bundle inventory or request field changes, A.28 fails closed.

The formal human stage times out after 30 minutes. Missing root preparation, reveal, attestation, verification or final comparison remains blocked and never becomes a pass.

Legacy `voiceover.json`, `completion.json` and `checksums.json` files may remain diagnostic records. They do not authenticate the formal gate context and can never set `humanWitnessed`.

These records do not claim axe equivalence, WCAG conformance or that automation is equivalent to VoiceOver.
