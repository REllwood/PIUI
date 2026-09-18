# A.28 authenticated VoiceOver witness

This directory contains the separately provisioned macOS witness for architecture gate A.28. It is not part of the ordinary PIUI build. The native app records the four dark/light and accessible/virtualised VoiceOver decisions, displays the complete immutable challenge and signs one canonical attestation with a non-exportable Secure Enclave P-256 key.

A root witness receipt authenticates the reviewer-reported VoiceOver behaviour only. Its fixed scope explicitly excludes authentication of the gate run, source, production artefact, automation twin and measured-delta metadata. Those fields remain continuity-only until the formal gate completes the independent comparison described below.

## Authority separation

The design has three separate authorities:

1. An Apple Developer administrator provisions the dedicated app identifier, Developer ID Application certificate and profile. The only keychain group is TEAMID.au.com.piui.a28-witness.secure-enclave.
2. A security administrator reviews the sources and accepted installed instances, then installs the app, native process inspector, hardened root launcher, private Node runtime, root entrypoints, three launch configurations and canonical policy under /Library/Application Support/PIUI/A28Witness.
3. The named reviewer enrols and uses the Secure Enclave key under their own macOS account. Root retains control of the enrolment output, challenge requests, checkpoint secrets, attestation output slots, consumption records and public receipts.

No script changes the Apple Developer portal, invokes sudo, replaces existing evidence or installs files. Privileged launch is an external managed ceremony. Repository JavaScript must never run as root.

## Non-root provisioning plan

`stage-provisioning.mjs` closes the repository-side hand-off between reviewed
source and the external Apple Developer and security-administrator ceremonies.
It produces and validates canonical JSON on standard output. It never creates a
staging directory or writes an installation payload. It refuses root execution
and has no signing, Keychain, TCC, enrolment, elevation, network, installation,
removal or overwrite operation.

The canonical plan is private operator material and must never be published or
attached to architecture-gate evidence. It intentionally contains the named
reviewer's identity, username, UID, GID and home-directory policy, plus fixed
`/Library` installation paths. Its narrower privacy guarantee is that original
accepted-input paths and accepted binary payloads are absent.

The workflow has two deliberate external passes because neither a final
installed inode nor post-enrolment hashes can be guessed safely:

1. Generate the reviewed-input template envelope. It contains no accepted
   instance and grants no authority:

       node scripts/a28-witness/stage-provisioning.mjs template

   Save the canonical stdout if required. Complete the envelope's `template`
   value using an independently reviewed process and save that value alone as
   one canonical sorted-key JSON line.
2. An Apple Developer administrator supplies the dedicated Developer ID
   Application identity and matching macOS provisioning profile. A separate
   reviewed build produces the signed witness application, signed root
   launcher, process inspector, private Node runtime and retained unsigned
   witness and launcher inputs. This tool does not create or sign them.
3. Measure the complete accepted application tree without invoking it:

       node scripts/a28-witness/stage-provisioning.mjs measure-application \
         --application '/canonical/accepted/PIUI A28 VoiceOver Witness.app'

4. Under a separately reviewed first-pass privileged procedure, the security
   administrator creates the PIUI/A28Witness/app ancestry exclusively and
   installs the complete accepted witness application tree. Validate and seal
   that tree, then record the final witness executable device and inode.
   Complete every `REQUIRED_` field. The input remains a measurement record
   only; its local paths never become installation authority.
5. Produce the canonical, non-authoritative provisioning plan:

       node scripts/a28-witness/stage-provisioning.mjs stage \
         --input /canonical/reviewed/accepted-instance-input.json \
         > /private/caller-owned/a28-provisioning-plan.json

6. Revalidate the saved plan immediately before any separately authorised
   privileged work:

       node scripts/a28-witness/stage-provisioning.mjs validate \
         --input /private/caller-owned/a28-provisioning-plan.json

The stage command reopens and hashes all five reviewed native sources, the
exact checkpoint, enrolment and verifier tools, every caller-supplied native
binary and the complete signed application tree. It verifies the embedded
profile hash, derives all launch-config hashes and validates the authority and
launch configurations with the production A.28 contract. The emitted plan
contains the accepted tree records, hashes, sizes and logical source roles, but
no original accepted-input path and no binary payload. It does contain the
private reviewer-account policy described above.

The validator reconstructs the complete plan from its accepted-instance record
and the current reviewed repository, then requires exact equality. It rejects
extra keys, stale repository inputs, malformed or incomplete application trees,
repository-tool pin drift, embedded-profile disagreement, unsafe captured mode,
ASCII case collision, non-portable non-ASCII bundle segment, oversized Darwin target path,
changed metadata policy, path-bearing source role and any receipt or recipe
change. It deliberately does not reopen the original measurement paths: a
validated plan does not authorise those paths, and changing them after the plan
was made cannot redirect later installation.

The plan treats the Developer ID identity, certificate, profile metadata,
CDHashes, designated requirements and final installed device and inode as
external reviewed pins. Hashing accepted bytes does not authenticate those
claims. The reproduction builder and installed verifier must still prove the
profile, code signatures, hardened runtime, entitlements and live installed
identity before any witness ceremony can begin.

The installation manifest records a four-state sequence: validate the complete
preinstalled witness tree; exclusively create the absent supporting targets;
validate root enrolment outputs; then exclusively create the final policy. All
PIUI-owned targets use root:wheel `0700`/`0755` directories and
`0400`/`0444`/`0500`/`0555` files with zero BSD flags, zero extended ACL entries
and zero extended attributes.

The two pre-existing system ancestors, `/Library` and `/Library/Application
Support`, must be canonical root-owned `0755` directories with no symlink, no
group/other write and no write-granting ACL. Their group is not forced to wheel:
standard macOS uses `root:admin` for `/Library/Application Support`. Zero or the
protective `SF_NOUNLINK` BSD flag is allowed and no xattr is allowed. The PIUI
ancestor must either already satisfy its stricter recorded policy or be created
exclusively as root:wheel `0755` during the app preinstall pass. The plan remains
`authoritative: false`, `credentialsAccessed: false`,
`enrolmentPerformed: false`, `installationRequired: true` and
`policyFinalisationRequired: true`.

The external security administrator must independently acquire every logical
source, compare its exact hash, size and application-tree digest, create absent
`installation` targets exclusively, validate every `preinstalled-validation`
target by complete membership, metadata, bytes and recorded identity, and stop
on every unrecorded collision. After managed
enrolment, the administrator must replace the two explicit post-enrolment
placeholders with the canonical enrolment and authority-receipt hashes,
construct the unchanged authority plus those pins, and validate the result with
`assertA28PolicyPin`, `assertA28Enrolment` and
`assertA28EnrolmentAuthorityReceipt` before installing `policy-pin.json`. The
plan never represents those human or privileged steps as completed.

## Installed policy and modes

The static enrolment-authority configuration and final policy are canonical sorted-key JSON followed by one newline. The final policy additionally pins the exact enrolment manifest, root enrolment receipt and static authority configuration hashes.

The policy fixes:

- reviewer name, username, UID, GID and home directory;
- app, team, certificate, profile, entitlements, CDHash and designated requirement;
- the accepted installed app executable and root launcher full SHA-256 values;
- unsigned witness and launcher SHA-256 values used only for reproduction;
- inspector, private Node, contract, registrar, checkpoint authority and verifier paths and hashes;
- root launcher CDHash, requirement and team identifier;
- host, runner and VoiceOver positive requirements and team identifiers;
- private checkpoint, public commitment, token-delivery, audit and result directories; and
- all three canonical launch-configuration paths and hashes.

Required installed modes are:

- root launcher and process inspector: root-owned 0555;
- private Node runtime: root-owned 0500;
- root JavaScript entrypoints and contract: root-owned 0444;
- launch configurations, authority configuration, policy and enrolment: root-owned 0444;
- private enrolment receipt and checkpoint records: root-owned 0400;
- checkpoint-private and consumed directories: root-owned 0700;
- commitment, delivery and result directories: root-owned 0755; and
- installed app directories 0755, executable files 0555 and other files 0444.

Every ancestor is root-owned and non-writable by group or other users. Every launch configuration contains exactly the pinned launcher, Node, entrypoint and contract paths and hashes, launcher requirement/CDHash, team identifier, mode and schema version.

The effective app entitlements are limited to the application identifier, developer team identifier and the one dedicated keychain group. get-task-allow is forbidden.

sourceSha256 covers A28ProcessIdentity.m, A28RootLauncher.m, A28Witness.entitlements.in, A28WitnessApp.m and Info.plist in that order.

## Reproduction build

build.mjs is a reproduction check, not a bootstrap authority. It requires an already installed root policy, exact profile and exact Developer ID identity. Those requirements are unchanged by the workspace hardening. The builder selects the unique profile certificate whose DER matches the policy-pinned SHA-256, derives its SHA-1 selector, cross-checks that exact SHA-1/SHA-256 pair and identity name across all matching keychain certificates and signs all four targets with the fingerprint selector rather than the non-unique common name. The builder snapshots the reviewed sources, uses root-owned Apple clang and SDK inputs and checks the pre-sign witness and launcher bytes against the unsigned policy pins.

The requested output path must be an absent leaf beneath a canonical, trusted directory chain on the same filesystem as the Darwin user temporary directory. Before creating the private build, the builder opens and retains descriptors for every output ancestor and the destination parent. Compilation, reproduction copying, signing and verification occur under an atomically created 0700 workspace beneath the canonical Darwin user temporary directory. The builder retains descriptors for every workspace ancestor, the private parent, workspace, build root, all four signing targets, the entitlements file and their direct parents.

Signing and signature inspection run through fixed source passed to the root-owned system Ruby. The helper changes directory with fchdir on the retained workspace descriptor, confirms that each workspace-relative pathname still names the retained device and inode, then execs the absolute root-owned /usr/bin/codesign. A validation-only preflight executes those same descriptor, fchdir and pathname checks for the app, launcher and inspector paths, then exits before either external tool can run. The parent retains all descriptors throughout the command and rejects any target, entitlement, workspace or output-chain substitution before a later command can start.

After signing, the builder opens every file and directory in the complete build tree and retains its device, inode, ownership, full permission mode, timestamps, size, directory membership, file SHA-256, BSD flags and extended attributes. It rejects extended ACLs, every special permission bit, every non-zero BSD flag and every extended attribute except an absent attribute set or the exact OS-managed com.apple.provenance value established on the private build root. It compares the source subtree with a fixed manifest constructed directly from the policy-verified source buffers and rendered entitlement bytes, rechecks the held inspector bytes against the policy hash and requires each signed executable's non-signature regions to match its policy-pinned unsigned bytes. Non-generated app resources must still match the authorised pre-sign bundle. Every codesign verification, codesign display and native inspection is bracketed by comparison with that held tree, including a second descriptor/stat check around each directory-membership read. Reproduction comparisons read the retained file descriptors. Publication uses descriptor-relative renameatx_np with RENAME_EXCL to move that exact verified build-directory inode into the still-absent output leaf. It then compares every retained object and directory membership again at the published path. It does not create a second tree by copying verified pathnames.

There is one precise same-UID residual: the remaining system interfaces consume names. Apple's codesign interface accepts target and entitlement pathnames rather than target file descriptors. A malicious process already running as the builder's UID can access that UID's 0700 workspace and could race after the helper's final pathname checks but before codesign opens either input. The parent detects substitution after the command, prevents later signing commands and prevents publication, but it cannot undo a signing side effect that codesign may already have applied using a transient target or entitlement. The inspection helper must likewise exec the inspector by pathname, and the inspector then opens the app by pathname; a winning race can execute attacker code as the builder UID before the parent rejects the changed held tree. Descriptor-relative renameatx_np makes publication exclusive and anchors both parents, but its source is still a name. A same-UID race after the helper's source check can therefore make an unverified directory visible at the output path; the retained-inode comparison rejects the build but cannot safely roll that pathname back, so the rejected output may remain indefinitely. Eliminating this residual requires a separately isolated build identity, a non-builder-writable output parent with a privileged publisher or a kernel-enforced sandbox boundary. This unprivileged build does not claim to provide any of those boundaries.

Timestamped Developer ID CMS data is not reproducible byte-for-byte. The build therefore signs two independent copies. It requires equal CodeDirectory/CDHash, designated requirement, team, leaf certificate, entitlements, hardened-runtime flags, every non-CMS code-signature slot, the normalised pre-signing region and all non-executable bundle resources. Only CMS bytes and the containing signature length may differ. Both full signed SHA-256 results are reported separately; neither replaces the full SHA pin for an accepted installed instance.

Compilation and signing can take time, so callers must display the build's working state while waiting. The output remains non-authoritative, reports humanWitnessed false and is never installed automatically.

## Root enrolment ceremony

The legacy user-owned candidate command in enrol.mjs is retired and always fails. Enrolment uses only the installed hardened root launcher in enrol mode.

The root registrar creates the final manifest inode exclusively as root:root 0400 and retains its descriptor. It launches the exact installed witness app after dropping to the reviewer UID and GID, passing that descriptor as FD 3. The exact protocol is READY, G, SIGNED and A. Root independently inspects the live app before and after key creation, validates the held canonical bytes and enrolment nonce, writes an exclusive root:root 0400 authority receipt and then seals the manifest 0444.

The app creates one permanent Secure Enclave P-256 key with biometryCurrentSet and privateKeyUsage in the data-protection keychain. It queries the stored key reference and attributes, proves that private bytes are not exportable and requires biometric authentication for the domain-separated enrolment signature. Existing keys and existing output files fail closed. The registrar shows a working indicator while biometric confirmation is pending.

## Challenge and checkpoint ceremony

The formal gate independently constructs the exact challenge request from retained started.json, frozen-source, production, twin, measured-delta and live-process evidence. It sends one bounded canonical line on standard input to the already privileged root launcher:

    a28-root-launcher --mode checkpoint --action prepare

Before reading input, the native launcher validates its own Developer ID signature, positive team requirement, hardened-runtime flag, CDHash, path and hash, then validates the root-owned config, private Node, entrypoint and contract. It reads stdin non-blockingly with a fixed timeout and size bound. It creates an unpredictable O_EXCL root:root 0400 request under the pinned 0700 private directory, verifies full held and pathname identity, fsyncs the file and directory, scrubs all inherited descriptors and interpreter-hook environment variables, changes to /private/var/empty and execve launches only the pinned Node with fixed arguments.

The root authority limits the number of retained records and consumes each domain-separated challengeRequestSha256 once. Duplicate, incomplete, oversized, non-canonical, swapped and extra-field requests fail closed. The root authority independently samples the live host, exact authenticated runner and VoiceOver processes and exact system versions.

Root creates a random session, nonce and four secret tokens. Each token commitment includes challengeRequestSha256, gate run ID, session, checkpoint ID, ordinal, appearance, mode, token and witness nonce. The root private session contains the raw tokens; the root-owned 0444 challenge contains commitments only.

Root also creates the exact empty attestation slot in the delivery directory, changes its ownership to the reviewer and mode to 0200, and places its dev, ino, path, UID and GID in the challenge. The reviewer cannot create, replace or remove a peer in the root-owned directory.

For each row, the managed root launch performs reveal with the exact challenge, delivery directory and live witness PID. Root reveals only the next ordinal, resamples all four processes, creates a reviewer-owned 0400 token delivery and retains a root-only reveal receipt. The app verifies each commitment locally and enables rows only in order.

The app accepts only the challenge's exact output path. It opens the pre-existing slot with O_NOFOLLOW, verifies the challenge dev, ino, UID, GID, mode and empty size, writes with pwrite, fsyncs and seals the same inode 0400. All decision, token and defect controls are disabled and a progress indicator remains visible while biometric signing is pending.

## Root verification and final comparison

The verifier runs only through the hardened root launcher. It validates the installed runtime and sources, app/profile/enrolment, exact root-owned challenge, exact sealed attestation inode and live host, runner, VoiceOver and witness identities on both sides of signature verification. It then asks the root checkpoint authority to authorise the exact four reveal receipts and atomically consumes the session with O_EXCL.

The public root receipt is root-owned 0444 under results/WITNESS_NONCE.json. It binds the attestation output identity, attestation hash, challenge and request hashes, all checkpoint checks, enrolment authorities, process identities and reviewer scope. The verifier result reports the public receipt path and SHA-256. A second session or witness-nonce use fails.

The root receipt alone is not a passing formal A.28 result. gateContextAuthority is always external-final-consumer-required and gateContextComparisonRequired is true. While the exact host and runner remain live, the formal gate must:

1. retain its independently created O_EXCL expected context by O_NOFOLLOW descriptor;
2. validate the root-owned receipt with assertA28PublishedReceipt;
3. compare every request field with independently held started.json, frozen source, production/twin inventories, measured delta and live identities; and
4. create one exclusive comparison receipt binding expected-context SHA-256, root-receipt SHA-256, attestation SHA-256 and started.json SHA-256.

Only that independent one-use comparison may produce gate-valid humanWitnessed true. Reading the root request back and comparing it with the same runner object is circular and has no authority.

The required runner is the fresh authenticated official Node binary retained from the formal bootstrap receipt. Its current accepted code identity is identifier node, team HX7739G8FX, CDHash 59cdea89a982b05f23e756c08115bebc555ff092 and SHA-256 2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d. Its per-run path, dev and ino must match the live retained process. It remains continuity-only because its entitlements do not make it a semantic root authority.

Legacy voiceover.json and completion.json can remain diagnostic evidence but can never set humanWitnessed. Standalone accessibility runs without an exact formal started.json context cannot enter this ceremony. The ceremony remains incomplete until a real reviewer has exercised VoiceOver in all four combinations. Automated accessibility-tree output is supplementary and cannot replace that reviewer.
