import { spawnSync } from 'node:child_process';
import { constants } from 'node:fs';
import {
  mkdir,
  open,
} from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  assertMeasuredTwinDeltaRecord,
  canonicalArchitectureJson,
  sha256Bytes,
} from './architecture-gate-schema.mjs';
import {
  assertAppliedArchitectureVariant,
} from './architecture-artifact-evidence.mjs';
import {
  assertAutomationHostSigningEvidence,
  inspectAppleDevelopmentSignatureBytes,
  verifyCodeSignatureBytesWithLease,
} from './automation-host-signing.mjs';
import {
  HOST_PATH,
  inventoryBundle,
  inspectMachOBytes,
} from '../tests/packaged/bundle-inspection.mjs';

const INFO_PATH = 'Contents/Info.plist';
const LC_CODE_SIGNATURE = 0x1d;
const LC_UUID = 0x1b;
const LC_BUILD_VERSION = 0x32;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_RPATH = 0x8000001c;
const DYLIB_COMMANDS = new Set([
  0x0c,
  0x18,
  0x1f,
  0x20,
  0x23,
  0x80000018,
  0x8000001f,
  0x80000023,
]);
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_BLOBWRAPPER = 0xfade0b01;
const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_REQUIREMENTS = 2;
const CSSLOT_ENTITLEMENTS = 5;
const CSSLOT_DER_ENTITLEMENTS = 7;
const CSSLOT_SIGNATURESLOT = 0x10000;
const CS_ADHOC = 0x2;
const CS_LINKER_SIGNED = 0x20000;
const SHA256 = /^[0-9a-f]{64}$/u;
const ALLOWED_ADHOC_SLOTS = new Set([
  CSSLOT_CODEDIRECTORY,
  CSSLOT_REQUIREMENTS,
  CSSLOT_SIGNATURESLOT,
]);

const EXPECTED_PLIST_VALUES = Object.freeze({
  'approval-twin': Object.freeze({
    identifier: 'au.com.piui.desktop.a25-test',
    productName: 'PIUI A25 Architecture Test',
  }),
  'automation-twin': Object.freeze({
    identifier: 'au.com.piui.desktop.architecture-test',
    productName: 'PIUI Architecture Test',
  }),
  'credential-twin': Object.freeze({
    identifier: 'au.com.piui.desktop.a23-test',
    productName: 'PIUI A23 Architecture Test',
  }),
});

function reject(detail = 'Measured architecture twin delta rejected') {
  throw new Error(detail);
}

function exactSha(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) reject(`${label} is not a SHA-256 digest`);
}

function sanitiseEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) reject();
  return Object.freeze({
    bytes: entry.bytes,
    kind: entry.kind,
    mode: entry.mode,
    path: entry.path,
    provenance: entry.provenance,
    sha256: entry.sha256,
  });
}

function entryMap(inventory) {
  if (!inventory || !Array.isArray(inventory.entries)) reject();
  const rows = inventory.entries.map(sanitiseEntry);
  const map = new Map(rows.map((entry) => [entry.path, entry]));
  if (map.size !== rows.length) reject('Bundle inventory contains duplicate paths');
  return map;
}

function exactEntryShape(left, right, label) {
  if (left.kind !== right.kind
    || left.mode !== right.mode
    || left.provenance !== right.provenance) {
    reject(`${label} changed kind, mode, or provenance`);
  }
}

function exactEntry(left, right, label) {
  if (canonicalArchitectureJson(left) !== canonicalArchitectureJson(right)) {
    reject(`${label} changed outside the measured twin allowlist`);
  }
}

function compareInventories(base, twin, repeat, kind) {
  if (base.rootProvenance !== twin.rootProvenance
    || twin.rootProvenance !== repeat.rootProvenance) {
    reject('Bundle root provenance changed between measured builds');
  }
  const baseMap = entryMap(base);
  const twinMap = entryMap(twin);
  const repeatMap = entryMap(repeat);
  const basePaths = [...baseMap.keys()].sort();
  const twinPaths = [...twinMap.keys()].sort();
  const repeatPaths = [...repeatMap.keys()].sort();
  if (canonicalArchitectureJson(basePaths) !== canonicalArchitectureJson(twinPaths)
    || canonicalArchitectureJson(twinPaths) !== canonicalArchitectureJson(repeatPaths)) {
    reject('Measured twin added or removed a bundle path');
  }
  const mutable = new Set([INFO_PATH, HOST_PATH]);
  const equalEntries = [];
  for (const path of basePaths) {
    const baseEntry = baseMap.get(path);
    const twinEntry = twinMap.get(path);
    const repeatEntry = repeatMap.get(path);
    if (mutable.has(path)) {
      exactEntryShape(baseEntry, twinEntry, path);
      exactEntryShape(twinEntry, repeatEntry, `${path} repeat`);
      if (!(kind === 'automation-twin' && path === HOST_PATH)
        && (twinEntry.sha256 !== repeatEntry.sha256
        || twinEntry.bytes !== repeatEntry.bytes)) {
        reject(`${path} repeat bytes are not exact`);
      }
      continue;
    }
    exactEntry(baseEntry, twinEntry, path);
    exactEntry(twinEntry, repeatEntry, `${path} repeat`);
    equalEntries.push(baseEntry);
  }
  return Object.freeze({
    baseMap,
    equalEntriesSha256: sha256Bytes(Buffer.from(canonicalArchitectureJson({
      entries: equalEntries,
      rootProvenance: base.rootProvenance,
    }), 'utf8')),
    repeatMap,
    twinMap,
  });
}

function plistSemanticPatch(kind, base, twin, repeat) {
  const expected = EXPECTED_PLIST_VALUES[kind];
  if (!expected
    || !base || typeof base !== 'object' || Array.isArray(base)
    || !twin || typeof twin !== 'object' || Array.isArray(twin)
    || !repeat || typeof repeat !== 'object' || Array.isArray(repeat)
    || canonicalArchitectureJson(twin) !== canonicalArchitectureJson(repeat)) reject();
  if (base.CFBundleIdentifier !== 'au.com.piui.desktop'
    || base.CFBundleName !== 'PIUI'
    || (Object.hasOwn(base, 'CFBundleDisplayName')
      && base.CFBundleDisplayName !== 'PIUI')) {
    reject('Production Info.plist identity is not exact');
  }
  const keys = [...new Set([...Object.keys(base), ...Object.keys(twin)])].sort();
  const changed = keys.filter(
    (key) => canonicalArchitectureJson(Object.hasOwn(base, key) ? base[key] : null)
      !== canonicalArchitectureJson(Object.hasOwn(twin, key) ? twin[key] : null),
  );
  if (!changed.includes('CFBundleIdentifier')
    || twin.CFBundleIdentifier !== expected.identifier
    || changed.some((key) => ![
      'CFBundleDisplayName',
      'CFBundleIdentifier',
      'CFBundleName',
    ].includes(key))) {
    reject('Info.plist changed outside the exact twin identity allowlist');
  }
  const productKeys = changed.filter(
    (key) => key === 'CFBundleDisplayName' || key === 'CFBundleName',
  );
  if (productKeys.length < 1
    || productKeys.some((key) => twin[key] !== expected.productName)
    || ['CFBundleDisplayName', 'CFBundleName'].some(
      (key) => Object.hasOwn(twin, key) && twin[key] !== expected.productName,
    )) {
    reject('Info.plist product name did not match the exact twin definition');
  }
  return Object.freeze(changed.map((key) => Object.freeze({
    base: base[key] ?? null,
    key,
    twin: twin[key] ?? null,
  })));
}

function readCommandString(bytes, commandOffset, commandSize, relativeOffset) {
  if (relativeOffset < 8 || relativeOffset >= commandSize) reject('Malformed Mach-O string offset');
  const start = commandOffset + relativeOffset;
  const endLimit = commandOffset + commandSize;
  const zero = bytes.indexOf(0, start);
  const end = zero === -1 || zero > endLimit ? endLimit : zero;
  return bytes.subarray(start, end).toString('utf8');
}

function codeSignatureDetails(bytes, signature) {
  if (!signature) return Object.freeze({
    codeDirectorySha256: null,
    flags: null,
    entitlements: false,
    form: 'none',
    slots: Object.freeze([]),
  });
  let blob = bytes.subarray(signature.offset, signature.offset + signature.size);
  let codeDirectorySha256 = null;
  let flags = null;
  let entitlements = false;
  let cms = false;
  const slots = [];
  const seenSlots = new Set();
  const inspectSlot = (slot, offset) => {
    if (seenSlots.has(slot) || !ALLOWED_ADHOC_SLOTS.has(slot)) {
      reject('Measured host signature contains a duplicate or unknown slot');
    }
    seenSlots.add(slot);
    if (offset + 8 > blob.length) reject('Malformed Mach-O signature slot');
    const length = blob.readUInt32BE(offset + 4);
    if (length < 8 || offset + length > blob.length) reject('Malformed Mach-O signature blob');
    slots.push(Object.freeze({
      sha256: sha256Bytes(blob.subarray(offset, offset + length)),
      size: length,
      slot,
    }));
    if (slot === CSSLOT_CODEDIRECTORY) {
      if (codeDirectorySha256 !== null) reject('Duplicate Mach-O CodeDirectory');
      if (length < 16 || blob.readUInt32BE(offset) !== 0xfade0c02) {
        reject('Malformed Mach-O CodeDirectory');
      }
      codeDirectorySha256 = sha256Bytes(blob.subarray(offset, offset + length));
      flags = blob.readUInt32BE(offset + 12);
    }
    if (slot === CSSLOT_ENTITLEMENTS || slot === CSSLOT_DER_ENTITLEMENTS) entitlements = true;
    if (slot === CSSLOT_SIGNATURESLOT) {
      if (blob.readUInt32BE(offset) !== CSMAGIC_BLOBWRAPPER) {
        reject('Measured host has a malformed CMS wrapper');
      }
      cms ||= length > 8;
    }
  };
  if (blob.length >= 16 && blob.readUInt32BE(0) === 0xfade0c02) {
    const length = blob.readUInt32BE(4);
    if (length < 16 || length > blob.length) reject('Malformed bare Mach-O CodeDirectory');
    codeDirectorySha256 = sha256Bytes(blob.subarray(0, length));
    flags = blob.readUInt32BE(12);
    slots.push(Object.freeze({
      sha256: codeDirectorySha256,
      size: length,
      slot: CSSLOT_CODEDIRECTORY,
    }));
    return Object.freeze({
      codeDirectorySha256,
      entitlements: false,
      flags,
      form: 'code-directory',
      slots: Object.freeze(slots),
    });
  }
  if (blob.length < 12 || blob.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE) {
    reject('Measured signed host has an unknown signature container');
  }
  const length = blob.readUInt32BE(4);
  const count = blob.readUInt32BE(8);
  if (length > blob.length || count > 256 || 12 + count * 8 > length) {
    reject('Malformed Mach-O signature superblob');
  }
  blob = blob.subarray(0, length);
  for (let index = 0; index < count; index += 1) {
    inspectSlot(blob.readUInt32BE(12 + index * 8), blob.readUInt32BE(16 + index * 8));
  }
  if (cms || entitlements || codeDirectorySha256 === null) {
    reject('Measured host signature contains CMS, entitlements, or no CodeDirectory');
  }
  return Object.freeze({
    codeDirectorySha256,
    entitlements,
    flags,
    form: 'superblob',
    slots: Object.freeze(slots),
  });
}

function machOContract(bytes) {
  const signatureState = inspectMachOBytes(bytes);
  if (!signatureState || signatureState.architecture !== 'arm64') {
    reject('Measured host is not an accepted arm64 Mach-O');
  }
  const commands = bytes.readUInt32LE(16);
  const commandBytes = bytes.readUInt32LE(20);
  const normalised = Buffer.from(bytes);
  const commandKinds = [];
  const dylibs = [];
  const rpaths = [];
  const platforms = [];
  let cursor = 32;
  let uuid = null;
  let signature = null;
  for (let index = 0; index < commands; index += 1) {
    const command = bytes.readUInt32LE(cursor);
    const size = bytes.readUInt32LE(cursor + 4);
    if (size < 8 || cursor + size > 32 + commandBytes) reject('Malformed measured Mach-O command');
    commandKinds.push(command);
    if (command === LC_UUID) {
      if (uuid !== null || size !== 24) reject('Measured Mach-O must contain at most one canonical LC_UUID');
      uuid = bytes.subarray(cursor + 8, cursor + 24).toString('hex');
      normalised.fill(0, cursor + 8, cursor + 24);
    } else if (command === LC_CODE_SIGNATURE) {
      if (signature !== null || size < 16) reject('Malformed measured Mach-O signature command');
      signature = Object.freeze({
        offset: bytes.readUInt32LE(cursor + 8),
        size: bytes.readUInt32LE(cursor + 12),
      });
    } else if (DYLIB_COMMANDS.has(command)) {
      if (size < 24) reject('Malformed measured Mach-O dylib command');
      dylibs.push(Object.freeze({
        command,
        compatibilityVersion: bytes.readUInt32LE(cursor + 20),
        currentVersion: bytes.readUInt32LE(cursor + 16),
        name: readCommandString(bytes, cursor, size, bytes.readUInt32LE(cursor + 8)),
        timestamp: bytes.readUInt32LE(cursor + 12),
      }));
    } else if (command === LC_RPATH) {
      if (size < 12) reject('Malformed measured Mach-O rpath command');
      rpaths.push(readCommandString(bytes, cursor, size, bytes.readUInt32LE(cursor + 8)));
    } else if (command === LC_BUILD_VERSION) {
      if (size < 24) reject('Malformed measured Mach-O build-version command');
      const toolCount = bytes.readUInt32LE(cursor + 20);
      if (24 + toolCount * 8 > size) reject('Malformed measured Mach-O build tool list');
      const tools = [];
      for (let toolIndex = 0; toolIndex < toolCount; toolIndex += 1) {
        tools.push(Object.freeze({
          tool: bytes.readUInt32LE(cursor + 24 + toolIndex * 8),
          version: bytes.readUInt32LE(cursor + 28 + toolIndex * 8),
        }));
      }
      platforms.push(Object.freeze({
        command,
        minos: bytes.readUInt32LE(cursor + 12),
        platform: bytes.readUInt32LE(cursor + 8),
        sdk: bytes.readUInt32LE(cursor + 16),
        tools: Object.freeze(tools),
      }));
    } else if (command === LC_VERSION_MIN_MACOSX) {
      if (size < 16) reject('Malformed measured Mach-O minimum-version command');
      platforms.push(Object.freeze({
        command,
        minos: bytes.readUInt32LE(cursor + 8),
        sdk: bytes.readUInt32LE(cursor + 12),
      }));
    }
    cursor += size;
  }
  if (uuid === null) reject('Measured Mach-O has no LC_UUID');
  const appleDevelopmentSignature = signatureState.cms
    ? inspectAppleDevelopmentSignatureBytes(bytes)
    : null;
  const signatureDetails = appleDevelopmentSignature
    ? Object.freeze({
      codeDirectorySha256: appleDevelopmentSignature.codeDirectorySha256,
      entitlements: false,
      flags: appleDevelopmentSignature.codeDirectoryFlags,
      form: 'superblob',
      slots: Object.freeze(appleDevelopmentSignature.signatureSlots.map((entry) => Object.freeze({
        sha256: entry.sha256,
        size: entry.size,
        slot: entry.slot,
      }))),
    })
    : codeSignatureDetails(bytes, signature);
  const structural = Object.freeze({
    commandKinds: Object.freeze(commandKinds),
    cpuSubtype: bytes.readUInt32LE(8),
    cpuType: bytes.readUInt32LE(4),
    dylibs: Object.freeze(dylibs),
    fileType: bytes.readUInt32LE(12),
    flags: bytes.readUInt32LE(24),
    platforms: Object.freeze(platforms),
    reserved: bytes.readUInt32LE(28),
    rpaths: Object.freeze(rpaths),
  });
  return Object.freeze({
    appleDevelopmentSignature,
    codeDirectorySha256: signatureDetails.codeDirectorySha256,
    codeDirectoryFlags: signatureDetails.flags,
    normalisedSha256: sha256Bytes(normalised),
    signature: signatureState.signature,
    signatureForm: signatureDetails.form,
    signatureSlots: signatureDetails.slots,
    structural,
    structuralSha256: sha256Bytes(Buffer.from(canonicalArchitectureJson(structural), 'utf8')),
    uuid,
  });
}

export function inspectMeasuredHostContract(bytes) {
  return machOContract(bytes);
}

function exactSignatureSlots(contract, expectedSlots) {
  return contract.signatureSlots.length === expectedSlots.length
    && contract.signatureSlots.every(
      (entry, index) => entry.slot === expectedSlots[index],
    );
}

function assertLinkerSignature(contract, verified, label) {
  if (contract.signature !== 'adhoc'
    || !['code-directory', 'superblob'].includes(contract.signatureForm)
    || contract.codeDirectoryFlags !== (CS_ADHOC | CS_LINKER_SIGNED)
    || !exactSignatureSlots(contract, [CSSLOT_CODEDIRECTORY])
    || verified !== true) {
    reject(`${label} is not an exact verified linker signature`);
  }
}

function assertAppleDevelopmentSignature(contract, verified, signingIdentity) {
  const identity = assertAutomationHostSigningEvidence(signingIdentity);
  const signature = contract.appleDevelopmentSignature;
  if (contract.signature !== 'cms'
    || contract.signatureForm !== 'superblob'
    || contract.codeDirectoryFlags !== 0
    || !exactSignatureSlots(contract, [
      CSSLOT_CODEDIRECTORY,
      CSSLOT_REQUIREMENTS,
      CSSLOT_SIGNATURESLOT,
    ])
    || verified !== true
    || !signature
    || signature.executableSha256 !== identity.executableSha256
    || signature.codeDirectorySha256 !== identity.codeDirectorySha256
    || signature.codeDirectoryFlags !== identity.codeDirectoryFlags
    || signature.cdHash !== identity.cdHash
    || signature.cmsBytes !== identity.cmsBytes
    || signature.cmsSha256 !== identity.cmsSha256
    || signature.executableBytes !== identity.executableBytes
    || signature.nonCmsSignatureSha256 !== identity.nonCmsSignatureSha256
    || signature.requirementsSha256 !== identity.requirementsSha256
    || signature.signatureContainerBytes !== identity.signatureContainerBytes
    || canonicalArchitectureJson(signature.signatureSlots)
      !== canonicalArchitectureJson(identity.signatureSlots)) {
    reject('Automation host is not an exact verified Apple Development signature');
  }
  return identity;
}

function assertBundleIdentity(snapshot, label) {
  exactSha(snapshot.fingerprint, `${label} fingerprint`);
  if (!snapshot.inventory || snapshot.inventory.fingerprint !== snapshot.fingerprint) {
    reject(`${label} inventory does not match its held bundle fingerprint`);
  }
  const infoEntry = snapshot.inventory.entries.find((entry) => entry.path === INFO_PATH);
  const hostEntry = snapshot.inventory.entries.find((entry) => entry.path === HOST_PATH);
  if (!infoEntry || !hostEntry
    || infoEntry.sha256 !== sha256Bytes(snapshot.infoBytes)
    || hostEntry.sha256 !== sha256Bytes(snapshot.hostBytes)) {
    reject(`${label} bytes do not match its held inventory`);
  }
}

function deterministicAutomationSigningIdentity(value) {
  return Object.freeze({
    bundleIdentifier: value.bundleIdentifier,
    cdHash: value.cdHash,
    certificateSha1: value.certificateSha1,
    certificateSha256: value.certificateSha256,
    codeDirectoryFlags: value.codeDirectoryFlags,
    codeDirectorySha256: value.codeDirectorySha256,
    designatedRequirement: value.designatedRequirement,
    entitlements: value.entitlements,
    nonCmsSignatureSha256: value.nonCmsSignatureSha256,
    nonCmsSignatureSlots: Object.freeze(value.signatureSlots.slice(0, 2)),
    requirementsSha256: value.requirementsSha256,
    schemaVersion: value.schemaVersion,
    signature: value.signature,
    teamIdentifier: value.teamIdentifier,
  });
}

function deterministicAutomationSigningIdentitySha256(value) {
  return sha256Bytes(Buffer.from(
    canonicalArchitectureJson(deterministicAutomationSigningIdentity(value)),
    'utf8',
  ));
}

export function measureTwinDeltaSnapshots({
  appliedVariant,
  kind,
  production,
  twin,
  twinRepeat,
}) {
  if (!EXPECTED_PLIST_VALUES[kind]) reject('Unknown measured twin kind');
  assertAppliedArchitectureVariant(kind, appliedVariant);
  for (const [label, snapshot] of [
    ['production', production],
    ['twin', twin],
    ['repeat twin', twinRepeat],
  ]) assertBundleIdentity(snapshot, label);
  if (production.fingerprint === twin.fingerprint) reject('Measured twin aliases production');
  if (kind !== 'automation-twin' && twin.fingerprint !== twinRepeat.fingerprint) {
    reject('Repeated measured twin fingerprint is not exact');
  }
  const inventories = compareInventories(
    production.inventory,
    twin.inventory,
    twinRepeat.inventory,
    kind,
  );
  const semanticPatch = plistSemanticPatch(
    kind,
    parsePlistBytes(production.infoBytes),
    parsePlistBytes(twin.infoBytes),
    parsePlistBytes(twinRepeat.infoBytes),
  );
  const baseHost = machOContract(production.preSignHostBytes);
  const twinHost = machOContract(twin.preSignHostBytes);
  const repeatHost = machOContract(twinRepeat.preSignHostBytes);
  assertLinkerSignature(
    baseHost,
    production.preSignSignatureVerified,
    'Production pre-explicit-sign host',
  );
  assertLinkerSignature(
    twinHost,
    twin.preSignSignatureVerified,
    'Twin pre-explicit-sign host',
  );
  assertLinkerSignature(
    repeatHost,
    twinRepeat.preSignSignatureVerified,
    'Repeat twin pre-explicit-sign host',
  );
  if (!production.hostBytes.equals(production.preSignHostBytes)) {
    reject('Production final host differs from its pre-explicit-sign bytes');
  }
  if (!twin.preSignHostBytes.equals(twinRepeat.preSignHostBytes)) {
    reject('Repeated measured twin pre-sign host bytes are not exact');
  }
  if (kind !== 'automation-twin' && (!twin.hostBytes.equals(twin.preSignHostBytes)
    || !twinRepeat.hostBytes.equals(twinRepeat.preSignHostBytes))) {
    reject('Non-automation final host differs from its pre-explicit-sign bytes');
  }
  if (baseHost.structuralSha256 !== twinHost.structuralSha256
    || twinHost.structuralSha256 !== repeatHost.structuralSha256
    || twinHost.normalisedSha256 !== repeatHost.normalisedSha256) {
    reject('Measured twin Mach-O structure or repeat build is not reproducible');
  }
  const finalBaseHost = machOContract(production.hostBytes);
  const finalTwinHost = machOContract(twin.hostBytes);
  const finalRepeatHost = machOContract(twinRepeat.hostBytes);
  if (finalBaseHost.structuralSha256 !== baseHost.structuralSha256
    || finalTwinHost.structuralSha256 !== twinHost.structuralSha256
    || finalRepeatHost.structuralSha256 !== repeatHost.structuralSha256) {
    reject('Explicit signing changed the measured Mach-O load-command contract');
  }
  assertLinkerSignature(
    finalBaseHost,
    production.finalSignatureVerified,
    'Production final host',
  );
  let twinSigningIdentity = null;
  let repeatSigningIdentity = null;
  if (kind === 'automation-twin') {
    twinSigningIdentity = assertAppleDevelopmentSignature(
      finalTwinHost,
      twin.finalSignatureVerified,
      twin.hostSigningIdentity,
    );
    repeatSigningIdentity = assertAppleDevelopmentSignature(
      finalRepeatHost,
      twinRepeat.finalSignatureVerified,
      twinRepeat.hostSigningIdentity,
    );
    if (canonicalArchitectureJson(deterministicAutomationSigningIdentity(twinSigningIdentity))
        !== canonicalArchitectureJson(
          deterministicAutomationSigningIdentity(repeatSigningIdentity),
        )
      || finalTwinHost.appleDevelopmentSignature.nonCmsSignatureSha256
        !== finalRepeatHost.appleDevelopmentSignature.nonCmsSignatureSha256
      || canonicalArchitectureJson(finalTwinHost.signatureSlots.slice(0, 2))
        !== canonicalArchitectureJson(finalRepeatHost.signatureSlots.slice(0, 2))) {
      reject('Measured Apple Development twin differs outside its CMS signature slot');
    }
  } else {
    assertLinkerSignature(finalTwinHost, twin.finalSignatureVerified, 'Twin final host');
    assertLinkerSignature(
      finalRepeatHost,
      twinRepeat.finalSignatureVerified,
      'Repeat twin final host',
    );
  }
  if (finalTwinHost.codeDirectorySha256 !== finalRepeatHost.codeDirectorySha256
    || (kind !== 'automation-twin'
      && canonicalArchitectureJson(finalTwinHost.signatureSlots)
        !== canonicalArchitectureJson(finalRepeatHost.signatureSlots))) {
    reject('Measured twin post-sign identity is not reproducible');
  }
  const variantDefinitionSha256 = sha256Bytes(Buffer.from(
    `${canonicalArchitectureJson(appliedVariant)}\n`,
    'utf8',
  ));
  const record = Object.freeze({
    added: Object.freeze([]),
    baseFingerprint: production.fingerprint,
    changes: Object.freeze([
      Object.freeze({
        baseSha256: inventories.baseMap.get(INFO_PATH).sha256,
        path: INFO_PATH,
        semanticPatch,
        twinSha256: inventories.twinMap.get(INFO_PATH).sha256,
        type: 'plist',
      }),
      Object.freeze({
        baseCodeDirectoryFlags: finalBaseHost.codeDirectoryFlags,
        baseCodeDirectorySha256: finalBaseHost.codeDirectorySha256,
        baseSha256: inventories.baseMap.get(HOST_PATH).sha256,
        baseSignature: finalBaseHost.signature,
        baseSignatureForm: finalBaseHost.signatureForm,
        basePreSignNormalisedSha256: baseHost.normalisedSha256,
        baseUuid: baseHost.uuid,
        loadCommandContractSha256: baseHost.structuralSha256,
        path: HOST_PATH,
        postSignBundleIdentifier: twinSigningIdentity?.bundleIdentifier ?? null,
        postSignCdHash: twinSigningIdentity?.cdHash ?? null,
        postSignCertificateSha1: twinSigningIdentity?.certificateSha1 ?? null,
        postSignCertificateSha256: twinSigningIdentity?.certificateSha256 ?? null,
        postSignCmsBytes: twinSigningIdentity?.cmsBytes ?? null,
        postSignCmsSha256: twinSigningIdentity?.cmsSha256 ?? null,
        postSignCodeDirectoryFlags: finalTwinHost.codeDirectoryFlags,
        postSignCodeDirectorySha256: finalTwinHost.codeDirectorySha256,
        postSignDesignatedRequirement: twinSigningIdentity?.designatedRequirement ?? null,
        postSignDeterministicIdentitySha256: twinSigningIdentity
          ? deterministicAutomationSigningIdentitySha256(twinSigningIdentity)
          : null,
        postSignEntitlements: twinSigningIdentity?.entitlements ?? null,
        postSignExecutableBytes: twinSigningIdentity?.executableBytes ?? null,
        postSignForm: finalTwinHost.signatureForm,
        postSignNonCmsSignatureSha256:
          twinSigningIdentity?.nonCmsSignatureSha256 ?? null,
        postSignRequirementsSha256: twinSigningIdentity?.requirementsSha256 ?? null,
        postSignSignatureContainerBytes:
          twinSigningIdentity?.signatureContainerBytes ?? null,
        postSignSlots: finalTwinHost.signatureSlots,
        postSignTeamIdentifier: twinSigningIdentity?.teamIdentifier ?? null,
        repeatPreSignCodeDirectorySha256: repeatHost.codeDirectorySha256,
        repeatPostSignCmsSha256: repeatSigningIdentity?.cmsSha256 ?? null,
        repeatPostSignCmsBytes: repeatSigningIdentity?.cmsBytes ?? null,
        repeatPostSignCodeDirectorySha256: kind === 'automation-twin'
          ? finalRepeatHost.codeDirectorySha256
          : null,
        repeatPostSignDeterministicIdentitySha256: repeatSigningIdentity
          ? deterministicAutomationSigningIdentitySha256(repeatSigningIdentity)
          : null,
        repeatPostSignExecutableBytes: repeatSigningIdentity?.executableBytes ?? null,
        repeatPostSignNonCmsSignatureSha256:
          repeatSigningIdentity?.nonCmsSignatureSha256 ?? null,
        repeatPostSignSignatureContainerBytes:
          repeatSigningIdentity?.signatureContainerBytes ?? null,
        repeatPostSignSlots: kind === 'automation-twin'
          ? finalRepeatHost.signatureSlots
          : null,
        repeatTwinSha256: kind === 'automation-twin'
          ? inventories.repeatMap.get(HOST_PATH).sha256
          : null,
        repeatTwinUuid: repeatHost.uuid,
        twinSha256: inventories.twinMap.get(HOST_PATH).sha256,
        twinSignature: finalTwinHost.signature,
        twinPreSignCodeDirectoryFlags: twinHost.codeDirectoryFlags,
        twinPreSignCodeDirectorySha256: twinHost.codeDirectorySha256,
        twinPreSignForm: twinHost.signatureForm,
        twinPreSignNormalisedSha256: twinHost.normalisedSha256,
        twinUuid: twinHost.uuid,
        type: 'macho',
      }),
    ]),
    equalEntriesSha256: inventories.equalEntriesSha256,
    kind,
    removed: Object.freeze([]),
    repeatTwinFingerprint: twinRepeat.fingerprint,
    schemaVersion: 1,
    twinFingerprint: twin.fingerprint,
    variantDefinitionSha256,
  });
  assertMeasuredTwinDeltaRecord(record, kind, {
    baseFingerprint: production.fingerprint,
    twinFingerprint: twin.fingerprint,
  });
  return Object.freeze({
    record,
    sha256: sha256Bytes(Buffer.from(canonicalArchitectureJson(record), 'utf8')),
  });
}

function parsePlistBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 1_048_576) {
    reject('Held bundle Info.plist bytes are invalid');
  }
  const result = spawnSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], {
    encoding: 'utf8',
    env: { LANG: 'en_AU.UTF-8', PATH: '/usr/bin:/bin' },
    input: bytes,
    maxBuffer: 1_048_576,
  });
  if (result.status !== 0 || result.signal !== null) reject('Could not parse held Info.plist bytes');
  try {
    return JSON.parse(result.stdout);
  } catch {
    return reject('Held Info.plist bytes did not convert to JSON');
  }
}

async function readHeldInventoryFile(inventory, path, label) {
  const expected = inventory.entries.find(
    (entry) => entry.path === path && entry.kind === 'file',
  );
  if (!expected) reject(`${label} is absent from the held bundle inventory`);
  const handle = await open(
    resolve(inventory.root, path),
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    if (!before.isFile()
      || before.dev !== expected.dev
      || before.ino !== expected.ino
      || before.size !== expected.bytes) {
      reject(`${label} descriptor does not match the held inventory`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || sha256Bytes(bytes) !== expected.sha256) {
      reject(`${label} changed while read through its held descriptor`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function verifyCodeSignatureBytes(bytes, verificationRoot, label) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 32) reject('Signature verification input is invalid');
  const digest = sha256Bytes(bytes);
  const leased = await verifyCodeSignatureBytesWithLease(
    bytes,
    verificationRoot,
    `${label}-${digest.slice(0, 16)}`,
  );
  const { verified } = leased;
  if (verified.status !== 0 || verified.signal !== null) {
    reject('Held host bytes failed strict code-signature verification');
  }
  if (leased.sourceSha256 !== digest || leased.cloneSha256 !== digest) {
    reject('Private signature-verification copy changed');
  }
  return true;
}

async function captureBundleSnapshot(
  bundle,
  preSignHostBytes,
  verificationRoot,
  label,
) {
  const inventory = await inventoryBundle(bundle.appPath);
  if (inventory.fingerprint !== bundle.fingerprint) reject('Held bundle changed before delta measurement');
  const [infoBytes, hostBytes] = await Promise.all([
    readHeldInventoryFile(inventory, INFO_PATH, `${label} Info.plist`),
    readHeldInventoryFile(inventory, HOST_PATH, `${label} host`),
  ]);
  const heldPreSignHostBytes = preSignHostBytes ?? hostBytes;
  const [finalSignatureVerified, preSignSignatureVerified] = await Promise.all([
    verifyCodeSignatureBytes(hostBytes, verificationRoot, `${label}-final`),
    verifyCodeSignatureBytes(
      heldPreSignHostBytes,
      verificationRoot,
      `${label}-pre-explicit`,
    ),
  ]);
  const afterVerification = await inventoryBundle(bundle.appPath);
  if (afterVerification.fingerprint !== bundle.fingerprint) {
    reject('Held bundle changed during delta measurement');
  }
  return Object.freeze({
    fingerprint: bundle.fingerprint,
    hostBytes,
    hostSigningIdentity: bundle.hostSigningIdentity,
    infoBytes,
    inventory,
    finalSignatureVerified,
    preSignHostBytes: heldPreSignHostBytes,
    preSignSignatureVerified,
  });
}

export async function measureTwinDelta({
  appliedVariant,
  kind,
  productionBundle,
  productionPreSignHostBytes,
  twinBundle,
  twinPreSignHostBytes,
  twinRepeatBundle,
  twinRepeatPreSignHostBytes,
  verificationRoot,
}) {
  if (typeof verificationRoot !== 'string' || !verificationRoot.startsWith('/')) {
    reject('Measured-delta verification root is invalid');
  }
  await mkdir(verificationRoot, { mode: 0o700 });
  const [production, capturedTwin, capturedTwinRepeat] = await Promise.all([
    captureBundleSnapshot(
      productionBundle,
      productionPreSignHostBytes,
      verificationRoot,
      'production',
    ),
    captureBundleSnapshot(
      twinBundle,
      twinPreSignHostBytes,
      verificationRoot,
      'twin',
    ),
    captureBundleSnapshot(
      twinRepeatBundle,
      twinRepeatPreSignHostBytes,
      verificationRoot,
      'repeat-twin',
    ),
  ]);
  return measureTwinDeltaSnapshots({
    appliedVariant,
    kind,
    production,
    twin: capturedTwin,
    twinRepeat: capturedTwinRepeat,
  });
}
