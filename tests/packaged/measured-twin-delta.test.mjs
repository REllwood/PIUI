import assert from 'node:assert/strict';
import test from 'node:test';
import {
  architectureVariantDefinition,
} from '../../scripts/architecture-artifact-evidence.mjs';
import {
  measureTwinDeltaSnapshots,
} from '../../scripts/measured-twin-delta.mjs';
import { sha256Bytes } from '../../scripts/architecture-gate-schema.mjs';

const sha = (character) => character.repeat(64);

function command(type, payload) {
  const size = 8 + payload.length;
  const aligned = Math.ceil(size / 8) * 8;
  const bytes = Buffer.alloc(aligned);
  bytes.writeUInt32LE(type, 0);
  bytes.writeUInt32LE(aligned, 4);
  payload.copy(bytes, 8);
  return bytes;
}

function machO({
  payload = 'production',
  sdk = 0x000e0000,
  uuid = '00'.repeat(16),
  uuids = uuid === null ? [] : [uuid],
} = {}) {
  const uuidCommands = uuids.map((value) => command(0x1b, Buffer.from(value, 'hex')));
  const buildPayload = Buffer.alloc(16);
  buildPayload.writeUInt32LE(1, 0);
  buildPayload.writeUInt32LE(0x000d0000, 4);
  buildPayload.writeUInt32LE(sdk, 8);
  buildPayload.writeUInt32LE(0, 12);
  const buildCommand = command(0x32, buildPayload);
  const dylibName = Buffer.from('/usr/lib/libSystem.B.dylib\0', 'utf8');
  const dylibPayload = Buffer.alloc(16 + dylibName.length);
  dylibPayload.writeUInt32LE(24, 0);
  dylibPayload.writeUInt32LE(2, 4);
  dylibPayload.writeUInt32LE(0x00010000, 8);
  dylibPayload.writeUInt32LE(0x00010000, 12);
  dylibName.copy(dylibPayload, 16);
  const dylibCommand = command(0x0c, dylibPayload);
  const commands = Buffer.concat([...uuidCommands, buildCommand, dylibCommand]);
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(0x0100000c, 4);
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(2, 12);
  header.writeUInt32LE(uuidCommands.length + 2, 16);
  header.writeUInt32LE(commands.length, 20);
  header.writeUInt32LE(0x00200085, 24);
  return Buffer.concat([header, commands, Buffer.from(payload, 'utf8')]);
}

function signedMachO(unsignedBytes, {
  bare = false,
  cmsPayload = false,
  flags = 0x2,
  slots = [0, 2, 0x10000],
} = {}) {
  const blobs = slots.map((slot) => {
    if (slot === 0) {
      const codeDirectory = Buffer.alloc(16);
      codeDirectory.writeUInt32BE(0xfade0c02, 0);
      codeDirectory.writeUInt32BE(codeDirectory.length, 4);
      codeDirectory.writeUInt32BE(flags, 12);
      return codeDirectory;
    }
    if (slot === 0x10000) {
      const wrapper = Buffer.alloc(cmsPayload ? 9 : 8);
      wrapper.writeUInt32BE(0xfade0b01, 0);
      wrapper.writeUInt32BE(wrapper.length, 4);
      return wrapper;
    }
    const blob = Buffer.alloc(12);
    blob.writeUInt32BE(0xfade0c01, 0);
    blob.writeUInt32BE(blob.length, 4);
    return blob;
  });
  let signatureBlob;
  if (bare) {
    assert.deepEqual(slots, [0]);
    signatureBlob = blobs[0];
  } else {
    const indexBytes = 12 + slots.length * 8;
    signatureBlob = Buffer.alloc(
      indexBytes + blobs.reduce((total, blob) => total + blob.length, 0),
    );
    signatureBlob.writeUInt32BE(0xfade0cc0, 0);
    signatureBlob.writeUInt32BE(signatureBlob.length, 4);
    signatureBlob.writeUInt32BE(slots.length, 8);
    let blobOffset = indexBytes;
    slots.forEach((slot, index) => {
      signatureBlob.writeUInt32BE(slot, 12 + index * 8);
      signatureBlob.writeUInt32BE(blobOffset, 16 + index * 8);
      blobs[index].copy(signatureBlob, blobOffset);
      blobOffset += blobs[index].length;
    });
  }

  const commandBytes = unsignedBytes.readUInt32LE(20);
  const header = Buffer.from(unsignedBytes.subarray(0, 32));
  const existingCommands = unsignedBytes.subarray(32, 32 + commandBytes);
  const payload = unsignedBytes.subarray(32 + commandBytes);
  const signatureCommand = Buffer.alloc(16);
  signatureCommand.writeUInt32LE(0x1d, 0);
  signatureCommand.writeUInt32LE(signatureCommand.length, 4);
  const signatureOffset = 32 + existingCommands.length + signatureCommand.length + payload.length;
  signatureCommand.writeUInt32LE(signatureOffset, 8);
  signatureCommand.writeUInt32LE(signatureBlob.length, 12);
  header.writeUInt32LE(header.readUInt32LE(16) + 1, 16);
  header.writeUInt32LE(commandBytes + signatureCommand.length, 20);
  return Buffer.concat([
    header,
    existingCommands,
    signatureCommand,
    payload,
    signatureBlob,
  ]);
}

function linkerSignedMachO(options) {
  return signedMachO(machO(options), {
    bare: true,
    flags: 0x20002,
    slots: [0],
  });
}

function file(path, bytes, mode = 0o444) {
  return {
    bytes: bytes.length,
    dev: 1,
    ino: 1,
    kind: 'file',
    mode,
    path,
    provenance: null,
    sha256: sha256Bytes(bytes),
  };
}

function directory(path) {
  return {
    bytes: 0,
    dev: 1,
    ino: 1,
    kind: 'directory',
    mode: 0o555,
    path,
    provenance: null,
    sha256: null,
  };
}

function snapshot({
  finalHostBytes,
  fingerprint,
  hostBytes,
  infoPlist,
  preSignHostBytes: suppliedPreSignHostBytes,
  reproducedFinalHostBytes,
  signatureVerified = true,
  uuid,
}) {
  const infoBytes = Buffer.from(JSON.stringify(infoPlist), 'utf8');
  const preSignHostBytes = suppliedPreSignHostBytes
    ?? linkerSignedMachO({ payload: hostBytes, uuid });
  const heldHostBytes = finalHostBytes ?? preSignHostBytes;
  const nodeBytes = Buffer.from('fixed-node', 'utf8');
  const sidecarBytes = Buffer.from('fixed-sidecar', 'utf8');
  return {
    fingerprint,
    infoBytes,
    infoPlist,
    inventory: {
      entries: [
        directory('Contents/'),
        file('Contents/Info.plist', infoBytes),
        directory('Contents/MacOS/'),
        file('Contents/MacOS/piui', heldHostBytes, 0o555),
        file('Contents/MacOS/piui-node', nodeBytes, 0o555),
        directory('Contents/Resources/'),
        file('Contents/Resources/fixed.txt', sidecarBytes),
      ],
      fingerprint,
      rootProvenance: null,
    },
    hostBytes: heldHostBytes,
    preSignHostBytes,
    finalSignatureVerified: signatureVerified,
    preSignSignatureVerified: true,
    reproducedFinalHostBytes,
  };
}

function replaceHost(snapshotValue, {
  finalHostBytes,
  preSignHostBytes = finalHostBytes,
  signatureVerified = true,
}) {
  snapshotValue.hostBytes = finalHostBytes;
  snapshotValue.preSignHostBytes = preSignHostBytes;
  snapshotValue.finalSignatureVerified = signatureVerified;
  snapshotValue.preSignSignatureVerified = true;
  const entry = snapshotValue.inventory.entries.find(
    (candidate) => candidate.path === 'Contents/MacOS/piui',
  );
  entry.bytes = finalHostBytes.length;
  entry.sha256 = sha256Bytes(finalHostBytes);
}

function replaceInfo(snapshotValue, infoPlist, { pretty = false } = {}) {
  const infoBytes = Buffer.from(
    pretty ? JSON.stringify(infoPlist, null, 2) : JSON.stringify(infoPlist),
    'utf8',
  );
  snapshotValue.infoBytes = infoBytes;
  snapshotValue.infoPlist = infoPlist;
  const entry = snapshotValue.inventory.entries.find(
    (candidate) => candidate.path === 'Contents/Info.plist',
  );
  entry.bytes = infoBytes.length;
  entry.sha256 = sha256Bytes(infoBytes);
}

function fixture() {
  const productionPlist = {
    CFBundleExecutable: 'piui',
    CFBundleIdentifier: 'au.com.piui.desktop',
    CFBundleName: 'PIUI',
    CFBundlePackageType: 'APPL',
    CFBundleShortVersionString: '0.1.0',
  };
  const twinPlist = {
    ...productionPlist,
    CFBundleIdentifier: 'au.com.piui.desktop.a23-test',
    CFBundleName: 'PIUI A23 Architecture Test',
  };
  return {
    appliedVariant: architectureVariantDefinition('credential-twin'),
    kind: 'credential-twin',
    production: snapshot({
      fingerprint: sha('1'),
      hostBytes: 'production-host',
      infoPlist: productionPlist,
      uuid: '01'.repeat(16),
    }),
    twin: snapshot({
      fingerprint: sha('2'),
      hostBytes: 'credential-host',
      infoPlist: twinPlist,
      uuid: '02'.repeat(16),
    }),
    twinRepeat: snapshot({
      fingerprint: sha('2'),
      hostBytes: 'credential-host',
      infoPlist: twinPlist,
      uuid: '02'.repeat(16),
    }),
  };
}

function automationFixture() {
  const value = fixture();
  const productionPlist = value.production.infoPlist;
  const twinPlist = {
    ...productionPlist,
    CFBundleIdentifier: 'au.com.piui.desktop.architecture-test',
    CFBundleName: 'PIUI Architecture Test',
  };
  const rawTwin = machO({
    payload: 'automation-host',
    uuid: '04'.repeat(16),
  });
  const twinPreSign = signedMachO(rawTwin, {
    bare: true,
    flags: 0x20002,
    slots: [0],
  });
  const twinFinal = signedMachO(rawTwin);
  return {
    appliedVariant: architectureVariantDefinition('automation-twin'),
    kind: 'automation-twin',
    production: value.production,
    twin: snapshot({
      finalHostBytes: twinFinal,
      fingerprint: sha('4'),
      infoPlist: twinPlist,
      preSignHostBytes: twinPreSign,
      reproducedFinalHostBytes: twinFinal,
      signatureVerified: true,
    }),
    twinRepeat: snapshot({
      finalHostBytes: twinFinal,
      fingerprint: sha('4'),
      infoPlist: twinPlist,
      preSignHostBytes: twinPreSign,
      reproducedFinalHostBytes: twinFinal,
      signatureVerified: true,
    }),
  };
}

test('hashes a complete measured and repeatable twin delta', () => {
  const measured = measureTwinDeltaSnapshots(fixture());
  assert.match(measured.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(measured.record.added.length, 0);
  assert.equal(measured.record.removed.length, 0);
  assert.deepEqual(
    measured.record.changes.map((change) => change.path),
    ['Contents/Info.plist', 'Contents/MacOS/piui'],
  );
  assert.deepEqual(
    measured.record.changes[0].semanticPatch.map((change) => change.key),
    ['CFBundleIdentifier', 'CFBundleName'],
  );
  assert.match(measured.record.changes[1].loadCommandContractSha256, /^[0-9a-f]{64}$/u);
});

test('binds an automation delta to an exact verified ad-hoc signature policy', () => {
  const measured = measureTwinDeltaSnapshots(automationFixture());
  const host = measured.record.changes[1];
  assert.equal(host.baseSignature, 'adhoc');
  assert.equal(host.twinSignature, 'adhoc');
  assert.match(host.postSignCodeDirectorySha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(host.postSignSlots.map(({ slot }) => slot), [0, 2, 0x10000]);
  assert.equal(host.baseUuid, '01'.repeat(16));
  assert.equal(host.twinUuid, '04'.repeat(16));
  assert.equal(host.repeatTwinUuid, '04'.repeat(16));
});

test('accepts the linker CodeDirectory in its observed Apple superblob form', () => {
  const value = fixture();
  const definitions = [
    [value.production, 'production-host', '01'.repeat(16)],
    [value.twin, 'credential-host', '02'.repeat(16)],
    [value.twinRepeat, 'credential-host', '02'.repeat(16)],
  ];
  for (const [snapshotValue, payload, uuid] of definitions) {
    const linkerHost = signedMachO(machO({ payload, uuid }), {
      flags: 0x20002,
      slots: [0],
    });
    replaceHost(snapshotValue, {
      finalHostBytes: linkerHost,
      preSignHostBytes: linkerHost,
    });
  }
  const measured = measureTwinDeltaSnapshots(value);
  assert.equal(measured.record.changes[1].baseSignatureForm, 'superblob');
});

test('rejects any unlisted file, metadata, or plist semantic change', () => {
  const changedFile = fixture();
  changedFile.twin.inventory.entries.find(
    (entry) => entry.path === 'Contents/Resources/fixed.txt',
  ).sha256 = sha('9');
  assert.throws(() => measureTwinDeltaSnapshots(changedFile), /outside the measured twin allowlist/u);

  const added = fixture();
  added.twin.inventory.entries.push(file('Contents/Resources/extra.txt', Buffer.from('extra')));
  assert.throws(() => measureTwinDeltaSnapshots(added), /added or removed/u);

  const plist = fixture();
  replaceInfo(plist.twin, {
    ...plist.twin.infoPlist,
    CFBundleVersion: 'forged',
  });
  replaceInfo(plist.twinRepeat, {
    ...plist.twinRepeat.infoPlist,
    CFBundleVersion: 'forged',
  });
  assert.throws(() => measureTwinDeltaSnapshots(plist), /Info\.plist changed outside/u);

  const baseIdentity = fixture();
  replaceInfo(baseIdentity.production, {
    ...baseIdentity.production.infoPlist,
    CFBundleIdentifier: 'au.com.piui.wrong',
  });
  assert.throws(() => measureTwinDeltaSnapshots(baseIdentity), /Production Info\.plist identity/u);

  const staleDisplayName = fixture();
  for (const snapshotValue of [staleDisplayName.twin, staleDisplayName.twinRepeat]) {
    replaceInfo(snapshotValue, {
      ...snapshotValue.infoPlist,
      CFBundleDisplayName: 'PIUI',
    });
  }
  assert.throws(
    () => measureTwinDeltaSnapshots(staleDisplayName),
    /product name did not match/u,
  );

  const wrongVariant = fixture();
  wrongVariant.appliedVariant = architectureVariantDefinition('approval-twin');
  assert.throws(() => measureTwinDeltaSnapshots(wrongVariant), /artefact evidence rejected/u);
});

test('rejects a non-reproducible twin host or changed Mach-O contract', () => {
  const changedPayload = fixture();
  changedPayload.twinRepeat.preSignHostBytes = linkerSignedMachO({
    payload: 'different-host',
    uuid: '02'.repeat(16),
  });
  assert.throws(
    () => measureTwinDeltaSnapshots(changedPayload),
    /not reproducible|differs from its pre-explicit-sign bytes/u,
  );

  const changedSdk = fixture();
  changedSdk.twin.preSignHostBytes = linkerSignedMachO({
    payload: 'credential-host',
    sdk: 0x000f0000,
    uuid: '02'.repeat(16),
  });
  assert.throws(
    () => measureTwinDeltaSnapshots(changedSdk),
    /differs from its pre-explicit-sign bytes|structure or repeat build/u,
  );
});

test('binds plist semantics and repeat checks to the exact inventoried bytes', () => {
  const repeatPlistBytes = fixture();
  replaceInfo(
    repeatPlistBytes.twinRepeat,
    repeatPlistBytes.twinRepeat.infoPlist,
    { pretty: true },
  );
  assert.throws(() => measureTwinDeltaSnapshots(repeatPlistBytes), /repeat bytes are not exact/u);

  const repeatFinalHost = fixture();
  repeatFinalHost.twinRepeat.preSignHostBytes = machO({
    payload: 'credential-host',
    uuid: '03'.repeat(16),
  });
  repeatFinalHost.twinRepeat.hostBytes = repeatFinalHost.twinRepeat.preSignHostBytes;
  const hostEntry = repeatFinalHost.twinRepeat.inventory.entries.find(
    (entry) => entry.path === 'Contents/MacOS/piui',
  );
  hostEntry.bytes = repeatFinalHost.twinRepeat.hostBytes.length;
  hostEntry.sha256 = sha256Bytes(repeatFinalHost.twinRepeat.hostBytes);
  assert.throws(() => measureTwinDeltaSnapshots(repeatFinalHost), /repeat bytes are not exact/u);

  const claimedObjectDoesNotOverrideBytes = fixture();
  claimedObjectDoesNotOverrideBytes.twin.infoPlist = claimedObjectDoesNotOverrideBytes.production.infoPlist;
  const measured = measureTwinDeltaSnapshots(claimedObjectDoesNotOverrideBytes);
  assert.match(measured.sha256, /^[0-9a-f]{64}$/u);

  const invalidHeldBytes = fixture();
  replaceInfo(invalidHeldBytes.twin, { claimed: 'valid' });
  invalidHeldBytes.twin.infoBytes = Buffer.from('not a plist', 'utf8');
  invalidHeldBytes.twinRepeat.infoBytes = Buffer.from('not a plist', 'utf8');
  for (const value of [invalidHeldBytes.twin, invalidHeldBytes.twinRepeat]) {
    const infoEntry = value.inventory.entries.find(
      (entry) => entry.path === 'Contents/Info.plist',
    );
    infoEntry.bytes = value.infoBytes.length;
    infoEntry.sha256 = sha256Bytes(value.infoBytes);
  }
  assert.throws(() => measureTwinDeltaSnapshots(invalidHeldBytes), /Could not parse held/u);
});

test('rejects wrong signing states and non-canonical signature slots', () => {
  const substitutedFinal = automationFixture();
  const substitutedBytes = signedMachO(machO({
    payload: 'substituted-final-host',
    uuid: '04'.repeat(16),
  }));
  for (const snapshotValue of [substitutedFinal.twin, substitutedFinal.twinRepeat]) {
    replaceHost(snapshotValue, {
      finalHostBytes: substitutedBytes,
      preSignHostBytes: snapshotValue.preSignHostBytes,
    });
  }
  assert.throws(
    () => measureTwinDeltaSnapshots(substitutedFinal),
    /does not match an exact signing reproduction/u,
  );

  const unsignedAutomation = automationFixture();
  for (const snapshotValue of [unsignedAutomation.twin, unsignedAutomation.twinRepeat]) {
    replaceHost(snapshotValue, {
      finalHostBytes: snapshotValue.preSignHostBytes,
      preSignHostBytes: snapshotValue.preSignHostBytes,
    });
  }
  assert.throws(
    () => measureTwinDeltaSnapshots(unsignedAutomation),
    /signing reproduction|post-sign identity|explicit ad-hoc signature/u,
  );

  const signedCredential = fixture();
  for (const snapshotValue of [signedCredential.twin, signedCredential.twinRepeat]) {
    const finalHostBytes = signedMachO(machO({
      payload: 'credential-host',
      uuid: '02'.repeat(16),
    }));
    replaceHost(snapshotValue, {
      finalHostBytes,
      preSignHostBytes: snapshotValue.preSignHostBytes,
      signatureVerified: true,
    });
  }
  assert.throws(
    () => measureTwinDeltaSnapshots(signedCredential),
    /differs from its pre-explicit-sign bytes|post-sign identity|linker signature/u,
  );

  for (const slots of [[0, 5], [0, 8], [0, 0], [0, 0x10000]]) {
    const nonCanonical = automationFixture();
    for (const snapshotValue of [nonCanonical.twin, nonCanonical.twinRepeat]) {
      const finalHostBytes = signedMachO(machO({
        payload: 'automation-host',
        uuid: '04'.repeat(16),
      }), { slots });
      replaceHost(snapshotValue, {
        finalHostBytes,
        preSignHostBytes: snapshotValue.preSignHostBytes,
        signatureVerified: true,
      });
    }
    assert.throws(
      () => measureTwinDeltaSnapshots(nonCanonical),
      /signing reproduction|signature|accepted arm64 Mach-O/u,
    );
  }

  const cms = automationFixture();
  for (const snapshotValue of [cms.twin, cms.twinRepeat]) {
    const finalHostBytes = signedMachO(machO({
      payload: 'automation-host',
      uuid: '04'.repeat(16),
    }), { cmsPayload: true });
    replaceHost(snapshotValue, {
      finalHostBytes,
      preSignHostBytes: snapshotValue.preSignHostBytes,
    });
  }
  assert.throws(
    () => measureTwinDeltaSnapshots(cms),
    /signing reproduction|accepted arm64 Mach-O/u,
  );
});

test('rejects absent or duplicate LC_UUID commands', () => {
  const missing = fixture();
  const withoutUuid = machO({ payload: 'production-host', uuid: null });
  replaceHost(missing.production, { finalHostBytes: withoutUuid });
  assert.throws(() => measureTwinDeltaSnapshots(missing), /no LC_UUID/u);

  const duplicate = fixture();
  const duplicateUuid = machO({
    payload: 'credential-host',
    uuids: ['02'.repeat(16), '03'.repeat(16)],
  });
  for (const snapshotValue of [duplicate.twin, duplicate.twinRepeat]) {
    replaceHost(snapshotValue, { finalHostBytes: duplicateUuid });
  }
  assert.throws(() => measureTwinDeltaSnapshots(duplicate), /at most one canonical LC_UUID/u);
});
