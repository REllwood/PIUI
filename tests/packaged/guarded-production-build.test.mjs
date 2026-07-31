import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  architectureArtifactFromBundle,
  architectureVariantDefinition,
} from '../../scripts/architecture-artifact-evidence.mjs';
import {
  ARCHITECTURE_PROOF_CONTRACTS,
  ARCHITECTURE_PROOF_IDS,
  canonicalArchitectureJson,
  createArchitecturePassMarker,
  sha256Bytes,
} from '../../scripts/architecture-gate-schema.mjs';
import {
  buildGuardedProduction,
  createPrivateTemporary,
} from '../../scripts/build-production.mjs';
import { snapshotArchitectureSource } from '../../scripts/architecture-source-snapshot.mjs';
import { validateLatestArchitectureGate } from '../../scripts/check-architecture-gate.mjs';
import {
  createGuardedProductionResult,
  parseGuardedProductionResult,
} from '../../scripts/guarded-production-contract.mjs';
import {
  architectureProofBatch,
} from './architecture-proof-fixtures.mjs';

const sha = (character) => character.repeat(64);
const runId = '20260731T120000000Z-0123456789abcdef0123456789abcdef';

function productionArtifact(fingerprint = sha('1')) {
  return architectureArtifactFromBundle({
    entries: 101,
    files: 93,
    fingerprint,
    hostSignature: 'none',
    machoFiles: 2,
    nodeSha256: sha('3'),
    sidecarSha256: sha('4'),
  }, {
    appliedVariant: architectureVariantDefinition('production'),
    kind: 'production',
  });
}

function gate(overrides = {}) {
  return Object.freeze({
    decision: 'pass',
    distributionAuthorised: false,
    productionFingerprint: sha('1'),
    runId,
    sourceDigest: sha('2'),
    target: 'aarch64-apple-darwin',
    ...overrides,
  });
}

function source(digest = sha('2'), inventory = 'stable', lease = inventory) {
  return Object.freeze({
    inventoryBytes: Buffer.from(`${inventory}\n`, 'utf8'),
    lease: Object.freeze({ entries: 1, sha256: sha(lease === 'stable' ? '5' : '6') }),
    leaseBytes: Buffer.from(`${lease}-lease\n`, 'utf8'),
    source: Object.freeze({ digest }),
  });
}

async function fixture(t) {
  const temporaryRoot = await realpath(tmpdir());
  const repositoryRoot = await mkdtemp(join(temporaryRoot, 'piui-production-runner.'));
  t.after(async () => removeTestTree(repositoryRoot));
  await mkdir(join(repositoryRoot, '.forge'), { mode: 0o700 });
  await mkdir(join(repositoryRoot, 'src-tauri'), { mode: 0o700 });
  for (const name of ['ARCHITECTURE-GATE', 'FORGE', 'PLAN', 'SPEC', 'UI-DESIGN']) {
    await writeFile(join(repositoryRoot, '.forge', `${name}.md`), `${name}\n`, { mode: 0o600 });
  }
  await writeFile(join(repositoryRoot, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n', { mode: 0o600 });
  await writeFile(join(repositoryRoot, 'src-tauri', 'Cargo.lock'), 'version = 4\n', { mode: 0o600 });
  return repositoryRoot;
}

async function removeTestTree(path) {
  let state;
  try {
    state = await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (state.isDirectory() && !state.isSymbolicLink()) {
    await chmod(path, 0o700);
    const children = await readdir(path);
    for (const child of children) await removeTestTree(join(path, child));
  }
  await rm(path, { force: true, recursive: true });
}

function line(value) {
  return Buffer.from(`${canonicalArchitectureJson(value)}\n`, 'utf8');
}

async function recordPassingGate(repositoryRoot) {
  const sourceRecord = (await snapshotArchitectureSource(repositoryRoot)).source;
  const productionBatch = architectureProofBatch('production', undefined, sourceRecord.digest);
  const batches = {
    approval: architectureProofBatch('approval', productionBatch.artifact, sourceRecord.digest),
    automation: architectureProofBatch('automation', productionBatch.artifact, sourceRecord.digest),
    credential: architectureProofBatch('credential', productionBatch.artifact, sourceRecord.digest),
    production: productionBatch,
  };
  const proofValues = Object.assign({}, ...Object.values(batches).map((batch) => batch.proofs));
  const evidence = Object.fromEntries(
    ARCHITECTURE_PROOF_IDS.map((id) => [id, line(proofValues[id])]),
  );
  const proofs = Object.fromEntries(ARCHITECTURE_PROOF_IDS.map((id) => {
    const contract = ARCHITECTURE_PROOF_CONTRACTS[id];
    const artifact = batches[contract.batchId].artifact;
    return [id, {
      artifactFingerprint: artifact.fingerprint,
      artifactKind: contract.artifactKind,
      commandId: contract.commandId,
      evidenceSha256: sha256Bytes(evidence[id]),
      sourceDigest: sourceRecord.digest,
      status: 'pass',
    }];
  }));
  const results = {
    artifacts: {
      approvalTwin: batches.approval.artifact,
      automationTwin: batches.automation.artifact,
      credentialTwin: batches.credential.artifact,
      production: productionBatch.artifact,
    },
    externalReleaseGates: {
      developerId: 'not-provided',
      distributionAuthorised: false,
      notarisation: 'not-provided',
      updaterHosting: 'not-provided',
      updaterSigning: 'not-provided',
    },
    limitations: {
      automationConformanceEquivalence: 'not-claimed',
      publicDistribution: 'not-authorised',
      trustedExtensionContainment: 'not-claimed',
    },
    proofs,
    schemaVersion: 1,
    source: sourceRecord,
    target: 'aarch64-apple-darwin',
  };
  const run = join(repositoryRoot, '.forge', 'evidence', 'architecture-gate', 'runs', runId);
  await mkdir(join(run, 'proofs'), { mode: 0o700, recursive: true });
  await writeFile(join(run, 'started.json'), line({
    runId,
    schemaVersion: 1,
    sourceDigest: sourceRecord.digest,
    startedAt: '2026-07-31T12:00:00.000Z',
    status: 'started',
    target: 'aarch64-apple-darwin',
  }), { mode: 0o600 });
  for (const id of ARCHITECTURE_PROOF_IDS) {
    await writeFile(join(run, 'proofs', `${id}.json`), evidence[id], { mode: 0o600 });
  }
  await writeFile(join(run, 'results.json'), line(results), { mode: 0o600 });
  await writeFile(
    join(run, 'pass-marker.json'),
    line(createArchitecturePassMarker(results)),
    { mode: 0o600 },
  );
  return results;
}

function executorFor(artifact = productionArtifact()) {
  return async ({ gate: acceptedGate, outputRoot }) => {
    await mkdir(join(outputRoot, 'PIUI.app'), { mode: 0o555 });
    return createGuardedProductionResult({
      artifact,
      gateRunId: acceptedGate.runId,
      generatedOutputsRemoved: true,
      sourceDigest: acceptedGate.sourceDigest,
    });
  };
}

function dependencies(overrides = {}) {
  return {
    bundleInventory: async () => ({ fingerprint: sha('1') }),
    gateValidator: async () => gate(),
    nonceFactory: () => 'abcdef0123456789abcdef0123456789',
    now: () => new Date('2026-07-31T12:30:00.000Z'),
    packageExecutor: executorFor(),
    snapshotter: async () => source(),
    ...overrides,
  };
}

test('publishes only the exact recorded build with an append-only final record', async (t) => {
  const repositoryRoot = await fixture(t);
  const result = await buildGuardedProduction(repositoryRoot, dependencies());
  assert.equal(result.status, 'pass');
  assert.equal(result.distributionAuthorised, false);
  assert.equal(result.productionFingerprint, sha('1'));
  assert.match(result.bundlePath, /^\.forge\/artifacts\/production-builds\//u);

  const record = JSON.parse(await readFile(join(repositoryRoot, result.buildRecord), 'utf8'));
  assert.equal(record.status, 'pass');
  assert.equal(record.distributionAuthorised, false);
  assert.equal(record.artifact.fingerprint, sha('1'));
  assert.equal(record.gateRunId, runId);
  assert.equal(record.sourceDigest, sha('2'));
  const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
  assert.deepEqual(await readdir(builds), [basename(dirname(join(repositoryRoot, result.bundlePath)))]);
});

test('an invalid initial gate leaves production output directories uncreated', async (t) => {
  const repositoryRoot = await fixture(t);
  let packageCalled = false;
  await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
    gateValidator: async () => gate({ decision: 'fail' }),
    packageExecutor: async () => {
      packageCalled = true;
      throw new Error('must not run');
    },
  })), /does not authorise/u);
  assert.equal(packageCalled, false);
  await assert.rejects(lstat(join(repositoryRoot, '.forge', 'artifacts')), { code: 'ENOENT' });
});

test('copies into a destination-filesystem incoming directory before one sibling commit', async (t) => {
  const repositoryRoot = await fixture(t);
  let stagingRoot;
  const renames = [];
  const result = await buildGuardedProduction(repositoryRoot, dependencies({
    packageExecutor: async ({ gate: acceptedGate, outputRoot }) => {
      stagingRoot = outputRoot;
      const app = join(outputRoot, 'PIUI.app');
      await mkdir(app, { mode: 0o700 });
      await writeFile(join(app, 'payload.txt'), 'copied\n', { mode: 0o600 });
      await chmod(app, 0o555);
      return createGuardedProductionResult({
        artifact: productionArtifact(),
        gateRunId: acceptedGate.runId,
        generatedOutputsRemoved: true,
        sourceDigest: acceptedGate.sourceDigest,
      });
    },
    publicationRenamer: async (sourcePath, destinationPath) => {
      renames.push({ destinationPath, sourcePath });
      assert.equal(dirname(sourcePath), dirname(destinationPath));
      assert.match(basename(sourcePath), /^\.incoming-/u);
      assert.doesNotMatch(basename(destinationPath), /^\./u);
      const [sourceState, parentState] = await Promise.all([
        stat(sourcePath),
        stat(dirname(destinationPath)),
      ]);
      assert.equal(sourceState.dev, parentState.dev);
      assert.deepEqual((await readdir(sourcePath)).sort(), ['PIUI.app', 'build.json']);
      await rename(sourcePath, destinationPath);
    },
  }));

  assert.equal(renames.length, 1);
  assert.equal(await readFile(join(repositoryRoot, result.bundlePath, 'payload.txt'), 'utf8'), 'copied\n');
  await assert.rejects(lstat(stagingRoot), { code: 'ENOENT' });
});

test('rejects a no-op publication renamer without reporting a final candidate', async (t) => {
  const repositoryRoot = await fixture(t);
  let renameCalls = 0;
  await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
    publicationRenamer: async () => {
      renameCalls += 1;
    },
  })), (error) => {
    assert.ok(error instanceof AggregateError);
    return true;
  });

  assert.equal(renameCalls, 2);
  const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
  const entries = await readdir(builds);
  assert.equal(entries.length, 1);
  assert.match(entries[0], /^\.incoming-/u);
  assert.doesNotMatch(entries[0], /^\d/u);
  assert.deepEqual(
    (await readdir(join(builds, entries[0]))).sort(),
    ['PIUI.app', 'build.json'],
  );
});

test('moves a committed native rename into failed evidence when helper cleanup rejects', async (t) => {
  if (process.platform !== 'darwin') {
    t.skip('native exclusive rename requires macOS');
    return;
  }
  const repositoryRoot = await fixture(t);
  const temporaryRoot = await realpath(tmpdir());
  const helperTemporaryRoot = await mkdtemp(join(temporaryRoot, 'piui-publisher-helper-race.'));
  await chmod(helperTemporaryRoot, 0o700);
  t.after(async () => removeTestTree(helperTemporaryRoot));

  const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
  const publicationStem = `${runId}-abcdef0123456789abcdef0123456789`;
  const incomingPath = join(builds, `.incoming-${publicationStem}`);
  const watcherSource = String.raw`
    const {
      existsSync,
      mkdirSync,
      readdirSync,
      writeFileSync,
    } = require('node:fs');
    const { join } = require('node:path');
    const root = process.env.PIUI_WATCH_ROOT;
    const incoming = process.env.PIUI_WATCH_INCOMING;
    const prefix = process.env.PIUI_WATCH_PREFIX;
    const waitArray = new Int32Array(new SharedArrayBuffer(4));
    process.stdout.write('ready\n');
    const deadline = Date.now() + 20_000;
    let injected = false;
    while (Date.now() < deadline) {
      const workspaceName = readdirSync(root).find((name) => name.startsWith(prefix));
      if (workspaceName) {
        const workspace = join(root, workspaceName);
        if (!injected) {
          try {
            writeFileSync(join(workspace, 'unexpected-owned-entry'), 'retain\n', {
              flag: 'wx',
              mode: 0o600,
            });
            injected = true;
          } catch (error) {
            if (error.code !== 'EEXIST' && error.code !== 'ENOENT') throw error;
          }
        }
        if (injected && !existsSync(incoming)) {
          try {
            mkdirSync(incoming, { mode: 0o700 });
            writeFileSync(join(incoming, 'foreign-marker.txt'), 'foreign\n', {
              flag: 'wx',
              mode: 0o600,
            });
            process.exit(0);
          } catch (error) {
            if (error.code !== 'EEXIST' && error.code !== 'ENOENT') throw error;
          }
        }
      }
      Atomics.wait(waitArray, 0, 0, 2);
    }
    process.exit(2);
  `;
  const watcher = spawn(process.execPath, ['-e', watcherSource], {
    env: {
      PATH: '/usr/bin:/bin',
      PIUI_WATCH_INCOMING: incomingPath,
      PIUI_WATCH_PREFIX: `piui-exclusive-rename-${process.pid}-`,
      PIUI_WATCH_ROOT: helperTemporaryRoot,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let watcherError = '';
  watcher.stderr.setEncoding('utf8');
  watcher.stderr.on('data', (chunk) => {
    watcherError += chunk;
  });
  await new Promise((resolveReady, rejectReady) => {
    watcher.once('error', rejectReady);
    watcher.stdout.once('data', (chunk) => {
      if (chunk.toString('utf8') === 'ready\n') resolveReady();
      else rejectReady(new Error('publisher helper watcher did not become ready'));
    });
  });
  const watcherExit = new Promise((resolveExit, rejectExit) => {
    watcher.once('error', rejectExit);
    watcher.once('exit', (code, signal) => resolveExit({ code, signal }));
  });

  const previousTemporaryRoot = process.env.TMPDIR;
  process.env.TMPDIR = `${helperTemporaryRoot}/`;
  try {
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies()));
  } finally {
    if (previousTemporaryRoot === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTemporaryRoot;
  }
  const watcherResult = await watcherExit;
  assert.deepEqual(watcherResult, { code: 0, signal: null }, watcherError);

  const entries = (await readdir(builds)).sort();
  const failedEntries = entries.filter((entry) => entry.startsWith('.failed-'));
  assert.equal(failedEntries.length, 1);
  assert.equal(entries.some((entry) => /^\d/u.test(entry)), false);
  assert.equal(await readFile(join(incomingPath, 'foreign-marker.txt'), 'utf8'), 'foreign\n');
  assert.deepEqual(
    (await readdir(join(builds, failedEntries[0]))).sort(),
    ['PIUI.app', 'build.json'],
  );
  const retainedRecord = JSON.parse(
    await readFile(join(builds, failedEntries[0], 'build.json'), 'utf8'),
  );
  assert.equal(retainedRecord.status, 'pass');
  assert.equal(retainedRecord.distributionAuthorised, false);
});

test('pre-publication validation failures expose only clearly failed evidence', async (t) => {
  const repositoryRoot = await fixture(t);
  await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
    bundleInventory: async (path) => ({
      fingerprint: path.includes(`${join('.forge', 'artifacts', 'production-builds')}`)
        ? sha('9')
        : sha('1'),
    }),
  })), /Copied production bundle fingerprint changed/u);

  const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
  const entries = await readdir(builds);
  assert.equal(entries.length, 1);
  assert.match(entries[0], /^\.failed-/u);
  assert.doesNotMatch(entries[0], /^\d/u);
  assert.deepEqual(await readdir(join(builds, entries[0])), ['PIUI.app']);
});

test('never adopts or moves a pre-existing incoming publication', async (t) => {
  const repositoryRoot = await fixture(t);
  const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
  const stem = `${runId}-abcdef0123456789abcdef0123456789`;
  const preExisting = join(builds, `.incoming-${stem}`);
  await mkdir(preExisting, { mode: 0o700, recursive: true });
  await writeFile(join(preExisting, 'owner-marker.txt'), 'pre-existing\n', { mode: 0o600 });

  await assert.rejects(
    buildGuardedProduction(repositoryRoot, dependencies()),
    (error) => error?.code === 'EEXIST',
  );
  assert.equal(await readFile(join(preExisting, 'owner-marker.txt'), 'utf8'), 'pre-existing\n');
  assert.deepEqual(await readdir(builds), [`.incoming-${stem}`]);
});

test('never overwrites an existing final publication', async (t) => {
  const repositoryRoot = await fixture(t);
  const first = await buildGuardedProduction(repositoryRoot, dependencies());
  const recordPath = join(repositoryRoot, first.buildRecord);
  const recordBefore = await readFile(recordPath);

  await assert.rejects(
    buildGuardedProduction(repositoryRoot, dependencies()),
    /Final production publication already exists/u,
  );
  assert.deepEqual(await readFile(recordPath), recordBefore);
  const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
  assert.deepEqual(await readdir(builds), [basename(dirname(recordPath))]);
});

test('accepts a real passing gate only as a non-distributable local candidate', async (t) => {
  const repositoryRoot = await fixture(t);
  const results = await recordPassingGate(repositoryRoot);
  const accepted = await validateLatestArchitectureGate(repositoryRoot);
  assert.equal(accepted.decision, 'pass');
  assert.equal(accepted.distributionAuthorised, false);

  const result = await buildGuardedProduction(repositoryRoot, dependencies({
    gateValidator: validateLatestArchitectureGate,
    packageExecutor: executorFor(results.artifacts.production),
    snapshotter: snapshotArchitectureSource,
  }));
  assert.equal(result.status, 'pass');
  assert.equal(result.productionFingerprint, results.artifacts.production.fingerprint);
});

test('rejects source and gate TOCTOU changes before publication', async (t) => {
  await t.test('source changes during the package build', async (nested) => {
    const repositoryRoot = await fixture(nested);
    let snapshots = 0;
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      snapshotter: async () => {
        snapshots += 1;
        return snapshots <= 2 ? source() : source(sha('2'), 'changed');
      },
    })), /gate or source changed/u);
  });

  await t.test('gate changes during the package build', async (nested) => {
    const repositoryRoot = await fixture(nested);
    let validations = 0;
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      gateValidator: async () => {
        validations += 1;
        return validations <= 2 ? gate() : gate({ runId: '20260731T120000001Z-fedcba9876543210fedcba9876543210' });
      },
    })), /gate or source changed/u);
  });

  await t.test('same-byte source lease changes during the package build', async (nested) => {
    const repositoryRoot = await fixture(nested);
    let snapshots = 0;
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      snapshotter: async () => {
        snapshots += 1;
        return snapshots <= 2 ? source() : source(sha('2'), 'stable', 'replaced');
      },
    })), /gate or source changed/u);
  });
});

test('rejects a built or reported artefact fingerprint mismatch', async (t) => {
  await t.test('bundle bytes differ', async (nested) => {
    const repositoryRoot = await fixture(nested);
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      bundleInventory: async () => ({ fingerprint: sha('9') }),
    })), /does not match the recorded/u);
  });

  await t.test('child report differs', async (nested) => {
    const repositoryRoot = await fixture(nested);
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      packageExecutor: executorFor(productionArtifact(sha('9'))),
    })), /rejected/u);
  });
});

test('rejects staging root and same-byte bundle ABA replacements', async (t) => {
  await t.test('same-path staging root replacement', async (nested) => {
    const repositoryRoot = await fixture(nested);
    let originalRoot;
    let replacementRoot;
    nested.after(async () => {
      if (originalRoot) await removeTestTree(originalRoot);
      if (replacementRoot) await removeTestTree(replacementRoot);
    });
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      packageExecutor: async ({ gate: acceptedGate, outputRoot }) => {
        originalRoot = `${outputRoot}.original`;
        replacementRoot = outputRoot;
        await rename(outputRoot, originalRoot);
        await mkdir(outputRoot, { mode: 0o700 });
        await mkdir(join(outputRoot, 'PIUI.app'), { mode: 0o555 });
        return createGuardedProductionResult({
          artifact: productionArtifact(),
          gateRunId: acceptedGate.runId,
          generatedOutputsRemoved: true,
          sourceDigest: acceptedGate.sourceDigest,
        });
      },
    })), (error) => {
      assert.ok(error instanceof AggregateError);
      assert.match(error.errors.map((entry) => entry.message).join(' '), /identity changed/u);
      return true;
    });
  });

  await t.test('same-byte bundle file replacement during copy', async (nested) => {
    const repositoryRoot = await fixture(nested);
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      bundleCopier: async ({ destination, source: sourcePath }) => {
        await cp(sourcePath, destination, {
          errorOnExist: true,
          force: false,
          preserveTimestamps: true,
          recursive: true,
        });
        const payload = join(sourcePath, 'payload.txt');
        const bytes = await readFile(payload);
        await chmod(sourcePath, 0o700);
        const replacement = join(sourcePath, 'replacement.txt');
        await writeFile(replacement, bytes, { mode: 0o600 });
        await rename(replacement, payload);
        await chmod(sourcePath, 0o555);
      },
      packageExecutor: async ({ gate: acceptedGate, outputRoot }) => {
        const app = join(outputRoot, 'PIUI.app');
        await mkdir(app, { mode: 0o700 });
        await writeFile(join(app, 'payload.txt'), 'same bytes\n', { mode: 0o600 });
        await chmod(app, 0o555);
        return createGuardedProductionResult({
          artifact: productionArtifact(),
          gateRunId: acceptedGate.runId,
          generatedOutputsRemoved: true,
          sourceDigest: acceptedGate.sourceDigest,
        });
      },
    })), /staging bundle lease changed/u);
  });
});

test('preserves primary and cleanup failures and never reports success with staging residue', async (t) => {
  await t.test('primary and cleanup failures are aggregated in order', async (nested) => {
    const repositoryRoot = await fixture(nested);
    const primary = new Error('package primary failure');
    const cleanup = new Error('staging cleanup failure');
    let stagingRoot;
    nested.after(async () => {
      if (stagingRoot) await removeTestTree(stagingRoot);
    });
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      packageExecutor: async ({ outputRoot }) => {
        stagingRoot = outputRoot;
        throw primary;
      },
      stagingCleaner: async () => {
        throw cleanup;
      },
    })), (error) => {
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [primary, cleanup]);
      return true;
    });
  });

  await t.test('a no-op cleaner leaves failed evidence and is not success', async (nested) => {
    const repositoryRoot = await fixture(nested);
    let stagingRoot;
    nested.after(async () => {
      if (stagingRoot) await removeTestTree(stagingRoot);
    });
    await assert.rejects(buildGuardedProduction(repositoryRoot, dependencies({
      packageExecutor: async (context) => {
        stagingRoot = context.outputRoot;
        return executorFor()(context);
      },
      stagingCleaner: async () => {},
    })), /staging root already exists/u);
    const builds = join(repositoryRoot, '.forge', 'artifacts', 'production-builds');
    const entries = await readdir(builds);
    assert.equal(entries.length, 1);
    assert.match(entries[0], /^\.failed-/u);
  });
});

test('temporary staging creation cleans partial state transactionally', async (t) => {
  const failure = new Error('mode hardening failed');
  let created;
  await assert.rejects(createPrivateTemporary('piui-transaction-test-', {
    makeTemporary: async (prefix) => {
      created = await mkdtemp(prefix);
      return created;
    },
    setMode: async () => {
      throw failure;
    },
  }), failure);
  assert.ok(created);
  await assert.rejects(lstat(created), { code: 'ENOENT' });
  t.after(async () => {
    if (created) await removeTestTree(created);
  });
});

test('guarded result parsing rejects tampering and non-canonical control bytes', () => {
  const result = createGuardedProductionResult({
    artifact: productionArtifact(),
    gateRunId: runId,
    generatedOutputsRemoved: true,
    sourceDigest: sha('2'),
  });
  const bytes = Buffer.from(`${canonicalArchitectureJson(result)}\n`, 'utf8');
  assert.deepEqual(parseGuardedProductionResult(bytes, {
    expectedFingerprint: sha('1'),
    expectedRunId: runId,
    expectedSourceDigest: sha('2'),
  }), result);
  assert.throws(() => parseGuardedProductionResult(Buffer.from(JSON.stringify(result)), {
    expectedFingerprint: sha('1'),
  }), /rejected/u);
  assert.throws(() => parseGuardedProductionResult(bytes, {
    expectedFingerprint: sha('9'),
  }), /rejected/u);
});

test('production command and Tauri hook are closed around the frozen authenticated path', async () => {
  const [packageJson, packageSource, hookSource, runnerSource, developmentSource] = await Promise.all([
    readFile(new URL('../../package.json', import.meta.url), 'utf8'),
    readFile(new URL('../../scripts/package-spike.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../../scripts/tauri-build-hook.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../../scripts/build-production.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../../scripts/tauri-development.mjs', import.meta.url), 'utf8'),
  ]);
  assert.equal(
    JSON.parse(packageJson).scripts.tauri,
    'node scripts/tauri-development.mjs',
  );
  assert.equal(
    JSON.parse(packageJson).scripts['tauri:build:production'],
    'node scripts/build-production.mjs',
  );
  assert.match(packageSource, /'--guarded-production-build': 'guarded-production'/u);
  assert.match(
    packageSource,
    /createIsolatedBuildSource\(\s*bootstrapIsolate,\s*bootstrapTools,\s*cutoffs\.signal,\s*\)/u,
  );
  assert.match(packageSource, /await resetGeneratedOutputs\(\);[\s\S]*?stage-sidecar\.mjs/u);
  assert.match(packageSource, /artifact\.fingerprint !== guardedContext\.productionFingerprint/u);
  assert.match(packageSource, /resolve\(guardedContext\.outputRoot, 'PIUI\.app'\)/u);
  assert.match(hookSource, /validateTauriBuildAuthorisation\(sourceRoot\)/u);
  assert.match(hookSource, /snapshotArchitectureSource\(sourceRoot\)/u);
  assert.doesNotMatch(hookSource, /process\.env\.PIUI_PNPM_ENTRY/u);
  assert.match(runnerSource, /validateGateAndSource[\s\S]*?packageExecutor/u);
  assert.match(runnerSource, /Copied production bundle fingerprint changed/u);
  assert.match(runnerSource, /\.incoming-/u);
  assert.match(runnerSource, /writeBuildRecord[\s\S]*?publicationRenamer/u);
  assert.match(developmentSource, /argumentsAfterScript\.length !== 1/u);
  assert.match(developmentSource, /tauri:build:production/u);
  assert.doesNotMatch(developmentSource, /process\.argv\.slice\(2\)[\s\S]*?\.\.\./u);
});

test('the package Tauri wrapper rejects build and configuration override arguments', () => {
  const wrapper = fileURLToPath(new URL('../../scripts/tauri-development.mjs', import.meta.url));
  for (const argumentsAfterScript of [
    ['build'],
    ['build', '--config', '{"build":{"beforeBuildCommand":""}}'],
    ['dev', '--config', 'alternate.json'],
    ['--config', 'alternate.json'],
  ]) {
    const result = spawnSync(process.execPath, [wrapper, ...argumentsAfterScript], {
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
    });
    assert.equal(result.status, 1, argumentsAfterScript.join(' '));
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /guarded production build/u);
    assert.match(result.stderr, /config overrides are unsupported/u);
  }
});
