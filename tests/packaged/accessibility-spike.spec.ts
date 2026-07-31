import { constants } from 'node:fs';
import {
  lstat,
  open,
  readFile,
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  $,
  $$,
  browser,
} from '@wdio/globals';
import {
  A28_HUMAN_WITNESS_READY_EVENT,
  assertA28HumanWitnessLease,
  type A28HumanWitnessLease,
} from '../../src/architecture-gate/a28WitnessContract';

const TRANSCRIPT_COUNT = 100;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_COORDINATION_BYTES = 1_024;
const HUMAN_WITNESS_TIMEOUT_MS = 30 * 60_000;
const prompts = Object.freeze([
  'Reviewing the project boundary before any local extension is loaded.',
  'Checking the acknowledged session state and the active branch.',
  'Summarising the proposed change without exposing private paths.',
  'Waiting for an explicit tool decision before continuing.',
  'Recording the completed operation and its safe recovery action.',
]);

type Appearance = 'dark' | 'light';
type TranscriptMode = 'accessible' | 'virtualised';
type RowSnapshot = Readonly<{
  body: string;
  id: string;
  ordinal: number;
  position: number;
  role: string | null;
  setSize: number;
  speaker: string;
}>;

type A28DomEvidence = Readonly<{
  accessibleOrderedRowsObserved: number;
  appearances: number;
  ariaPositionErrors: number;
  arrowTransitions: number;
  duplicateRows: number;
  focusRetentionChecks: number;
  focusRetentionFailures: number;
  homeEndTransitions: number;
  loadingIndicatorObserved: boolean;
  missingRows: number;
  modes: number;
  nameErrors: number;
  outOfOrderRows: number;
  pageTransitions: number;
  roleErrors: number;
  schemaVersion: 1;
  stableSelectionCount: number;
  transcriptItems: number;
  virtualOrderedRowsObserved: number;
  webdriverSessions: number;
}>;

function reject(): never {
  throw new Error('A.28 packaged accessibility WDIO proof rejected');
}

function requiredEnvironment(key: string): string {
  const value = process.env[key];
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) reject();
  return value;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) reject();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value !== 'object') reject();
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
}

async function publishExclusive(path: string, value: unknown): Promise<void> {
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(Buffer.from(`${canonicalJson(value)}\n`, 'utf8'));
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readStableRecord(path: string): Promise<Record<string, unknown>> {
  const before = await lstat(path);
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || before.size < 3
    || before.size > MAX_COORDINATION_BYTES
    || (before.mode & 0o777) !== 0o600
    || (typeof process.getuid === 'function' && before.uid !== process.getuid()) reject();
  const bytes = await readFile(path);
  const after = await lstat(path);
  if (before.dev !== after.dev
    || before.ino !== after.ino
    || before.size !== after.size
    || before.mtimeMs !== after.mtimeMs
    || bytes.length !== before.size
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x00)
    || bytes.includes(0x0d)) reject();
  let value: unknown;
  try {
    value = JSON.parse(bytes.subarray(0, -1).toString('utf8'));
  } catch {
    reject();
  }
  if (canonicalJson(value) !== bytes.subarray(0, -1).toString('utf8')
    || value === null
    || typeof value !== 'object'
    || Array.isArray(value)) reject();
  return value as Record<string, unknown>;
}

function assertRelease(record: Record<string, unknown>, nonce: string): void {
  if (Object.keys(record).sort().join(',') !== 'nonce,schemaVersion,state'
    || record.schemaVersion !== 1
    || record.state !== 'ax-complete'
    || record.nonce !== nonce) reject();
}

async function waitForHumanReadyOrRelease({
  humanReadyPath,
  nonce,
  releasePath,
}: {
  humanReadyPath: string;
  nonce: string;
  releasePath: string;
}): Promise<A28HumanWitnessLease | null> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    for (const [kind, path] of [
      ['release', releasePath],
      ['human', humanReadyPath],
    ] as const) {
      try {
        const record = await readStableRecord(path);
        if (kind === 'release') {
          assertRelease(record, nonce);
          return null;
        }
        return assertA28HumanWitnessLease(record);
      } catch (error) {
        const code = error instanceof Error && 'code' in error
          ? (error as NodeJS.ErrnoException).code
          : undefined;
        if (code !== 'ENOENT') throw error;
      }
    }
    await sleep(25);
  }
  reject();
}

async function readStableRelease(path: string, nonce: string): Promise<void> {
  const deadline = Date.now() + HUMAN_WITNESS_TIMEOUT_MS + 60_000;
  while (Date.now() < deadline) {
    try {
      assertRelease(await readStableRecord(path), nonce);
      return;
    } catch (error) {
      const code = error instanceof Error && 'code' in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
      if (code !== 'ENOENT') throw error;
    }
    await sleep(25);
  }
  reject();
}

function expectedRow(ordinal: number): Readonly<{ body: string; speaker: string }> {
  if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > TRANSCRIPT_COUNT) reject();
  const index = ordinal - 1;
  const body = prompts[index % prompts.length];
  if (typeof body !== 'string') reject();
  return Object.freeze({
    body,
    speaker: index % 3 === 0 ? 'You' : 'Assistant',
  });
}

function analyseRows(rows: readonly RowSnapshot[]): Readonly<{
  ariaPositionErrors: number;
  duplicateRows: number;
  missingRows: number;
  nameErrors: number;
  outOfOrderRows: number;
  roleErrors: number;
}> {
  const ordinals = rows.map((row) => row.ordinal);
  const unique = new Set(ordinals);
  let ariaPositionErrors = 0;
  let nameErrors = 0;
  let roleErrors = 0;
  for (const [index, row] of rows.entries()) {
    const expectedOrdinal = index + 1;
    const expected = expectedRow(row.ordinal);
    if (row.id !== `a28-transcript-row-${row.ordinal}`
      || row.position !== row.ordinal
      || row.setSize !== TRANSCRIPT_COUNT) ariaPositionErrors += 1;
    if (row.speaker !== expected.speaker || row.body !== expected.body) nameErrors += 1;
    if (row.role !== 'listitem') roleErrors += 1;
    if (row.ordinal !== expectedOrdinal) continue;
  }
  return Object.freeze({
    ariaPositionErrors,
    duplicateRows: rows.length - unique.size,
    missingRows: TRANSCRIPT_COUNT - unique.size,
    nameErrors,
    outOfOrderRows: ordinals.filter((ordinal, index) => ordinal !== index + 1).length,
    roleErrors,
  });
}

describe('A.28 packaged automation and accessibility feasibility', () => {
  it('proves deterministic virtual and accessible transcript operation', async () => {
    const runRoot = requiredEnvironment('PIUI_A28_RUN_ROOT');
    const nonce = requiredEnvironment('PIUI_ARCHITECTURE_TEST_NONCE');
    const domEvidencePath = requiredEnvironment('PIUI_A28_DOM_EVIDENCE');
    const axReadyPath = requiredEnvironment('PIUI_A28_AX_READY');
    const axReleasePath = requiredEnvironment('PIUI_A28_AX_RELEASE');
    const humanReadyPath = requiredEnvironment('PIUI_A28_HUMAN_READY');
    const humanVisiblePath = requiredEnvironment('PIUI_A28_HUMAN_VISIBLE');
    if (!SHA256.test(nonce)
      || resolve(runRoot) !== runRoot
      || [
        domEvidencePath,
        axReadyPath,
        axReleasePath,
        humanReadyPath,
        humanVisiblePath,
      ].some((path) =>
        resolve(path) !== path || dirname(path) !== runRoot)
      || typeof browser.sessionId !== 'string'
      || browser.sessionId.length === 0) reject();

    let stableSelectionCount = 0;
    let arrowTransitions = 0;
    let homeEndTransitions = 0;
    let pageTransitions = 0;
    let focusRetentionChecks = 0;
    let focusRetentionFailures = 0;
    const appearances = new Set<Appearance>();
    const modes = new Set<TranscriptMode>();

    const select = async (selector: string) => {
      stableSelectionCount += 1;
      const element = await $(selector);
      await element.waitForExist();
      return element;
    };

    const buttonNamed = async (name: string) => {
      stableSelectionCount += 1;
      const candidates = await $$('.a28-probe__toolbar button');
      for (const candidate of candidates) {
        if (await candidate.getText() === name) return candidate;
      }
      reject();
    };

    const focusedOrdinal = async (): Promise<number> => browser.execute(() => {
      const focused = document.activeElement;
      if (!(focused instanceof HTMLElement)) return 0;
      return Number(focused.dataset.a28Row ?? 0);
    });

    const logicalOrdinal = async (): Promise<number> => browser.execute(() => {
      const logical = document.querySelector<HTMLElement>('[data-a28-row][tabindex="0"]');
      return Number(logical?.dataset.a28Row ?? 0);
    });

    const waitForFocusedOrdinal = async (ordinal: number): Promise<void> => {
      await browser.waitUntil(async () => await focusedOrdinal() === ordinal, {
        interval: 20,
        timeout: 3_000,
        timeoutMsg: 'A.28 row focus did not settle',
      });
    };

    const waitForLogicalOrdinal = async (ordinal: number): Promise<void> => {
      await browser.waitUntil(async () => await logicalOrdinal() === ordinal, {
        interval: 20,
        timeout: 3_000,
        timeoutMsg: 'A.28 logical row focus did not settle',
      });
    };

    const focusRow = async (ordinal: number): Promise<void> => {
      const row = await select(`#a28-transcript-row-${ordinal}`);
      await row.scrollIntoView({ block: 'center', inline: 'nearest' });
      await row.click();
      await waitForFocusedOrdinal(ordinal);
    };

    const press = async (
      key: 'ArrowDown' | 'ArrowUp' | 'End' | 'Home' | 'PageDown' | 'PageUp',
      expectedOrdinal: number,
    ): Promise<void> => {
      await browser.keys(key);
      if (key.startsWith('Arrow')) arrowTransitions += 1;
      else if (key === 'End' || key === 'Home') homeEndTransitions += 1;
      else pageTransitions += 1;
      await waitForFocusedOrdinal(expectedOrdinal);
    };

    const currentRowSnapshot = async (): Promise<RowSnapshot> => browser.execute(() => {
      const row = document.activeElement;
      if (!(row instanceof HTMLElement) || !row.matches('[data-a28-row]')) {
        throw new Error('a28-focused-row-missing');
      }
      const content = row.querySelector('.a28-transcript__content');
      const speaker = content?.querySelector('.a28-transcript__speaker');
      const body = speaker?.nextElementSibling;
      return {
        body: body?.textContent?.trim() ?? '',
        id: row.id,
        ordinal: Number(row.dataset.a28Row ?? 0),
        position: Number(row.getAttribute('aria-posinset') ?? 0),
        role: row.getAttribute('role'),
        setSize: Number(row.getAttribute('aria-setsize') ?? 0),
        speaker: speaker?.textContent?.trim() ?? '',
      };
    });

    const allRenderedRows = async (): Promise<readonly RowSnapshot[]> => browser.execute(() =>
      Array.from(document.querySelectorAll<HTMLElement>('[data-a28-row]')).map((row) => {
        const content = row.querySelector('.a28-transcript__content');
        const speaker = content?.querySelector('.a28-transcript__speaker');
        const body = speaker?.nextElementSibling;
        return {
          body: body?.textContent?.trim() ?? '',
          id: row.id,
          ordinal: Number(row.dataset.a28Row ?? 0),
          position: Number(row.getAttribute('aria-posinset') ?? 0),
          role: row.getAttribute('role'),
          setSize: Number(row.getAttribute('aria-setsize') ?? 0),
          speaker: speaker?.textContent?.trim() ?? '',
        };
      }));

    const assertListContract = async (mode: TranscriptMode): Promise<void> => {
      const list = await select('[role="list"][aria-label="Architecture accessibility transcript"]');
      if (await list.getAttribute('role') !== 'list'
        || await list.getAttribute('aria-label') !== 'Architecture accessibility transcript') reject();
      const marker = await select('[data-a28-virtualised]');
      const virtualised = await marker.getAttribute('data-a28-virtualised');
      if (virtualised !== String(mode === 'virtualised')) reject();
      modes.add(mode);
    };

    const recordFocusRetention = async (action: () => Promise<void>): Promise<void> => {
      await action();
      focusRetentionChecks += 1;
      try {
        await waitForLogicalOrdinal(51);
      } catch {
        focusRetentionFailures += 1;
        reject();
      }
    };

    const root = await select('main.a28-probe[data-a28-mode="virtualised"]');
    appearances.add('dark');
    modes.add('virtualised');
    const prepare = await select('.a28-probe__start button');
    if (await prepare.getText() !== 'Prepare accessibility fixture') reject();
    await prepare.click();

    const loading = await select('.a28-probe__loading[role="status"]');
    const loadingText = await loading.getText();
    const loadingIndicatorObserved = await root.getAttribute('aria-busy') === 'true'
      && loadingText === 'Preparing the accessibility transcript…'
      && await (await select('.a28-probe__spinner[aria-hidden="true"]')).isDisplayed();
    if (!loadingIndicatorObserved) reject();

    await browser.waitUntil(async () =>
      await root.getAttribute('aria-busy') === 'false'
      && await (await $('.a28-probe__workspace')).isExisting(), {
      interval: 25,
      timeout: 5_000,
      timeoutMsg: 'A.28 fixture preparation did not complete',
    });

    await assertListContract('virtualised');
    await focusRow(1);
    await press('Home', 1);
    const virtualRows: RowSnapshot[] = [];
    for (let ordinal = 1; ordinal <= TRANSCRIPT_COUNT; ordinal += 1) {
      const snapshot = await currentRowSnapshot();
      if (snapshot.ordinal !== ordinal) reject();
      virtualRows.push(snapshot);
      if (ordinal < TRANSCRIPT_COUNT) await press('ArrowDown', ordinal + 1);
    }
    await press('End', 100);
    await press('Home', 1);
    await press('PageDown', 11);
    await press('PageUp', 1);
    for (const ordinal of [11, 21, 31, 41, 51]) await press('PageDown', ordinal);
    await press('ArrowUp', 50);
    await press('ArrowDown', 51);

    const virtualAnalysis = analyseRows(virtualRows);
    if (Object.values(virtualAnalysis).some((value) => value !== 0)) reject();

    await recordFocusRetention(async () => {
      const accessible = await buttonNamed('Accessible transcript');
      await accessible.click();
    });
    await assertListContract('accessible');
    const accessibleRows = await allRenderedRows();
    const accessibleAnalysis = analyseRows(accessibleRows);
    if (accessibleRows.length !== TRANSCRIPT_COUNT
      || Object.values(accessibleAnalysis).some((value) => value !== 0)) reject();

    await recordFocusRetention(async () => {
      const light = await buttonNamed('Light');
      await light.click();
      appearances.add('light');
    });
    if (await root.getAttribute('data-a28-appearance') !== 'light') reject();

    await recordFocusRetention(async () => {
      const virtualised = await buttonNamed('Virtualised transcript');
      await virtualised.click();
    });
    await assertListContract('virtualised');

    await recordFocusRetention(async () => {
      const dark = await buttonNamed('Dark');
      await dark.click();
      appearances.add('dark');
    });
    if (await root.getAttribute('data-a28-appearance') !== 'dark') reject();
    await focusRow(51);

    const combined = {
      ariaPositionErrors:
        virtualAnalysis.ariaPositionErrors + accessibleAnalysis.ariaPositionErrors,
      duplicateRows: virtualAnalysis.duplicateRows + accessibleAnalysis.duplicateRows,
      missingRows: virtualAnalysis.missingRows + accessibleAnalysis.missingRows,
      nameErrors: virtualAnalysis.nameErrors + accessibleAnalysis.nameErrors,
      outOfOrderRows: virtualAnalysis.outOfOrderRows + accessibleAnalysis.outOfOrderRows,
      roleErrors: virtualAnalysis.roleErrors + accessibleAnalysis.roleErrors,
    };
    const domEvidence: A28DomEvidence = Object.freeze({
      accessibleOrderedRowsObserved: accessibleRows.length,
      appearances: appearances.size,
      ariaPositionErrors: combined.ariaPositionErrors,
      arrowTransitions,
      duplicateRows: combined.duplicateRows,
      focusRetentionChecks,
      focusRetentionFailures,
      homeEndTransitions,
      loadingIndicatorObserved,
      missingRows: combined.missingRows,
      modes: modes.size,
      nameErrors: combined.nameErrors,
      outOfOrderRows: combined.outOfOrderRows,
      pageTransitions,
      roleErrors: combined.roleErrors,
      schemaVersion: 1,
      stableSelectionCount,
      transcriptItems: TRANSCRIPT_COUNT,
      virtualOrderedRowsObserved: virtualRows.length,
      webdriverSessions: 1,
    });
    await publishExclusive(domEvidencePath, domEvidence);
    await publishExclusive(axReadyPath, {
      nonce,
      schemaVersion: 1,
      state: 'ax-ready',
    });
    const witness = await waitForHumanReadyOrRelease({
      humanReadyPath,
      nonce,
      releasePath: axReleasePath,
    });
    if (witness) {
      const dispatched = await browser.execute(
        (eventName, lease) => window.dispatchEvent(
          new CustomEvent(eventName, { detail: lease }),
        ),
        A28_HUMAN_WITNESS_READY_EVENT,
        witness,
      );
      if (dispatched !== true) reject();
      const notice = await $('[data-a28-human-witness]');
      await notice.waitForDisplayed({ timeout: 5_000 });
      const progress = await notice.$(
        'progress[aria-label="Waiting for human VoiceOver evidence"]',
      );
      const noticeText = await notice.getText();
      const controls = await $$('.a28-probe__toolbar button');
      if (await notice.getAttribute('aria-busy') !== 'true'
        || await notice.getAttribute('data-a28-witness-pid')
          !== String(witness.applicationPid)
        || await notice.getAttribute('data-a28-witness-nonce')
          !== witness.witnessNonce
        || !(await progress.isDisplayed())
        || await root.getAttribute('aria-busy') !== 'false'
        || controls.length !== 4
        || (await Promise.all(controls.map((control) => control.isEnabled())))
          .some((enabled) => !enabled)
        || ![
          witness.evidenceDirectory,
          witness.sourceDigest,
          witness.productionFingerprint,
          witness.automationTwinFingerprint,
          witness.witnessNonce,
          String(witness.applicationPid),
        ].every((value) => noticeText.includes(value))) reject();
      await publishExclusive(humanVisiblePath, {
        schemaVersion: 1,
        state: 'human-visible',
        witnessNonce: witness.witnessNonce,
      });
      await readStableRelease(axReleasePath, nonce);
    }
  });
});
