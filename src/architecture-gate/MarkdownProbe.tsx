import { invoke } from '@tauri-apps/api/core';
import { useEffect, useMemo, useState } from 'react';
import { SafeMarkdownSpike } from '../security/SafeMarkdownSpike';
import {
  isOpaqueAssetCapability,
  isRasterMime,
  validateOpaqueAssetDescriptor,
  type OpaqueAssetDescriptor,
} from '../security/markdownPolicy';
import {
  A26_MARKDOWN_TEST_ACTIVE,
  installA26MarkdownPrelude,
} from './a26MarkdownPrelude';

type Preparation = Readonly<{
  schemaVersion: 1;
  testMode: true;
  engine: 'javascript-regex';
  wasmModules: 0;
  ownerWebviewLabel: 'main';
  hostileFixtureSha256: string;
  rasterFixtureSha256: string;
  asset: Readonly<{
    capability: string;
    url: string;
    mime: 'image/png' | 'image/jpeg' | 'image/webp';
    byteLength: number;
    expiresAt: number;
  }>;
}>;

type ProbeState =
  | Readonly<{ phase: 'loading' }>
  | Readonly<{ phase: 'verifying'; markdown: string; preparation: Preparation }>
  | Readonly<{ phase: 'ready'; markdown: string; preparation: Preparation }>
  | Readonly<{ phase: 'failed' }>;

const SHA256 = /^[0-9a-f]{64}$/;
const PREPARATION_KEYS = [
  'schemaVersion',
  'testMode',
  'engine',
  'wasmModules',
  'ownerWebviewLabel',
  'hostileFixtureSha256',
  'rasterFixtureSha256',
  'asset',
] as const;
const ASSET_KEYS = ['capability', 'url', 'mime', 'byteLength', 'expiresAt'] as const;
let fixedPreparation: Promise<Readonly<{ markdown: string; preparation: Preparation }>> | null = null;

function hasExactKeys(value: object, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

export function parseA26Preparation(value: unknown, now = Date.now()): Preparation | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !hasExactKeys(value, PREPARATION_KEYS)) return null;
  const candidate = value as Record<string, unknown>;
  const asset = candidate.asset;
  if (!asset || typeof asset !== 'object' || Array.isArray(asset)
    || !hasExactKeys(asset, ASSET_KEYS)) return null;
  const raster = asset as Record<string, unknown>;
  if (candidate.schemaVersion !== 1
    || candidate.testMode !== true
    || candidate.engine !== 'javascript-regex'
    || candidate.wasmModules !== 0
    || candidate.ownerWebviewLabel !== 'main'
    || typeof candidate.hostileFixtureSha256 !== 'string'
    || !SHA256.test(candidate.hostileFixtureSha256)
    || typeof candidate.rasterFixtureSha256 !== 'string'
    || !SHA256.test(candidate.rasterFixtureSha256)
    || typeof raster.capability !== 'string'
    || !isOpaqueAssetCapability(raster.capability)
    || typeof raster.url !== 'string'
    || !isRasterMime(raster.mime)
    || typeof raster.byteLength !== 'number'
    || typeof raster.expiresAt !== 'number') return null;

  const descriptor: OpaqueAssetDescriptor = {
    url: raster.url,
    mime: raster.mime,
    byteLength: raster.byteLength,
    expiresAt: raster.expiresAt,
  };
  if (!validateOpaqueAssetDescriptor(
    raster.capability,
    descriptor,
    now,
    'tauri://localhost',
  )) return null;

  return Object.freeze({
    schemaVersion: 1,
    testMode: true,
    engine: 'javascript-regex',
    wasmModules: 0,
    ownerWebviewLabel: 'main',
    hostileFixtureSha256: candidate.hostileFixtureSha256,
    rasterFixtureSha256: candidate.rasterFixtureSha256,
    asset: Object.freeze({ capability: raster.capability, ...descriptor }),
  });
}

function loadFixedPreparation(): Promise<Readonly<{ markdown: string; preparation: Preparation }>> {
  if (!fixedPreparation) {
    fixedPreparation = Promise.all([
      import('../../tests/fixtures/markdown/hostile.md?raw'),
      invoke<unknown>('a26_markdown_prepare'),
    ]).then(([fixture, response]) => {
      const preparation = parseA26Preparation(response);
      if (!preparation || typeof fixture.default !== 'string') {
        throw new Error('A.26 Markdown preparation rejected');
      }
      return Object.freeze({ markdown: fixture.default, preparation });
    }).catch((error: unknown) => {
      fixedPreparation = null;
      throw error;
    });
  }
  return fixedPreparation;
}

function ProbeProgress({ label, busy }: { label: string; busy: boolean }) {
  useEffect(() => {
    if (busy && A26_MARKDOWN_TEST_ACTIVE) {
      installA26MarkdownPrelude().recordLoadingIndicator();
    }
  }, [busy]);
  return (
    <p
      className="markdown-probe__progress"
      role="status"
      aria-live="polite"
      aria-busy={busy}
    >
      {busy ? <span className="markdown-probe__spinner" aria-hidden="true" /> : null}
      <span>{label}</span>
    </p>
  );
}

function LoadingProbe({ failed = false }: { failed?: boolean }) {
  return (
    <main className="markdown-spike markdown-probe" aria-labelledby="markdown-probe-title">
      <section className="markdown-spike__surface markdown-probe__loading-card">
        <p className="markdown-spike__eyebrow">Packaged containment proof</p>
        <h1 id="markdown-probe-title">Safe Markdown architecture test</h1>
        <ProbeProgress
          busy={!failed}
          label={failed ? 'The packaged Markdown test could not be prepared.' : 'Preparing the fixed hostile fixture…'}
        />
      </section>
    </main>
  );
}

export function MarkdownProbe() {
  const [state, setState] = useState<ProbeState>({ phase: 'loading' });

  useEffect(() => {
    let active = true;
    if (!A26_MARKDOWN_TEST_ACTIVE) {
      setState({ phase: 'failed' });
      return () => { active = false; };
    }

    void loadFixedPreparation().then(({ markdown: fixture, preparation }) => {
      if (!active) return;
      installA26MarkdownPrelude().begin(preparation.asset.url);
      const markdown = [
        fixture,
        '## Native one-shot raster positive control',
        `![Registered local raster](${preparation.asset.capability})`,
      ].join('\n\n');
      setState({ phase: 'verifying', markdown, preparation });
    }).catch(() => {
      if (active) setState({ phase: 'failed' });
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (state.phase !== 'verifying') return undefined;
    let active = true;
    const markReadyWhenComplete = () => {
      const image = document.querySelector<HTMLImageElement>('.markdown__asset-image');
      const highlighted = document.querySelector('[data-highlight-status="tokens"]');
      if (!image?.complete || image.naturalWidth < 1 || !highlighted) return;
      active = false;
      window.clearTimeout(deadline);
      window.clearInterval(poll);
      observer.disconnect();
      setState({ ...state, phase: 'ready' });
    };
    const deadline = window.setTimeout(() => {
      if (active) {
        active = false;
        window.clearInterval(poll);
        observer.disconnect();
        setState({ phase: 'failed' });
      }
    }, 20_000);
    const observer = new MutationObserver(markReadyWhenComplete);
    observer.observe(document.documentElement, { attributes: true, childList: true, subtree: true });
    const poll = window.setInterval(markReadyWhenComplete, 50);
    markReadyWhenComplete();
    return () => {
      active = false;
      window.clearTimeout(deadline);
      window.clearInterval(poll);
      observer.disconnect();
    };
  }, [state]);

  const assets = useMemo(() => {
    if (state.phase === 'loading' || state.phase === 'failed') {
      return new Map<string, OpaqueAssetDescriptor>();
    }
    return new Map([[state.preparation.asset.capability, state.preparation.asset]]);
  }, [state]);

  if (state.phase === 'loading') return <LoadingProbe />;
  if (state.phase === 'failed') return <LoadingProbe failed />;

  return (
    <div
      className="markdown-probe"
      data-a26-probe-state={state.phase}
      data-a26-engine={state.preparation.engine}
      data-a26-wasm-modules={state.preparation.wasmModules}
      data-a26-hostile-fixture-sha256={state.preparation.hostileFixtureSha256}
      data-a26-raster-fixture-sha256={state.preparation.rasterFixtureSha256}
      aria-busy={state.phase !== 'ready'}
    >
      <ProbeProgress
        busy={state.phase !== 'ready'}
        label={state.phase === 'ready'
          ? 'Packaged Markdown is ready for independent inspection.'
          : 'Rendering and checking the raster and syntax highlighter…'}
      />
      <SafeMarkdownSpike
        markdown={state.markdown}
        assetRegistry={assets}
        applicationOrigin="tauri://localhost"
        openExternal={() => installA26MarkdownPrelude().recordDisclosedExternalOpen()}
      />
    </div>
  );
}
