// Development-only browser proof route. App.tsx loads it only in development builds, so
// the hostile fixture and the test harness hook never reach a production bundle.
import hostileFixture from '../../tests/fixtures/markdown/hostile.md?raw';
import {
  isOpaqueAssetCapability,
  isRasterMime,
  type OpaqueAssetDescriptor,
  type ValidatedExternalTarget,
} from './markdownPolicy';
import { SafeMarkdownSpike } from './SafeMarkdownSpike';

type MarkdownHarnessAsset = Readonly<{
  capability: string;
  url: string;
  mime: unknown;
  byteLength: number;
  expiresAt: number;
}>;

type MarkdownHarness = Readonly<{
  markdown?: string;
  assets?: readonly MarkdownHarnessAsset[];
  complete?: boolean;
  openExternal?: (canonicalUrl: string) => void;
}>;

declare global {
  interface Window {
    __PIUI_MARKDOWN_HARNESS__?: MarkdownHarness;
  }
}

export function SafeMarkdownSpikeRoute() {
  const harness = window.__PIUI_MARKDOWN_HARNESS__;
  const assets = new Map<string, OpaqueAssetDescriptor>();
  for (const candidate of harness?.assets ?? []) {
    if (!isOpaqueAssetCapability(candidate.capability) || !isRasterMime(candidate.mime)) continue;
    assets.set(
      candidate.capability,
      Object.freeze({
        url: candidate.url,
        mime: candidate.mime,
        byteLength: candidate.byteLength,
        expiresAt: candidate.expiresAt,
      }),
    );
  }

  const openExternal = (target: ValidatedExternalTarget) => {
    harness?.openExternal?.(target.canonicalUrl);
  };

  return (
    <SafeMarkdownSpike
      markdown={harness?.markdown ?? hostileFixture}
      assetRegistry={assets}
      openExternal={openExternal}
      complete={harness?.complete ?? true}
    />
  );
}
