import { SafeMarkdownSpike } from '../../security/SafeMarkdownSpike';
import type { OpaqueAssetDescriptor, ValidatedExternalTarget } from '../../security/markdownPolicy';

const emptyAssets = new Map<string, OpaqueAssetDescriptor>();

function isLongPlainProse(markdown: string): boolean {
  return (
    markdown.length > 2_048 &&
    !/[*_~`#\[\]<>|\\]/u.test(markdown) &&
    !/^(?: {0,3}(?:[-+>] |\d+[.)] ))/mu.test(markdown)
  );
}

export function SafeMarkdown({
  markdown,
  complete = true,
}: Readonly<{ markdown: string; complete?: boolean }>) {
  if (isLongPlainProse(markdown)) {
    return (
      <section className="markdown-embedded" aria-label="Message content">
        <article className="markdown__prose markdown__plain-prose">
          <p>{markdown}</p>
        </article>
      </section>
    );
  }
  const openExternal = (target: ValidatedExternalTarget) => {
    window.dispatchEvent(new CustomEvent('piui:open-external', { detail: target.canonicalUrl }));
  };
  return (
    <SafeMarkdownSpike
      markdown={markdown}
      assetRegistry={emptyAssets}
      openExternal={openExternal}
      complete={complete}
      embedded
    />
  );
}
