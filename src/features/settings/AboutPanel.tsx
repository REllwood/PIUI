import type { NativeEnvironmentFact } from '../../platform/native';

// Versions come only from the native environment report. A missing fact reads as
// unknown rather than a remembered release number that may no longer be true.
export function AboutPanel({ facts }: Readonly<{ facts: readonly NativeEnvironmentFact[] }>) {
  const versions = new Map(facts.map((fact) => [fact.key, fact.value]));
  const known = (key: string) => versions.get(key) ?? 'Unknown';
  const architecture = versions.get('architecture');
  return (
    <section className="about-panel" aria-labelledby="about-piui-title">
      <div>
        <p className="ui-label">About</p>
        <h3 id="about-piui-title">PIUI</h3>
        <p>A private local desktop interface for the pinned public Pi SDK.</p>
      </div>
      <dl>
        <div>
          <dt>Version</dt>
          <dd>{known('piuiVersion')}</dd>
        </div>
        <div>
          <dt>Pi SDK</dt>
          <dd>{known('piVersion')}</dd>
        </div>
        <div>
          <dt>Bundled Node.js</dt>
          <dd>{known('nodeVersion')}</dd>
        </div>
        <div>
          <dt>Native host</dt>
          <dd>{architecture ? `${architecture} macOS` : 'Unknown'}</dd>
        </div>
      </dl>
      <p className="about-panel__notice">
        A deterministic CycloneDX SBOM and third-party notices are bundled inside every local app
        build. Public signing, notarisation and updating remain separate release gates.
      </p>
    </section>
  );
}
