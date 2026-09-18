import type { NativeEnvironmentFact } from '../../platform/native';

export function AboutPanel({ facts }: Readonly<{ facts: readonly NativeEnvironmentFact[] }>) {
  const versions = Object.fromEntries(facts.map((fact) => [fact.key, fact.value]));
  return (
    <section className="about-panel" aria-labelledby="about-piui-title">
      <div>
        <p className="ui-label">About</p>
        <h3 id="about-piui-title">PIUI {versions.piuiVersion ?? '0.1.0'}</h3>
        <p>A private local desktop interface for the pinned public Pi SDK.</p>
      </div>
      <dl>
        <div>
          <dt>Pi SDK</dt>
          <dd>{versions.piVersion ?? '0.82.0'}</dd>
        </div>
        <div>
          <dt>Bundled Node.js</dt>
          <dd>{versions.nodeVersion ?? '22.23.1'}</dd>
        </div>
        <div>
          <dt>Native host</dt>
          <dd>{versions.architecture ?? 'arm64'} macOS</dd>
        </div>
      </dl>
      <p className="about-panel__notice">
        A deterministic CycloneDX SBOM and third-party notices are bundled inside every local app
        build. Public signing, notarisation and updating remain separate release gates.
      </p>
    </section>
  );
}
