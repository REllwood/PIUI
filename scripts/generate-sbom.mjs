import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { assertReviewedLicences, collectReleaseDependencies } from './release-dependencies.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'src-tauri/resources/piui.cdx.json');
const components = collectReleaseDependencies();
assertReviewedLicences(components);
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    component: {
      type: 'application',
      name: 'PIUI',
      version: '0.1.0',
    },
  },
  components: components.map((component) => ({
    type: 'library',
    name: component.name,
    version: component.version,
    licenses: [{ license: { expression: component.license } }],
    purl: `pkg:${component.ecosystem}/${encodeURIComponent(component.name)}@${component.version}`,
    ...(component.homepage
      ? { externalReferences: [{ type: 'website', url: component.homepage }] }
      : {}),
  })),
};
await mkdir(resolve(root, 'src-tauri/resources'), { recursive: true });
await writeFile(output, `${JSON.stringify(sbom, null, 2)}\n`, 'utf8');
process.stdout.write(`Generated CycloneDX SBOM for ${components.length} release components.\n`);
