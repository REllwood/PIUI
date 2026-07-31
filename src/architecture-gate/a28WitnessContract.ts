export const A28_HUMAN_WITNESS_READY_EVENT =
  'piui:a28-human-witness-ready';

const SHA256 = /^[0-9a-f]{64}$/u;
const MACOS_VERSION = /^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?$/u;
const LEASE_KEYS = Object.freeze([
  'applicationPid',
  'automationTwinFingerprint',
  'evidenceDirectory',
  'macosVersion',
  'productionFingerprint',
  'schemaVersion',
  'sourceDigest',
  'startedAt',
  'state',
  'witnessNonce',
]);

export type A28HumanWitnessLease = Readonly<{
  applicationPid: number;
  automationTwinFingerprint: string;
  evidenceDirectory: string;
  macosVersion: string;
  productionFingerprint: string;
  schemaVersion: 1;
  sourceDigest: string;
  startedAt: string;
  state: 'waiting-for-human';
  witnessNonce: string;
}>;

export function assertA28HumanWitnessLease(
  value: unknown,
): A28HumanWitnessLease {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('a28-human-witness-lease-rejected');
  }
  const lease = value as Record<string, unknown>;
  if (
    JSON.stringify(Object.keys(lease).sort())
      !== JSON.stringify([...LEASE_KEYS].sort())
    || lease.schemaVersion !== 1
    || lease.state !== 'waiting-for-human'
    || !Number.isSafeInteger(lease.applicationPid)
    || Number(lease.applicationPid) < 2
    || typeof lease.automationTwinFingerprint !== 'string'
    || !SHA256.test(lease.automationTwinFingerprint)
    || typeof lease.productionFingerprint !== 'string'
    || !SHA256.test(lease.productionFingerprint)
    || typeof lease.sourceDigest !== 'string'
    || !SHA256.test(lease.sourceDigest)
    || typeof lease.witnessNonce !== 'string'
    || !SHA256.test(lease.witnessNonce)
    || lease.evidenceDirectory
      !== `.forge/evidence/architecture-accessibility/${lease.witnessNonce}`
    || typeof lease.macosVersion !== 'string'
    || !MACOS_VERSION.test(lease.macosVersion)
    || typeof lease.startedAt !== 'string'
    || Number.isNaN(Date.parse(lease.startedAt))
  ) {
    throw new Error('a28-human-witness-lease-rejected');
  }
  return Object.freeze({
    applicationPid: Number(lease.applicationPid),
    automationTwinFingerprint: lease.automationTwinFingerprint,
    evidenceDirectory: lease.evidenceDirectory,
    macosVersion: lease.macosVersion,
    productionFingerprint: lease.productionFingerprint,
    schemaVersion: 1,
    sourceDigest: lease.sourceDigest,
    startedAt: lease.startedAt,
    state: 'waiting-for-human',
    witnessNonce: lease.witnessNonce,
  });
}
