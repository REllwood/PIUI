import type { ProductSnapshot } from '../domain/types';

export type BridgeProductSnapshot = Readonly<{
  generation: number;
  sequence: number;
  product: ProductSnapshot;
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function isBridgeProductSnapshot(value: unknown): value is BridgeProductSnapshot {
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value.generation) ||
    !Number.isSafeInteger(value.sequence)
  ) {
    return false;
  }
  if (!isRecord(value.product)) return false;
  const product = value.product;
  return (
    product.generation === value.generation &&
    product.sequence === value.sequence &&
    Array.isArray(product.providers) &&
    Array.isArray(product.sessions) &&
    Array.isArray(product.messages) &&
    Array.isArray(product.activity) &&
    Array.isArray(product.approvals) &&
    Array.isArray(product.changes) &&
    Array.isArray(product.diagnostics) &&
    Array.isArray(product.resources)
  );
}

export function validateBridgeProductSnapshot(value: unknown): BridgeProductSnapshot {
  if (!isBridgeProductSnapshot(value)) throw new Error('bridge-snapshot-invalid');
  return Object.freeze(value);
}
