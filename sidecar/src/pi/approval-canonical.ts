import { createHash } from 'node:crypto';

const MAX_BYTES = 65_536;
const MAX_DEPTH = 16;
const MAX_NODES = 256;
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const REJECTED = 'approval-input-rejected';

export type CanonicalApprovalInput = Readonly<{
  bytes: Buffer;
  digest: string;
  value: Readonly<Record<string, unknown>>;
}>;

type CanonicalState = {
  nodes: number;
  ancestors: Set<object>;
};

function reject(): never {
  throw new Error(REJECTED);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasValidUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const following = value.charCodeAt(index + 1);
      if (following < 0xdc00 || following > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function utf8KeyCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function cloneCanonical(value: unknown, depth: number, state: CanonicalState): unknown {
  if (depth > MAX_DEPTH || state.nodes >= MAX_NODES) reject();
  state.nodes += 1;

  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (!hasValidUnicode(value)) reject();
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0) || Math.abs(value) > MAX_SAFE_INTEGER) reject();
    return value;
  }
  if (typeof value !== 'object' || state.ancestors.has(value)) reject();

  state.ancestors.add(value);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.some((key) => typeof key === 'symbol')) reject();

    if (Array.isArray(value)) {
      const keys = ownKeys.filter((key): key is string => key !== 'length');
      if (
        keys.length !== value.length
        || keys.some((key, index) => key !== String(index) || !Object.hasOwn(descriptors[key], 'value'))
      ) reject();
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        output.push(cloneCanonical(descriptors[String(index)].value, depth + 1, state));
      }
      return output;
    }

    if (!isPlainObject(value)) reject();
    const keys = ownKeys as string[];
    if (keys.some((key) => !hasValidUnicode(key) || !Object.hasOwn(descriptors[key], 'value'))) reject();
    keys.sort(utf8KeyCompare);
    const output: Record<string, unknown> = Object.create(null);
    for (const key of keys) output[key] = cloneCanonical(descriptors[key].value, depth + 1, state);
    return output;
  } finally {
    state.ancestors.delete(value);
  }
}

function quoted(value: string): string {
  let output = '"';
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    switch (character) {
      case '"': output += '\\"'; break;
      case '\\': output += '\\\\'; break;
      case '\b': output += '\\b'; break;
      case '\f': output += '\\f'; break;
      case '\n': output += '\\n'; break;
      case '\r': output += '\\r'; break;
      case '\t': output += '\\t'; break;
      default:
        output += codePoint <= 0x1f ? `\\u${codePoint.toString(16).padStart(4, '0')}` : character;
    }
  }
  return `${output}"`;
}

function emitCanonical(value: unknown, output: string[]): void {
  if (value === null) {
    output.push('null');
  } else if (typeof value === 'boolean' || typeof value === 'number') {
    output.push(String(value));
  } else if (typeof value === 'string') {
    output.push(quoted(value));
  } else if (Array.isArray(value)) {
    output.push('[');
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) output.push(',');
      emitCanonical(value[index], output);
    }
    output.push(']');
  } else {
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).sort(utf8KeyCompare);
    output.push('{');
    for (let index = 0; index < keys.length; index += 1) {
      if (index > 0) output.push(',');
      const key = keys[index];
      output.push(quoted(key), ':');
      emitCanonical(object[key], output);
    }
    output.push('}');
  }
}

export function deepFreezeApprovalValue<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value as Record<string, unknown>)) deepFreezeApprovalValue(entry);
    Object.freeze(value);
  }
  return value;
}

export function canonicaliseApprovalInput(input: unknown): CanonicalApprovalInput {
  if (!isPlainObject(input)) reject();
  const value = cloneCanonical(input, 0, { nodes: 0, ancestors: new Set() }) as Record<string, unknown>;
  const segments: string[] = [];
  emitCanonical(value, segments);
  const bytes = Buffer.from(segments.join(''), 'utf8');
  if (bytes.length > MAX_BYTES) {
    bytes.fill(0);
    reject();
  }
  return Object.freeze({
    bytes,
    digest: createHash('sha256').update(bytes).digest('hex'),
    value: deepFreezeApprovalValue(value),
  });
}

export const APPROVAL_CANONICAL_LIMITS = Object.freeze({
  maxBytes: MAX_BYTES,
  maxDepth: MAX_DEPTH,
  maxNodes: MAX_NODES,
});
