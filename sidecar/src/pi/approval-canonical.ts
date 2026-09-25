import { createHash } from 'node:crypto';

// Shared contract C4, mirrored by Rust: canonical JSON of at most 384 KiB,
// 4,096 nodes and depth 16 (the input root is depth 0). Ordinary write and edit
// calls fit; anything larger is too large for a person to review.
const MAX_BYTES = 393_216;
const MAX_DEPTH = 16;
const MAX_NODES = 4_096;
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const REJECTED = 'approval-input-rejected';
const TOO_LARGE = 'approval-input-too-large';

export type CanonicalApprovalInput = Readonly<{
  bytes: Buffer;
  digest: string;
  value: Readonly<Record<string, unknown>>;
}>;

type CanonicalState = {
  nodes: number;
  stringBytes: number;
  ancestors: Set<object>;
};

function reject(): never {
  throw new Error(REJECTED);
}

function tooLarge(): never {
  throw new Error(TOO_LARGE);
}

/** True only for a well-formed input rejected solely for exceeding C4. */
export function isApprovalInputTooLarge(error: unknown): boolean {
  return error instanceof Error && error.message === TOO_LARGE;
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
  if (depth > MAX_DEPTH || state.nodes >= MAX_NODES) tooLarge();
  state.nodes += 1;

  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (!hasValidUnicode(value)) reject();
    // Raw UTF-8 never exceeds its canonical encoding, so this rejects an
    // oversized input before building its full canonical text.
    state.stringBytes += Buffer.byteLength(value, 'utf8');
    if (state.stringBytes > MAX_BYTES) tooLarge();
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0) || Math.abs(value) > MAX_SAFE_INTEGER)
      reject();
    return value;
  }
  if (typeof value !== 'object' || state.ancestors.has(value)) reject();

  // Each element is one more node; refuse before copying a huge descriptor set.
  if (Array.isArray(value) && value.length > MAX_NODES - state.nodes) tooLarge();
  state.ancestors.add(value);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.some((key) => typeof key === 'symbol')) reject();

    if (Array.isArray(value)) {
      const keys = ownKeys.filter((key): key is string => key !== 'length');
      if (
        keys.length !== value.length ||
        keys.some(
          (key, index) => key !== String(index) || !Object.hasOwn(descriptors[key], 'value'),
        )
      )
        reject();
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        output.push(cloneCanonical(descriptors[String(index)].value, depth + 1, state));
      }
      return output;
    }

    if (!isPlainObject(value)) reject();
    const keys = ownKeys as string[];
    if (keys.some((key) => !hasValidUnicode(key) || !Object.hasOwn(descriptors[key], 'value')))
      reject();
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
      case '"':
        output += '\\"';
        break;
      case '\\':
        output += '\\\\';
        break;
      case '\b':
        output += '\\b';
        break;
      case '\f':
        output += '\\f';
        break;
      case '\n':
        output += '\\n';
        break;
      case '\r':
        output += '\\r';
        break;
      case '\t':
        output += '\\t';
        break;
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
    for (const entry of Object.values(value as Record<string, unknown>))
      deepFreezeApprovalValue(entry);
    Object.freeze(value);
  }
  return value;
}

export function canonicaliseApprovalInput(input: unknown): CanonicalApprovalInput {
  if (!isPlainObject(input)) reject();
  const value = cloneCanonical(input, 0, {
    nodes: 0,
    stringBytes: 0,
    ancestors: new Set(),
  }) as Record<string, unknown>;
  const segments: string[] = [];
  emitCanonical(value, segments);
  const bytes = Buffer.from(segments.join(''), 'utf8');
  if (bytes.length > MAX_BYTES) {
    bytes.fill(0);
    tooLarge();
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
