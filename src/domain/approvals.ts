import type { ApprovalRequest } from './types';

function sameApproval(left: ApprovalRequest, right: ApprovalRequest): boolean {
  // Approval views are small, plain and built in one field order, so a serialised
  // comparison is exact without a field list that could drift from the type.
  return JSON.stringify(left) === JSON.stringify(right);
}

// Merges a fresh poll into the visible approvals. An approval keeps the expiry first
// derived for its revision, and one that has not changed keeps its identity, so a poll
// that finds nothing new returns `current` itself and nothing re-renders.
export function reconcileApprovals(
  current: readonly ApprovalRequest[],
  incoming: readonly ApprovalRequest[],
): readonly ApprovalRequest[] {
  const previousById = new Map(current.map((approval) => [approval.id, approval]));
  let changed = incoming.length !== current.length;
  const next = incoming.map((approval, index) => {
    const previous = previousById.get(approval.id);
    const stable =
      previous &&
      previous.decisionId === approval.decisionId &&
      previous.revision === approval.revision &&
      previous.expiresAt !== undefined
        ? { ...approval, expiresAt: previous.expiresAt }
        : approval;
    if (previous && sameApproval(previous, stable)) {
      if (current[index] !== previous) changed = true;
      return previous;
    }
    changed = true;
    return stable;
  });
  return changed ? next : current;
}

// Characters that change how text looks without looking like anything themselves:
// bidirectional overrides and isolates, zero-width marks, and control characters other
// than line breaks and tabs. They could disguise what a command really does, so the
// approval shows each one as a visible code point instead.
const DISGUISING_CHARACTERS =
  /[\u0000-\u0008\u000B-\u001F\u007F-\u009F؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/gu;

export function visibleSubjectText(text: string): string {
  return text.replace(
    DISGUISING_CHARACTERS,
    (character) =>
      `⟨U+${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}⟩`,
  );
}
