#!/usr/bin/env node
const RETIRED_ENROLMENT_MESSAGE =
  'A.28 user-owned candidate enrolment is retired; use the installed root launcher with --mode enrol.';

export async function enrolPinnedA28Witness() {
  throw new Error(RETIRED_ENROLMENT_MESSAGE);
}

if (typeof process.argv[1] === 'string'
    && import.meta.url === new URL(process.argv[1], 'file:').href) {
  process.stderr.write(RETIRED_ENROLMENT_MESSAGE + '\n');
  process.exitCode = 1;
}
