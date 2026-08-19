/**
 * Negative fixture.
 *
 * The untrusted field is represented as its own independent argument with no
 * embedded delimiter grammar, so it cannot be reinterpreted as a sibling
 * option. There is no comma/equals option template built from external data,
 * so neither the intra-procedural nor the interprocedural rule should flag it.
 */

'use strict';

const { execFile } = require('child_process');

function handle(target, externalValue) {
  // Each logical field is passed as a separate argument. The receiving command
  // never reparses a delimiter-structured value built from untrusted input.
  execFile(target, ['--endpoint', 'trusted.example', '--id', externalValue]);
}

module.exports = { handle };
