/**
 * Positive fixture (intra-procedural).
 *
 * CWE-88 embedded sub-option injection: an externally controlled field is
 * embedded into ONE delimiter-structured option-argument (comma-separated
 * key=value grammar) via a template literal and passed to a non-shell process
 * launcher with a structured argument array. No shell is involved and the
 * OS-level argument count does not change, but the receiving command reparses
 * the value and an attacker-controlled delimiter can create an additional
 * logical option.
 *
 * The construction and the launch are in the same function, so the
 * intra-procedural rule flags it.
 */

'use strict';

const { execFile } = require('child_process');

function handle(target, externalValue) {
  // The untrusted field is embedded into a comma/equals option template
  // without neutralizing the sub-option delimiter.
  const opt = `endpoint=trusted.example,id=${externalValue}`;
  execFile(target, ['-o', opt]);
}

module.exports = { handle };
