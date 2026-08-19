/**
 * Positive fixture (interprocedural).
 *
 * Same CWE-88 embedded sub-option injection shape as vulnerable.js, but the
 * constructed option-argument is handed to a small launch wrapper that many
 * callers would share. The construction and the process launch are in
 * different functions, so only the interprocedural (taint-tracking) rule flags
 * it; the intra-procedural rule misses it.
 */

'use strict';

const { execFile } = require('child_process');

function launch(target, opt) {
  execFile(target, ['-o', opt]);
}

function handle(target, externalValue) {
  const opt = `endpoint=trusted.example,id=${externalValue}`;
  launch(target, opt);
}

module.exports = { handle, launch };
