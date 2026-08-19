/**
 * @name Embedded sub-option injection via a delimiter-structured argument (intra-procedural)
 * @description Finds Python code that embeds a value into a single
 *              comma-separated key=value option-argument and passes it to a
 *              process launcher (subprocess/os.exec*) through an argument list,
 *              within one function. The receiving command can reparse an
 *              attacker-controlled delimiter as an additional logical option
 *              even though an argument list is used and no shell tokenizes the
 *              value. This is the intra-procedural shape of the CWE-88 embedded
 *              sub-option injection submission; it misses the launch-wrapper
 *              idiom, which the interprocedural query covers.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id py/cwe88/embedded-suboption-injection
 * @tags security
 *       external/cwe/cwe-088
 */

import python
import semmle.python.dataflow.new.DataFlow

/** A concatenation `"...,...=..." + X` that builds a comma/equals option template from a non-constant part. */
predicate optionTemplate(DataFlow::Node n) {
  exists(BinaryExpr b, StringLiteral s, Expr other |
    n.asExpr() = b and
    b.getOp() instanceof Add and
    (
      s = b.getLeft() and other = b.getRight()
      or
      s = b.getRight() and other = b.getLeft()
    ) and
    s.getText().matches("%,%") and
    s.getText().matches("%=%") and
    not other instanceof StringLiteral
  )
}

/** A call to a non-shell process launcher that takes an argument list. */
predicate isProcessLauncher(Call c) {
  exists(Attribute a | a = c.getFunc() |
    a.getObject().(Name).getId() = "subprocess" and
    a.getName() in ["run", "Popen", "call", "check_call", "check_output"]
    or
    a.getObject().(Name).getId() = "os" and
    a.getName() in [
        "execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "spawnvp",
        "posix_spawn", "posix_spawnp"
      ]
  )
}

/** An element of an argument list passed to a process launcher. */
predicate launcherListElement(DataFlow::Node n) {
  exists(Call c, List l |
    isProcessLauncher(c) and
    l = c.getAnArg() and
    n.asExpr() = l.getAnElt()
  )
}

from DataFlow::Node src, DataFlow::Node snk
where
  optionTemplate(src) and
  launcherListElement(snk) and
  DataFlow::localFlow(src, snk)
select snk,
  "A value is embedded into one comma-separated option-argument and passed to a process " +
  "launcher. An attacker-controlled delimiter can be reparsed as an additional logical option (CWE-88)."
