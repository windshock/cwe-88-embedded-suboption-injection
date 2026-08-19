/**
 * @name Embedded sub-option injection via a delimiter-structured argument (interprocedural)
 * @description Finds a comma-separated key=value option-argument built from a
 *              non-constant part that reaches a non-shell process launcher
 *              (subprocess/os.exec*) argument list across function boundaries.
 *              Unlike the intra-procedural query, the constructed option-argument
 *              is tracked through helper/launch-wrapper functions, so the common
 *              idiom in which the launch is delegated to a shared wrapper is
 *              still reported. This is the CWE-88 embedded sub-option injection
 *              shape.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id py/cwe88/embedded-suboption-injection-interprocedural
 * @tags security
 *       external/cwe/cwe-088
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

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

predicate launcherListElement(DataFlow::Node n) {
  exists(Call c, List l |
    isProcessLauncher(c) and
    l = c.getAnArg() and
    n.asExpr() = l.getAnElt()
  )
}

module OptionInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { optionTemplate(source) }

  predicate isSink(DataFlow::Node sink) { launcherListElement(sink) }
}

module OptionInjectionFlow = TaintTracking::Global<OptionInjectionConfig>;

import OptionInjectionFlow::PathGraph

from OptionInjectionFlow::PathNode source, OptionInjectionFlow::PathNode sink
where OptionInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A comma-separated option-argument built from a non-constant part reaches a process launcher " +
  "across function boundaries. An attacker-controlled delimiter can be reparsed as an additional " +
  "logical option (CWE-88)."
