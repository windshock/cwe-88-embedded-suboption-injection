/**
 * @name Embedded sub-option injection via a delimiter-structured argument (interprocedural)
 * @description Finds a comma-separated key=value option-argument built from a
 *              non-constant part that reaches a non-shell process launcher
 *              (ProcessBuilder/Runtime.exec) argument across method boundaries.
 *              Unlike the intra-procedural query, the constructed option-argument
 *              is tracked through helper/launch-wrapper methods, so the common
 *              idiom in which the launch is delegated to a shared wrapper is
 *              still reported. This is the CWE-88 embedded sub-option injection
 *              shape.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/cwe88/embedded-suboption-injection-interprocedural
 * @tags security
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

predicate optionTemplate(DataFlow::Node n) {
  exists(AddExpr a, StringLiteral s, Expr other |
    n.asExpr() = a and
    (
      s = a.getLeftOperand() and other = a.getRightOperand()
      or
      s = a.getRightOperand() and other = a.getLeftOperand()
    ) and
    s.getValue().matches("%,%") and
    s.getValue().matches("%=%") and
    not other instanceof StringLiteral
  )
}

predicate launcherArgument(DataFlow::Node n) {
  exists(ClassInstanceExpr cie |
    cie.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder") and
    n.asExpr() = cie.getAnArgument()
  )
  or
  exists(MethodCall ma |
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    ma.getMethod().hasName("exec") and
    n.asExpr() = ma.getAnArgument()
  )
}

module OptionInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { optionTemplate(source) }

  predicate isSink(DataFlow::Node sink) { launcherArgument(sink) }
}

module OptionInjectionFlow = TaintTracking::Global<OptionInjectionConfig>;

import OptionInjectionFlow::PathGraph

from OptionInjectionFlow::PathNode source, OptionInjectionFlow::PathNode sink
where OptionInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A comma-separated option-argument built from a non-constant part reaches a process launcher " +
    "across method boundaries. An attacker-controlled delimiter can be reparsed as an additional " +
    "logical option (CWE-88)."
