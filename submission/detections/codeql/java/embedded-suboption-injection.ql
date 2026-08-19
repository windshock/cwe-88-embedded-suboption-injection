/**
 * @name Embedded sub-option injection via a delimiter-structured argument (intra-procedural)
 * @description Finds Java code that embeds a value into a single
 *              comma-separated key=value option-argument and passes it to a
 *              process launcher (ProcessBuilder/Runtime.exec) through an
 *              argument array, within one method. The receiving command can
 *              reparse an attacker-controlled delimiter as an additional logical
 *              option even though an argument array is used and no shell
 *              tokenizes the value. This is the intra-procedural shape of the
 *              CWE-88 embedded sub-option injection submission; it misses the
 *              launch-wrapper idiom, which the interprocedural query covers.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id java/cwe88/embedded-suboption-injection
 * @tags security
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.dataflow.DataFlow

/** A concatenation `"...,...=..." + X` that builds a comma/equals option template from a non-constant part. */
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

/** An argument of a non-shell process launcher. */
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

from DataFlow::Node src, DataFlow::Node snk
where
  optionTemplate(src) and
  launcherArgument(snk) and
  DataFlow::localFlow(src, snk)
select snk,
  "A value is embedded into one comma-separated option-argument and passed to a process " +
    "launcher. An attacker-controlled delimiter can be reparsed as an additional logical option (CWE-88)."
