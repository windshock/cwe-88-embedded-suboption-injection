/**
 * @name Embedded sub-option injection via a delimiter-structured argument (intra-procedural)
 * @description Finds JavaScript/Node code that embeds a value into a single
 *              comma-separated key=value option-argument and passes it to a
 *              non-shell process launcher (child_process execFile/spawn and
 *              their sync variants) through an argument array, within one
 *              function. The receiving command can reparse an
 *              attacker-controlled delimiter as an additional logical option
 *              even though an argument array is used and no shell tokenizes the
 *              value. This is the intra-procedural shape of the CWE-88 embedded
 *              sub-option injection submission; it misses the launch-wrapper
 *              idiom, which the interprocedural query covers.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id js/cwe88/embedded-suboption-injection
 * @tags security
 *       external/cwe/cwe-088
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking

/**
 * A template literal or string concatenation that builds a comma/equals option
 * template from a non-constant part.
 */
predicate optionTemplate(DataFlow::Node n) {
  // Template literal: `...,...=...${X}...` with a comma and an equals in the
  // constant parts and at least one interpolated (non-constant) element.
  exists(TemplateLiteral t |
    n = t.flow() and
    t.getAnElement().getStringValue().matches("%,%") and
    t.getAnElement().getStringValue().matches("%=%") and
    exists(Expr sub | sub = t.getAnElement() and not sub instanceof TemplateElement)
  )
  or
  // String concatenation: "...,...=..." + X where a constant operand carries
  // the comma/equals grammar and another operand is not a constant string.
  exists(DataFlow::Node joined, DataFlow::Node constOperand, DataFlow::Node other |
    n = joined and
    constOperand = StringConcatenation::getAnOperand(joined) and
    other = StringConcatenation::getAnOperand(joined) and
    constOperand != other and
    constOperand.getStringValue().matches("%,%") and
    constOperand.getStringValue().matches("%=%") and
    not exists(other.getStringValue())
  )
}

/** A call to a non-shell child_process launcher that takes an argument array. */
DataFlow::CallNode processLauncher() {
  result =
    DataFlow::moduleMember("child_process",
      ["execFile", "spawn", "execFileSync", "spawnSync"]).getACall()
}

/** An element of the argument array passed to a process launcher. */
predicate launcherArrayElement(DataFlow::Node n) {
  exists(DataFlow::CallNode c, DataFlow::ArrayCreationNode arr |
    c = processLauncher() and
    arr.flowsTo(c.getAnArgument()) and
    n = arr.getAnElement()
  )
}

from DataFlow::Node src, DataFlow::Node snk
where
  optionTemplate(src) and
  launcherArrayElement(snk) and
  DataFlow::localFlowStep*(src, snk)
select snk,
  "A value is embedded into one comma-separated option-argument and passed to a process " +
    "launcher. An attacker-controlled delimiter can be reparsed as an additional logical option (CWE-88)."
