/**
 * @name Embedded sub-option injection via a delimiter-structured argument (interprocedural)
 * @description Finds a comma-separated key=value option-argument built from a
 *              non-constant part that reaches a non-shell process launcher
 *              (child_process execFile/spawn and their sync variants) argument
 *              array across function boundaries. Unlike the intra-procedural
 *              query, the constructed option-argument is tracked through
 *              helper/launch-wrapper functions, so the common idiom in which the
 *              launch is delegated to a shared wrapper is still reported. This is
 *              the CWE-88 embedded sub-option injection shape.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id js/cwe88/embedded-suboption-injection-interprocedural
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

module OptionInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { optionTemplate(source) }

  predicate isSink(DataFlow::Node sink) { launcherArrayElement(sink) }
}

module OptionInjectionFlow = TaintTracking::Global<OptionInjectionConfig>;

import OptionInjectionFlow::PathGraph

from OptionInjectionFlow::PathNode source, OptionInjectionFlow::PathNode sink
where OptionInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A comma-separated option-argument built from a non-constant part reaches a process launcher " +
    "across function boundaries. An attacker-controlled delimiter can be reparsed as an additional " +
    "logical option (CWE-88)."
