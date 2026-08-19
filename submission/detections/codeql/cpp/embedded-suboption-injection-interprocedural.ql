/**
 * @name Embedded sub-option injection via a delimiter-structured argument (interprocedural)
 * @description Finds a comma-separated key=value option-argument built by a
 *              *printf-family call (a format literal containing a comma, an
 *              equals sign and a %s conversion) that reaches a non-shell process
 *              launcher (exec* / posix_spawn) argument across function boundaries.
 *              Unlike the intra-procedural query, the constructed option-argument
 *              is tracked through helper/launch-wrapper functions, so the common
 *              idiom in which the launch is delegated to a shared wrapper is
 *              still reported. This is the CWE-88 embedded sub-option injection
 *              shape.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/cwe88/embedded-suboption-injection-interprocedural
 * @tags security
 *       external/cwe/cwe-088
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow

/** A *printf-family call that builds a delimiter-structured option template. */
predicate isFormattingCall(FunctionCall fc) {
  fc.getTarget().getName().toLowerCase().matches("%printf%")
}

/**
 * A format string literal that contains BOTH a comma and an equals sign and a
 * `%s` conversion: a comma-separated key=value option grammar.
 */
predicate isOptionTemplate(StringLiteral lit) {
  lit.getValue().matches("%,%") and
  lit.getValue().matches("%=%") and
  lit.getValue().matches("%\\%s%")
}

/**
 * A buffer variable written by a *printf-family call whose format string is a
 * comma/equals/%s option template.
 */
predicate templatedBuffer(Variable v) {
  exists(FunctionCall fc, StringLiteral fmt |
    isFormattingCall(fc) and
    fmt = fc.getAnArgument() and
    isOptionTemplate(fmt) and
    fc.getArgument(0) = v.getAnAccess()
  )
}

/** A non-shell process launcher that takes an argument vector. */
predicate isProcessLauncher(Function f) {
  f.hasName([
      "execv", "execvp", "execve", "execvpe", "execl", "execlp", "execle",
      "posix_spawn", "posix_spawnp"
    ])
}

module OptionInjectionConfig implements DataFlow::ConfigSig {
  /**
   * Any subsequent use of a buffer that was formatted from an option template.
   * Seeding at the *use* (rather than trying to flow through the C array write)
   * lets the value be carried across a launch wrapper's parameter to the sink.
   */
  predicate isSource(DataFlow::Node src) {
    exists(Variable v | templatedBuffer(v) and src.asExpr() = v.getAnAccess())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall launcher |
      isProcessLauncher(launcher.getTarget()) and
      sink.asExpr() = launcher.getAnArgument()
    )
  }

  /**
   * The exec* argument vector is an argv array built with an aggregate
   * initializer, e.g. `char *argv[] = {target, "-o", opt, 0};`. Model the flow
   * from an element of that initializer (the option buffer) to every read of the
   * initialized array variable, so the taint on `opt` reaches the `argv`
   * expression passed to the launcher (including through a launch wrapper).
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Variable argv, ArrayAggregateLiteral agg |
      agg = argv.getInitializer().getExpr() and
      pred.asExpr() = agg.getAChild() and
      succ.asExpr() = argv.getAnAccess()
    )
  }
}

module OptionInjectionFlow = TaintTracking::Global<OptionInjectionConfig>;

import OptionInjectionFlow::PathGraph

from OptionInjectionFlow::PathNode source, OptionInjectionFlow::PathNode sink
where OptionInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "A comma-separated option-argument built from a non-constant part reaches a process launcher " +
  "across function boundaries. An attacker-controlled delimiter can be reparsed as an additional " +
  "logical option (CWE-88)."
