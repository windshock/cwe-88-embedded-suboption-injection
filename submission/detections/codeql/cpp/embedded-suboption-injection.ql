/**
 * @name Embedded sub-option injection via a delimiter-structured argument (intra-procedural)
 * @description Finds C/C++ code that formats a value into a single
 *              comma-separated key=value option-argument (a format literal that
 *              contains a comma, an equals sign and a %s conversion) and passes
 *              that buffer to a non-shell process launcher (exec* / posix_spawn)
 *              argument vector, within one function. The receiving command can
 *              reparse an attacker-controlled delimiter as an additional logical
 *              option even though an argument vector is used and no shell
 *              tokenizes the value. This is the intra-procedural shape of the
 *              CWE-88 embedded sub-option injection submission; it misses the
 *              launch-wrapper idiom, which the interprocedural query covers.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/cwe88/embedded-suboption-injection
 * @tags security
 *       external/cwe/cwe-088
 */

import cpp

/** A *printf-family call that builds a delimiter-structured option template. */
predicate isFormattingFunction(Function f) {
  f.getName().toLowerCase().matches("%printf%")
}

/**
 * A format string literal that contains BOTH a comma and an equals sign and a
 * `%s` conversion, i.e. a comma-separated key=value option grammar filled from a
 * non-constant argument.
 */
predicate isOptionTemplate(StringLiteral lit) {
  lit.getValue().matches("%,%") and
  lit.getValue().matches("%=%") and
  lit.getValue().matches("%\\%s%")
}

/** A call to a non-shell process launcher that takes an argument vector. */
predicate isProcessLauncher(Function f) {
  f.hasName([
      "execv", "execvp", "execve", "execvpe", "execl", "execlp", "execle",
      "posix_spawn", "posix_spawnp"
    ])
}

/**
 * `builder` is a *printf-family call whose format literal is a comma/equals/%s
 * option template and whose destination buffer is `optVar`.
 */
predicate builderWritesOption(FunctionCall builder, Variable optVar, StringLiteral fmt) {
  isFormattingFunction(builder.getTarget()) and
  builder.getArgument(0) = optVar.getAnAccess() and
  fmt = builder.getAnArgument() and
  isOptionTemplate(fmt)
}

/**
 * `launcher` is an exec* / posix_spawn call, and `optVar` appears (directly, or as
 * an element of an argv array initializer) among the values reaching that call
 * in the same function.
 */
predicate launcherUsesOption(FunctionCall launcher, Variable optVar) {
  isProcessLauncher(launcher.getTarget()) and
  exists(VariableAccess use |
    use = optVar.getAnAccess() and
    use.getEnclosingFunction() = launcher.getEnclosingFunction() and
    use.getLocation().getStartLine() <= launcher.getLocation().getStartLine()
  )
}

from
  Function enclosing, FunctionCall builder, FunctionCall launcher, Variable optVar,
  StringLiteral fmt
where
  builder.getEnclosingFunction() = enclosing and
  launcher.getEnclosingFunction() = enclosing and
  builderWritesOption(builder, optVar, fmt) and
  launcherUsesOption(launcher, optVar)
select launcher,
  "A value is formatted into one comma-separated option-argument and passed to a process " +
  "launcher. An attacker-controlled delimiter can be reparsed as an additional logical option (CWE-88)."
