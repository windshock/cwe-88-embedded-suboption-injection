# MITRE CWE Submission — Proposed Modification to CWE-88

## Submission header

```text
Submission Type : Software
Action Type     : Modification
Affected CWE    : CWE-88
Current Name    : Improper Neutralization of Argument Delimiters in a Command
                  ('Argument Injection')
Proposed Scope  : Clarify embedded sub-option grammars inside a single
                  OS-level command-line argument
```

This repository prepares a **modification to an existing CWE**, not a request for a new
weakness ID. The CWE submission overview states that a modification submission identifies
the relevant CWE-ID and provides details of the suggested modification.

This proposal is product-independent. It does not require a vendor binary or a specific
product vulnerability to establish the weakness class.

---

## Core claim

> **CWE-88 should explicitly cover cases in which externally controlled data is embedded
> within a single command-line argument whose value is parsed by the receiving component
> as a delimiter-separated sub-option language, allowing attacker-controlled delimiters to
> create additional logical options even when no new OS-level `argv` element is created.**

---

## Why modify CWE-88 instead of creating a new CWE

CWE-88 is already the CWE Base weakness for failure to neutralize argument delimiters in a
command. Its current Extended Description explains that untrusted argument-separating
characters can make a command contain more arguments than the developer intended.

The gap is **not the underlying weakness identity**. The gap is that the current wording and
examples can easily be read as focusing on command construction in which the attacker
creates additional top-level command-line arguments or switches, such as injecting another
`-o` or `-X` option.

A receiving command can also define a second grammar *inside one option-argument*:

```text
program -o "key=value,key=value,key=value"
```

The OS sees one option-argument. The receiving program sees several logical sub-options.
When untrusted data is inserted into one value without neutralizing the comma, the attacker
can manufacture an additional sibling sub-option. The command-specific security failure is
still improper neutralization of an argument delimiter, so CWE-88 is the natural existing
entry to clarify.

This interpretation is supported by recent published CVEs already assigned **CWE-88**:
CVE-2026-40113, CVE-2026-6437, and CVE-2026-41013. See `PRECEDENTS.md`.

---

## Existing wording that creates ambiguity

The current CWE-88 Extended Description says that attacker-controlled delimiters can cause
the resulting command to have **more arguments than intended**. That is correct at the
logical command-grammar level, but it may be misunderstood as requiring an increased
OS-level `argc`/`argv` count.

Recent CWE-88 mappings show that this distinction matters. In CVE-2026-40113, the caller
uses Python's argument-array form and does not invoke a shell; the vulnerable value remains
one `argv` element until `gcloud` applies its own comma-separated `KEY=VALUE` grammar.
CVE-2026-6437 similarly involves comma-delimited mount options parsed by the receiving mount
utility.

The proposed modification makes this already-observed CWE-88 usage explicit.

---

# Field: Extended Description — Proposed addition

Add a paragraph such as the following after the current discussion of argument-separating
delimiters:

> An argument delimiter does not need to separate OS-level command-line arguments. A
> receiving command may define an embedded grammar within a single argument or
> option-argument, such as a comma-separated list of key/value sub-options. If externally
> controlled data is inserted into one field without neutralizing delimiters that are
> significant to that embedded grammar, the receiving command can interpret attacker data
> as one or more additional logical options. This can occur even when the caller invokes
> the process directly with a structured argument array, the OS-level argument count does
> not change, and no command shell performs tokenization.

### Rationale

This addition preserves CWE-88's existing semantics while removing an implementation-level
ambiguity between:

```text
A. top-level argument injection

argv[N] = "safe"
        + attacker causes an additional argv element / switch
```

and:

```text
B. embedded sub-option injection

argv[N] = "safe_key=safe,user_key=<INPUT>"
                          |
                          +-- attacker supplies a delimiter

receiver parses argv[N] again
        -> safe_key=safe
        -> user_key=value
        -> injected_key=attacker_value
```

Both change the options processed by the receiving command through improper neutralization
of command argument delimiters.

---

# Field: Potential Mitigations — Proposed addition

CWE-88 currently recommends structured/independent argument APIs instead of constructing one
command string. That advice remains correct for shell and top-level argument boundaries, but
it is incomplete for commands that intentionally parse an internal option language.

Add a clarification such as:

> Using a process API that passes arguments as an array prevents many shell-tokenization
> and top-level argument-separation problems, but it does not neutralize delimiters that
> have special meaning inside an individual argument to the receiving command. When an
> option accepts a structured or delimiter-separated value, treat that option's documented
> grammar as a separate trust boundary. Prefer APIs or invocation forms that represent each
> logical field separately. Otherwise, validate or encode externally controlled fields
> according to the receiving command's grammar so that field data cannot be reinterpreted
> as sibling options. If duplicate security-sensitive options are possible, reject
> unexpected duplicates instead of relying on parser precedence.

### Why this mitigation text is important

A developer may correctly write:

```python
subprocess.run([
    "target",
    "-o",
    f"endpoint=trusted.example,id={user_input}",
], shell=False)
```

and conclude that argument injection is impossible because:

- no shell command string exists;
- `shell=False` is used; and
- every top-level argument is passed separately.

Those properties prevent one class of tokenization bug, but do not protect the *internal*
`-o` grammar. If commas delimit logical fields, then input such as:

```text
42,extra_option=attacker_value
```

still injects a new logical option at the target parser.

---

# Field: Demonstrative Examples — Proposed addition

## Example: delimiter injection inside one argument-array element

Consider a program that launches a helper using a structured argument array. The helper's
`-o` option accepts a comma-separated list of `key=value` sub-options.

### Caller

```python
user_id = get_untrusted_input()

subprocess.run([
    "demo-target",
    "-o",
    f"endpoint=trusted.example,id={user_id}",
], shell=False)
```

The developer intends the receiving command to parse exactly two sub-options:

```text
endpoint=trusted.example
id=<user data>
```

However, an attacker supplies:

```text
42,log_target=attacker.example
```

The OS still passes exactly one value for the `-o` option:

```text
endpoint=trusted.example,id=42,log_target=attacker.example
```

but the receiving command's internal parser interprets three logical sub-options:

```text
endpoint=trusted.example
id=42
log_target=attacker.example
```

The new `log_target` option was not intended by the caller. The failure is therefore an
argument-injection weakness even though the OS-level `argv` count did not increase.

### Duplicate-option variant

A stronger impact can occur when the attacker injects another occurrence of an existing
security-sensitive key:

```text
42,endpoint=attacker.example
```

If the receiving parser accepts duplicates and later assignment replaces earlier state,
the trusted destination can be overridden:

```text
endpoint=trusted.example
id=42
endpoint=attacker.example
```

The **creation of the extra logical option** is the CWE-88 step. The receiving program's
incorrect handling of a duplicate key can additionally satisfy **CWE-235**. Duplicate
handling is not required for CWE-88: injection of a previously absent sub-option is already
sufficient.

---

# Relationship to neighboring CWEs

## CWE-141 — Improper Neutralization of Parameter/Argument Delimiters

CWE-141 describes the generic upstream/downstream condition in which special input elements
become parameter or argument delimiters in a downstream component. This proposal does not
claim that CWE-141 is incorrect or redundant.

The distinction is scope:

- **CWE-141**: generic parameter/argument delimiter neutralization across component
  boundaries.
- **CWE-88**: delimiter neutralization in the construction or interpretation of a command's
  arguments/options.

The embedded-sub-option case is command-specific and published CVEs already map it to
CWE-88, so the requested change is a clarification of CWE-88 rather than a new generic
injection category.

No new formal CWE-88/CWE-141 relationship is required by this proposal; the comparison is
included to bound overlap for reviewers.

## CWE-235 — Improper Handling of Extra Parameters

CWE-235 applies when multiple parameters/fields/arguments with the same name exceed what the
product expects and the duplicates are handled incorrectly.

A duplicate key can amplify embedded sub-option injection:

```text
trusted endpoint
      |
      v
endpoint=trusted,id=<INPUT>
                    |
                    +-- ,endpoint=attacker
                              |
                              v
                     duplicate endpoint
                              |
                              v
                       precedence rule
```

But the two weaknesses are separable:

- CWE-88 exists as soon as the attacker creates an unintended logical option by injecting
  the delimiter.
- CWE-235 exists only when duplicate-name handling itself is incorrect or ambiguous.

Therefore this proposal should not be moved from CWE-88 to CWE-235 merely because one high-
impact exploit variant uses duplicate-option precedence.

## CWE-78 — OS Command Injection

A shell is **not required** for the proposed pattern. The receiving executable itself can
parse the injected delimiter. Therefore embedded sub-option injection should not be framed
as CWE-78 unless a separate shell/interpreter injection step is also present.

CVE-2026-40113 is especially useful here because its reviewed advisory explicitly notes that
Python passes the vulnerable string as one complete argument and that shell invocation is
not involved.

---

# Standardized command-line grammar precedent

The concept of multiple logical values inside one command-line argument is not unusual or
product-specific. POSIX Utility Syntax Guideline 8 describes cases where multiple option-
arguments following a single option are represented in one argument using comma or blank
separators, with the utility responsible for parsing the comma-separated list.

This supports the terminology used in this proposal:

```text
OS-level argument / option-argument
              |
              v
   embedded comma-separated list
              |
              v
     utility-level sub-options
```

The weakness occurs when externally controlled field data is inserted into such a grammar
without protecting its delimiter boundary.

---

# Supporting attack-pattern precedent

CAPEC-137 (Parameter Injection) states, at a general attack-pattern level, that text-based
parameter encodings are vulnerable when an attacker can inject characters that the encoding
uses as separators, and that this concept is not limited to HTTP.

CAPEC-460 (HTTP Parameter Pollution) provides the duplicate-parameter specialization: an
attacker injects a delimiter, adds another occurrence of a parameter, and may cause a hard-
coded value to be disregarded depending on backend duplicate handling. CAPEC-460 lists both
CWE-88 and CWE-235 as related weaknesses.

The proposed CWE-88 clarification is the command-argument analogue of that already-known
parser pattern.

---

# Explicit non-goals

This submission does **not** claim:

1. that delimiter-based parameter injection is a newly discovered attack concept;
2. that every comma in a command argument is dangerous;
3. that duplicate-option precedence is always CWE-88 rather than CWE-235;
4. that use of an argument array or `shell=False` is unsafe in general; or
5. that the receiving parser must use a particular parsing library or precedence rule.

The narrow claim is that **CWE-88 should explicitly document the already-observed case where
one OS-level argument contains a second command option grammar and attacker-controlled data
injects delimiters in that second grammar to create additional logical command options.**

---

# Why the modification is useful to CWE users

The clarification improves three common activities:

### Vulnerability mapping

Researchers can map vulnerabilities like CVE-2026-40113 and CVE-2026-6437 to CWE-88 without
having to imply that the process launcher created a new OS-level argument.

### Secure coding guidance

Developers are warned that converting from a shell command string to a structured argument
array is not the end of the analysis when a target utility parses structured option values.

### Static/dynamic analysis

Tool authors can model a second-stage command grammar:

```text
source
  -> string interpolation into a field
  -> option-argument construction
  -> command invocation
  -> recipient-specific delimiter parser
  -> unintended logical option
```

This is a different detection shape from classic `argv`/whitespace or leading-hyphen
argument injection and is easy to miss if a tool stops analysis at the process API boundary.

---

# References

## CWE / CAPEC

- CWE-88: https://cwe.mitre.org/data/definitions/88.html
- CWE-141: https://cwe.mitre.org/data/definitions/141.html
- CWE-235: https://cwe.mitre.org/data/definitions/235.html
- CAPEC-137 Parameter Injection: https://capec.mitre.org/data/definitions/137.html
- CAPEC-460 HTTP Parameter Pollution: https://capec.mitre.org/data/definitions/460.html
- CWE content submission overview: https://cwe.mitre.org/community/submissions/overview.html

## Published vulnerability precedents

- CVE-2026-40113 / GHSA-fvxx-ggmx-3cjg:
  https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-fvxx-ggmx-3cjg
- CVE-2026-6437 / GHSA-mph4-q2vm-w2pw:
  https://github.com/kubernetes-sigs/aws-efs-csi-driver/security/advisories/GHSA-mph4-q2vm-w2pw
- AWS Security Bulletin 2026-016:
  https://aws.amazon.com/security/security-bulletins/2026-016-aws/
- CVE-2026-41013:
  https://www.cloudfoundry.org/blog/cve-2026-41013-tenant-controlled-comma-smuggles-arbitrary-cifs-mount-options-2/

## Historical / standards precedent

- Black Hat DC 2010 — Connection String Parameter Pollution white paper:
  https://www.blackhat.com/presentations/bh-dc-10/Alonso_Chema/Blackhat-DC-2010-Alonso-Connection-String-Parameter-Pollution-wp.pdf
- POSIX Utility Syntax Guidelines:
  https://pubs.opengroup.org/onlinepubs/9699919799.orig/basedefs/V1_chap12.html
