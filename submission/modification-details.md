# MITRE CWE Submission — Proposed Modification to CWE-88

## Submission header

```text
Submission Type : Software
Action Type     : Modification
Affected CWE    : CWE-88
Current Name    : Improper Neutralization of Argument Delimiters in a Command
                  ('Argument Injection')
Proposed Scope  : Clarify command argument injection when a receiving command
                  parses a delimiter-separated option grammar inside one
                  OS-level argument
```

This is a **modification to an existing CWE**, not a request for a new weakness ID.
The proposal is product-independent and is supported by a generalized demonstrator,
published CWE-88 CVE mappings, and explicit overlap analysis.

---

## Core claim

> **CWE-88 should explicitly cover cases in which externally controlled data is embedded
> within a single command-line argument whose value is parsed by the receiving component
> as a delimiter-separated option grammar, allowing attacker-controlled delimiters to
> create additional logical options even when no new OS-level `argv` element is created.**

---

## Why modify CWE-88 instead of creating a new CWE

The underlying security failure is already argument injection: attacker-controlled text
crosses a command-option grammar boundary and causes the receiving command to process an
option that the caller did not intend.

The gap is **documentation and implementation framing**, not weakness identity.

Current CWE-88 text is strongly oriented toward building a command string and creating
additional top-level command-line arguments or switches. In current real-world mapping,
however, CWE-88 is also assigned to cases where:

1. the caller uses a structured process argument interface;
2. the untrusted value remains within one OS-level argument;
3. no command shell performs the relevant tokenization; and
4. the receiving command reparses that argument using its own delimiter grammar and thereby
   creates additional logical options.

Recent examples include CVE-2026-40113, CVE-2026-6437, and CVE-2026-41013.
See [`PRECEDENTS.md`](PRECEDENTS.md).

Delimiter-based parameter injection itself is not new. CAPEC-137, HTTP Parameter Pollution,
and Connection String Parameter Pollution already demonstrate the broader parser pattern.
That history is another reason to modify an existing CWE rather than create a new one.

---

## Current CWE-88 wording that creates ambiguity

As of CWE 4.20, the CWE-88 Description is framed around a product that constructs a
**string for a command** and does not properly delimit the intended arguments/options/
switches within that command string.

Its Extended Description likewise discusses interpolation into a string and says that
attacker-controlled argument separators can cause the resulting command to have more
arguments than the developer intended.

The current high-effectiveness mitigation correctly recommends avoiding one combined command
string where possible and using independent arguments, such as argument-array or
`exec()`-style interfaces.

That guidance is important and should remain. The ambiguity is that a reader may infer:

```text
independent OS-level arguments
        ==
all argument-injection boundaries have been removed
```

That is not true when an individual argument intentionally contains another grammar that the
receiving command parses.

Example:

```text
argv[0] = program
argv[1] = -o
argv[2] = "endpoint=trusted.example,id=<EXTERNAL>"
```

If `-o` is a comma-separated option language, the OS can preserve all three `argv` elements
perfectly while the receiving command still interprets an attacker-controlled comma as a
new logical option boundary.

---

# Field: Description — Proposed replacement

A conservative replacement that removes the string-only implementation assumption is:

> **The product constructs or supplies arguments, options, or switches for a command to be
> executed by a separate component in another control sphere, but it does not properly
> preserve or neutralize delimiters that determine the logical argument or option boundaries
> interpreted by the receiving command.**

This retains CWE-88's command/program-invocation scope while allowing the logical delimiter
to exist either:

- between OS-level command-line arguments; or
- inside an individual OS-level argument that the receiving command parses as a structured
  option value.

### Lower-risk alternative

If the CWE Team considers changing the Description too broad, retain the current Description
and make the single-argument case explicit in the Extended Description and Mapping Notes,
including a clear CWE-88/CWE-141 boundary statement.

The essential goal is discoverability and mapping consistency, not any particular wording.

---

# Field: Extended Description — Proposed addition

Add a paragraph such as:

> **An argument delimiter does not need to separate OS-level command-line arguments. A
> receiving command may define an embedded grammar within a single argument or
> option-argument, such as a comma-separated list of key/value options. If externally
> controlled data is inserted into one field without neutralizing delimiters that are
> significant to that embedded grammar, the receiving command can interpret attacker data
> as one or more additional logical options. This can occur even when the caller invokes
> the process directly with a structured argument array, the OS-level argument count does
> not change, and no command shell performs tokenization.**

### Rationale

The distinction is:

```text
A. traditional top-level argument injection

command representation
        |
        +-- attacker changes top-level argument/switch boundaries
```

versus:

```text
B. embedded option-grammar injection

argv[N] = "safe_key=safe,user_key=<INPUT>"
                              |
                              +-- attacker supplies ','

receiving command reparses argv[N]
        -> safe_key=safe
        -> user_key=value
        -> injected_key=attacker_value
```

The OS-level `argc` does not need to change for the command to process more **logical
options** than the caller intended.

---

# Field: Potential Mitigations — Proposed addition

Add a clarification such as:

> **Using a process API that passes arguments independently, such as an argument array,
> prevents many shell-tokenization and top-level argument-separation problems, but it does
> not neutralize delimiters that have special meaning inside an individual argument to the
> receiving command. When an option accepts a structured or delimiter-separated value,
> treat that option's documented grammar as a separate trust boundary. Prefer interfaces or
> invocation forms that represent each logical field separately. Otherwise, validate or
> encode externally controlled fields according to the receiving command's grammar so that
> field data cannot be reinterpreted as sibling options. If duplicate security-sensitive
> options are possible, reject unexpected duplicates instead of relying on parser
> precedence.**

This is an extension, not a reversal, of the existing CWE-88 mitigation.

For example, the following outer process invocation is preferable to a shell string but is
still vulnerable if `-o` defines comma as syntax:

```python
subprocess.run([
    "target",
    "-o",
    f"endpoint=trusted.example,id={user_input}",
], shell=False)
```

Input:

```text
42,log_target=attacker.example
```

still changes the receiving command's logical option set.

---

# Field: Demonstrative Examples — Proposed addition

## Example: delimiter injection inside one argument-array element

A caller invokes a helper with a structured argument array. The helper's `-o` option accepts
a comma-separated list of `key=value` options.

### Intended invocation

```text
argv[0] = demo_target
argv[1] = -o
argv[2] = "endpoint=trusted.example,id=42"
```

The receiver parses:

```text
endpoint=trusted.example
id=42
```

### Injected new-option case

Externally controlled `id` data contains:

```text
42,log_target=attacker.example
```

The caller still supplies exactly one value for `argv[2]`:

```text
endpoint=trusted.example,id=42,log_target=attacker.example
```

The receiving command parses:

```text
endpoint=trusted.example
id=42
log_target=attacker.example
```

The additional `log_target` option was not intended by the caller. No duplicate parameter is
required, so this case stands independently from CWE-235.

### Duplicate-option variant

Externally controlled data instead contains:

```text
42,endpoint=attacker.example
```

The receiver parses:

```text
endpoint=trusted.example
id=42
endpoint=attacker.example
```

If the receiving application accepts duplicates and later assignment replaces earlier
state, the attacker-controlled endpoint becomes final.

The **creation of the unintended second logical option** is the CWE-88 step. Incorrect
handling of the duplicate may additionally satisfy CWE-235.

The repository demonstrator reproduces all three cases (`control`, `inject-new`, and
`override`) and asserts that target `argc` remains 3 in every case while the internal logical
option count changes from 2 to 3.

---

# Field: Selected Observed Examples — Candidate additions

These are candidates for CWE Team consideration, not a requirement for acceptance of the
core modification.

### CVE-2026-40113

PraisonAI constructs a single comma-delimited value for `gcloud run deploy
--set-env-vars`. Externally influenced values can contain commas, causing `gcloud` to parse
additional `KEY=VALUE` definitions. The reviewed advisory explicitly explains that Python
passes the constructed value as one complete argument and that shell parsing is not the
injection boundary. The CNA assigns **CWE-88**.

This is the strongest direct observed example for the proposed clarification.

### CVE-2026-6437

Amazon EFS CSI Driver accepts attacker-controlled values where appended comma-separated text
is parsed by the mount utility as additional mount options. Amazon assigns **CWE-88**.

### CVE-2026-41013

Cloud Foundry SMB volume handling allows a tenant-controlled comma to smuggle additional
CIFS mount options past the intended allowlist. The CNA assigns **CWE-88**.

---

# Relationship to neighboring CWEs

## CWE-141 — Improper Neutralization of Parameter/Argument Delimiters

This is the strongest overlap question.

CWE-141 describes the generic upstream/downstream condition in which special input elements
can be interpreted as parameter or argument delimiters by a downstream component.

The proposed distinction is scope:

- **CWE-141:** generic parameter/argument delimiter neutralization across component
  boundaries.
- **CWE-88:** the program-invocation / receiving-command option manifestation, where the
  delimiter changes the arguments/options/switches logically processed by a command.

The proposal does **not** claim CWE-141 is wrong or redundant. It asks CWE-88 to explicitly
document command-option behavior that current CVE mappings already place under CWE-88.

If the CWE Team prefers CWE-141 as the primary root-cause mapping for structured-argument
cases, a useful fallback modification is a CWE-88 Mapping Note that explains this boundary.

## CWE-235 — Improper Handling of Extra Parameters

CWE-235 applies when parameters/fields/arguments with the same name occur more times than
expected and the product handles those duplicates incorrectly.

It can amplify the proposed pattern, but is not required:

```text
inject-new
  -> delimiter creates a previously absent option
  -> CWE-88 behavior exists without duplicate handling

override
  -> delimiter creates a duplicate option
  -> receiver precedence/duplicate handling may additionally implicate CWE-235
```

Therefore the presence of a high-impact duplicate override should not collapse the entire
injection chain into CWE-235.

## CWE-78 — OS Command Injection

A shell or command interpreter is not required for this pattern. The receiving executable
can parse the embedded delimiter itself.

CWE-78 can coexist downstream in a specific implementation, but it is not a prerequisite for
this CWE-88 modification.

---

# Standardized command-line grammar precedent

Multiple logical values within one OS-level option-argument are not a product-specific
oddity. POSIX utility syntax recognizes option-arguments that represent lists of values,
including comma-separated values interpreted by the receiving utility.

Conceptually:

```text
OS-level argv

argv[N] = "one,two,three"
              |
              v
receiving utility grammar

value[0] = one
value[1] = two
value[2] = three
```

This is why safe representation of the **outer argv boundary** and safe construction of an
**inner option grammar** are distinct concerns.

---

# Supporting attack-pattern and historical precedent

## CAPEC-137 — Parameter Injection

CAPEC-137 generalizes attacks in which text-based parameter encodings use delimiter
characters and attacker-controlled text injects those separators to create or alter
parameters. The concept is not limited to HTTP, and CAPEC-137 relates to CWE-88.

## CAPEC-460 — HTTP Parameter Pollution

CAPEC-460 demonstrates the duplicate-parameter specialization: injected delimiters create
additional/duplicate parameters and backend precedence may cause an earlier hard-coded value
to be disregarded. It relates to both CWE-88 and CWE-235.

## Connection String Parameter Pollution — Black Hat DC 2010

Connection String Parameter Pollution demonstrated the same broad parser structure in a
database connection-string grammar: untrusted text is placed into a delimiter-separated
string, a separator creates a new or duplicate connection parameter, and connection
behavior can change.

This is used only as **historical conceptual precedent**, not as a claim that CSPP was a
CWE-88 command-line vulnerability.

---

# Explicit non-goals

This submission does **not** claim:

1. delimiter-based parameter injection is newly discovered;
2. every delimiter inside a command argument is dangerous;
3. duplicate-option precedence is always CWE-88 instead of CWE-235;
4. argument-array APIs or `shell=False` are unsafe in general;
5. `getsubopt()` is vulnerable or defines last-wins behavior;
6. a command shell is required; or
7. a new CWE named "Embedded Sub-option Injection" is necessary.

The narrow claim is that **CWE-88 should document the already-observed command-specific case
where one OS-level argument contains a second option grammar and attacker-controlled data
injects a delimiter in that grammar to create additional logical options.**

---

# Demonstrated generalized evidence

The repository contains a product-independent local demonstrator with no networking,
filesystem mounting, credentials, vendor code, or shell execution.

Its decisive comparison is:

| Case | Target `argc` | Logical options | Result |
|---|---:|---:|---|
| control | 3 | 2 | intended options only |
| inject-new | 3 | 3 | previously absent logical option appears |
| override | 3 | 3 | duplicate endpoint appears; later demo assignment becomes final |

The parser uses `getsubopt()` only to expose a simple comma-delimited second-stage grammar.
The demonstration does **not** attribute duplicate precedence to `getsubopt()` itself;
repeated assignment in the demo application determines the final value.

See:

- [`EXPECTED-RESULTS.md`](EXPECTED-RESULTS.md)
- [`evidence/run_demo.txt`](evidence/run_demo.txt)
- [`evidence/build_log.txt`](evidence/build_log.txt)
- [`REVIEWER-NOTES.md`](REVIEWER-NOTES.md)

---

# Why the modification is useful to CWE users

### Vulnerability mapping

Researchers can map command-option cases such as CVE-2026-40113 and CVE-2026-6437 without
implying that the operating system created a new `argv` element.

### Secure coding guidance

Developers retain the strong recommendation to use structured process invocation, while also
learning to examine structured grammars *inside* individual arguments.

### Static and dynamic analysis

Analysis tools can model a second-stage command grammar:

```text
untrusted source
  -> interpolation into one field
  -> structured option-argument construction
  -> process invocation
  -> receiver-specific delimiter parser
  -> unintended logical option
```

This detection shape is easy to miss when analysis stops at the process-API boundary.

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
- NVD CVE-2026-40113:
  https://nvd.nist.gov/vuln/detail/CVE-2026-40113
- CVE-2026-6437 / GHSA-mph4-q2vm-w2pw:
  https://github.com/kubernetes-sigs/aws-efs-csi-driver/security/advisories/GHSA-mph4-q2vm-w2pw
- AWS Security Bulletin 2026-016:
  https://aws.amazon.com/security/security-bulletins/2026-016-aws/
- NVD CVE-2026-6437:
  https://nvd.nist.gov/vuln/detail/CVE-2026-6437
- CVE-2026-41013:
  https://www.cloudfoundry.org/blog/cve-2026-41013-tenant-controlled-comma-smuggles-arbitrary-cifs-mount-options-2/
- NVD CVE-2026-41013:
  https://nvd.nist.gov/vuln/detail/CVE-2026-41013

## Historical / standards precedent

- Black Hat DC 2010 — Connection String Parameter Pollution white paper:
  https://www.blackhat.com/presentations/bh-dc-10/Alonso_Chema/Blackhat-DC-2010-Alonso-Connection-String-Parameter-Pollution-wp.pdf
- POSIX Utility Syntax Guidelines:
  https://pubs.opengroup.org/onlinepubs/9699919799.orig/basedefs/V1_chap12.html
