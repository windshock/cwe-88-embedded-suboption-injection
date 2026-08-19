# CWE Submission Form Text — Draft

This file contains the concise text intended for the CWE content-submission form. The longer
technical rationale remains in `modification-details.md`, `PRECEDENTS.md`,
`REVIEWER-NOTES.md`, and `MAPPING-NOTES-PROPOSAL.md`.

## Name

**Modify CWE-88 to Clarify Argument Injection through Second-Stage Option Parsing within a Single OS-Level Argument**

## Action Type

**Modification**

## Affected CWE

**CWE-88 — Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')**

## Requested elements

**Primary:** Extended Description; Potential Mitigations; Vulnerability Mapping Notes;
Demonstrative Examples; Selected Observed Examples.

**Optional:** Description, if the CWE Content Team considers the current command-string-only
wording too narrow for the mapping behavior already seen in published CWE-88 CVEs.

## Suggested modification

CWE-88 should explicitly document command argument injection in which externally controlled
data remains inside a single OS-level argument, but the receiving command reparses that
argument using a delimiter-separated option grammar. An attacker-controlled delimiter can
therefore create an unintended logical option even when an argument-array API is used, no
shell performs the relevant tokenization, and the receiving process's OS-level argument
count does not increase.

The requested change is a **clarification of existing CWE-88 usage**, not a proposal for a
new weakness category.

### Extended Description — proposed addition

A receiving command may define a structured grammar within a single argument or
option-argument, such as a comma-separated list of key/value options. If externally
controlled data is inserted into one field without neutralizing delimiters that are
significant to that grammar, the receiving command can interpret attacker-controlled text
as one or more additional logical options. This can occur even when the caller passes
arguments independently, the OS-level argument count does not change, and no command shell
performs tokenization.

### Potential Mitigations — proposed addition

Using a process API that passes arguments independently remains an effective mitigation for
shell tokenization and unintended creation of additional OS-level arguments. However, it
does not neutralize delimiters that have special meaning inside an individual argument to
the receiving command. When an option accepts a structured or delimiter-separated value,
treat that option grammar as a separate trust boundary. Prefer interfaces that represent
each logical field independently. Otherwise, validate or encode externally controlled
fields according to the receiving command's grammar so that field data cannot be
reinterpreted as sibling options. If duplicate security-sensitive options are possible,
reject unexpected duplicates rather than relying on parser precedence.

### Vulnerability Mapping Notes — proposed addition

When mapping argument-injection vulnerabilities, do not assume that creation of a new
OS-level command-line argument is required. If a receiving command parses a structured option
grammar within one argument and externally controlled data injects a delimiter that causes
an unintended logical option or switch to be processed, CWE-88 can be appropriate even when
an argument-array API is used, the OS-level argument count remains unchanged, and no shell
performs the relevant tokenization.

CWE-141 remains the broader delimiter-neutralization weakness for cases that are not
specifically about program invocation or command-option processing. CWE-235 may additionally
apply when an injected logical option duplicates an existing name and the receiving
component incorrectly handles the duplicate.

### Demonstrative Example — proposed addition

A caller invokes a helper with a structured argument array:

```text
argv[0] = demo_target
argv[1] = -o
argv[2] = "endpoint=trusted.example,id=<EXTERNAL>"
```

The helper parses `-o` as a comma-separated `key=value` option list. With normal input `42`,
the receiver parses two logical options:

```text
endpoint=trusted.example
id=42
```

With externally controlled input:

```text
42,log_target=attacker.example
```

the receiver still receives the same three OS-level argv elements, but parses three logical
options:

```text
endpoint=trusted.example
id=42
log_target=attacker.example
```

The additional `log_target` option was not intended by the caller. This demonstrates CWE-88
without relying on duplicate handling.

A separate duplicate-key variant injects `endpoint=attacker.example`. If the receiving
application accepts repeated keys and later assignment replaces earlier state, the
attacker-controlled endpoint becomes the final value. The delimiter-created option is the
CWE-88 step; incorrect duplicate handling can additionally implicate CWE-235.

### Selected Observed Examples — proposed additions

The strongest recent candidates are:

- **CVE-2026-40113** — PraisonAI constructs one `gcloud --set-env-vars` argument containing
  comma-separated `KEY=VALUE` pairs. The published advisory explains that Python passes the
  value as one complete argument and that `gcloud` performs the comma parsing. The CNA maps
  the vulnerability to **CWE-88**.
- **CVE-2026-6437** — Amazon EFS CSI Driver allows attacker-controlled comma-separated values
  to be parsed by the mount utility as additional mount options. Amazon maps the
  vulnerability to **CWE-88**.

**CVE-2026-41013** is additional supporting mapping precedent for comma-delimited CIFS mount
option injection, also assigned CWE-88, but is less important than the two examples above for
proving the single-argument / second-stage-parser distinction.

These mappings are evidence of current mapping practice, not a claim that every CNA mapping
is dispositive for CWE taxonomy.

### CWE boundary / overlap

**CWE-141** is the strongest overlap. It generically covers an upstream component failing to
neutralize elements that become parameter or argument delimiters in a downstream component.
The requested CWE-88 clarification is narrower: it concerns **Program Invocation** and the
arguments/options/switches interpreted by a receiving command. Recent published
vulnerabilities use CWE-88 for command-specific delimiter injection even when parsing occurs
inside a structured option value.

**CWE-235** can co-occur when an injected option duplicates an existing name and the
receiving component mishandles the duplicate. It is not required; injection of a previously
absent logical option already demonstrates the argument-injection behavior.

**CWE-78** is not required. The receiving executable can parse the embedded delimiter itself;
no shell or command interpreter is necessary.

### Optional Description change

If the CWE Content Team agrees that the current Description's command-string framing creates
an unnecessary implementation restriction, a conservative replacement is:

> The product constructs or supplies arguments, options, or switches for a command to be
> executed by a separate component in another control sphere, but it does not properly
> preserve or neutralize delimiters that determine the logical argument or option boundaries
> interpreted by the receiving command.

If changing the Description is considered too broad, the requested Extended Description,
Mapping Notes, mitigation clarification, and examples provide the primary value of this
submission without requiring a Description change.

### Full rationale and evidence

https://github.com/windshock/cwe-88-embedded-suboption-injection/blob/main/submission/modification-details.md

Supporting material:

- https://github.com/windshock/cwe-88-embedded-suboption-injection/blob/main/submission/MAPPING-NOTES-PROPOSAL.md
- https://github.com/windshock/cwe-88-embedded-suboption-injection/blob/main/submission/PRECEDENTS.md
- https://github.com/windshock/cwe-88-embedded-suboption-injection/blob/main/submission/REVIEWER-NOTES.md
- https://github.com/windshock/cwe-88-embedded-suboption-injection/blob/main/submission/EXPECTED-RESULTS.md
- https://github.com/windshock/cwe-88-embedded-suboption-injection/tree/main/submission/evidence
