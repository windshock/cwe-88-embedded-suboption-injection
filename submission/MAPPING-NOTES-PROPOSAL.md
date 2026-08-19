# CWE-88 Mapping Notes — Fallback Proposal

This file provides a conservative fallback if the CWE Content Team prefers not to broaden
CWE-88's current Description. The primary proposal remains the field-level modification in
`modification-details.md`.

## Why a mapping note is useful

CWE-88 currently emphasizes command-string construction, while modern process APIs often
preserve OS-level `argv` boundaries by passing arguments independently. That outer boundary
can be correct and still leave an argument-injection weakness when a receiving command
intentionally reparses one argument using a delimiter-separated option grammar.

Published vulnerabilities already assigned CWE-88 demonstrate this command-option shape.
The ambiguity is therefore useful to document even if the CWE Team decides that the current
Description should remain unchanged.

## Proposed Mapping Notes text

> **When mapping argument-injection vulnerabilities, do not assume that creation of a new
> OS-level command-line argument is required. A receiving command may parse a structured
> option grammar within a single argument, such as a comma-separated list of key/value
> options. If externally controlled data injects a delimiter that causes the receiving
> command to process an unintended logical option or switch, CWE-88 can be appropriate even
> when the caller uses an argument-array API, the OS-level argument count remains unchanged,
> and no shell performs the relevant tokenization.**
>
> **Use CWE-141 when the issue is better characterized as generic parameter/argument
> delimiter neutralization across components without a specific command/program-invocation
> option boundary. CWE-235 may additionally apply when an injected logical option duplicates
> an existing name and the receiving component incorrectly handles the duplicate.**

## Mapping decision guide

```text
Does attacker-controlled data cross into a downstream parser?
        |
        +-- No --> not this pattern
        |
        +-- Yes
              |
              v
Does the downstream parser interpret the delimiter as part of a
command/program invocation option, switch, or structured option-argument?
              |
              +-- No --> consider CWE-141 / another parser-specific CWE
              |
              +-- Yes
                    |
                    v
Does the delimiter create an unintended logical option/switch?
                    |
                    +-- Yes --> CWE-88 candidate
                    |
                    +-- No --> inspect another weakness

If the injected option duplicates an existing name:
        CWE-88 explains creation of the unintended option boundary.
        CWE-235 may additionally explain incorrect duplicate handling.
```

## Examples that support this boundary

- **CVE-2026-40113:** one `gcloud --set-env-vars` argument is reparsed as comma-separated
  `KEY=VALUE` entries; the published advisory maps the issue to CWE-88 even though a Python
  argument list is used and no shell performs the delimiter parsing.
- **CVE-2026-6437:** comma-separated attacker-controlled values become additional mount
  options; assigned CWE-88.
- **CVE-2026-41013:** comma-delimited CIFS mount options are smuggled past an allowlist;
  assigned CWE-88.

The product-independent demonstrator in this repository supplies an additional mapping
control: both the negative and positive cases enter the target with `argc=3`, while the
positive case increases the number of logical options parsed inside `argv[2]`.

## Relationship to the primary proposal

Preferred outcome:

1. adjust CWE-88 Description so it is not limited to a single combined command string;
2. add the embedded-grammar paragraph to Extended Description;
3. clarify the argument-array mitigation; and
4. add the generalized demonstrative example.

Conservative outcome:

1. retain the existing Description;
2. add the Extended Description clarification and/or this Mapping Notes guidance; and
3. add an example or Selected Observed Example showing one-`argv` second-stage option
   parsing.

Either outcome improves mapping consistency without creating a new CWE or claiming that the
underlying delimiter-injection concept is novel.
