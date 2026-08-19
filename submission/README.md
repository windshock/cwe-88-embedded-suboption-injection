# CWE-88 Modification Submission — Generalized Demonstrator

This directory is the **canonical submission set** for a proposed modification to
**CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument
Injection')**.

The proposal is product-independent. It documents and reproduces an argument-injection
shape in which a receiving command applies a second, delimiter-separated option grammar
inside one OS-level argument.

## Core claim

> **CWE-88 should explicitly cover cases in which externally controlled data is embedded
> within a single command-line argument whose value is parsed by the receiving component
> as a delimiter-separated sub-option language, allowing attacker-controlled delimiters to
> create additional logical options even when no new OS-level `argv` element is created.**

The main documents are:

- [`FORM-TEXT.md`](FORM-TEXT.md) — concise text intended for the CWE submission form;
- [`modification-details.md`](modification-details.md) — field-by-field rationale and
  proposed CWE content;
- [`PRECEDENTS.md`](PRECEDENTS.md) — published CVE, CAPEC, historical, and standards
  precedents;
- [`REVIEWER-NOTES.md`](REVIEWER-NOTES.md) — likely overlap/reviewer objections and proposed
  responses;
- [`EXPECTED-RESULTS.md`](EXPECTED-RESULTS.md) — exact demonstrator assertions; and
- [`evidence/`](evidence/) — captured build/run evidence and source integrity manifest.

> **Submission status.** Prepared for review; not yet submitted to or accepted by the CWE
> Program. Nothing in this repository should be interpreted as MITRE endorsement.

---

## 1. What the demonstrator proves

The demonstrator uses two programs:

- `poc/caller.py` — constructs a process invocation with Python's argument-list API and
  explicitly uses `shell=False`;
- `poc/demo_target.c` — receives exactly one `-o` option-argument and parses its contents
  with a comma-delimited `getsubopt()` grammar.

The intended structure is:

```text
OS process layer

argv[0] = demo_target
argv[1] = -o
argv[2] = "endpoint=trusted.example,id=<EXTERNAL>"

                                 |
                                 v
receiving command layer

endpoint=<value>,id=<value>,...
        comma-delimited logical sub-options
```

The negative control uses external data that contains no comma. Two logical options are
parsed.

The first positive case embeds:

```text
42,log_target=attacker.example
```

inside the `id` field. The receiving target still reports `argc=3`, but its internal parser
now sees three logical options instead of two.

The second positive case embeds:

```text
42,endpoint=attacker.example
```

which creates a duplicate `endpoint` sub-option. The demo's own repeated assignment logic
makes the later endpoint the final parser state. This illustrates how CWE-88 can combine
with duplicate-parameter handling similar to CWE-235, while keeping the two weaknesses
conceptually separate.

---

## 2. Why the outer argument array is not enough

The caller deliberately uses:

```python
subprocess.run(command, shell=False)
```

where `command` is a Python list.

This preserves the outer OS argument boundary and prevents a shell from splitting the
comma-delimited text. The receiving executable nevertheless assigns syntax to the comma
inside `argv[2]` and parses it again.

Therefore the key comparison is not:

```text
safe argv API  vs.  unsafe shell string
```

It is:

```text
outer argv grammar
        |
        v
one preserved argument
        |
        v
receiver-specific embedded grammar
        |
        v
untrusted delimiter creates another logical option
```

The proposed CWE-88 clarification is specifically about this second boundary.

---

## 3. Reproducing the demonstration

Prerequisites:

- a POSIX-like environment;
- a C compiler available as `cc`;
- Python 3; and
- a C library providing `getsubopt()`.

From the repository root:

```sh
bash submission/scripts/run_demo.sh
```

The script:

1. compiles `poc/demo_target.c` locally;
2. runs a negative control;
3. runs the new-sub-option injection case;
4. runs the duplicate-option override case;
5. asserts the expected `argc`, logical option counts, and final parser state; and
6. exits nonzero if any assertion fails.

A successful run ends with:

```text
[PASS] all generalized CWE-88 embedded sub-option tests passed
```

See [`EXPECTED-RESULTS.md`](EXPECTED-RESULTS.md) for the complete expected state for each
case.

To refresh the captured evidence after an intentional PoC change:

```sh
bash submission/scripts/capture_evidence.sh
```

This updates `evidence/build_log.txt`, `evidence/run_demo.txt`, and the SHA-256 manifest for
the core demonstrator files.

---

## 4. Why the demonstrator is product-independent

The code is written from scratch for this submission and intentionally has no externally
meaningful side effect.

It does **not**:

- contact a network destination;
- invoke a command shell;
- modify system configuration;
- mount a filesystem;
- access credentials;
- contain a vendor binary or vendor source; or
- reproduce any product-specific command name, parameter name, endpoint, or protocol.

The strings `trusted.example` and `attacker.example` are documentation-only reserved domain
names. The target merely stores and prints them.

A concrete product vulnerability may motivate or later support the CWE modification, but it
is outside the demonstrator itself and should be handled through that product's coordinated
disclosure process.

---

## 5. Package layout

```text
submission/
├── README.md
├── FORM-TEXT.md
├── modification-details.md
├── PRECEDENTS.md
├── REVIEWER-NOTES.md
├── EXPECTED-RESULTS.md
├── poc/
│   ├── caller.py
│   └── demo_target.c
├── scripts/
│   ├── run_demo.sh
│   └── capture_evidence.sh
└── evidence/
    ├── README.md
    ├── build_log.txt
    ├── run_demo.txt
    └── sha256.txt
```

The compiled `demo_target` binary is a local build artifact and should not be committed.

The repository-level package builder runs the demonstrator, verifies the integrity manifest,
and creates a ZIP containing only the canonical submission material plus the license/scope
notices:

```sh
bash tools/make-submission.sh
```

Expected output files:

```text
dist/cwe-88-embedded-suboption-injection-submission.zip
dist/cwe-88-embedded-suboption-injection-submission.zip.sha256
```

The `dist/` tree and local binary are ignored by git. GitHub Actions performs the same test
and package build on push/pull request and publishes the generated ZIP as a workflow
artifact.

---

## 6. CWE boundary

### CWE-88 — primary focus

The attacker-controlled delimiter creates a logical command option that the caller did not
intend the receiving program to process.

### CWE-141 — strongest overlap question

CWE-141 describes the generic case where input contains delimiters that become significant
to a downstream component. The proposal does not dispute that overlap. Instead, it asks
CWE-88 to make its **program-invocation / command-option** manifestation explicit, consistent
with recent published vulnerabilities already mapped to CWE-88.

The current CWE-88 Description is also string-focused. `REVIEWER-NOTES.md` therefore treats
this as the main review question rather than hiding it: either CWE-88's Description should be
slightly generalized to cover the receiving command's logical option grammar, or the CWE
entry should at minimum contain a mapping/boundary note explaining when the single-argument
case belongs to CWE-88 versus CWE-141.

### CWE-235 — optional duplicate-handling step

The `inject-new` case contains no duplicate key and already proves the CWE-88 behavior.
Therefore duplicate processing is not required for the proposed pattern.

The `override` case separately demonstrates how an injected duplicate may become more
security-significant when the receiver accepts repeated keys and later assignment replaces
earlier state.

### CWE-78 — not required

No shell or command interpreter is involved in the demonstrator. A CWE-78 weakness could
exist downstream in some real system, but it is not required for embedded sub-option
injection.

---

## 7. Important parser note

The demonstrator uses `getsubopt()` because it makes the second-stage grammar visible and
compact. It does **not** claim that `getsubopt()` is itself vulnerable or that the function
mandates a last-wins policy.

`getsubopt()` returns sub-options sequentially. The demonstration application's assignment
logic determines the final state when a key repeats. That distinction is intentional and
should be preserved in the CWE submission wording.

---

## 8. Evidence strategy

The strongest proof is the three-way contrast:

| Case | Target `argc` | Logical options | Final result |
|---|---:|---:|---|
| control | 3 | 2 | intended options only |
| inject-new | 3 | 3 | previously absent option appears |
| override | 3 | 3 | duplicate endpoint appears; later demo assignment is final |

Thus the outer process interface is unchanged while the receiving command's logical option
set changes because of attacker-controlled delimiter data.

That is the exact ambiguity the proposed CWE-88 modification is intended to remove.

---

## 9. Submission posture

The strongest form of the submission is intentionally conservative:

> Recent vulnerabilities already assigned CWE-88 demonstrate command option injection in
> which OS-level argument boundaries remain intact but a receiving command reparses one
> argument as a delimiter-separated option language. The requested modification aligns
> CWE-88's wording, mitigation guidance, and examples with that observed mapping practice
> while explicitly bounding overlap with CWE-141 and CWE-235.

This is a **CWE content-improvement request**, not a claim that delimiter injection or
parameter pollution is a newly discovered attack category.
