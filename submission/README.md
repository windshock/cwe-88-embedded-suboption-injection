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
> as a delimiter-separated option language, allowing attacker-controlled delimiters to
> create additional logical options even when no new OS-level `argv` element is created.**

The main documents are:

- [`FORM-TEXT.md`](FORM-TEXT.md) — concise Markdown text intended for the CWE submission
  form;
- [`form-description.txt`](form-description.txt) — plain-text copy/paste form content;
- [`modification-details.md`](modification-details.md) — field-by-field rationale and
  proposed CWE content;
- [`MAPPING-NOTES-PROPOSAL.md`](MAPPING-NOTES-PROPOSAL.md) — conservative fallback wording
  if the CWE Team prefers to keep the current CWE-88 Description unchanged;
- [`PRECEDENTS.md`](PRECEDENTS.md) — published CVE, CAPEC, historical, and standards
  precedents;
- [`REVIEWER-NOTES.md`](REVIEWER-NOTES.md) — likely overlap/reviewer objections and proposed
  responses;
- [`SUBMISSION-CHECKLIST.md`](SUBMISSION-CHECKLIST.md) — pre-submit, receipt, and follow-up
  checklist;
- [`EXPECTED-RESULTS.md`](EXPECTED-RESULTS.md) — exact demonstrator assertions; and
- [`evidence/`](evidence/) — captured build/run evidence and source integrity manifest.

> **Submission status.** Prepared for review; not yet submitted to or accepted by the CWE
> Program. Nothing in this repository should be interpreted as MITRE endorsement.

---

## 1. What the demonstrator proves

The demonstrator uses two programs:

- `poc/web_app.py` — models the front-end intake. In one process it runs a **simulated
  external requester** that issues an HTTP request whose `id` parameter carries the untrusted
  value, and the **vulnerable web application** that receives that parameter, embeds it into
  one `-o` option-argument without neutralizing the delimiter, and then invokes the target
  with Python's argument-list API and explicitly uses `shell=False`;
- `poc/demo_target.c` — receives exactly one `-o` option-argument and parses its contents
  with a comma-delimited `getsubopt()` grammar.

The intended structure is:

```text
intake layer (untrusted)

GET /run?id=<EXTERNAL>            <- externally controlled web request parameter
        |
        v
web application layer (CWE-88 weak product)

option_argument = "endpoint=trusted.example,id=<EXTERNAL>"   <- no delimiter neutralization
        |
        v
OS process layer (argument array, shell=False)

argv[0] = demo_target
argv[1] = -o
argv[2] = "endpoint=trusted.example,id=<EXTERNAL>"

                                 |
                                 v
receiving command layer

endpoint=<value>,id=<value>,...
        comma-delimited logical options
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

which creates a duplicate `endpoint` option. The demo's own repeated assignment logic makes
the later endpoint the final parser state. This illustrates how CWE-88 can combine with
duplicate-parameter handling similar to CWE-235, while keeping the two weaknesses
conceptually separate.

---

## 2. Why the outer argument array is not enough

The web application deliberately uses:

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
untrusted request parameter
        |
        v
web application builds one option-argument (no delimiter neutralization)
        |
        v
outer argv grammar (argument array, shell=False)
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

The proposed CWE-88 clarification is specifically about this second boundary. The intake is
included only to make the untrusted provenance explicit; a web request parameter is one
representative source among many (CLI argument, environment variable, file, message field).

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
3. runs the new-option injection case;
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

- contact any external network destination (the only network activity is a single HTTP
  request over the loopback interface, used to model the untrusted intake);
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

The repository-level `tools/validate-submission.sh` enforces this boundary before packaging:
it checks required files, verifies the core SHA-256 manifest, rejects compiled artifacts,
and fails if identifiers from the separately coordinated product report are accidentally
introduced into the canonical generalized submission material.

---

## 5. Package layout

```text
submission/
├── README.md
├── FORM-TEXT.md
├── form-description.txt
├── modification-details.md
├── MAPPING-NOTES-PROPOSAL.md
├── PRECEDENTS.md
├── REVIEWER-NOTES.md
├── SUBMISSION-CHECKLIST.md
├── EXPECTED-RESULTS.md
├── detections/            (Semgrep + CodeQL rules, fixtures, tests — Python/Java/JS/C)
├── poc/
│   ├── web_app.py
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

Validate the canonical set from the repository root:

```sh
bash tools/validate-submission.sh
```

The package builder reruns that validation and the generalized demonstrator, then creates a
ZIP containing only the canonical submission material plus the repository-level license and
scope notice:

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
artifact. The workflow also supports manual dispatch for an on-demand clean package build.

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

The ready-to-use conservative version of that fallback is in
[`MAPPING-NOTES-PROPOSAL.md`](MAPPING-NOTES-PROPOSAL.md).

### CWE-235 — optional duplicate-handling step

The `inject-new` case contains no duplicate key and already proves the CWE-88 behavior.
Therefore duplicate processing is not required for the proposed pattern.

The `override` case separately demonstrates how an injected duplicate may become more
security-significant when the receiver accepts repeated keys and later assignment replaces
earlier state.

### CWE-78 — not required

No shell or command interpreter is involved in the demonstrator. A CWE-78 weakness could
exist downstream in some real system, but it is not required for embedded option injection.

---

## 7. Important parser note

The demonstrator uses `getsubopt()` because it makes the second-stage grammar visible and
compact. It does **not** claim that `getsubopt()` is itself vulnerable or that the function
mandates a last-wins policy.

`getsubopt()` returns options sequentially. The demonstration application's assignment
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

If the CWE Team is reluctant to change the top-level Description, the fallback request is
still useful: retain the current Description and add Extended Description / Mapping Notes
text that explicitly captures the second-stage command-option grammar and its boundary with
CWE-141.

Use [`SUBMISSION-CHECKLIST.md`](SUBMISSION-CHECKLIST.md) for the final pre-submit and
post-receipt sequence.

---

## 10. Static detection rules

[`detections/`](detections/) contains product-independent Semgrep and CodeQL rules for
**Python, Java, JavaScript/Node, and C** that flag the generalized weakness: an externally
influenced value embedded into one comma-separated `key=value` option-argument and passed to
a non-shell process launcher. Each language ships an intra-procedural rule and an
interprocedural CodeQL query that also catches the shared launch-wrapper idiom, with
positive/negative fixtures and reproducible test scripts:

```sh
bash detections/test/run-semgrep.sh
bash detections/test/run-codeql.sh
```

The verified matrix is `vulnerable`=flagged, `vulnerable_wrapped`=flagged only by the
interprocedural CodeQL query, `safe_fixed`=never flagged. See
[`detections/README.md`](detections/README.md). This demonstrates that the mapping shape the
proposal asks CWE-88 to document is machine-detectable.
