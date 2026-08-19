# CWE-88 Modification — Embedded Sub-option Injection

This repository contains **product-independent** research, a generalized demonstrator, and
submission material for a proposed modification to **CWE-88: Improper Neutralization of
Argument Delimiters in a Command ('Argument Injection')**.

The proposal focuses on a recurring argument-injection shape that is easy to miss when a
process is launched with a structured argument array and no shell: **one OS-level argument
can itself contain a delimiter-separated option language, and untrusted data embedded
inside one field can inject additional logical options that are parsed by the receiving
program.**

> **Status.** This proposal is being prepared and has **not yet been submitted to or
> accepted by the CWE Program**. This repository is not affiliated with or endorsed by
> MITRE.

## Core claim

> **CWE-88 should explicitly cover cases in which externally controlled data is embedded
> within a single command-line argument whose value is parsed by the receiving component
> as a delimiter-separated option grammar, allowing attacker-controlled delimiters to
> create additional logical options even when no new OS-level `argv` element is created.**

## Why this clarification matters

A common mitigation for argument injection is to avoid a shell command string and invoke a
program with a structured argument array. That is important, but it is **not sufficient**
when the receiving program defines its own grammar inside one argument.

For example:

```text
argv[0] = "demo-target"
argv[1] = "-o"
argv[2] = "endpoint=trusted.example,id=<UNTRUSTED>"
```

If `-o` is a comma-delimited option list, an input such as:

```text
42,endpoint=attacker.example
```

can cause the receiver to interpret the single `argv[2]` value as:

```text
endpoint=trusted.example
id=42
endpoint=attacker.example
```

The OS-level argument count did not change. No shell expansion was required. The injection
occurred in a **second-stage parser inside the receiving command**.

## Generalized demonstrator

The repository contains a small, self-contained demonstration written specifically for this
CWE proposal:

- [`submission/poc/caller.py`](submission/poc/caller.py) invokes a target with a Python
  argument list and `shell=False`;
- [`submission/poc/demo_target.c`](submission/poc/demo_target.c) receives one `-o`
  option-argument and parses it as a comma-separated `getsubopt()` language; and
- [`submission/scripts/run_demo.sh`](submission/scripts/run_demo.sh) builds the target and
  verifies one control and two positive cases.

Run it on a POSIX-like environment with `cc` and Python 3:

```sh
bash submission/scripts/run_demo.sh
```

The three cases intentionally prove different points:

| Case | Target `argc` | Logical options | Result |
|---|---:|---:|---|
| `control` | 3 | 2 | only intended `endpoint` and `id` |
| `inject-new` | 3 | 3 | attacker delimiter creates previously absent `log_target` |
| `override` | 3 | 3 | attacker delimiter creates duplicate `endpoint`; demo assignment leaves the later value |

The key invariant is **`argc=3` in all cases**. The outer OS argument vector is unchanged,
but the target's logical option set changes after it reparses the contents of `argv[2]`.

See [`submission/EXPECTED-RESULTS.md`](submission/EXPECTED-RESULTS.md) and the captured
[`submission/evidence/`](submission/evidence/) for exact assertions and a reference run.

The demonstrator has no network side effects, does not launch a shell, uses no vendor code,
and treats `trusted.example` / `attacker.example` only as inert documentation strings.

## Published precedent

This is not merely a theoretical interpretation. Published vulnerabilities already mapped
to **CWE-88** show the same broad shape:

- **CVE-2026-40113 (PraisonAI):** a Python subprocess argument passed as one complete
  `--set-env-vars` value is later split by `gcloud` on commas, creating additional
  `KEY=VALUE` definitions. The reviewed advisory explicitly explains that the vulnerable
  value remains one argument and shell parsing is not involved.
- **CVE-2026-6437 (Amazon EFS CSI Driver):** attacker-controlled comma-separated text is
  parsed by the mount utility as additional mount options.
- **CVE-2026-41013 (Cloud Foundry):** tenant-controlled comma injection smuggles additional
  CIFS mount options and is assigned CWE-88.

An older conceptual precedent is **Connection String Parameter Pollution (CSPP)** from
Black Hat DC 2010, which demonstrated delimiter injection and duplicate-parameter override
in connection-string grammars. It is used here as historical parser-pattern precedent, not
as a historical CWE-88 mapping claim.

See [`submission/PRECEDENTS.md`](submission/PRECEDENTS.md) for the detailed evidence and
CWE-boundary analysis.

## Proposed CWE-88 changes

The submission proposes a modification rather than a new CWE:

1. **Description** — consider removing the string-only implementation assumption so CWE-88
   can describe arguments/options interpreted by a receiving command even when the caller
   preserves OS-level argument boundaries.
2. **Extended Description** — explicitly state that an argument delimiter can belong to an
   embedded grammar inside one OS-level argument, so argument injection does not require
   creating an additional `argv` element.
3. **Potential Mitigations** — clarify that argument-array APIs remain highly effective for
   outer argument boundaries but do not protect fields that are subsequently parsed as a
   delimiter-separated option language by the receiver.
4. **Demonstrative Example** — add a product-independent example in which an untrusted field
   injects a sibling logical option into a single `-o` argument.
5. **Mapping / boundary guidance** — distinguish the command-specific CWE-88 case from the
   broader delimiter weakness in **CWE-141** and from duplicate-parameter handling in
   **CWE-235**.

The concise Markdown submission draft is in
[`submission/FORM-TEXT.md`](submission/FORM-TEXT.md), with a direct copy/paste plain-text
version in [`submission/form-description.txt`](submission/form-description.txt).
The longer field-by-field rationale is in
[`submission/modification-details.md`](submission/modification-details.md), and the most
likely reviewer objections are stress-tested in
[`submission/REVIEWER-NOTES.md`](submission/REVIEWER-NOTES.md).

## CWE boundary in one diagram

```text
externally controlled value
          |
          v
single command-line argument
"endpoint=trusted,id=<INPUT>"
          |
          | embedded delimiter is not neutralized
          v
recipient parses internal option grammar           <- CWE-88 focus
          |
          +--> previously absent logical option
          |
          +--> duplicate security-sensitive option
                         |
                         v
                 duplicate resolution               <- CWE-235 may co-occur
```

**CWE-141** is the strongest overlap question because it already describes generic
parameter/argument delimiter neutralization across upstream/downstream component boundaries.
This proposal does not attempt to replace it. The argument for CWE-88 is narrower:
**program invocation and command-option processing**, backed by recent published CWE-88
mappings.

The `inject-new` case is important because it proves that **CWE-235 is not required**: a new
logical option is injected even when no duplicate exists. The `override` case then shows how
duplicate handling can amplify the impact.

## Important parser note

The demonstrator uses `getsubopt()` as a compact sub-option parser. The proposal does **not**
claim that `getsubopt()` itself defines a last-wins duplicate policy. It returns sub-options
sequentially; the demonstration program's repeated assignment to its configuration state is
what makes the later `endpoint` value final.

## Product-independent scope

This repository intentionally does **not** contain:

- a vendor product binary;
- vendor source code;
- vendor-specific hashes, credentials, production endpoints, or signatures; or
- an exploit package for a non-public product vulnerability.

A concrete product instance belongs in its own coordinated disclosure process and can be
referenced later only when public and appropriate. See [`NOTICE.md`](NOTICE.md).

Before packaging, [`tools/validate-submission.sh`](tools/validate-submission.sh) automatically
checks the required files, verifies the PoC integrity manifest, rejects compiled artifacts,
and fails if identifiers from the separately coordinated product report accidentally appear
inside the canonical generalized submission material.

## Repository layout

```text
.
├── .github/workflows/generalized-demo.yml
├── .gitignore
├── LICENSE
├── NOTICE.md
├── README.md
├── tools/
│   ├── make-submission.sh
│   └── validate-submission.sh
└── submission/
    ├── README.md
    ├── FORM-TEXT.md
    ├── form-description.txt
    ├── modification-details.md
    ├── PRECEDENTS.md
    ├── REVIEWER-NOTES.md
    ├── SUBMISSION-CHECKLIST.md
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

## Validate and build the submission ZIP

Run the submission hygiene checks directly with:

```sh
bash tools/validate-submission.sh
```

Then build the package:

```sh
bash tools/make-submission.sh
```

The package builder reruns the validation and generalized demo before creating:

```text
dist/cwe-88-embedded-suboption-injection-submission.zip
dist/cwe-88-embedded-suboption-injection-submission.zip.sha256
```

GitHub Actions performs the same verification on push/pull request and uploads the generated
package as a workflow artifact. The workflow also supports **manual dispatch**, so a clean
submission ZIP can be generated on demand from the repository state. The compiled target and
`dist/` output are generated artifacts and are excluded by `.gitignore`.

For the final pre-submit and post-receipt procedure, use
[`submission/SUBMISSION-CHECKLIST.md`](submission/SUBMISSION-CHECKLIST.md).

## Primary references

- CWE-88 — https://cwe.mitre.org/data/definitions/88.html
- CWE-141 — https://cwe.mitre.org/data/definitions/141.html
- CWE-235 — https://cwe.mitre.org/data/definitions/235.html
- CAPEC-137 Parameter Injection — https://capec.mitre.org/data/definitions/137.html
- CAPEC-460 HTTP Parameter Pollution — https://capec.mitre.org/data/definitions/460.html
- CWE content submission process — https://cwe.mitre.org/community/submissions/overview.html
- CVE-2026-40113 — https://nvd.nist.gov/vuln/detail/CVE-2026-40113
- CVE-2026-6437 — https://aws.amazon.com/security/security-bulletins/2026-016-aws/
- CVE-2026-41013 — https://www.cloudfoundry.org/blog/cve-2026-41013-tenant-controlled-comma-smuggles-arbitrary-cifs-mount-options-2/
- Black Hat DC 2010 CSPP white paper — https://www.blackhat.com/presentations/bh-dc-10/Alonso_Chema/Blackhat-DC-2010-Alonso-Connection-String-Parameter-Pollution-wp.pdf
