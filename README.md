# CWE-88 Modification — Embedded Sub-option Injection

This repository contains **product-independent** research, a generalized demonstrator, and
submission material for a proposed modification to **CWE-88: Improper Neutralization of
Argument Delimiters in a Command ('Argument Injection')**.

The proposal focuses on a recurring argument-injection shape that is easy to miss when a
process is launched with a structured argument array and no shell: **one OS-level argument
can itself contain a delimiter-separated sub-option language, and untrusted data embedded
inside one field can inject additional logical options that are parsed by the receiving
program.**

> **Status.** This proposal is being prepared and has **not yet been submitted to or
> accepted by the CWE Program**. This repository is not affiliated with or endorsed by
> MITRE.

## Core claim

> **CWE-88 should explicitly cover cases in which externally controlled data is embedded
> within a single command-line argument whose value is parsed by the receiving component
> as a delimiter-separated sub-option language, allowing attacker-controlled delimiters to
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

If `-o` is a comma-delimited sub-option list, an input such as:

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

The repository now contains a small, self-contained demonstration written specifically for
this CWE proposal:

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

See [`submission/EXPECTED-RESULTS.md`](submission/EXPECTED-RESULTS.md) for exact assertions.

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

The submission proposes targeted clarification rather than a new CWE:

1. **Extended Description** — explicitly state that an argument delimiter can belong to an
   embedded grammar inside one OS-level argument, so argument injection does not require
   creating an additional `argv` element.
2. **Potential Mitigations** — clarify that argument-array APIs alone do not protect values
   that are subsequently parsed as delimiter-separated option lists; the receiving
   command's documented argument grammar must also be respected.
3. **Demonstrative Example** — add a product-independent example in which an untrusted field
   injects a sibling sub-option into a single `-o` argument.
4. **Boundary notes** — distinguish the command-specific CWE-88 case from the broader
   delimiter weakness in **CWE-141** and from duplicate-parameter handling in **CWE-235**.

Field-by-field proposed wording is in
[`submission/modification-details.md`](submission/modification-details.md).

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
recipient parses internal sub-option grammar       <- CWE-88 focus
          |
          +--> previously absent logical option
          |
          +--> duplicate security-sensitive option
                         |
                         v
                 duplicate resolution               <- CWE-235 may co-occur
```

**CWE-141** overlaps at the broader delimiter-neutralization axis. This proposal does not
try to replace CWE-141; it documents the **command/option-specific** manifestation already
seen in CWE-88 mappings.

The `inject-new` case is important because it proves that **CWE-235 is not required**: a new
logical option is injected even when no duplicate exists. The `override` case then shows how
duplicate handling can amplify the impact.

## Important parser note

The demonstrator uses `getsubopt()` as a compact standardized-style sub-option parser. The
proposal does **not** claim that `getsubopt()` itself defines a last-wins duplicate policy.
It returns sub-options sequentially; the demonstration program's repeated assignment to its
configuration state is what makes the later `endpoint` value final.

## Product-independent scope

This repository intentionally does **not** contain:

- a vendor product binary;
- vendor source code;
- vendor-specific hashes, credentials, production endpoints, or signatures; or
- an exploit package for a non-public product vulnerability.

A concrete product instance belongs in its own coordinated disclosure process and can be
referenced later only when public and appropriate. See [`NOTICE.md`](NOTICE.md).

## Repository layout

```text
.
├── .github/workflows/generalized-demo.yml
├── .gitignore
├── LICENSE
├── NOTICE.md
├── README.md
└── submission/
    ├── README.md
    ├── modification-details.md
    ├── PRECEDENTS.md
    ├── EXPECTED-RESULTS.md
    ├── poc/
    │   ├── caller.py
    │   └── demo_target.c
    └── scripts/
        └── run_demo.sh
```

The GitHub Actions workflow runs the same generalized demonstrator on each push and pull
request. The compiled target is a generated local artifact and is excluded by `.gitignore`.

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
