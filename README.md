# CWE-88 Modification — Embedded Sub-option Injection

This repository contains **product-independent** research and submission material for a
proposed modification to **CWE-88: Improper Neutralization of Argument Delimiters in a
Command ('Argument Injection')**.

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

If `-o` is documented as a comma-delimited sub-option list, an input such as:

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

This is not merely hypothetical. Published vulnerabilities already mapped to **CWE-88**
show this shape:

- **CVE-2026-40113 (PraisonAI):** a Python subprocess argument passed as one complete
  `--set-env-vars` value was later split by `gcloud` on commas, creating additional
  `KEY=VALUE` definitions. The reviewed advisory explicitly notes that `shell=True` was
  not involved.
- **CVE-2026-6437 (Amazon EFS CSI Driver):** comma-separated attacker-controlled text was
  parsed by the mount utility as additional mount options.
- **CVE-2026-41013 (Cloud Foundry):** tenant-controlled comma injection smuggled additional
  CIFS mount options and was assigned CWE-88 by the CNA.

An older conceptual precedent is **Connection String Parameter Pollution (CSPP)** from
Black Hat DC 2010, which showed the same delimiter-injection + duplicate-parameter +
last-occurrence-override pattern in connection strings rather than command arguments.

See [`submission/PRECEDENTS.md`](submission/PRECEDENTS.md) for the detailed precedent and
CWE-boundary analysis.

## Proposed CWE-88 changes

The submission proposes targeted clarification rather than a new CWE:

1. **Extended Description** — explicitly state that an argument delimiter can belong to an
   embedded grammar inside one OS-level argument, so argument injection does not require
   creating an additional `argv` element.
2. **Potential Mitigations** — state that argument-array APIs alone do not protect values
   that are subsequently parsed as delimiter-separated option lists; the receiver's
   documented argument grammar must also be respected.
3. **Demonstrative Example** — add a product-independent example in which an untrusted field
   injects a sibling sub-option into a single `-o` argument.
4. **Boundary notes** — distinguish the command-specific CWE-88 case from the broader
   delimiter weakness in **CWE-141** and from duplicate-parameter handling in **CWE-235**.

Field-by-field proposed text is in
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
          +--> additional new option
          |
          +--> duplicate security-sensitive option
                         |
                         v
                 duplicate resolution               <- CWE-235 may co-occur
                 (e.g. later assignment wins)
```

**CWE-141** overlaps at a more general delimiter-neutralization axis: it covers input that
contains parameter/argument delimiters before being sent to a downstream component. This
proposal does not try to replace CWE-141. It documents why the **command-construction**
instance belongs explicitly in CWE-88 as well, consistent with recent CWE-88 CVE mappings.

## Product-independent scope

This repository intentionally does **not** contain:

- a vendor product binary;
- vendor source code;
- vendor-specific hashes, credentials, or production endpoints; or
- an exploit package for a non-public product vulnerability.

The planned demonstrator will be written from scratch and will model only the generalized
weakness class. Concrete product vulnerabilities belong in their own disclosure/advisory
process and can be referenced later as Selected Observed Examples only when public.

## Repository layout

```text
.
├── README.md
└── submission/
    ├── modification-details.md
    └── PRECEDENTS.md
```

The next phase will add a minimal generalized demonstrator, repeatable evidence, and the
submission packaging scripts after the wording of the CWE modification is stable.

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
