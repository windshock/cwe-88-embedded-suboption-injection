# Notice

This repository contains a **product-independent demonstrative example** and supporting
research for a proposed modification to **CWE-88: Improper Neutralization of Argument
Delimiters in a Command ('Argument Injection')**.

It does **not** contain:

- vendor source code;
- vendor binaries;
- vendor-specific hashes, credentials, endpoints, or signatures;
- confidential product information; or
- an exploit package for a specific product vulnerability.

The generalized demonstration is written from scratch. It models only this parser boundary:

```text
structured process invocation
        |
        v
one OS-level option-argument
        |
        v
delimiter-separated sub-option grammar
        |
        v
externally controlled delimiter creates an unintended logical option
```

The demonstration has no network side effect, does not invoke a shell, does not alter
system configuration, and uses reserved `.example` domain names only as inert strings.

A concrete observed instance of this weakness class, if disclosed separately under a
product's own coordinated vulnerability-disclosure process, is outside the scope of this
repository. Such an instance should be referenced in CWE material only after it is public
and appropriate to cite.

## CWE Program status

This repository is independent research material. It is **not affiliated with, sponsored
by, or endorsed by MITRE or the CWE Program**. The proposed modification is not an accepted
CWE change unless and until the CWE Program explicitly accepts it.
