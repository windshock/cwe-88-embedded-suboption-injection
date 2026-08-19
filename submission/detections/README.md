# Static Detection Rules for CWE-88 Embedded Sub-option Injection

This directory contains static-analysis rules for the CWE-88 modification
package. The rules target the product-independent weakness class demonstrated by
the repository's PoC (`../poc/web_app.py` builds the vulnerable option-argument):

1. an externally influenced value is embedded into **one** delimiter-structured
   option-argument — a comma-separated `key=value` option grammar, e.g.
   `endpoint=trusted.example,id=<INPUT>`;
2. the delimiter that is significant to that grammar is **not neutralized**; and
3. the string is passed to a **non-shell** process launcher through an argument
   array (so the OS-level argument count does not change and no shell tokenizes
   it), where the receiving command reparses it and an attacker-controlled
   delimiter can create an additional logical option.

The rules do not claim to find every argument injection. They are specialized to
this shape: the **detection source** is the option-template construction (a
literal that contains both a `,` and an `=`, combined with a non-constant part),
and the **detection sink** is that value reaching a process-launcher argument.

## Two detection tiers

Real code rarely launches the process in the same function that builds the
command. The constructed value is usually handed to a small **launch wrapper**
that many callers share. A rule that requires the construction and the launch in
one function body misses this. So two tiers are shipped per language:

| Tier | Engine | Scope | Catches wrapper idiom? |
|------|--------|-------|------------------------|
| `semgrep/*.yml` | Semgrep | intra-procedural | No |
| `codeql/<lang>/embedded-suboption-injection.ql` | CodeQL | intra-procedural (`localFlow`) | No |
| `codeql/<lang>/embedded-suboption-injection-interprocedural.ql` | CodeQL | interprocedural (taint through the wrapper) | **Yes** |

## Languages

Rules are provided for the four ecosystems where this construction commonly
occurs (and where published CWE-88 CVEs live): **Python, Java, JavaScript/Node,
and C**. The vulnerable construction differs per language but the shape is
identical:

| Language | Construction | Non-shell launcher sink |
|----------|--------------|-------------------------|
| Python | `"...,id=" + x` / f-string / `%` | `subprocess.*`, `os.exec*`/`posix_spawn*` |
| Java | `"...,id=" + x` / `String.format` | `ProcessBuilder`, `Runtime.exec(String[])` |
| JavaScript | `` `...,id=${x}` `` / concat | `child_process.execFile`/`spawn`(`Sync`) |
| C | `snprintf(buf, n, "...,id=%s", x)` | `execv`/`execvp`/`execlp`/`posix_spawn` |

## Layout

```
detections/
├─ README.md
├─ semgrep/
│  ├─ cwe88_embedded_suboption_injection_python.yml
│  ├─ cwe88_embedded_suboption_injection_java.yml
│  ├─ cwe88_embedded_suboption_injection_js.yml
│  └─ cwe88_embedded_suboption_injection_c.yml
├─ codeql/
│  ├─ python/  { qlpack.yml, embedded-suboption-injection.ql, embedded-suboption-injection-interprocedural.ql }
│  ├─ java/    { ... }
│  ├─ javascript/ { ... }
│  └─ cpp/     { ... }
├─ fixtures/
│  ├─ python/  { vulnerable.py, vulnerable_wrapped.py, safe_fixed.py }
│  ├─ java/    { Vulnerable.java, VulnerableWrapped.java, SafeFixed.java }
│  ├─ javascript/ { vulnerable.js, vulnerable_wrapped.js, safe_fixed.js }
│  └─ c/       { vulnerable.c, vulnerable_wrapped.c, safe_fixed.c }
└─ test/
   ├─ run-semgrep.sh
   └─ run-codeql.sh
```

For each language: `vulnerable` builds the option template and launches it in one
function; `vulnerable_wrapped` builds it and launches through a shared wrapper
(different function); `safe_fixed` passes the untrusted field as its own
independent argument with no embedded delimiter grammar.

## Expected detection matrix

For every language, the rules produce the same matrix. This is verified by the
two test scripts.

| fixture | Semgrep | CodeQL intra | CodeQL interprocedural |
|---------|:-------:|:------------:|:----------------------:|
| `vulnerable`         | 1 | 1 | 1 |
| `vulnerable_wrapped` | **0 (missed — wrapper)** | **0 (missed — wrapper)** | **1 (flagged across the wrapper)** |
| `safe_fixed`         | 0 | 0 | 0 |

The `vulnerable_wrapped` row is the point of the suite: the interprocedural
CodeQL query catches a shared launch wrapper that the intra-procedural rule and
Semgrep both miss.

## Running the tests

```sh
bash submission/detections/test/run-semgrep.sh
bash submission/detections/test/run-codeql.sh
```

- `run-semgrep.sh` runs each Semgrep rule against its fixtures and asserts the
  intra-procedural column. Override the tool with `SEMGREP=/path/to/semgrep`.
- `run-codeql.sh` builds one CodeQL database per language and runs both queries,
  asserting the full matrix. Override with `CODEQL=/path/to/codeql`.

The fixtures are self-contained (Python/JavaScript need no build; the Java and C
fixtures declare their own prototypes so CodeQL's `--build-mode=none` extraction
is complete), so **no compiler is required** to reproduce the tests. The scripts
run only static analysis against the fixture files; they do not run the PoC or
any product binary.

### Tool versions

These rules were authored and verified with **Semgrep 1.78.0** and **CodeQL
2.26.3** (library packs: `python-all`, `java-all`, `javascript-all`, `cpp-all`).
A current CodeQL CLI is required: older CLIs (e.g. 2.17.x) cannot fetch the
current standard-library packs. The pinned pack versions are recorded in each
language's `codeql-pack.lock.yml`.

## Note on scanning a real codebase

These fixtures isolate the weakness shape; pointing the queries at a real product
is more involved. Interprocedural detection requires (a) a database built with
the project's real dependencies and build/extraction settings, and (b) taint
tracking that follows the constructed option-argument across the launch wrapper —
which is exactly what the interprocedural query and the `vulnerable_wrapped`
fixtures model here. For interpreted languages the source root is usually
sufficient; for compiled languages, prefer a real build over `--build-mode=none`
so that feature code behind build flags is extracted.

## What these rules do not claim

- that every delimiter-separated argument is vulnerable;
- that a shell is involved (it is deliberately not);
- that duplicate options are required (the `vulnerable` fixtures inject a new,
  previously absent option); or
- that any specific vendor product is vulnerable.

They exist to show that the generalized CWE-88 weakness class proposed for
clearer documentation is machine-detectable, and to give mappers and tool
authors a concrete, reproducible starting point.
