# Expected Results — CWE-88 Embedded Sub-option Injection

This document defines the expected output of the product-independent demonstrator under
`submission/poc/`.

The demonstrator models the front-end intake explicitly. `poc/web_app.py` starts a small
web application on the loopback interface and issues one HTTP request whose `id` parameter
carries the externally controlled value. The web application (the CWE-88 weak product) then
embeds that value into a single `-o` option-argument **without neutralizing the sub-option
delimiter** and invokes `poc/demo_target` with a structured argument array and `shell=False`.

The test intentionally separates three properties:

1. a negative control with no embedded delimiter;
2. injection of a previously absent logical sub-option; and
3. injection of a duplicate security-sensitive sub-option whose later assignment replaces
   the earlier state in this demonstration parser.

The demonstrator performs **no external network egress** (only a single loopback HTTP
request), no shell execution, no privilege change, and no vendor-specific operation. Its
observable result is the web-application response body, which contains the intake markers and
the receiving parser state printed to standard output.

## Build and run

From the repository root on a POSIX-like system with a C compiler and Python 3:

```sh
bash submission/scripts/run_demo.sh
```

A successful run ends with:

```text
[PASS] all generalized CWE-88 embedded sub-option tests passed
```

and exits with status `0`.

---

## Case 1 — `control`

The external requester supplies an `id` parameter containing only ordinary data:

```text
42
```

The web application constructs one option-argument:

```text
endpoint=trusted.example,id=42
```

Expected properties:

```text
[web] request_param id=<42>
[web] delimiter_neutralization=none
[web] constructed option_argument=<endpoint=trusted.example,id=42>
[web] subprocess argv elements=3
[web] shell=False
[target] argc=3
[target] argv[2]=<endpoint=trusted.example,id=42>
[result] parsed_options=2
[result] endpoint_occurrences=1
[result] endpoint=trusted.example
[result] id=42
[result] log_target=unset
[PASS] control
```

This establishes the baseline: two intended logical sub-options are parsed from one
OS-level argument.

---

## Case 2 — `inject-new`

The fixed demonstration `id` parameter is:

```text
42,log_target=attacker.example
```

The web application still creates the same number of OS-level arguments, but the third
element now contains:

```text
endpoint=trusted.example,id=42,log_target=attacker.example
```

Expected properties:

```text
[web] request_param id=<42,log_target=attacker.example>
[web] constructed option_argument=<endpoint=trusted.example,id=42,log_target=attacker.example>
[web] subprocess argv elements=3
[web] shell=False
[target] argc=3
[target] argv[2]=<endpoint=trusted.example,id=42,log_target=attacker.example>
[result] parsed_options=3
[result] endpoint=trusted.example
[result] log_target=attacker.example
[PASS] inject-new
```

The decisive comparison with the control is:

```text
OS-level target argc:     3 -> 3
logical parsed options:   2 -> 3
```

The additional logical option therefore arises **inside the receiving command's parser**,
not from shell tokenization and not from creation of another OS-level `argv` element.

This is the core CWE-88 behavior proposed for explicit documentation.

---

## Case 3 — `override`

The fixed demonstration `id` parameter is:

```text
42,endpoint=attacker.example
```

The single option-argument becomes:

```text
endpoint=trusted.example,id=42,endpoint=attacker.example
```

Expected properties:

```text
[web] request_param id=<42,endpoint=attacker.example>
[web] constructed option_argument=<endpoint=trusted.example,id=42,endpoint=attacker.example>
[web] subprocess argv elements=3
[web] shell=False
[target] argc=3
[target] argv[2]=<endpoint=trusted.example,id=42,endpoint=attacker.example>
[result] parsed_options=3
[result] endpoint_occurrences=2
[result] endpoint=attacker.example
[PASS] override
```

This case demonstrates a possible **CWE-88 -> CWE-235-style chain**:

```text
embedded delimiter injection
        |
        v
unintended duplicate endpoint option       <- CWE-88 creation step
        |
        v
later assignment replaces earlier state    <- duplicate-handling consequence
```

The demonstration deliberately attributes last-assignment-wins to its own state-update
logic:

```c
cfg.endpoint = later_value;
```

It does **not** claim that `getsubopt()` itself defines a last-wins duplicate policy.
`getsubopt()` supplies the tokens sequentially; the application decides what repeated
assignment means.

---

## What constitutes proof for this proposal

The central invariant across all three cases is that the receiving process reports:

```text
[target] argc=3
```

The injection cases nevertheless report an increase from two to three **logical** parsed
options.

That contrast directly demonstrates the proposed clarification to CWE-88:

> argument injection can occur in an embedded sub-option grammar inside one OS-level
> argument, even when structured process invocation preserves the outer argument vector.

## What this demonstration does not prove or claim

It does not claim that:

- all delimiter-separated arguments are vulnerable;
- a shell is involved;
- duplicate options are necessary for CWE-88;
- `getsubopt()` is inherently unsafe;
- last-wins behavior is mandated by `getsubopt()`; or
- any specific vendor product is vulnerable.

The demonstrator exists only to isolate and reproduce the generalized parser-boundary
weakness proposed for clearer documentation in CWE-88.
