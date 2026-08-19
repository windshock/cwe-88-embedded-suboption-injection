# Captured Evidence

This directory contains a reference capture from the **product-independent** CWE-88
generalized demonstrator.

- `build_log.txt` records the toolchain and successful local compilation.
- `run_demo.txt` records the negative control, new-sub-option injection case, and duplicate
  override case.
- `sha256.txt` is the integrity manifest for the three core demonstrator files.

The important invariant in `run_demo.txt` is:

```text
control:     target argc=3, parsed_options=2
inject-new:  target argc=3, parsed_options=3
override:    target argc=3, parsed_options=3
```

Thus the receiving process obtains the same number of OS-level arguments in all three
cases, while attacker-controlled delimiter data changes the number and meaning of logical
options parsed **inside one argument**.

The `override` case additionally shows two occurrences of `endpoint`, with the demo's own
repeated assignment logic leaving `attacker.example` as the final value. This is not a
claim that `getsubopt()` defines a last-wins policy; the precedence is produced by the
example program's state update.

## Reproduce / refresh

From the repository root:

```sh
bash submission/scripts/capture_evidence.sh
```

Or simply validate behavior without replacing the captured files:

```sh
bash submission/scripts/run_demo.sh
```

The GitHub Actions workflow independently compiles and runs the generalized demonstrator on
push and pull request.

No evidence file contains vendor binaries, vendor source, credentials, network captures, or
product-specific payloads.
