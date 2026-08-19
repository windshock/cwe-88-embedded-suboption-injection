"""Negative fixture.

The untrusted field is represented as its own independent argument with no
embedded delimiter grammar, so it cannot be reinterpreted as a sibling option.
There is no comma/equals option template built from external data, so neither
the intra-procedural nor the interprocedural rule should flag it.
"""

import subprocess


def handle(target, external_value):
    # Each logical field is passed as a separate argument. The receiving command
    # never reparses a delimiter-structured value built from untrusted input.
    subprocess.run(
        [target, "--endpoint", "trusted.example", "--id", external_value],
        shell=False,
        check=False,
    )
