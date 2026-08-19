"""Positive fixture (intra-procedural).

CWE-88 embedded sub-option injection: an externally controlled field is
concatenated into ONE delimiter-structured option-argument (comma-separated
key=value grammar) and passed to a process launcher with a structured argument
list. No shell is involved and the OS-level argument count does not change, but
the receiving command reparses the value and an attacker-controlled delimiter
can create an additional logical option.

The construction and the launch are in the same function, so the
intra-procedural rule flags it.
"""

import subprocess


def handle(target, external_value):
    # The untrusted field is embedded into a comma/equals option template
    # without neutralizing the sub-option delimiter.
    option_argument = "endpoint=trusted.example,id=" + external_value
    subprocess.run([target, "-o", option_argument], shell=False, check=False)
