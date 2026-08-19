"""Positive fixture (interprocedural).

Same CWE-88 embedded sub-option injection shape as vulnerable.py, but the
constructed option-argument is handed to a small launch wrapper that many
callers would share. The construction and the process launch are in different
functions, so only the interprocedural (taint-tracking) rule flags it; the
intra-procedural rule misses it.
"""

import subprocess


def launch(target, option_argument):
    subprocess.run([target, "-o", option_argument], shell=False, check=False)


def handle(target, external_value):
    option_argument = "endpoint=trusted.example,id=" + external_value
    launch(target, option_argument)
