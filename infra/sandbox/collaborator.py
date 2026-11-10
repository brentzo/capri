#!/usr/bin/env python3
"""In-range out-of-band collaborator for the Docker sandbox range (HC-SUB-01).

This is harness infrastructure, not a target. It logs every inbound request's path and
client address to a file, so the harness can confirm out of band that a range target made
a server-side request to it, which is how a server-side request forgery (SSRF) is proved
when egress is denied and there is nothing off the range to call.

It runs ONLY inside the egress-denied range and is never in scope: the attacker's scope
guard allows only the pinned targets, so the agent cannot reach it, and the harness reads
its log with `docker exec`, not over the network. A forged request from a target carries a
random token the harness picked, so the model can neither forge the inbound hit nor read
the log. Standard library only, so it runs on the tiny base image.

Never deploy this anywhere reachable.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

_LOG = "/tmp/hits.log"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep the range quiet
        pass

    def _record(self):
        # Append the requested path and the caller's address, so the harness can read back
        # both which token was requested and that the request came from the target.
        try:
            with open(_LOG, "a", encoding="utf-8") as fh:
                fh.write("%s %s\n" % (self.path, self.client_address[0]))
        except OSError:
            pass
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
