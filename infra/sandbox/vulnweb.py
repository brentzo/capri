#!/usr/bin/env python3
"""Intentionally vulnerable stand-in web app for the Docker sandbox range (HC-SUB-01).

This is a deliberately-insecure target, run ONLY inside the egress-denied range so the
harness has a real web vulnerability to find and independently confirm. It reflects the
`q` query parameter into the response HTML with no output encoding, which is a textbook
reflected cross-site scripting hole. It is seeded into a target container at provision
time (not baked into the golden image) and is never reachable off the range.

Never deploy this anywhere reachable. Standard library only, so it runs on the tiny base.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

_PAGE = "<!doctype html><title>hc-shop</title><body><h1>hc-shop</h1>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep the range quiet
        pass

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/search":
            q = (parse_qs(parts.query).get("q") or [""])[0]
            # VULNERABLE BY DESIGN: q is written into the HTML with no encoding, so an
            # injected "><svg ...> breaks out of the text and reflects as live markup.
            html = _PAGE + "<p>No results for: " + q + "</p>"
        else:
            html = _PAGE + "<p>Try /search?q=...</p>"
        body = html.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
