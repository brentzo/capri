#!/usr/bin/env python3
"""Intentionally vulnerable stand-in web app for the Docker sandbox range (HC-SUB-01).

This is a deliberately-insecure target, run ONLY inside the egress-denied range so the
harness has real web vulnerabilities to find and independently confirm:
  - /search?q=   reflects the query parameter into HTML with no encoding (reflected XSS).
  - /item?id=    concatenates the id into a SQL query (boolean-blind SQL injection).
  - /login?user= issues a JWT for that user (a toy issuer, no password).
  - /account?id= returns an account to any authenticated caller with no ownership check
                 (broken object-level authorization / IDOR).
It is seeded into a target container at provision time (not baked into the golden image)
and is never reachable off the range.

Never deploy this anywhere reachable. Standard library only, so it runs on the tiny base.
"""
import base64
import hashlib
import hmac
import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

_PAGE = "<!doctype html><title>hc-shop</title><body><h1>hc-shop</h1>"
_JWT_SECRET = b"hc-very-secret-key"

# A tiny in-memory catalog, so the SQL-injectable endpoint has real rows to leak.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.executescript(
    "CREATE TABLE items(id INTEGER, name TEXT);"
    "INSERT INTO items VALUES (1,'widget'),(2,'gadget'),(3,'gizmo');")


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_dec(txt):
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def _jwt_issue(claims):
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps(claims).encode())
    sig = _b64u(hmac.new(_JWT_SECRET, ("%s.%s" % (head, payload)).encode(), hashlib.sha256).digest())
    return "%s.%s.%s" % (head, payload, sig)


def _jwt_verify(token):
    try:
        head, payload, sig = token.split(".")
        header = json.loads(_b64u_dec(head))
        claims = json.loads(_b64u_dec(payload))
        # VULNERABLE BY DESIGN: honors alg "none", accepting an unsigned token whose
        # claims the caller forged (JWT algorithm confusion). A correct verifier would
        # reject alg "none" outright and only trust a signature it recomputed.
        if header.get("alg") == "none":
            return claims
        expected = _b64u(hmac.new(_JWT_SECRET, ("%s.%s" % (head, payload)).encode(),
                                  hashlib.sha256).digest())
        if hmac.compare_digest(expected, sig):
            return claims
    except Exception:
        return None
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep the range quiet
        pass

    def _respond(self, status, text, ctype="text/html; charset=utf-8"):
        body = text.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlparse(self.path)
        query = parse_qs(parts.query)
        if parts.path == "/search":
            q = (query.get("q") or [""])[0]
            # VULNERABLE BY DESIGN: q is written into the HTML with no encoding, so an
            # injected "><svg ...> breaks out of the text and reflects as live markup.
            self._respond(200, _PAGE + "<p>No results for: " + q + "</p>")
        elif parts.path == "/item":
            item_id = (query.get("id") or ["1"])[0]
            # VULNERABLE BY DESIGN: id is concatenated into the query, so a boolean
            # condition (AND 1=1 vs AND 1=2) changes the result set it returns.
            try:
                rows = _DB.execute("SELECT name FROM items WHERE id = " + item_id).fetchall()
                inner = "".join("<li>" + r[0] + "</li>" for r in rows) if rows else "no item"
            except Exception:                 # a broken injection errors; stays distinct
                inner = "query error"
            self._respond(200, _PAGE + "<ul>" + inner + "</ul>")
        elif parts.path == "/login":
            uid = (query.get("user") or ["1"])[0]
            # A toy login with no password, enough to hand out an identity for the
            # authorization techniques to carry.
            self._respond(200, _jwt_issue({"sub": uid, "role": "user"}), "text/plain")
        elif parts.path == "/account":
            auth = self.headers.get("Authorization", "")
            claims = _jwt_verify(auth[7:]) if auth.startswith("Bearer ") else None
            if not claims:
                self._respond(401, "unauthorized", "text/plain")
                return
            # VULNERABLE BY DESIGN: the requested account is returned to any authenticated
            # caller with no check that they own it, so user 1 can read user 2's account.
            acct = (query.get("id") or [str(claims.get("sub", "1"))])[0]
            self._respond(200, "account %s: secret-%s" % (acct, acct), "text/plain")
        elif parts.path == "/admin":
            auth = self.headers.get("Authorization", "")
            claims = _jwt_verify(auth[7:]) if auth.startswith("Bearer ") else None
            if not claims:
                self._respond(401, "unauthorized", "text/plain")
                return
            # VULNERABLE BY DESIGN: an admin-only function with no role check, so any
            # authenticated user (role "user") reaches it (broken function-level authz).
            self._respond(200, "admin panel: accounts 1,2,3 secrets exposed", "text/plain")
        else:
            self._respond(200, _PAGE + "<p>Try /search?q=... /item?id=... /account?id=...</p>")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
