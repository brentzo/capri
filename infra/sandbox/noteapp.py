"""hc-notes: a second deliberately-vulnerable practice target (HC-SUB-01 fixtures).

A different app from vulnweb, on purpose. Its routes and parameters share nothing with the
capability registry's old literals (`/item?id`, `/greet?name`, `/download?file`, `/ping?host`):
the injection points live at `/notes?tag`, `/preview?body`, `/attachment?file` and
`/net/trace?target`, reachable only by following the links on the landing page. It exists to
prove that black-box discovery plus recon-derived binding route the injection techniques at
endpoints the harness never had hard-coded, so a confirmed finding here comes from a crawl,
not from a lookup table.

The four holes reproduce exactly the behaviours the existing adapters detect (boolean SQL
oracle, server-side template arithmetic, path traversal to a planted canary, a timing-oracle
command injection), so no adapter changes are needed. The landing page exposes every injection
point as a real anchor, because the crawler follows links; a route reachable no other way would
not be found, which is the honest limit of link-driven crawling.

A fifth hole, `/vault/notes?tag`, is the same boolean SQL oracle but behind a bearer gate: it
answers 401 without `Authorization: Bearer <demo-token>` and runs the injectable query with it.
Its path and parameter are still link-discoverable, but a probe confirms the finding only when
the engagement threads a caller-supplied session onto its requests, which is what proves the
session-threading path end to end.

Never deploy this anywhere reachable. Standard library only, so it runs on the tiny target base.
"""
import os
import re
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

_PAGE = "<!doctype html><title>hc-notes</title><body><h1>hc-notes</h1>"
_TMPL_RE = re.compile(r"\{\{(.+?)\}\}")

# A public attachments dir with one legit file, plus a range canary written OUTSIDE it. The
# marker is a fixed sentinel no normal endpoint returns, so finding it in an /attachment
# response proves the path escaped the public dir. The adapter looks for it; it is never sent
# in the request, so the signal is harness-owned.
_PUBDIR = "/tmp/hcnotes_pub"
_CANARY_PATH = "/tmp/hc_canary.txt"
_CANARY_MARKER = "HC-RANGE-CANARY-d41d8cd98f00b204"

# The demo session the auth-gated route requires. The engagement supplies it as
# `session.bearer`, the harness presents it as `Authorization: Bearer <this>` on every probe,
# and only then does /vault/notes run its query instead of answering 401. A fixed opaque string
# (not a real credential); it stands in for the operator token a real run would carry.
_SESSION_TOKEN = "hc-demo-session-7f3a9c21"

# A tiny in-memory catalog so the SQL-injectable endpoint has real rows to leak.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.executescript(
    "CREATE TABLE notes(id INTEGER, body TEXT);"
    "INSERT INTO notes VALUES (1,'groceries'),(2,'standup'),(3,'ideas');")

_LINKS = ("<ul>"
          '<li><a href="/notes?tag=1">tagged notes</a></li>'
          '<li><a href="/preview?body=hello">preview</a></li>'
          '<li><a href="/attachment?file=readme.txt">attachment</a></li>'
          '<li><a href="/net/trace?target=127.0.0.1">net trace</a></li>'
          '<li><a href="/vault/notes?tag=1">vault notes (members only)</a></li>'
          "</ul>")


def _seed_files():
    try:
        os.makedirs(_PUBDIR, exist_ok=True)
        with open(os.path.join(_PUBDIR, "readme.txt"), "w", encoding="utf-8") as fh:
            fh.write("hc-notes attachments\n")
        with open(_CANARY_PATH, "w", encoding="utf-8") as fh:
            fh.write(_CANARY_MARKER + "\n")
    except OSError:
        pass


def _authorized(auth_header):
    """Whether a request carries the demo session the gated route requires."""
    return auth_header == f"Bearer {_SESSION_TOKEN}"


def _notes_query(tag):
    # VULNERABLE BY DESIGN: tag is concatenated into the query, so a boolean condition
    # (AND 1=1 vs AND 1=2) changes the result set (boolean-blind SQLi). Shared by the open
    # /notes route and the auth-gated /vault/notes route.
    try:
        rows = _DB.execute("SELECT body FROM notes WHERE id = " + tag).fetchall()
        return "".join("<li>" + r[0] + "</li>" for r in rows) if rows else "no note"
    except Exception:
        return "query error"


def _render(text):
    # VULNERABLE BY DESIGN: evaluates a {{ expression }} the caller controls (SSTI). Builtins
    # are stripped so the fixture stays bounded, but arithmetic like {{7*7}} still evaluates.
    def sub(match):
        try:
            return str(eval(match.group(1), {"__builtins__": {}}, {}))
        except Exception:
            return match.group(0)
    return _TMPL_RE.sub(sub, text)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
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
        if parts.path == "/notes":
            tag = (query.get("tag") or ["1"])[0]
            self._respond(200, _PAGE + "<ul>" + _notes_query(tag) + "</ul>")
        elif parts.path == "/vault/notes":
            # AUTH-GATED BY DESIGN: without the bearer the route is 401, so a probe that does
            # not carry the caller session sees no SQL at all. With it, the same boolean-blind
            # SQLi runs - so a confirmed finding here proves the session reached the probe.
            if not _authorized(self.headers.get("Authorization")):
                self._respond(401, _PAGE + "<p>members only</p>")
                return
            tag = (query.get("tag") or ["1"])[0]
            self._respond(200, _PAGE + "<ul>" + _notes_query(tag) + "</ul>")
        elif parts.path == "/preview":
            body = (query.get("body") or ["guest"])[0]
            # VULNERABLE BY DESIGN: body is rendered through the template engine, so an
            # injected {{ expression }} is evaluated server-side (SSTI).
            self._respond(200, _render(_PAGE + "<p>Preview: " + body + "</p>"))
        elif parts.path == "/attachment":
            fname = (query.get("file") or ["readme.txt"])[0]
            # VULNERABLE BY DESIGN: the caller's path is joined to the public dir and read
            # with no containment check, so "../" walks out and reads any file (path traversal).
            target = os.path.normpath(os.path.join(_PUBDIR, fname))
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as fh:
                    self._respond(200, fh.read(65536), "text/plain")
            except OSError:
                self._respond(404, "not found", "text/plain")
        elif parts.path == "/net/trace":
            target = (query.get("target") or ["127.0.0.1"])[0]
            # VULNERABLE BY DESIGN: target is interpolated into a shell command with no
            # validation, so "; sleep N" runs as a second command (OS command injection). A
            # timeout caps a runaway sleep so the fixture cannot hang the range.
            try:
                out = subprocess.run(["sh", "-c", "echo tracing " + target],
                                     capture_output=True, text=True, timeout=30).stdout
            except Exception:
                out = "trace failed"
            self._respond(200, out, "text/plain")
        else:
            self._respond(200, _PAGE + "<p>notes workspace</p>" + _LINKS)


def main():
    _seed_files()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
