"""The local run dashboard (HC-REPORT-01 §6).

`capri dashboard` serves a read-only web view of the runs a self-hoster has accumulated under
`~/.capri/`, so the operator can browse past engagements, read each one's report, and inspect
its audit trail. It is served by the standard-library `http.server`, binds to the loopback
interface only (never 0.0.0.0), performs no egress, and runs no tool: it only reads the
persisted store, which keeps it outside the sandbox threat model entirely. Every dynamic value
is HTML-escaped, so target strings and any model-authored text render as inert text.

The routing and rendering are a pure function of the store (`route`), separated from the socket
I/O, so they are unit-tested with no server bound. The report page reuses `report_render`
(HC-REPORT-01 §5); the run list, reasoning, and audit pages are rendered here. The reasoning
view shows each role's verbatim proposal (HC-REPORT-01 §3) as escaped, display-only text, the
Operator's turns and the Verifier's kept visibly distinct so the two independent sessions are
never merged into one voice. The per-finding raw-evidence view (HC-REPORT-01 §4) is next.
"""
import argparse
import html
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from harness import report_render
from harness.store import datadir, db, engagements

_HOST = "127.0.0.1"   # loopback only; a run history is never exposed on the network

_STYLE = (
    "<style>"
    ":root{color-scheme:light dark}"
    "body{font:16px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;"
    "max-width:60rem;margin:0 auto;padding:2rem 1rem;color:#1b1f24;background:#fff}"
    "h1{font-size:1.5rem}a{color:#1a5fb4;text-decoration:none}a:hover{text-decoration:underline}"
    ".meta{color:#5b6470;font-size:.9rem}"
    ".row{display:flex;gap:1rem;align-items:baseline;padding:.6rem 0;border-bottom:1px solid #e3e7ec}"
    ".row .id{font-weight:600;flex:1}"
    ".badge{display:inline-block;padding:.05rem .5rem;border-radius:1rem;color:#fff;font-size:.75rem}"
    "table{border-collapse:collapse;width:100%;font-size:.9rem}"
    "td,th{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #e3e7ec;vertical-align:top}"
    "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}"
    ".ok{color:#2f6f4e;font-weight:600}.bad{color:#b00020;font-weight:600}"
    ".turn{border:1px solid #e3e7ec;border-radius:.5rem;padding:.75rem 1rem;margin:.75rem 0}"
    ".turn h3{font-size:.95rem;margin:0 0 .4rem;display:flex;gap:.6rem;align-items:baseline;flex-wrap:wrap}"
    ".sid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.75rem;color:#5b6470}"
    ".act{font-size:.9rem;margin:.2rem 0}"
    ".raw{white-space:pre-wrap;word-break:break-word;overflow-x:auto;background:#f6f8fa;"
    "border-radius:.4rem;padding:.6rem .75rem;font-size:.82rem;margin:.4rem 0 0}"
    # dark-mode overrides last, so source order lets them win over the base rules above
    "@media (prefers-color-scheme: dark){"
    "body{background:#15171a;color:#e6e8ea}"
    "a{color:#6ab0ff}"
    ".meta{color:#9aa3ad}"
    ".row,td,th{border-color:#2c3139}"
    ".ok{color:#5ec98b}.bad{color:#ff6b6b}"
    ".turn{border-color:#2c3139}.sid{color:#9aa3ad}.raw{background:#1d2024}"
    "}</style>")


def _esc(v):
    return html.escape("" if v is None else str(v))


def _page(title, body):
    return (f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{_esc(title)}</title>{_STYLE}</head><body>{body}</body></html>")


def render_run_list(runs):
    """The index: every persisted run, most recent first, linking into each one."""
    if not runs:
        rows = '<p class="meta">No runs yet. Run <code>capri run</code>, then refresh.</p>'
    else:
        rows = ""
        for r in runs:
            cov = r.get("coverage_summary") or {}
            confirmed = cov.get("confirmed", 0)
            mode = r.get("mode") or ""
            color = "#2f6f4e" if mode == "sandboxed" else "#8a5a00"
            rows += (
                f'<div class="row"><span class="id"><a href="/run/{_esc(r["id"])}">'
                f'{_esc(r["id"])}</a></span>'
                f'<span class="badge" style="background:{color}">{_esc(mode)}</span>'
                f'<span class="meta">{_esc(confirmed)} confirmed</span>'
                f'<span class="meta">{_esc(report_render.am_pm(r.get("started_at")))}</span></div>')
    return _page("Capri runs", f"<h1>Runs</h1>{rows}")


_ROLE_COLOR = {"operator": "#1a5fb4", "verifier": "#6c3fb5"}


def _action(turn):
    """One line describing what the role proposed this turn: the parsed action, or the
    rejection reason when the turn was unparseable. Every field escaped (untrusted text)."""
    if turn.get("rejection"):
        return f'<span class="bad">rejected: {_esc(turn["rejection"])}</span>'
    parsed = turn.get("parsed") or {}
    if not parsed:
        return '<span class="meta">no action</span>'
    target = _esc(parsed.get("target"))
    port = parsed.get("port")
    where = f"{target}:{_esc(port)}" if port else target
    return (f'<code>{_esc(parsed.get("tool"))}</code> '
            f'<span class="meta">{_esc(parsed.get("intent"))}</span> &rarr; {where}')


def render_reasoning(turns, eid):
    """The step-by-step reasoning view (HC-REPORT-01 §3): each role's verbatim proposal as
    escaped, display-only text. The Operator's turns and the Verifier's are labelled as the
    distinct independent sessions they are, never merged, and nothing here is ever trusted."""
    head = (f'<p class="meta"><a href="/run/{_esc(eid)}">&larr; report</a> &middot; '
            f'<a href="/run/{_esc(eid)}/audit">audit trail</a></p>'
            "<h1>Reasoning</h1>"
            '<p class="meta">What each role proposed, step by step. This is model-authored '
            "text shown for review only: it is never trusted, never fed back into a run, and "
            "never crosses from the finder to the verifier.</p>")
    if not turns:
        return _page(f"Reasoning {eid}", head
                     + '<p class="meta">No role turns were recorded for this run.</p>')
    cards = ""
    for t in turns:
        color = _ROLE_COLOR.get(t.get("role"), "#5b6470")
        probe = (f' &middot; <span class="meta">probe {_esc(t["probe_event_id"])}</span>'
                 if t.get("probe_event_id") else "")
        cards += (
            '<div class="turn"><h3>'
            f'<span class="badge" style="background:{color}">{_esc(t.get("role"))}</span>'
            f'<span>step {_esc(t.get("step"))}</span>'
            f'<span class="meta">{_esc(t.get("asset"))} &middot; {_esc(t.get("technique_id"))}</span>'
            f'<span class="sid">{_esc(t.get("session_id"))}</span>'
            f'<span class="meta">{_esc(report_render.am_pm(t.get("at")))}</span>'
            "</h3>"
            f'<p class="act">{_action(t)}{probe}</p>'
            f'<pre class="raw">{_esc(t.get("raw"))}</pre></div>')
    return _page(f"Reasoning {eid}", head + cards)


def render_audit(trail, eid):
    """One run's audit timeline with the hash-chain verification result shown, not assumed."""
    status = ('<span class="ok">intact</span>' if trail.get("chain_ok")
              else f'<span class="bad">BROKEN at seq {_esc(trail.get("broken_seq"))}</span>')
    head = (f'<p class="meta"><a href="/run/{_esc(eid)}">&larr; report</a> &middot; '
            f'<a href="/run/{_esc(eid)}/reasoning">reasoning</a></p>'
            f"<h1>Audit trail</h1><p>Hash chain: {status}</p>")
    rows = "".join(
        f"<tr><td>{_esc(report_render.am_pm(row.get('ts')))}</td>"
        f"<td>{_esc(row.get('actor'))}</td><td>{_esc(row.get('category'))}</td>"
        f"<td>{_esc(row.get('decision'))}</td><td>{_esc(row.get('reason'))}</td></tr>"
        for row in trail.get("rows", []))
    table = (f"<table><tr><th>Time</th><th>Actor</th><th>Category</th>"
             f"<th>Decision</th><th>Reason</th></tr>{rows}</table>")
    return _page(f"Audit {eid}", head + table)


def route(conn, path):
    """Map a request path to (status_code, html). Pure: no socket, no globals."""
    path = path.split("?", 1)[0].rstrip("/") or "/"
    if path == "/":
        return 200, render_run_list(engagements.list_all(conn))
    parts = [p for p in path.split("/") if p]            # ["run", "<id>"(, "audit")]
    if parts and parts[0] == "run" and len(parts) in (2, 3):
        eid = parts[1]
        run = engagements.get(conn, eid)
        if run is None:
            return 404, _page("Not found", f"<h1>Run {_esc(eid)} not found</h1>"
                              '<p class="meta"><a href="/">&larr; all runs</a></p>')
        if len(parts) == 2:
            body = ('<p class="meta"><a href="/">&larr; all runs</a> &middot; '
                    f'<a href="/run/{_esc(eid)}/reasoning">reasoning</a> &middot; '
                    f'<a href="/run/{_esc(eid)}/audit">audit trail</a></p>')
            return 200, report_render.render_html(run["report"]).replace("<body>", "<body>" + body, 1)
        if parts[2] == "reasoning":
            return 200, render_reasoning(engagements.reasoning(conn, eid), eid)
        if parts[2] == "audit":
            return 200, render_audit(engagements.audit(conn, eid), eid)
    return 404, _page("Not found", '<h1>Not found</h1><p class="meta"><a href="/">&larr; all runs</a></p>')


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        conn = db.connect(datadir.db_path(self.server.data_dir))  # per request: fresh + thread-safe
        try:
            status, body = route(conn, self.path)
        finally:
            conn.close()
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):                                    # read-only: no writes, ever
        self.send_response(405)
        self.end_headers()

    def log_message(self, *args):                         # quiet by default
        pass


def serve(data_dir=None, port=8787):
    """Serve the dashboard on loopback until interrupted; each request reads the store fresh."""
    server = HTTPServer((_HOST, port), _Handler)
    server.data_dir = data_dir
    url = f"http://{_HOST}:{server.server_address[1]}"
    print(f"Capri dashboard on {url}  (reading {datadir.db_path(data_dir)})")
    print("Read-only, loopback only. Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Browse your Capri runs in a local web view.")
    parser.add_argument("--port", type=int, default=8787, help="loopback port (default 8787)")
    parser.add_argument("--data-dir", help="data directory (default ~/.capri or $HC_DATA_DIR)")
    args = parser.parse_args(argv)
    return serve(data_dir=args.data_dir, port=args.port)


if __name__ == "__main__":
    sys.exit(main())
