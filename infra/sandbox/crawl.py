#!/usr/bin/env python3
"""Black-box web crawler, run inside the attacker container (HC-AGENT-01 recon).

Drives headless chromium through Playwright against a single in-scope target and emits a
surface map of the endpoints, methods and parameters it actually reached, as one JSON
object on stdout. It observes runtime behaviour rather than parsing the app: the browser
executes the app's JavaScript and the crawler records the requests it issues, so a
single-page app's XHR and fetch endpoints are discovered without any knowledge of the
framework or its routes.

It is deliberately read-only for this slice: it follows same-origin links and reads form
definitions from the DOM, but never submits a form, so it discovers POST endpoints and
their field names without mutating target state. Scope is enforced twice over: the crawler
keeps itself same-origin, and the attacker container's scope guard drops anything off the
pinned target regardless.

This file is baked into the attacker image (it needs Playwright, which the harness itself
does not); the harness drives it over `docker exec` and parses the JSON it prints.

Usage:  python3 crawl.py <start-url> [max-pages]
"""
import json
import sys
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.sync_api import sync_playwright

_NAV_TIMEOUT_MS = 8000
_FORMS_JS = """els => els.map(f => ({
  action: f.getAttribute('action') || '',
  method: (f.getAttribute('method') || 'GET').toUpperCase(),
  fields: Array.from(f.querySelectorAll('input[name],select[name],textarea[name]'))
             .map(i => i.getAttribute('name')).filter(Boolean)
}))"""


def _norm(url):
    """Drop the fragment; keep scheme, host, path and query."""
    p = urlparse(url)
    q = f"?{p.query}" if p.query else ""
    return f"{p.scheme}://{p.netloc}{p.path or '/'}{q}"


def crawl(start, max_pages=40):
    host = urlparse(start).netloc
    endpoints = {}        # (path, method) -> set(param names)
    meta = {}             # (path, method) -> {status, content_type, renders_html, source}

    def record(url, method, source):
        p = urlparse(url)
        if p.netloc and p.netloc != host:
            return                                   # same-origin only
        key = (p.path or "/", method.upper())
        endpoints.setdefault(key, set()).update(parse_qs(p.query).keys())
        meta.setdefault(key, {}).setdefault("source", source)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        ctx = browser.new_context(ignore_https_errors=True)
        ctx.set_default_navigation_timeout(_NAV_TIMEOUT_MS)
        ctx.set_default_timeout(_NAV_TIMEOUT_MS)
        page = ctx.new_page()
        page.on("request", lambda req: record(req.url, req.method, "xhr"))

        seen, queue = set(), [_norm(start)]
        while queue and len(seen) < max_pages:
            target = queue.pop(0)
            if target in seen:
                continue
            seen.add(target)
            resp = None
            for wait in ("networkidle", "domcontentloaded"):
                try:
                    resp = page.goto(target, wait_until=wait)
                    break
                except Exception:
                    continue
            key = (urlparse(target).path or "/", "GET")
            record(target, "GET", "nav")
            ctype = (resp.headers.get("content-type", "") if resp else "")
            meta.setdefault(key, {}).update(
                {"status": resp.status if resp else None, "content_type": ctype,
                 "renders_html": "html" in ctype.lower()})
            if resp is None:
                continue
            try:
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []
            except Exception:
                hrefs = []
            for href in hrefs:
                nu = _norm(urljoin(target, href))
                if urlparse(nu).netloc == host:
                    record(nu, "GET", "link")
                    if nu not in seen:
                        queue.append(nu)
            try:
                forms = page.eval_on_selector_all("form", _FORMS_JS) or []
            except Exception:
                forms = []
            for form in forms:
                action = urljoin(target, form.get("action") or target)
                p = urlparse(action)
                if p.netloc and p.netloc != host:
                    continue
                fkey = (p.path or "/", form.get("method", "GET"))
                endpoints.setdefault(fkey, set()).update(form.get("fields") or [])
                meta.setdefault(fkey, {}).setdefault("source", "form")
        browser.close()

    out = {"base_url": start, "endpoints": []}
    for (path, method), params in sorted(endpoints.items()):
        m = meta.get((path, method), {})
        out["endpoints"].append(
            {"path": path, "method": method, "params": sorted(p for p in params if p),
             "status": m.get("status"), "content_type": m.get("content_type"),
             "renders_html": bool(m.get("renders_html")), "source": m.get("source")})
    return out


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"base_url": None, "endpoints": [], "error": "no start url"}))
        return 2
    start = sys.argv[1]
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    try:
        print(json.dumps(crawl(start, max_pages)))
        return 0
    except Exception as e:  # noqa: BLE001 - emit a valid, empty surface rather than crashing
        print(json.dumps({"base_url": start, "endpoints": [],
                          "error": f"{type(e).__name__}: {e}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
