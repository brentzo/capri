"""Black-box crawl adapter for the Docker sandbox range (HC-AGENT-01 recon).

Drives the Playwright crawler that is baked into the attacker image (`infra/sandbox/crawl.py`)
over `docker exec`, and parses the JSON surface map it prints. The harness itself stays free
of the browser dependency: only the attacker container carries Playwright, and this adapter
reaches it through the injected runner, so the same code is unit-tested with no Docker and no
browser present. It holds no engagement secrets and reaches only the attacker container it was
handed, pointed at one pinned in-scope target whose scheme follows its port.
"""
import json

from harness.sandbox.base import default_run

# Where crawl.py lands in the attacker image (see infra/sandbox/Dockerfile.attacker).
_CRAWL_PATH = "/opt/hc/crawl.py"


class CrawlerAdapter:
    """Run the in-container crawler against one pinned target and return its surface map.

    `pinned` is the engagement's host->IP map, so a target name resolves to the IP the scope
    guard enforces on; an IP target is used as is."""

    def __init__(self, attacker, pinned, *, run=None, crawl_path=_CRAWL_PATH):
        self.attacker = attacker
        self.pinned = pinned
        self._run = run or default_run
        self.crawl_path = crawl_path

    def _resolve(self, target):
        ip = self.pinned.get(target)
        return str(ip) if ip is not None else target

    def crawl(self, target, port, *, budget=40, scheme=None):
        """Crawl `http(s)://<target>:<port>/` and return the parsed surface map
        `{base_url, endpoints: [{path, method, params, status, content_type, renders_html,
        source}]}`. A crawl that yields nothing parseable returns an empty surface rather than
        raising, so recon degrades to the host asset alone."""
        ip = self._resolve(target)
        port = int(port)
        scheme = scheme or ("https" if port in (443, 8443) else "http")
        url = f"{scheme}://{ip}:{port}/"
        r = self._run(["docker", "exec", self.attacker, "python3", self.crawl_path,
                       url, str(int(budget))])
        return parse_surface(r.out or "", base_url=url)


def parse_surface(out, *, base_url):
    """Parse the crawler's JSON surface map out of its stdout, tolerating noise.

    chromium can write to stdout, so the surface object is taken from the last line that
    parses as a JSON object; a run that prints nothing usable yields an empty surface."""
    surface = _last_json_object(out)
    if not isinstance(surface, dict):
        return {"base_url": base_url, "endpoints": []}
    surface.setdefault("base_url", base_url)
    eps = surface.get("endpoints")
    surface["endpoints"] = [e for e in eps if isinstance(e, dict)] if isinstance(eps, list) else []
    return surface


def _last_json_object(out):
    for line in reversed((out or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None
