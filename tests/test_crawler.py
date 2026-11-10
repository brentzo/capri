"""Black-box crawl adapter (HC-AGENT-01 recon): the adapter builds the right in-container
command and parses the crawler's JSON surface map, tolerating chromium noise on stdout. No
Docker and no browser: a fake runner returns captured crawler output. The Playwright script
itself (infra/sandbox/crawl.py) is exercised live in the range, not here."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.sandbox.base import RunResult
from harness.sandbox.crawler import CrawlerAdapter, parse_surface

PINNED = {"t1.sandbox.local": "10.90.0.4"}

_SURFACE = {
    "base_url": "http://10.90.0.4:8080/",
    "endpoints": [
        {"path": "/item", "method": "GET", "params": ["id"], "status": 200,
         "content_type": "text/html", "renders_html": True, "source": "link"},
        {"path": "/api/cart", "method": "POST", "params": ["sku", "qty"], "source": "form"},
    ],
}


class _FakeRunner:
    """Records the argv it was called with and returns canned crawler stdout."""

    def __init__(self, out):
        self.out = out
        self.calls = []

    def __call__(self, argv, input=None):
        self.calls.append(argv)
        return RunResult(0, self.out, "")


def test_crawl_execs_the_baked_script_against_the_pinned_target():
    fake = _FakeRunner(json.dumps(_SURFACE))
    CrawlerAdapter("hc-range-attacker", PINNED, run=fake).crawl(
        "t1.sandbox.local", 8080, budget=25)
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "exec", "hc-range-attacker"]
    assert argv[3:5] == ["python3", "/opt/hc/crawl.py"]
    assert argv[5] == "http://10.90.0.4:8080/"      # pinned IP, not the name
    assert argv[6] == "25"                          # budget forwarded


def test_crawl_parses_the_surface_map():
    fake = _FakeRunner(json.dumps(_SURFACE))
    surface = CrawlerAdapter("atk", PINNED, run=fake).crawl("t1.sandbox.local", 8080)
    paths = {(e["path"], e["method"]) for e in surface["endpoints"]}
    assert paths == {("/item", "GET"), ("/api/cart", "POST")}
    cart = next(e for e in surface["endpoints"] if e["path"] == "/api/cart")
    assert cart["params"] == ["sku", "qty"]


def test_https_scheme_follows_the_port():
    fake = _FakeRunner(json.dumps({"endpoints": []}))
    CrawlerAdapter("atk", PINNED, run=fake).crawl("t1.sandbox.local", 8443)
    assert fake.calls[0][5] == "https://10.90.0.4:8443/"


def test_chromium_noise_before_the_json_is_tolerated():
    noisy = "libva error: /usr/lib failed\n[warn] gpu init\n" + json.dumps(_SURFACE)
    surface = parse_surface(noisy, base_url="http://x/")
    assert len(surface["endpoints"]) == 2


def test_empty_output_yields_an_empty_surface_not_an_error():
    surface = parse_surface("", base_url="http://x/")
    assert surface == {"base_url": "http://x/", "endpoints": []}


def test_non_dict_endpoints_are_dropped():
    surface = parse_surface(json.dumps({"endpoints": ["oops", {"path": "/a", "method": "GET"}]}),
                            base_url="http://x/")
    assert surface["endpoints"] == [{"path": "/a", "method": "GET"}]


def test_crawl_result_feeds_project_surface():
    """The adapter's output is exactly what recon.project_surface consumes."""
    from harness import recon
    fake = _FakeRunner(json.dumps(_SURFACE))
    surface = CrawlerAdapter("atk", PINNED, run=fake).crawl("t1.sandbox.local", 8080)
    model = recon.project_surface(surface, "t1.sandbox.local", "10.90.0.4")
    assert "t1::/item?id" in model
    assert model["t1::/item?id"]["asset.param"] == "id"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
