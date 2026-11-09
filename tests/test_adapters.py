#!/usr/bin/env python3
"""Live pentest-tool adapters (HC-AGENT-01 §5.3).

Adapters run a real tool on the attacker container and return the raw signals the harness
triages. These tests drive them through a fake runner fed the exact XML a real `nmap -sV`
emits (captured from a live scan), so the parsing and the signal shape are pinned with no
Docker and no real tool present - the same no-dependency pattern as the sandbox tests.

Zero-dependency: `python3 tests/test_adapters.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness.sandbox.adapters import NmapAdapter, _parse_nmap_services   # noqa: E402
from harness.sandbox.base import RunResult                               # noqa: E402

# Real `nmap -sV -Pn -p 8080 -oX -` output (captured live), trimmed to the shape we parse.
NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sV -Pn -p 8080 -oX - 10.90.0.3" start="1794226837" version="7.95">
<host starttime="1794226837"><status state="up" reason="arp-response"/>
<address addr="10.90.0.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="SimpleHTTPServer" version="0.6" extrainfo="Python 3.12.16" method="probed" conf="10"><cpe>cpe:/a:python:simplehttpserver:0.6</cpe></service></port>
</ports>
</host>
</nmaprun>"""

NMAP_XML_CLOSED = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.90.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="9999"><state state="closed" reason="reset"/></port></ports>
</host></nmaprun>"""

NMAP_XML_NO_SERVICE = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.90.0.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port></ports>
</host></nmaprun>"""


class FakeRunner:
    def __init__(self, out):
        self.out = out
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        return RunResult(0, self.out, "")


PINNED = {"t1.sandbox.local": "10.90.0.3"}


def test_nmap_extracts_service_product_version_and_cpe():
    fake = FakeRunner(NMAP_XML)
    adapter = NmapAdapter("atk", PINNED, run=fake)
    res = adapter.run({"tool": "nmap", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    assert res["status"] == "ok"
    sig = res["deterministic_signals"]
    assert sig["hit"] is True
    assert sig["open_ports"] == [8080]
    assert sig["service"] == "http"
    assert sig["product"] == "SimpleHTTPServer"
    assert sig["version"] == "0.6"
    assert sig["cpe"] == "cpe:/a:python:simplehttpserver:0.6"
    assert isinstance(res["request_bytes"], bytes) and isinstance(res["response_bytes"], bytes)


def test_nmap_runs_sV_and_resolves_the_pinned_name_to_the_guarded_ip():
    fake = FakeRunner(NMAP_XML)
    NmapAdapter("atk", PINNED, run=fake).run(
        {"tool": "nmap", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "exec", "atk"]
    assert "-sV" in argv and "-Pn" in argv                     # service detection, no discovery
    assert "10.90.0.3" in argv                                 # resolved to the guarded IP
    assert "t1.sandbox.local" not in argv                      # not the bare name


def test_nmap_no_open_port_is_not_a_hit():
    res = NmapAdapter("atk", PINNED, run=FakeRunner(NMAP_XML_CLOSED)).run(
        {"tool": "nmap", "target": "10.90.0.9", "port": 9999, "args": {}})
    assert res["status"] == "error"
    assert res["deterministic_signals"]["hit"] is False
    assert res["deterministic_signals"]["open_ports"] == []


def test_nmap_open_port_without_a_service_still_registers_the_port():
    svcs = _parse_nmap_services(NMAP_XML_NO_SERVICE)
    assert len(svcs) == 1
    assert svcs[0]["port"] == 22 and svcs[0]["product"] is None


def test_nmap_malformed_output_is_tolerated_not_raised():
    res = NmapAdapter("atk", PINNED, run=FakeRunner("this is not xml")).run(
        {"tool": "nmap", "target": "10.90.0.3", "port": 80, "args": {}})
    assert res["deterministic_signals"]["hit"] is False        # no hit, no exception


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
