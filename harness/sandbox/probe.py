"""Live probe adapter for the Docker sandbox range (HC-AGENT-01, HC-SUB-01 §6.1).

After the dispatcher passes a request through scope, blast, and rate, it runs an
adapter on the attacker VM. `DockerProbe` is that adapter for the Docker backend: it
issues an HTTP request from the attacker container to a pinned in-scope target and
returns the raw observable signals the harness triages (never the agent) into a lead.
It holds no engagement secrets and reaches only the attacker container it was handed,
through the injected runner, so the same code is unit-tested with no Docker present.
"""
from harness.sandbox.base import default_run

# Issued inside the attacker container; stdlib only, so the node image stays tiny.
_HTTP_PROBE = (
    "import socket,sys\n"
    "ip,port,path=sys.argv[1],int(sys.argv[2]),sys.argv[3]\n"
    "try:\n"
    "    s=socket.socket(); s.settimeout(4); s.connect((ip,port))\n"
    "    s.sendall(('GET %s HTTP/1.0\\r\\nHost: %s\\r\\n\\r\\n'%(path,ip)).encode())\n"
    "    line=s.recv(4096).split(b'\\r\\n',1)[0].decode('latin1').split()\n"
    "    print('STATUS', line[1] if len(line)>1 else '0')\n"
    "except Exception as e: print('ERR', type(e).__name__)\n"
)


class DockerProbe:
    """An HTTP probe that runs `docker exec <attacker> python3 -c ...` against a target.

    `pinned` is the engagement's host->IP map, so a request aimed at a pinned name
    resolves to the same IP the scope guard enforces on; an IP target is used as is."""

    def __init__(self, attacker, pinned, *, run=None):
        self.attacker = attacker
        self.pinned = pinned
        self._run = run or default_run

    def _resolve(self, target):
        ip = self.pinned.get(target)
        return str(ip) if ip is not None else target

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        path = (req.get("args") or {}).get("path", "/")
        r = self._run(["docker", "exec", self.attacker, "python3", "-c", _HTTP_PROBE,
                       ip, str(port), path])
        out = (r.out or "").strip()
        parts = out.split()
        code = int(parts[1]) if out.startswith("STATUS") and parts[1].isdigit() else 0
        hit = code != 0
        return {
            "status": "ok" if hit else "error",
            "parsed": {"http_status": code},
            "request_bytes": f"GET {path} HTTP/1.0 -> {ip}:{port}".encode(),
            "response_bytes": out.encode(),
            "deterministic_signals": {"hit": hit, "status_code": code,
                                      "confidence": 0.9 if hit else 0.0},
        }
