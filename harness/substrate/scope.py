"""Scope guard pre-check (HC-SUB-01 §5.3).

`scope_validate` is the software defense-in-depth check the harness runs before
every tool-adapter call; the no-route gateway (§5.1) remains the real
enforcement. Default-deny: anything not provably in scope is denied, and
out_of_scope always wins (§4.2).
"""
import ipaddress


def _ports_for(eng, ip):
    """The allowed ports for a target IP: the most specific matching CIDR key,
    else 'default'. Missing default means no ports are allowed (fail-closed)."""
    best, best_prefix = None, -1
    for key, ports in eng.allowed_ports.items():
        if key == "default":
            continue
        try:
            net = ipaddress.ip_network(str(key), strict=False)
        except ValueError:
            continue
        if ip in net and net.prefixlen > best_prefix:
            best, best_prefix = ports, net.prefixlen
    if best is not None:
        return best
    return eng.allowed_ports.get("default", [])


def scope_validate(eng, target, port):
    """Return ('allow', None) or ('deny', reason).

    `target` is an IP literal or a pinned in-scope hostname; an unpinned host
    is denied (anti-TOCTOU, §4.3)."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        if target in eng.pinned:
            ip = eng.pinned[target]
        else:
            return "deny", f"unpinned_host:{target}"

    if eng._is_out_of_scope(ip):
        return "deny", f"out_of_scope:{ip}"

    in_scope = any(ip in n for n in eng.in_scope_nets) or ip in eng.pinned.values()
    if not in_scope:
        return "deny", f"not_in_scope:{ip}"

    try:
        p = int(port)
    except (TypeError, ValueError):
        return "deny", f"bad_port:{port}"
    if p not in _ports_for(eng, ip):
        return "deny", f"port_not_allowed:{ip}:{p}"

    return "allow", None
