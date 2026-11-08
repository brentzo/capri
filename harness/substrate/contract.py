"""Engagement-contract parser and validator (HC-SUB-01 §4).

The engagement contract is the single source of truth for what a run may do.
Validation is fail-closed: a missing, malformed, or contradictory field makes
`parse` return errors and no Engagement, so nothing is provisioned (§4.2).
"""
import ipaddress
from datetime import datetime

from harness import yamlmini

BLAST_TIERS = (0, 1, 2, 3)


class Engagement:
    """A validated engagement. Built only by `parse`; never from raw input."""

    def __init__(self, raw):
        self.raw = raw
        e, s, p = raw["engagement"], raw["scope"], raw.get("policy", {})
        self.id = e["id"]
        self.authorized_by = e["authorized_by"]
        self.window_start = _parse_ts(e["window"]["start"])
        self.window_end = _parse_ts(e["window"]["end"])
        self.max_blast_tier = int(e["max_blast_tier"])
        self.in_scope_hosts = list(s.get("in_scope_hosts", []))
        self.in_scope_nets = [ipaddress.ip_network(c, strict=False)
                              for c in s.get("in_scope_cidrs", [])]
        self.out_of_scope = [_as_net(x) for x in s.get("out_of_scope", [])]
        self.allowed_ports = s.get("allowed_ports", {}) or {}
        self.allowed_tactics = list(p.get("allowed_tactics", []))
        self.forbidden = list(p.get("forbidden", []))
        self.rate = p.get("rate", {}) or {}
        self.tier3_techniques = list(p.get("tier3_techniques", []))
        self.pinned = {}   # host -> ipaddress, set at provisioning (§4.3)

    def pin(self, host_to_ip):
        """Pin in-scope hostnames to resolved IPs (anti-TOCTOU, §4.3).

        Returns a list of error strings; on error nothing is pinned."""
        errs, pinned = [], {}
        for host, ip_str in host_to_ip.items():
            if host not in self.in_scope_hosts:
                errs.append(f"pin: '{host}' is not an in_scope_host")
                continue
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                errs.append(f"pin: '{ip_str}' is not a valid IP")
                continue
            if not any(ip in n for n in self.in_scope_nets):
                errs.append(f"pin: {host} -> {ip} falls outside in_scope_cidrs")
                continue
            if self._is_out_of_scope(ip):
                errs.append(f"pin: {host} -> {ip} is out_of_scope")
                continue
            pinned[host] = ip
        if errs:
            return errs
        self.pinned = pinned
        return []

    def _is_out_of_scope(self, ip):
        for entry in self.out_of_scope:
            if isinstance(entry, ipaddress._BaseNetwork):
                if ip in entry:
                    return True
            elif ip == entry:
                return True
        return False


def _parse_ts(v):
    return datetime.fromisoformat(str(v))


def _as_net(x):
    s = str(x)
    if "/" in s:
        return ipaddress.ip_network(s, strict=False)
    return ipaddress.ip_address(s)


def parse(text, management_cidrs=None):
    """Parse and validate contract YAML.

    Returns (engagement, errors). On any error, engagement is None and errors
    is a non-empty list (fail-closed, HC-SUB-01 §4.2)."""
    try:
        raw = yamlmini.load(text)
    except yamlmini.YamlError as ex:
        return None, [f"contract is not valid YAML: {ex}"]
    errs = validate(raw, management_cidrs=management_cidrs)
    if errs:
        return None, errs
    return Engagement(raw), []


def validate(raw, management_cidrs=None):
    """Return a list of error strings; empty means the contract is valid."""
    errs = []
    if not isinstance(raw, dict):
        return ["contract must be a mapping with engagement/scope/policy"]

    eng = raw.get("engagement")
    if not isinstance(eng, dict):
        errs.append("missing 'engagement' section")
        eng = {}
    for f in ("id", "authorized_by", "window", "max_blast_tier"):
        if eng.get(f) in (None, ""):
            errs.append(f"engagement.{f} is required")
    win = eng.get("window")
    if isinstance(win, dict):
        for f in ("start", "end"):
            if f not in win:
                errs.append(f"engagement.window.{f} is required")
        try:
            if "start" in win and "end" in win:
                if _parse_ts(win["start"]) >= _parse_ts(win["end"]):
                    errs.append("engagement.window.start must be before end")
        except ValueError:
            errs.append("engagement.window has an unparseable timestamp")
    elif win is not None:
        errs.append("engagement.window must be { start, end }")
    mbt = eng.get("max_blast_tier")
    if mbt is not None and (not isinstance(mbt, int) or mbt not in BLAST_TIERS):
        errs.append("engagement.max_blast_tier must be an integer 0..3")

    scope = raw.get("scope")
    if not isinstance(scope, dict):
        errs.append("missing 'scope' section")
        scope = {}
    hosts = scope.get("in_scope_hosts", [])
    cidrs = scope.get("in_scope_cidrs", [])
    if not hosts and not cidrs:
        errs.append("scope must declare in_scope_hosts or in_scope_cidrs")
    in_nets = []
    for c in cidrs or []:
        try:
            in_nets.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            errs.append(f"scope.in_scope_cidrs: '{c}' is not a valid CIDR")
    for x in scope.get("out_of_scope", []) or []:
        try:
            _as_net(x)
        except ValueError:
            errs.append(f"scope.out_of_scope: '{x}' is not a valid IP or CIDR")
    # in_scope must not overlap the operator's management network (§4.2)
    for mc in management_cidrs or []:
        mnet = ipaddress.ip_network(str(mc), strict=False)
        for n in in_nets:
            if n.overlaps(mnet):
                errs.append(f"scope.in_scope_cidrs {n} overlaps management network {mnet}")
    ap = scope.get("allowed_ports", {})
    if ap and not isinstance(ap, dict):
        errs.append("scope.allowed_ports must be a mapping")

    pol = raw.get("policy")
    if pol is not None and not isinstance(pol, dict):
        errs.append("policy must be a mapping")
    return errs


if __name__ == "__main__":  # python3 -m harness.substrate.contract <file|->
    import sys

    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    text = sys.stdin.read() if src == "-" else open(src).read()
    e, errs = parse(text)
    if errs:
        print("INVALID contract:")
        for x in errs:
            print("  -", x)
        sys.exit(1)
    print(f"valid: {e.id}  (max_blast_tier={e.max_blast_tier}, "
          f"{len(e.in_scope_nets)} in-scope CIDR(s), "
          f"{len(e.out_of_scope)} excluded, "
          f"window {e.window_start:%Y-%m-%d %I:%M%p}-{e.window_end:%I:%M%p})")
