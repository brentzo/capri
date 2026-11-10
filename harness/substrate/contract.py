"""Engagement-contract parser and validator (HC-SUB-01 §4).

The engagement contract is the single source of truth for what a run may do.
Validation is fail-closed: a missing, malformed, or contradictory field makes
`parse` return errors and no Engagement, so nothing is provisioned (§4.2).
"""
import ipaddress
import re
from datetime import datetime

from harness import predicates, yamlmini

BLAST_TIERS = (0, 1, 2, 3)

# A conservative default on the model tokens a run may spend, applied when the contract names
# none, so a live run is always bounded rather than open-ended.
_DEFAULT_MODEL_BUDGET = 300_000


def _session_headers(session):
    """Normalize an optional `engagement.session` block into the request headers the harness
    presents on every probe: `bearer` -> `Authorization: Bearer ...`, `cookie` -> `Cookie: ...`,
    and `headers` merged verbatim. Returns a dict or None. Shape is validated separately."""
    if not isinstance(session, dict):
        return None
    out = {}
    extra = session.get("headers")
    if isinstance(extra, dict):
        out.update({str(k): str(v) for k, v in extra.items()})
    bearer = session.get("bearer")
    if isinstance(bearer, str) and bearer:
        out["Authorization"] = f"Bearer {bearer}"
    cookie = session.get("cookie")
    if isinstance(cookie, str) and cookie:
        out["Cookie"] = cookie
    return out or None

# Objective block (HC-OBJ-01 §4). Optional and additive: a contract with no
# objective validates and runs exactly as before.
OBJECTIVE_TYPES = ("capability", "canary", "reach")
PROOF_KINDS = ("canary", "oob_marker")
ON_SUCCESS = ("stop", "continue-for-coverage")
# A canary objective carries a hash, never the secret (§4.4); these keys would be
# the plaintext inlined, so a proof block that has one is rejected.
_PLAINTEXT_KEYS = ("secret", "plaintext", "value", "content", "flag")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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
        self.lateral_movement = p.get("lateral_movement", False) is True  # HC-OBJ-01 §8
        self.objective = raw.get("objective")   # validated objective block, or None
        # Optional path to the target app's own source on the operator host. When present,
        # source-aware recon reads it to enumerate the full HTTP surface (every registered
        # route, including the auth-gated ones a crawl can't reach); absent, recon stays
        # black-box. The operator has the source because Capri is run against its own app.
        self.source_root = e.get("source_root") or None
        # A caller-supplied authenticated session the harness presents on every probe, so a
        # probe reaches an auth-gated route instead of the login. Normalized to a header dict;
        # it is a credential, so it stays off the target model, the logs, and the report.
        self.session_headers = _session_headers(e.get("session"))
        # The total model tokens a run may spend, a fail-closed cap on the model plane. Absent
        # falls back to a conservative default, so every run is bounded, not only configured ones.
        mb = e.get("model_budget")
        self.model_budget = int(mb) if isinstance(mb, int) and mb > 0 else _DEFAULT_MODEL_BUDGET
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
    sr = eng.get("source_root")
    if sr is not None and (not isinstance(sr, str) or not sr.strip()):
        errs.append("engagement.source_root must be a non-empty path string when present")
    sess = eng.get("session")
    if sess is not None:
        if not isinstance(sess, dict):
            errs.append("engagement.session must be a mapping when present")
        else:
            for f in ("bearer", "cookie"):
                if f in sess and not isinstance(sess[f], str):
                    errs.append(f"engagement.session.{f} must be a string")
            if "headers" in sess and not (isinstance(sess["headers"], dict) and all(
                    isinstance(v, str) for v in sess["headers"].values())):
                errs.append("engagement.session.headers must be a map of string values")
    mb = eng.get("model_budget")
    if mb is not None and (not isinstance(mb, int) or isinstance(mb, bool) or mb <= 0):
        errs.append("engagement.model_budget must be a positive integer when present")

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
    out_nets = []
    for x in scope.get("out_of_scope", []) or []:
        try:
            out_nets.append(_as_net(x))
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
    pol = pol if isinstance(pol, dict) else {}
    lateral = pol.get("lateral_movement")
    if lateral is not None and not isinstance(lateral, bool):
        errs.append("policy.lateral_movement must be a boolean")

    if "objective" in raw:            # optional; absent means a pure-coverage run (§3)
        _validate_objective(raw["objective"], list(hosts), in_nets, out_nets,
                            lateral is True, errs)
    return errs


def _validate_objective(obj, hosts, in_nets, out_nets, lateral, errs):
    """Fail-closed validation of the HC-OBJ-01 §4 objective block (§4.4)."""
    if not isinstance(obj, dict):
        errs.append("objective must be a mapping")
        return
    for f in ("id", "description", "type", "target", "success"):
        if obj.get(f) in (None, ""):
            errs.append(f"objective.{f} is required")

    otype = obj.get("type")
    if otype is not None and otype not in OBJECTIVE_TYPES:
        errs.append(f"objective.type must be one of {list(OBJECTIVE_TYPES)}")

    target = obj.get("target")
    if target not in (None, "") and not _target_in_scope(str(target), hosts, in_nets, out_nets):
        errs.append(f"objective.target '{target}' must be an in_scope_host or an "
                    "in-scope, pinned IP; an out-of-scope target aborts before provisioning")

    success = obj.get("success")
    if isinstance(success, str) and success.strip():
        try:
            predicates.evaluate(success, {})      # parse-check only, over empty facts
        except predicates.PredicateError as ex:
            errs.append(f"objective.success does not parse under the predicate DSL: {ex}")

    if otype == "reach" and not lateral:          # internally contradictory (§4.4)
        errs.append("objective.type 'reach' requires policy.lateral_movement: true")

    on_success = obj.get("on_success")
    if on_success is not None and on_success not in ON_SUCCESS:
        errs.append(f"objective.on_success must be one of {list(ON_SUCCESS)}")

    _validate_proof(otype, obj.get("proof"), errs)


def _validate_proof(otype, proof, errs):
    """A proof binds completion to a deterministic artifact (§4.3). Required for a
    canary or reach objective; a capability's proof is its confirmed fact."""
    if proof is None:
        if otype in ("canary", "reach"):
            errs.append(f"objective.type '{otype}' requires a proof block")
        return
    if not isinstance(proof, dict):
        errs.append("objective.proof must be a mapping")
        return
    kind = proof.get("kind")
    if kind not in PROOF_KINDS:
        errs.append(f"objective.proof.kind must be one of {list(PROOF_KINDS)}")
    if otype == "canary" and kind != "canary":
        errs.append("a canary objective requires proof.kind: canary")
    if otype == "reach" and kind != "oob_marker":
        errs.append("a reach objective requires proof.kind: oob_marker")

    if kind == "canary":
        if not _SHA256.match(str(proof.get("sha256", ""))):
            errs.append("objective.proof.sha256 must be a 64-character lowercase hex digest")
        if proof.get("location") in (None, ""):
            errs.append("objective.proof.location is required for a canary")
        leaked = sorted(k for k in proof if str(k).lower() in _PLAINTEXT_KEYS)
        if leaked:
            errs.append("objective.proof carries a hash, not the plaintext secret; "
                        f"remove {', '.join(leaked)}")
    elif kind == "oob_marker":
        if proof.get("marker") in (None, "") and proof.get("collaborator") in (None, ""):
            errs.append("an oob_marker proof must name an in-sandbox marker or collaborator")
        for v in (proof.get("collaborator"), proof.get("location"), proof.get("marker")):
            if isinstance(v, str) and ("://" in v or "@" in v):
                errs.append("an oob_marker proof must terminate in-sandbox, not at an "
                            "external host or URL")


def _target_in_scope(target, hosts, in_nets, out_nets):
    if target in hosts:
        return True                               # a declared, pinnable in-scope host
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False                              # a hostname not declared in scope
    if not any(ip in n for n in in_nets):
        return False
    for entry in out_nets:
        if isinstance(entry, ipaddress._BaseNetwork) and ip in entry:
            return False
        if ip == entry:
            return False
    return True


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
    if e.objective:
        print(f"objective: {e.objective.get('id')} "
              f"(type={e.objective.get('type')}, target={e.objective.get('target')}, "
              f"lateral_movement={e.lateral_movement})")
