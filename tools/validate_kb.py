#!/usr/bin/env python3
"""HC-KB-01 technique-card validator (zero third-party dependency).

Implements the validation gate specified in HC-KB-01 §9 and the acceptance
behaviors in HC-KB-01 §12. It reads the authored technique cards (by default
from the condensed YAML blocks in specs/HC-KB-*.md, the current source of
truth) and checks each one:

  - schema shape and required fields (HC-KB-01 §3)
  - id naming convention KB-<CLASS>-<FAMILY>-<nnn> (HC-KB-01 §3.1)
  - applicability / when-clause parse under the predicate DSL (HC-KB-01 §4)
  - success_signal type + evaluator (HC-KB-01 §5)
  - blast_tier range and cleanup-when-tier>=2 (HC-KB-01 §7, §9)
  - oob_callback terminates at an in-sandbox collaborator (HC-KB-01 §5)
  - taxonomy id format and resolution against tools/taxonomy.py (HC-KB-01 §9)
  - severity_rubric base and raise_if/lower_if {when,to} shape (HC-KB-01 §5)

Findings are graded:
  ERROR       a substantive schema/DSL/safety violation; fails the build.
  UNRESOLVED  a well-formed taxonomy id not in the bundled reference; this is
              the `# verify` to-do surface. Non-fatal unless --strict.
  WARN        a card that omits a "shipping" field the condensed blocks leave
              to the full template (version/status/references/test_fixture).
              Non-fatal; it tracks the gap to materializing the KB (M2).

Exit code is nonzero when any ERROR is found (or any UNRESOLVED under --strict).
"""

import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import taxonomy as tx  # noqa: E402

ERROR, UNRESOLVED, WARN = "ERROR", "UNRESOLVED", "WARN"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RE_ID = re.compile(r"^KB-([A-Z]+)-([A-Z0-9]+(?:-[A-Z0-9]+)*)-(\d{3})$")
CONDENSED_OPTIONAL = ("version", "status", "references", "test_fixture",
                      "inputs", "cvss_base_vector")


# --------------------------------------------------------------------------
# tiny YAML-subset helpers (stdlib only)
# --------------------------------------------------------------------------
def strip_comments(text):
    """Remove `#` comments, respecting single/double quotes."""
    out = []
    for line in text.splitlines():
        res, i, q = [], 0, None
        while i < len(line):
            c = line[i]
            if q:
                res.append(c)
                if c == q:
                    q = None
            elif c in "'\"":
                q = c
                res.append(c)
            elif c == "#":
                break
            else:
                res.append(c)
            i += 1
        out.append("".join(res).rstrip())
    return "\n".join(out)


def _depth_delta(line):
    """Net bracket depth change on a line, ignoring quoted regions."""
    d, q = 0, None
    for c in line:
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c in "{[":
            d += 1
        elif c in "}]":
            d -= 1
    return d


def merge_logical_lines(text):
    """Join physical lines while a flow collection ({ or [) stays open."""
    merged, buf, depth = [], "", 0
    for line in text.splitlines():
        buf = line if not buf else buf + " " + line.strip()
        depth += _depth_delta(line)
        if depth <= 0:
            merged.append(buf)
            buf, depth = "", 0
    if buf:
        merged.append(buf)
    return merged


def split_top_items(s):
    """Split a flow-collection body on top-level commas (ignore nesting/quotes)."""
    items, cur, depth, q = [], "", 0, None
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
        elif c in "'\"":
            q = c
            cur += c
        elif c in "{[":
            depth += 1
            cur += c
        elif c in "}]":
            depth -= 1
            cur += c
        elif c == "," and depth == 0:
            items.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        items.append(cur.strip())
    return items


def unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def flow_list(body):
    """Parse `[ a, b ]` body into a list of unquoted strings."""
    return [unquote(x) for x in split_top_items(body)]


# --------------------------------------------------------------------------
# applicability predicate DSL (HC-KB-01 §4)
# --------------------------------------------------------------------------
DSL_TOKEN = re.compile(r"""
    \s+
  | "(?:[^"\\]|\\.)*"            # double string
  | '(?:[^'\\]|\\.)*'            # single string
  | /(?:[^/\\]|\\.)*/            # regex literal
  | \d+(?:\.\d+)?                # number
  | ==|!=|&&|\|\||<=|>=|[<>!]    # operators
  | \bin\b                       # membership
  | [()]                        # parens
  | ,                           # arg separator
  | [A-Za-z_][A-Za-z0-9_.]*(?:\[\*\])?   # dotted identifier (opt [*])
""", re.VERBOSE)
DSL_FUNCS = {"exists", "matches"}
DSL_KEYWORDS = {"in", "true", "false", "null"}


def check_dsl(expr):
    """Return a list of error strings if `expr` is not a valid predicate."""
    errs = []
    pos, n = 0, len(expr)
    toks = []
    while pos < n:
        m = DSL_TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            errs.append(f"unparseable near '{expr[pos:pos+20]}'")
            return errs
        t = m.group().strip()
        pos = m.end()
        if t:
            toks.append(t)
    # function names: an identifier immediately followed by '(' must be allowed
    depth = 0
    for i, t in enumerate(toks):
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
            if depth < 0:
                errs.append("unbalanced ')'")
                return errs
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", t) and i + 1 < len(toks) and toks[i + 1] == "(":
            if t not in DSL_FUNCS:
                errs.append(f"disallowed function call '{t}(' (only exists/matches)")
    if depth != 0:
        errs.append("unbalanced '('")
    return errs


# --------------------------------------------------------------------------
# card extraction + field parsing
# --------------------------------------------------------------------------
def extract_card_blocks(md_text):
    """Yield raw text of each ```yaml fenced block that defines a card."""
    for m in re.finditer(r"```yaml\n(.*?)```", md_text, re.S):
        block = m.group(1)
        if re.search(r"^id:\s*KB-", block, re.M):
            yield block


def parse_card(raw):
    """Parse a condensed card block into a dict of the fields we validate."""
    clean = strip_comments(raw)
    lines = merge_logical_lines(clean)
    fields = {}
    for ln in lines:
        m = re.match(r"^([a-z_]+):(.*)$", ln)
        if m:
            fields[m.group(1)] = m.group(2).strip()
    return fields, clean


def _inner(flow):
    """Strip one layer of surrounding { } or [ ]."""
    flow = flow.strip()
    if flow[:1] in "{[" and flow[-1:] in "}]":
        return flow[1:-1].strip()
    return flow


def parse_kv_flow(body):
    """Parse `k: v, k2: {..}, k3: [..]` into a dict of raw string values."""
    out = {}
    for item in split_top_items(body):
        if ":" in item:
            k, v = item.split(":", 1)
            out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------
def validate_card(fields, clean, source="", full=False):
    """Return a list of (grade, message) for one card.

    full=True enforces the shipping fields of a materialized kb/ card
    (version, status, references, test_fixture, cvss_base_vector,
    confidence_floor); full=False validates a condensed spec block."""
    issues = []

    def err(m): issues.append((ERROR, m))
    def unr(m): issues.append((UNRESOLVED, m))

    # id + naming (§3.1)
    cid = fields.get("id", "")
    m = RE_ID.match(cid)
    if not cid:
        err("missing id")
    elif not m:
        err(f"id '{cid}' does not match KB-<CLASS>-<FAMILY>-<nnn>")
    elif m.group(1) not in tx.KB_CLASSES:
        err(f"id class '{m.group(1)}' is not a known KB class")

    if not fields.get("title"):
        err("missing title")

    # blast_tier (§7) + cleanup (§9)
    bt_raw = fields.get("blast_tier")
    bt = None
    if bt_raw is None:
        err("missing blast_tier")
    else:
        try:
            bt = int(bt_raw)
            if bt < 0 or bt > 3:
                err(f"blast_tier {bt} out of range 0..3")
        except ValueError:
            err(f"blast_tier '{bt_raw}' is not an integer")
    cleanup = fields.get("cleanup")
    if cleanup is None:
        err("missing cleanup")
    elif bt is not None and bt >= 2 and cleanup.strip().lower() in ("none", ""):
        err(f"blast_tier {bt} requires a non-empty cleanup (got '{cleanup}')")

    # required list fields
    for lf in ("applicability", "preconditions", "yields_on_success", "probe_steps"):
        if lf not in fields:
            err(f"missing {lf}")

    # applicability DSL (§4)
    if "applicability" in fields:
        for clause in flow_list(_inner(fields["applicability"])):
            for e in check_dsl(clause):
                err(f"applicability clause [{clause}]: {e}")
    if not flow_list(_inner(fields.get("applicability", "[]"))):
        err("applicability is empty")

    # success_signal (§5)
    ss = fields.get("success_signal")
    if not ss:
        err("missing success_signal")
    else:
        kv = parse_kv_flow(_inner(ss))
        stype = kv.get("type")
        if stype not in tx.SIGNAL_TYPES:
            err(f"success_signal.type '{stype}' is not a known signal type")
        ev = unquote(kv.get("evaluator", ""))
        if not ev:
            err("success_signal missing evaluator")
        elif ev != "deterministic" and not re.match(r"^laya:[a-z_]+$", ev):
            err(f"success_signal.evaluator '{ev}' must be 'deterministic' or 'laya:<decision_point>'")
        if "assert" not in kv:
            err("success_signal missing assert")
        # oob must be in-range (§5)
        if stype == "oob_callback" or "collaborator" in clean:
            for host in re.findall(r"collaborator[:=]\s*([A-Za-z0-9_.:-]+)", clean):
                h = host.strip().strip(",")
                if tx.RE_EXTERNAL_HOST.search(h) and not tx.RE_RANGE_HOST.search(h):
                    err(f"oob collaborator '{h}' is not an in-sandbox listener")

    # taxonomy (§9)
    tax = fields.get("taxonomy")
    if not tax:
        err("missing taxonomy")
    else:
        kv = parse_kv_flow(_inner(tax))
        cwes = flow_list(_inner(kv.get("cwe", "[]"))) if "cwe" in kv else []
        if not cwes:
            err("taxonomy has no cwe")
        for c in cwes:
            fmt, res = tx.resolve("cwe", c)
            if not fmt:
                err(f"cwe '{c}' is malformed")
            elif not res:
                unr(f"cwe '{c}' not in reference")
        for ident in flow_list(_inner(kv.get("atlas", "[]"))):
            fmt, res = tx.resolve("atlas", ident)
            if not fmt:
                err(f"atlas id '{ident}' is malformed")
            elif not res:
                unr(f"atlas '{ident}' not in reference (needs verification)")
        for ident in flow_list(_inner(kv.get("capec", "[]"))):
            fmt, res = tx.resolve("capec", ident)
            if not fmt:
                err(f"capec '{ident}' is malformed")
            elif not res:
                unr(f"capec '{ident}' not in reference")
        for ident in flow_list(_inner(kv.get("owasp", "[]"))):
            fmt, _ = tx.resolve("owasp", ident)
            if not fmt:
                err(f"owasp ref '{ident}' is malformed")
        if "attack" in kv:
            akv = parse_kv_flow(_inner(kv["attack"]))
            if "technique" in akv:
                t = akv["technique"].strip()
                fmt, res = tx.resolve("attack_technique", t)
                if not fmt:
                    err(f"attack technique '{t}' is malformed")
                elif not res:
                    unr(f"attack technique '{t}' not in reference")
            if "tactic" in akv:
                t = akv["tactic"].strip()
                fmt, res = tx.resolve("attack_tactic", t)
                if not fmt:
                    err(f"attack tactic '{t}' is malformed")
                elif not res:
                    unr(f"attack tactic '{t}' not in reference")

    # severity_rubric (§5)
    sr = fields.get("severity_rubric")
    if not sr:
        err("missing severity_rubric")
    else:
        kv = parse_kv_flow(_inner(sr))
        base = kv.get("base")
        if base not in tx.SEVERITIES:
            err(f"severity_rubric.base '{base}' is not a valid severity")
        for clause_key in ("raise_if", "lower_if"):
            if clause_key in kv:
                for obj in split_top_items(_inner(kv[clause_key])):
                    okv = parse_kv_flow(_inner(obj))
                    if "when" not in okv or "to" not in okv:
                        err(f"{clause_key} entry missing when/to: {obj}")
                        continue
                    if unquote(okv["to"]) not in tx.SEVERITIES:
                        err(f"{clause_key} 'to' is not a severity: {okv['to']}")
                    for e in check_dsl(unquote(okv["when"])):
                        err(f"{clause_key} when-clause: {e}")

    # full-template shipping fields (materialized kb/ cards; HC-KB-01 §3, §9)
    if full:
        ver = fields.get("version", "")
        if not re.match(r"^\d+\.\d+\.\d+$", ver):
            err(f"version '{ver}' is not semver")
        if fields.get("status") not in ("draft", "active", "deprecated"):
            err(f"status '{fields.get('status')}' is not draft|active|deprecated")
        if not flow_list(_inner(fields.get("references", "[]"))):
            err("references is empty")
        tf = parse_kv_flow(_inner(fields.get("test_fixture", "{}")))
        if "fires_on" not in tf or "does_not_fire" not in tf:
            err("test_fixture must have fires_on and does_not_fire")
        srkv = parse_kv_flow(_inner(fields.get("severity_rubric", "{}")))
        cvss = unquote(srkv.get("cvss_base_vector", ""))
        if not cvss.startswith("CVSS:4.0/"):
            err("severity_rubric.cvss_base_vector missing or not a CVSS v4 vector")
        sskv = parse_kv_flow(_inner(fields.get("success_signal", "{}")))
        if "confidence_floor" not in sskv:
            err("success_signal missing confidence_floor")

    return issues


def is_condensed(fields, clean):
    """A card is 'condensed' when it omits the always-present shipping fields.
    (`inputs` is optional and `cvss_base_vector` is nested, so neither counts.)"""
    return any(f not in fields for f in ("version", "status", "references", "test_fixture"))


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="HC-KB-01 technique-card validator")
    ap.add_argument("paths", nargs="*",
                    help="card .yaml files, or spec .md files with --from-specs")
    ap.add_argument("--from-specs", action="store_true",
                    help="validate the condensed blocks in specs/HC-KB-*.md "
                         "instead of the materialized kb/<class>/*.yaml tree")
    ap.add_argument("--strict", action="store_true",
                    help="treat UNRESOLVED taxonomy ids as failures too")
    ap.add_argument("--quiet", action="store_true",
                    help="only print the summary and any ERROR/UNRESOLVED")
    args = ap.parse_args()

    # Build the list of (source_label, card_text, full, expected_id) units.
    units = []
    if args.from_specs:
        # Condensed blocks in the class specs. HC-KB-01.md holds the block-style
        # schema TEMPLATE (the definition), not a card instance, so it is skipped.
        specs = args.paths or sorted(glob.glob(os.path.join(ROOT, "specs", "HC-KB-*.md")))
        for path in [p for p in specs if os.path.basename(p) != "HC-KB-01.md"]:
            rel = os.path.relpath(path, ROOT)
            for raw in extract_card_blocks(open(path).read()):
                units.append((rel, raw, False, None))
    else:
        files = args.paths or sorted(
            glob.glob(os.path.join(ROOT, "kb", "**", "*.yaml"), recursive=True))
        for f in files:
            rel = os.path.relpath(f, ROOT)
            units.append((rel, open(f).read(), True, os.path.basename(f)[:-5]))

    if not units:
        print("no cards found. Run tools/materialize_kb.py, or pass --from-specs.")
        return 1

    totals = {ERROR: 0, UNRESOLVED: 0, WARN: 0}
    n_cards = n_condensed = 0
    unresolved_ids = {}
    seen_ids = set()

    for rel, raw, full, expect_id in units:
        n_cards += 1
        fields, clean = parse_card(raw)
        cid = fields.get("id", "<no-id>")
        seen_ids.add(cid)
        if is_condensed(fields, clean):
            n_condensed += 1
        issues = validate_card(fields, clean, source=rel, full=full)
        if expect_id and cid != expect_id:
            issues.append((ERROR, f"id '{cid}' does not match filename '{expect_id}'"))
        lines = []
        for grade, msg in issues:
            totals[grade] += 1
            if grade == UNRESOLVED:
                unresolved_ids.setdefault(msg.split(" not in")[0], []).append(cid)
            if grade == ERROR or grade == UNRESOLVED or not args.quiet:
                lines.append(f"    [{grade:10}] {cid}: {msg}")
        if lines:
            print(f"\n{rel}")
            print("\n".join(lines))

    # manifest coverage: every materialized card must have an eval manifest
    # entry (HC-EVAL-01 §9). Only meaningful for the kb/ tree.
    if not args.from_specs:
        manifest_ids = set()
        for mf in glob.glob(os.path.join(ROOT, "eval", "manifests", "*.yaml")):
            manifest_ids |= set(re.findall(r"card:\s*(KB-\S+)", open(mf).read()))
        for missing in sorted(seen_ids - manifest_ids):
            totals[ERROR] += 1
            print(f"\n(manifest)\n    [{ERROR:10}] {missing}: no eval manifest entry "
                  f"(HC-EVAL-01 §9)")

    print("\n" + "=" * 68)
    print(f"source: {'specs (condensed)' if args.from_specs else 'kb/ (materialized)'}")
    print(f"cards checked: {n_cards}   "
          f"ERROR: {totals[ERROR]}   "
          f"UNRESOLVED: {totals[UNRESOLVED]}   "
          f"WARN: {totals[WARN]}")
    if n_condensed:
        print(f"condensed cards (substantive fields only): {n_condensed}")
    if unresolved_ids:
        print("\nUNRESOLVED taxonomy ids (the `# verify` to-do surface):")
        for ident, cards in sorted(unresolved_ids.items()):
            print(f"  - {ident}  ({len(cards)} card(s): {', '.join(sorted(set(cards)))})")

    failed = totals[ERROR] > 0 or (args.strict and totals[UNRESOLVED] > 0)
    print("\nRESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
