#!/usr/bin/env python3
"""Materialize the condensed technique cards into the full kb/<class>/*.yaml tree.

Reads the authored condensed card blocks from docs/specs/HC-KB-*.md and writes one
complete card file per card under kb/<class-dir>/<id>.yaml, filling the
full-template fields HC-KB-01 §3 requires that the condensed blocks omit:

  version, status, supersedes, inputs, success_signal.confidence_floor,
  severity_rubric.cvss_base_vector, test_fixture, references

Derived fields are honest defaults, not invented precision:
  - cvss_base_vector is a CVSS v4 base vector derived from the severity band
    and class; it is a starting point the report pipeline refines per finding
    (HC-FIND-01), not a per-card hand-scored vector.
  - references are the canonical catalog URLs for the card's taxonomy ids.
  - test_fixture paths follow the seed/<class-dir>/<id>-vuln|-patched convention.

Idempotent: re-running regenerates the tree. Also writes kb/index.md
(HC-KB-01 §7) and eval/manifests/<class>.yaml (HC-EVAL-01 §4).

Usage: python3 tools/materialize_kb.py
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import taxonomy as tx                     # noqa: E402
from validate_kb import (                 # noqa: E402
    strip_comments, _depth_delta, split_top_items, parse_kv_flow, _inner,
    flow_list, unquote, extract_card_blocks,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CLASS_DIR = {
    "WEB": "web-protocol-auth", "CLIENT": "client-side", "AILLM": "ai-llm",
    "CLOUD": "cloud-deployment", "SUPPLY": "supply-chain", "RPC": "rpc-messaging",
    "DOS": "resource-exhaustion", "DATA": "data-isolation", "BIN": "memory-binary",
    "MOBILE": "mobile-local-ipc",
}
# AV:L where the attack surface is local (mobile IPC, native host); AV:N otherwise.
CLASS_AV = {c: "N" for c in CLASS_DIR}
CLASS_AV["MOBILE"] = "L"


# --------------------------------------------------------------------------
# condensed-block parsing (into scalars / flow strings / block sequences)
# --------------------------------------------------------------------------
def parse_condensed(raw):
    clean = strip_comments(raw)
    lines = clean.split("\n")
    fields, order = {}, []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        m = re.match(r"^([a-z_]+):(.*)$", line)
        if not m:
            i += 1
            continue
        key, rest = m.group(1), m.group(2).strip()
        if key not in fields:
            order.append(key)
        if rest == "":
            items, j = [], i + 1
            while j < n and (lines[j].startswith(" ") or not lines[j].strip()):
                s = lines[j].strip()
                if s.startswith("- "):
                    items.append(s[2:].strip())
                j += 1
            fields[key] = ("seq", items)
            i = j
        else:
            buf, depth, j = rest, _depth_delta(rest), i + 1
            while depth > 0 and j < n:
                buf += " " + lines[j].strip()
                depth += _depth_delta(lines[j])
                j += 1
            fields[key] = ("val", buf)
            i = j
    return fields, order


# --------------------------------------------------------------------------
# derived fields
# --------------------------------------------------------------------------
def cvss_vector(cls, base):
    av = CLASS_AV.get(cls, "N")
    # (PR, VC, VI, VA) per band; DOS expresses availability instead of C/I.
    if cls == "DOS":
        table = {"critical": ("N", "N", "N", "H"), "high": ("N", "N", "N", "H"),
                 "medium": ("N", "N", "N", "L"), "low": ("N", "N", "N", "L"),
                 "info": ("N", "N", "N", "N")}
    else:
        table = {"critical": ("N", "H", "H", "N"), "high": ("N", "H", "N", "N"),
                 "medium": ("L", "L", "L", "N"), "low": ("N", "L", "N", "N"),
                 "info": ("N", "N", "N", "N")}
    pr, vc, vi, va = table.get(base, table["medium"])
    return (f"CVSS:4.0/AV:{av}/AC:L/AT:N/PR:{pr}/UI:N/"
            f"VC:{vc}/VI:{vi}/VA:{va}/SC:N/SI:N/SA:N")


def references(taxonomy_raw):
    kv = parse_kv_flow(_inner(taxonomy_raw)) if taxonomy_raw else {}
    urls = []
    for c in flow_list(_inner(kv.get("cwe", "[]"))):
        m = re.match(r"CWE-(\d+)", c)
        if m:
            urls.append(f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html")
    if "attack" in kv:
        akv = parse_kv_flow(_inner(kv["attack"]))
        t = akv.get("technique", "").strip()
        if t:
            path = t.replace(".", "/")
            urls.append(f"https://attack.mitre.org/techniques/{path}/")
    for a in flow_list(_inner(kv.get("atlas", "[]"))):
        urls.append(f"https://atlas.mitre.org/techniques/{a}")
    for o in flow_list(_inner(kv.get("owasp", "[]"))):
        if o.startswith("WSTG"):
            urls.append("https://owasp.org/www-project-web-security-testing-guide/")
        elif o.startswith("API"):
            urls.append("https://owasp.org/API-Security/editions/2023/en/0x11-t10/")
        elif o.startswith("LLM"):
            urls.append("https://genai.owasp.org/llm-top-10/")
        elif o.startswith("M") and ":" in o:
            urls.append("https://owasp.org/www-project-mobile-top-10/")
    # dedupe, keep order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def augment_flow_map(raw, additions):
    """Parse a `{ ... }` flow map, append k:v additions not already present,
    and re-emit, preserving the original raw values verbatim."""
    kv = parse_kv_flow(_inner(raw))
    for k, v in additions:
        if k not in kv:
            kv[k] = v
    return "{ " + ", ".join(f"{k}: {v}" for k, v in kv.items()) + " }"


def emit_card(fields, order, cls):
    cid = fields["id"][1]
    base = parse_kv_flow(_inner(fields["severity_rubric"][1])).get("base", "medium")
    evaluator = parse_kv_flow(_inner(fields["success_signal"][1])).get("evaluator", "")
    floor = "0.7" if "laya:" in evaluator else "0.0"

    # inputs only when a card iterates params
    uses_params = "asset.params" in (fields.get("applicability", ("", ""))[1] or "")

    ss = augment_flow_map(fields["success_signal"][1], [("confidence_floor", floor)])
    sr = augment_flow_map(fields["severity_rubric"][1],
                          [("cvss_base_vector", f'"{cvss_vector(cls, base)}"')])
    short = cid.lower()
    cdir = CLASS_DIR[cls]
    fixt = (f"{{ fires_on: seed/{cdir}/{short}-vuln, "
            f"does_not_fire: seed/{cdir}/{short}-patched }}")
    refs = "[ " + ", ".join(f'"{u}"' for u in references(fields["taxonomy"][1])) + " ]"

    out = []
    out.append(f"id: {cid}")
    out.append(f"title: {fields['title'][1]}")
    out.append("version: 1.0.0")
    out.append("status: active")
    out.append("supersedes: null")
    out.append(f"taxonomy: {fields['taxonomy'][1]}")
    out.append(f"applicability: {fields['applicability'][1]}")
    out.append(f"preconditions: {fields['preconditions'][1]}")
    out.append(f"yields_on_success: {fields['yields_on_success'][1]}")
    if uses_params:
        out.append('inputs: { param: "{asset.params[*]}" }')
    out.append(f"blast_tier: {fields['blast_tier'][1]}")
    out.append(f"cleanup: {fields['cleanup'][1]}")
    out.append("probe_steps:")
    for step in fields["probe_steps"][1]:
        out.append(f"  - {step}")
    out.append(f"success_signal: {ss}")
    out.append(f"severity_rubric: {sr}")
    if "false_positive_notes" in fields:
        out.append(f"false_positive_notes: {fields['false_positive_notes'][1]}")
    out.append(f"test_fixture: {fixt}")
    out.append(f"references: {refs}")
    return cid, "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def main():
    specs = sorted(glob.glob(os.path.join(ROOT, "docs", "specs", "HC-KB-*.md")))
    specs = [p for p in specs if os.path.basename(p) != "HC-KB-01.md"]
    by_class = {}
    written = 0
    for path in specs:
        for raw in extract_card_blocks(open(path).read()):
            fields, order = parse_condensed(raw)
            cid = fields["id"][1]
            cls = cid.split("-")[1]
            cdir = CLASS_DIR[cls]
            cid, text = emit_card(fields, order, cls)
            d = os.path.join(ROOT, "kb", cdir)
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, cid + ".yaml"), "w").write(text)
            by_class.setdefault(cls, []).append(cid)
            written += 1

    # kb/index.md (HC-KB-01 §7)
    lines = ["# KB card index", "",
             "Generated by tools/materialize_kb.py. Do not edit by hand.", ""]
    for cls in sorted(by_class):
        lines.append(f"## {cls}  ({CLASS_DIR[cls]}) - {len(by_class[cls])} cards")
        for cid in sorted(by_class[cls]):
            lines.append(f"- {cid}")
        lines.append("")
    open(os.path.join(ROOT, "kb", "index.md"), "w").write("\n".join(lines))

    # eval/manifests/<class>.yaml (HC-EVAL-01 §4): one ground-truth entry per card
    man_dir = os.path.join(ROOT, "eval", "manifests")
    os.makedirs(man_dir, exist_ok=True)
    for cls, cids in sorted(by_class.items()):
        cdir = CLASS_DIR[cls]
        m = [f"# Ground-truth manifest for the {cdir} seed targets (HC-EVAL-01 §4).",
             "# Generated by tools/materialize_kb.py; one planted entry per active card.",
             f"target_class: {cdir}", "provenance: eval_seed", "planted:"]
        for cid in sorted(cids):
            short = cid.lower()
            m.append(f"  - card: {cid}")
            m.append(f"    fixture: seed/{cdir}/{short}-vuln")
            m.append("    expect: { verdict: confirmed }")
        m.append("negatives:")
        for cid in sorted(cids):
            short = cid.lower()
            m.append(f"  - card: {cid}")
            m.append(f"    fixture: seed/{cdir}/{short}-patched")
            m.append("    expect: { fire: false }")
        open(os.path.join(man_dir, cdir + ".yaml"), "w").write("\n".join(m) + "\n")

    print(f"materialized {written} cards across {len(by_class)} classes")
    print(f"  kb/<class>/*.yaml, kb/index.md, eval/manifests/*.yaml")


if __name__ == "__main__":
    main()
