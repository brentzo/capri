"""Knowledge-base index (HC-KB-01).

Loads the materialized technique cards into an index keyed by
(technique_id, version), so the report validator can resolve a finding's
technique to a known card (HC-FIND-01 §7.2) and the loop can look up a card's
success signal and severity rubric. Pure standard library via yamlmini.
"""
import glob
import os

from harness import yamlmini

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_DIR = os.path.join(ROOT, "kb")


def load(kb_dir=KB_DIR):
    """Return {(id, version): card_dict} for every card under kb_dir."""
    index = {}
    for path in sorted(glob.glob(os.path.join(kb_dir, "**", "*.yaml"), recursive=True)):
        card = yamlmini.load(open(path).read())
        cid, ver = card.get("id"), card.get("version")
        if cid and ver:
            index[(cid, ver)] = card
    return index


def known_pairs(index):
    """The set of (id, version) pairs in the index, for the report validator."""
    return set(index.keys())
