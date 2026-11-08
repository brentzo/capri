"""Deterministic Planner (HC-AGENT-01 §3, the read-only planning role).

The Planner orders the candidate (asset, technique) pairs the loop will hunt. It
proposes nothing and holds no tools; it only ranks. This is the v1 stand-in for
the "mid reasoning" LLM planner: a transparent, reproducible priority that the
loop drives through its role seam, with the LLM planner a later swap behind the
same `plan(target_model, candidates, ledger_summary)` interface.

Priority is most-severe-first by the card's base severity band, then
lowest-blast-tier-first (a cheaper, safer probe that needs no snapshot comes
before a heavier one of equal severity), then a stable (technique, asset)
tiebreak so a plan is byte-for-byte reproducible across runs. The loop already
skips any pair the coverage ledger records, so the Planner orders the whole
candidate set and leaves done-skipping to the loop; the ledger summary is
accepted for the re-plan cadence HC-AGENT-01 §12 leaves open and does not yet
change the ordering.
"""
from harness import severity

_MEDIUM = severity.BANDS.index("medium")


class DeterministicPlanner:
    def __init__(self, kb_index):
        self.kb_index = kb_index

    def plan(self, target_model, candidates, ledger_summary=None):
        """Return the candidate pairs in hunt order (a new list; input untouched)."""
        return sorted(candidates, key=self._priority)

    def _priority(self, pair):
        card = self.kb_index.get((pair.technique_id, pair.technique_version)) or {}
        band = (card.get("severity_rubric") or {}).get("base", "medium")
        rank = severity.BANDS.index(band) if band in severity.BANDS else _MEDIUM
        tier = int(card.get("blast_tier", 0))
        # -rank => most severe first; tier asc => cheapest/safest first within a band
        return (-rank, tier, pair.technique_id, pair.asset)
