"""Severity from the card's rubric (HC-FIND-01 §5, HC-KB-01 §5, §6).

Severity starts at `severity_rubric.base` and is adjusted by `raise_if` /
`lower_if` clauses evaluated against the blackboard facts: a raise clause can
only move the band up, a lower clause only down, so severity tracks demonstrated
impact rather than theoretical reach. The CVSS v4 vector is carried from the
card; the numeric score here is the band's representative value, not a
re-derivation of the vector (exact CVSS v4 vector scoring is a deferred
refinement, not hand-rolled, so we never present a guessed number as precise).
"""
from harness.predicates import evaluate

BANDS = ["none", "low", "medium", "high", "critical"]
_REP_SCORE = {"none": 0.0, "low": 2.0, "medium": 5.0, "high": 8.0, "critical": 9.5}


def _rank(band):
    try:
        return BANDS.index(band)
    except ValueError:
        return BANDS.index("medium")       # unknown band -> treat as medium, fail-safe


def score(rubric, facts=None):
    """Return {'version','vector','band','score'} for a card's severity_rubric."""
    rubric = rubric or {}
    facts = facts or {}
    band = rubric.get("base", "medium")
    if band not in BANDS:
        band = "medium"

    for clause in rubric.get("raise_if", []) or []:
        to = clause.get("to")
        if to in BANDS and evaluate(clause["when"], facts) and _rank(to) > _rank(band):
            band = to
    for clause in rubric.get("lower_if", []) or []:
        to = clause.get("to")
        if to in BANDS and evaluate(clause["when"], facts) and _rank(to) < _rank(band):
            band = to

    return {"version": "4.0", "vector": rubric.get("cvss_base_vector"),
            "band": band, "score": _REP_SCORE[band]}
