"""Blast-tier gate (HC-SUB-01 §7).

`blast_gate` decides whether an action of a given tier may run under the
engagement's cap, with the snapshot and tier-3 authorization rules. Fail-closed:
tiers 2 and 3 require a live snapshot handle, and tier 3 additionally requires
that the contract names the technique.
"""


def blast_gate(eng, tier, has_snapshot, technique_id=None):
    """Return ('allow', None) or ('deny', reason)."""
    try:
        tier = int(tier)
    except (TypeError, ValueError):
        return "deny", f"bad_tier:{tier}"
    if tier < 0 or tier > 3:
        return "deny", f"tier_out_of_range:{tier}"

    if tier > eng.max_blast_tier:
        return "deny", f"blocked_by_policy:tier_{tier}>cap_{eng.max_blast_tier}"

    if tier >= 2 and not has_snapshot:
        return "deny", f"snapshot_required:tier_{tier}"

    if tier == 3 and technique_id not in eng.tier3_techniques:
        return "deny", f"tier3_not_authorized:{technique_id}"

    return "allow", None
