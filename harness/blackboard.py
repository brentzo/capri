"""Run-local world-state blackboard (HC-OBJ-01 §5; realizes HC-KB-01 §6).

The blackboard makes the KB's preconditions and yields live. It is the append-only,
provenance-tagged store of facts that cards read as preconditions and that the
harness writes as yields. Two tiers carry finder-is-not-verifier into every hop of
a chain:

- a `provisional` fact is written when a lead is emitted; it may inform the
  Operator's exploration and the Planner, but it never gates anything;
- a `confirmed` fact is written only when the independent Verifier confirms the
  producing finding, and only confirmed facts satisfy a precondition that gates
  escalation or lateral movement, or are read by the objective predicate (§3).

Only the harness writes facts; a role never does, it only produces the probe
evidence the harness derives a fact from (§5.2). A fact is immutable and is never
mutated: a confirmed fact supersedes its provisional predecessor of the same
(name, scope) without losing the audit trail, so the full append-only log
reconstructs the attack path (§9). This is run-local in-memory state; a resumed run
rebuilds it by replaying the confirmed findings (§6), which are the durable record
in HC-DATA-01.
"""
from harness.store.db import now

PROVISIONAL = "provisional"
CONFIRMED = "confirmed"
_TIER_RANK = {PROVISIONAL: 0, CONFIRMED: 1}


class Fact:
    """One immutable fact. `value` defaults True so a bare capability name is truthy
    for the predicate DSL; `scope` locates it (for example a host), and `produced_by`
    plus `event_ids` tie it back to the finding and evidence that yielded it."""
    __slots__ = ("name", "scope", "tier", "value", "produced_by", "event_ids", "at")

    def __init__(self, name, scope, tier, value, produced_by, event_ids, at):
        self.name = name
        self.scope = dict(scope or {})
        self.tier = tier
        self.value = value
        self.produced_by = produced_by
        self.event_ids = tuple(event_ids or ())
        self.at = at

    def as_dict(self):
        return {"name": self.name, "scope": dict(self.scope), "tier": self.tier,
                "value": self.value, "produced_by": self.produced_by,
                "event_ids": list(self.event_ids), "at": self.at}


def _canon(scope):
    """A hashable, order-independent key for a scope mapping."""
    return tuple(sorted((str(k), str(v)) for k, v in (scope or {}).items()))


class Blackboard:
    def __init__(self, seed=None, *, clock=now):
        self._clock = clock
        self._log = []                 # append-only: every fact ever written
        self._current = {}             # (name, canon scope) -> the best current Fact
        for spec in seed or []:        # recon ground truth enters confirmed
            self.put(spec["name"], spec.get("scope"), CONFIRMED,
                     value=spec.get("value", True),
                     produced_by=spec.get("produced_by", "recon"),
                     event_ids=spec.get("event_ids"))

    def put(self, name, scope=None, tier=CONFIRMED, *, value=True,
            produced_by=None, event_ids=None):
        """Write a fact. Appends to the log always; updates the current view only
        when the new fact does not downgrade a higher-tier predecessor (§5.2)."""
        if tier not in _TIER_RANK:
            raise ValueError(f"unknown fact tier {tier!r}")
        fact = Fact(name, scope, tier, value, produced_by, event_ids, self._clock())
        self._log.append(fact)
        key = (name, _canon(scope))
        cur = self._current.get(key)
        if cur is None or _TIER_RANK[tier] >= _TIER_RANK[cur.tier]:
            self._current[key] = fact
        return fact

    def put_many(self, specs, tier=CONFIRMED, *, produced_by=None, event_ids=None):
        """Write a card's yields in one call (used at lead emission and confirmation)."""
        return [self.put(s["name"], s.get("scope"), tier, value=s.get("value", True),
                         produced_by=produced_by, event_ids=event_ids)
                for s in (specs or [])]

    def get(self, name, scope=None):
        return self._current.get((name, _canon(scope)))

    def is_confirmed(self, name, scope=None):
        fact = self.get(name, scope)
        return fact is not None and fact.tier == CONFIRMED

    def view(self, context=None, *, tier=CONFIRMED):
        """A flat {name: value} of current facts at or above `tier` whose scope is
        satisfied by `context` (every key/value in the fact's scope is present in
        context, so a globally-scoped fact is always visible), for the predicate
        evaluator. `tier=CONFIRMED` is the gating view (§3); `tier=PROVISIONAL`
        also includes provisional facts, for exploration only."""
        context = context or {}
        min_rank = _TIER_RANK[tier]
        out = {}
        for fact in self._current.values():
            if _TIER_RANK[fact.tier] < min_rank:
                continue
            if all(context.get(k) == v for k, v in fact.scope.items()):
                out[fact.name] = fact.value
        return out

    def facts(self):
        """The full append-only history, superseded facts included (for the §9 trace)."""
        return list(self._log)

    def current(self):
        return list(self._current.values())

    def producer(self, name, scope=None):
        """The finding id that produced the current fact, for attack-path tracing (§9)."""
        fact = self.get(name, scope)
        return fact.produced_by if fact else None
