"""Outer control loop and role orchestration (HC-AGENT-01 §4).

The harness owns control flow; the four roles are propose-only sessions injected
as dependencies. `Loop.run()` drives a run through plan -> hunt -> verify ->
report: the Planner orders (asset, technique) pairs, the Operator proposes probes
the loop disposes through `dispatch()` until a deterministic success signal fires
and a lead is emitted, the Verifier independently reproduces the lead on a
disjoint session (finder != verifier, asserted here and enforced at the DB), and
the report ships only if `validate_report` passes.

Signal triage stays in harness code: the loop reads the probe_event's recorded
deterministic_signals and applies the card's success_signal rule itself, so the
Operator never sees the raw signal (§7 - a classifier emits a label, not an
action, which shrinks the prompt-injection surface). An injected `signal_evaluator`
is the seam where Laya (HC-MODEL-02) replaces the deterministic default later.

The sandbox (provisioning, snapshot/restore, guard proofs) and the model plane
(Bifrost, the role LLMs) are infrastructure, injected here; tests drive the loop
with deterministic stub roles and a stub sandbox, the same way `dispatch()` is
driven with stub adapters. With the sandbox down the loop runs passive-only:
every lead is held `needs_validation` and the report ships nothing confirmed.
"""
import json
import uuid

from harness import bind
from harness import kb as kbmod
from harness import predicates
from harness import report as reportmod
from harness import roleio
from harness.blackboard import CONFIRMED, PROVISIONAL, Blackboard
from harness.dispatch import ProbeContext
from harness.store import audit, evidence, findings, ledger, reasoning

GOLDEN = "golden"


# --- role seam ----------------------------------------------------------
# The roles are propose-only sessions, injected. A later milestone backs them
# with Bifrost virtual keys (HC-MODEL-01); this slice defines the contract they
# implement and drives it with deterministic stubs.
#
# A role's propose_next returns raw model output (text) or None to give up; the
# harness, not the role, parses that text into a validated request or rejects the
# turn (roleio.parse_request, §5.1). The probe-history argument is the harness-owned
# untrusted-data view (roleio.role_context, §7), not the raw store rows.
#
#   planner.plan(target_model, candidates, ledger_summary) -> [Pair]   (ordered)
#   operator.begin(pair, facts) -> session   (session.id is the Bifrost vkey/session id;
#                                             facts are the asset's recon facts that scope the hunt)
#   operator.propose_next(session, card, role_context) -> str | None
#   verifier.begin() -> session             (session.id; disjoint provider from the Operator)
#   verifier.propose_next(session, vinput, role_context) -> str | None
#       vinput = {steps: [the recorded requests], evidence: [probe_event ids]}; only this crosses over
#       a Verifier may set session.disproved = True to actively reject (vs inconclusive)
#   reporter.render(conn, eng, *, mode, kb_version) -> report dict


class Pair:
    """One (asset, technique) unit of work. `asset` keys into the target model."""
    __slots__ = ("asset", "technique_id", "technique_version")

    def __init__(self, asset, technique_id, technique_version):
        self.asset = asset
        self.technique_id = technique_id
        self.technique_version = technique_version


class RunResult:
    __slots__ = ("report", "mode", "valid", "errors", "objective")

    def __init__(self, report, mode, valid, errors, objective=None):
        self.report = report
        self.mode = mode
        self.valid = valid
        self.errors = errors
        self.objective = objective      # HC-OBJ-01 §6b outcome, or not_applicable


# Proof facts the harness derives from a confirming probe's deterministic signals
# (HC-OBJ-01 §4.3). They are harness-observed, never model-asserted.
PROOF_CANARY = "proof.canary_sha256"
PROOF_OOB = "proof.oob_fired"


class DeterministicReporter:
    """Default Reporter: the HC-FIND-01 structured builder is the render. The
    cheap prose Reporter role (Bifrost) can wrap this later without changing the
    ship gate, which stays `validate_report`."""

    def render(self, conn, eng, *, mode, kb_version=None, objective=None):
        return reportmod.build_report(conn, eng, mode=mode, kb_version=kb_version,
                                      objective=objective)


def deterministic_signal(card, signals):
    """Default success-signal rule (HC-AGENT-01 §4.1, HC-MODEL-02 fallback).

    An adapter reports `deterministic_signals["hit"] = True` when the card's
    asserted condition holds on the probe response. A card whose evaluator is not
    `deterministic` needs Laya; without it the signal never fires here, so the
    lead is not auto-emitted (it never silently confirms on a model we do not
    have), matching the graceful-degradation decision in the log."""
    sig = (card or {}).get("success_signal") or {}
    if sig.get("evaluator") != "deterministic":
        return False
    return bool(signals.get("hit"))


def _applicable(card, facts):
    """All of a card's applicability predicates hold over the asset facts."""
    for expr in card.get("applicability") or []:
        try:
            if not predicates.evaluate(expr, facts):
                return False
        except predicates.PredicateError:
            return False
    return True


def _card_identifiers(card):
    """The fact names a card reads across its applicability and preconditions, used to
    tell which cross-host facts a card actually depends on (HC-OBJ-01 §8.1)."""
    names = set()
    for expr in (card.get("applicability") or []) + (card.get("preconditions") or []):
        names |= predicates.identifiers(expr)
    return names


def phase_threat_model(target_model, kb_index):
    """Assets x applicable KB cards -> candidate pairs (HC-AGENT-01 §4).

    Deterministic and model-free: a card is a candidate for an asset only if its
    applicability DSL holds over that asset's recon facts. `phase_recon` (which
    produces the target model) needs the live sandbox and is the injected
    upstream of this call, passed to `run()` as `target_model`."""
    pairs = []
    for asset in sorted(target_model):
        facts = target_model[asset]
        for (tid, ver) in sorted(kb_index):
            if _applicable(kb_index[(tid, ver)], facts):
                pairs.append(Pair(asset, tid, ver))
    return pairs


class Loop:
    def __init__(self, conn, eng, *, kb_index, dispatcher, sandbox,
                 planner, operator, verifier, reporter=None,
                 signal_evaluator=deterministic_signal, budget=16, max_denied=4,
                 max_invalid=3, kb_version=None):
        self.conn = conn
        self.eng = eng
        self.kb_index = kb_index
        self.dispatcher = dispatcher
        self.sandbox = sandbox
        self.planner = planner
        self.operator = operator
        self.verifier = verifier
        self.reporter = reporter or DeterministicReporter()
        self.signal_evaluator = signal_evaluator
        self.budget = budget
        self.max_denied = max_denied
        self.max_invalid = max_invalid
        self.kb_version = kb_version
        self.passive_only = False
        self.target_model = {}
        self.board = None       # the live blackboard, set only for an objective run (§6)
        self.objective_outcome = None

    # --- public entry ---------------------------------------------------
    def run(self, target_model):
        """Drive one engagement end to end and return the validated report.

        `target_model` is the recon output: `{asset: facts}`. Resumable - a pair
        the ledger already records (any status but `pending`) is skipped, so a
        killed run re-driven over the same target reaches the same confirmed set
        (HC-AGENT-01 §8)."""
        self.target_model = target_model
        self.passive_only = not self._sandbox_proven(startup=True)  # HC-SUB-01 §8

        if not self.passive_only:
            if self.eng.objective:
                self._run_objective()                          # HC-OBJ-01 §6 frontier loop
            else:
                self._run_coverage()                           # HC-AGENT-01 §4 coverage run
                self.objective_outcome = {"id": None, "status": "not_applicable"}

        if self.passive_only:
            self._hold_unverified_leads()
            if self.eng.objective:
                if self.board is None:
                    self.board = Blackboard(seed=self._seed_specs())
                self._record_outcome("not_achieved")
            else:
                self.objective_outcome = {"id": None, "status": "not_applicable"}
        mode = "passive-only" if self.passive_only else "sandboxed"

        report = self.reporter.render(self.conn, self.eng, mode=mode,
                                      kb_version=self.kb_version,
                                      objective=self.objective_outcome)
        status, errs = reportmod.validate_report(report, kbmod.known_pairs(self.kb_index))
        return RunResult(report, mode, status == "ok", errs, objective=self.objective_outcome)

    def _sandbox_proven(self, *, startup=False):
        """Run full proofs at startup and the lightweight guard proof during a run."""
        if self.passive_only:
            return False
        error_type = None
        try:
            proof = self.sandbox.proofs_pass() if startup else self.sandbox.guard_proof()
            proven = bool(proof) if startup else bool(proof.get("pass", False))
        except Exception as exc:
            proven = False
            error_type = type(exc).__name__
        if not proven:
            audit.record(
                self.conn, self.eng.id, "harness", "sandbox_proof",
                decision="passive-only", reason="sandbox containment was not proven",
                detail={"error_type": error_type} if error_type else {})
            self.passive_only = True
        return bool(proven)

    def _hold_unverified_leads(self):
        for row in findings.leads(self.conn, self.eng.id):
            if row["verdict"] == "lead":
                findings.transition(
                    self.conn, row["id"], "needs_validation", by="harness",
                    reason="passive-only: sandbox containment was not proven")

    def _run_coverage(self):
        """Today's batch run (HC-AGENT-01 §4): hunt every pending pair, then verify
        every lead. A contract with no objective runs exactly here, unchanged."""
        candidates = phase_threat_model(self.target_model, self.kb_index)
        plan = self.planner.plan(self.target_model, candidates,
                                 ledger.summary(self.conn, self.eng.id))
        for pair in plan:
            if self.passive_only:
                break
            if ledger.done(self.conn, self.eng.id, pair.asset, pair.technique_id):
                continue
            self._hunt(pair)
            if self.passive_only:
                break
        if not self.passive_only:
            for row in findings.leads(self.conn, self.eng.id):
                if self.passive_only:
                    break
                self._verify(row)

    def _run_objective(self):
        """Capability-frontier loop (HC-OBJ-01 §6): hunt a pair, verify it at once on
        a disjoint session, write its yields (provisional at lead, confirmed on
        confirm), then re-evaluate applicability and preconditions over the live
        board, so a confirmed fact opens the next card. Only confirmed facts gate a
        new card, so finder-is-not-verifier holds at every hop (§6.2). Objective
        completion and its deterministic proof are the next slice (§6b); this loop
        drives the chain and terminates on frontier exhaustion or the step cap."""
        self.board = Blackboard(seed=self._seed_specs())       # recon as confirmed ground truth
        cap = len(self.target_model) * max(1, len(self.kb_index)) + 2
        for _ in range(cap):
            pending = self._frontier_pending()                 # applicability+preconditions over the board
            if not pending:
                break                                          # frontier exhausted (§6.3)
            plan = self.planner.plan(self.target_model, pending,
                                     ledger.summary(self.conn, self.eng.id))
            if not plan:
                break
            pair = plan[0]
            fid = self._hunt(pair)
            if self.passive_only:
                break
            if fid is None:
                continue                                       # no lead; the pair is marked, move on
            card = self.kb_index[(pair.technique_id, pair.technique_version)]
            self._yield(pair, card, PROVISIONAL, fid)          # guides exploration, gates nothing
            if self.passive_only:
                continue                                       # no confirm, no escalation (§6.3)
            self._verify(findings.current(self.conn, fid))
            if self.passive_only:
                break
            if findings.current(self.conn, fid)["verdict"] != "confirmed":
                continue
            self._yield(pair, card, CONFIRMED, fid)            # only now can it open the next card
            self._record_proof(pair, fid)                      # §4.3 proof from the confirming signal
            if self._objective_met():                          # deterministic, §4.3
                self._record_outcome("achieved")
                if (self.eng.objective.get("on_success") or "stop") == "stop":
                    break                                      # §6.3 termination
        if self.objective_outcome is None:                     # frontier exhausted, goal not met
            self._record_outcome("not_achieved")

    # --- objective completion (§4.3, §6b) -------------------------------
    def _record_proof(self, pair, fid):
        """Derive proof facts from the confirming finding's recorded signals and write
        them confirmed. Harness-observed, so a role cannot assert completion (§3)."""
        scope = self._scope_of(pair.asset)
        for peid in self._found_event_ids(fid):
            sig = evidence.get_signals(self.conn, peid)
            if sig.get("canary_sha256"):
                self.board.put(PROOF_CANARY, scope, CONFIRMED, value=sig["canary_sha256"],
                               produced_by=fid, event_ids=[peid])
            if sig.get("oob_fired"):
                self.board.put(PROOF_OOB, scope, CONFIRMED, value=True,
                               produced_by=fid, event_ids=[peid])

    def _objective_met(self):
        """The objective is met only when the success predicate holds over the
        confirmed board at the target host AND the deterministic proof holds (§4.3).
        Never in passive-only, where nothing is confirmed (§9.2)."""
        if self.passive_only:
            return False
        obj = self.eng.objective
        scope = {"host": obj.get("target")}
        view = self.board.view(scope, tier=CONFIRMED)
        try:
            if not predicates.evaluate(obj.get("success") or "", view):
                return False
        except predicates.PredicateError:
            return False
        return self._proof_holds(obj, scope)

    def _proof_holds(self, obj, scope):
        otype = obj.get("type")
        if otype == "capability":
            return True                                        # the confirmed fact is the proof (§4.2)
        proof = obj.get("proof") or {}
        if proof.get("kind") == "canary":
            fact = self.board.get(PROOF_CANARY, scope)
            return (fact is not None and fact.tier == CONFIRMED
                    and fact.value == proof.get("sha256"))
        if proof.get("kind") == "oob_marker":
            return self.board.is_confirmed(PROOF_OOB, scope)
        return False

    def _record_outcome(self, status):
        obj = self.eng.objective
        self.objective_outcome = {
            "id": obj.get("id"), "status": status,
            "proof": self._proof_summary(obj),
            "attack_path": self._attack_path() if status == "achieved" else [],
            "reached_facts": [] if status == "achieved" else self._reached_facts()}

    def _proof_summary(self, obj):
        scope = {"host": obj.get("target")}
        if obj.get("type") == "canary":
            return {"kind": "canary", "sha256_matched": self._proof_holds(obj, scope)}
        if obj.get("type") == "reach":
            return {"kind": "oob_marker", "marker_fired": self._proof_holds(obj, scope)}
        return {"kind": "capability"}

    def _attack_path(self):
        """The kill chain: the confirmed findings on the path from recon to the
        objective, in dependency order (recon -> goal), each with the facts it
        yielded. Off-path confirmed findings are pruned by tracing the objective's
        required facts back through `yields_on_success <- preconditions` over the
        confirmed board; the order comes from those same edges, never from the
        random finding id, so a branch that converges reads in causal order (§9.1)."""
        chain = self._on_path_chain()
        rows = {r["id"]: r for r in findings.confirmed(self.conn, self.eng.id)}
        path = []
        for step, fid in enumerate(chain, 1):
            row = rows.get(fid)
            if row is None:
                continue
            card = self.kb_index.get((row["technique_id"], row["technique_version"]))
            path.append({"step": step, "finding_id": fid,
                         "technique_id": row["technique_id"],
                         "yielded": (card or {}).get("yields_on_success") or []})
        return path

    def _on_path_chain(self):
        """The on-path confirmed findings in dependency order. Start from the
        objective's required facts (the success predicate's identifiers, plus the
        recorded proof facts), follow each confirmed fact to the finding that produced
        it, add that finding's preconditions to the frontier, and stop at recon. Then
        order the reached findings by precondition depth, so each comes after the
        findings that produced its inputs; ties break on finding id for determinism."""
        producer, consumes = {}, {}            # fact name -> finding, finding -> precondition names
        for fact in self.board.current():
            if fact.tier != CONFIRMED or fact.produced_by in (None, "recon"):
                continue
            producer[fact.name] = fact.produced_by
            if fact.produced_by not in consumes:
                row = findings.current(self.conn, fact.produced_by)
                card = (self.kb_index.get((row["technique_id"], row["technique_version"]))
                        if row is not None else None)
                consumes[fact.produced_by] = list((card or {}).get("preconditions") or [])
        goals = predicates.identifiers(self.eng.objective.get("success") or "")
        on_path, frontier = set(), list(goals | {PROOF_CANARY, PROOF_OOB})
        while frontier:
            fid = producer.get(frontier.pop())
            if fid is None or fid in on_path:
                continue
            on_path.add(fid)
            frontier.extend(consumes.get(fid, ()))

        depth, resolving = {}, set()

        def _depth(fid):
            if fid in depth:
                return depth[fid]
            resolving.add(fid)                 # cycle guard; the board edges are a DAG in practice
            d = 0
            for pre in consumes.get(fid, ()):
                pf = producer.get(pre)
                if pf in on_path and pf not in resolving:
                    d = max(d, _depth(pf) + 1)
            resolving.discard(fid)
            depth[fid] = d
            return d

        return sorted(on_path, key=lambda f: (_depth(f), f))

    def _reached_facts(self):
        """Confirmed capabilities gained (not recon, not internal proof facts), so a
        not_achieved objective still states how far the chain got (§9.2)."""
        out = set()
        for fact in self.board.current():
            if (fact.tier == CONFIRMED and fact.produced_by not in (None, "recon")
                    and not fact.name.startswith("proof.")):
                host = fact.scope.get("host")
                out.add(f"{fact.name}@{host}" if host else fact.name)
        return sorted(out)

    # --- frontier helpers (§5, §6) --------------------------------------
    def _seed_specs(self):
        """Recon facts seeded into the board as confirmed, host-scoped ground truth."""
        specs = []
        for asset in self.target_model:
            scope = self._scope_of(asset)
            for name, value in self.target_model[asset].items():
                specs.append({"name": name, "scope": scope, "value": value})
        return specs

    def _frontier_pending(self):
        """Pairs whose applicability and preconditions both hold over the live
        confirmed board and that the ledger has not processed (§6.1).

        A card that holds over the asset's own host is pending as usual. A card that
        holds only once a confirmed foothold on a different in-scope host is merged in
        is a lateral move (§8.1): with `lateral_movement` it is pending; without it the
        pair is marked `blocked_by_policy / blocked_lateral` and never runs, so a
        negative result still names why. The probe target is always the pair's own
        in-scope asset, so a foothold changes only which techniques apply, never which
        hosts are reachable (the no-scope-widening invariant, §8.2)."""
        pending = []
        for asset in sorted(self.target_model):
            own = self._facts_for(asset)
            for (tid, ver) in sorted(self.kb_index):
                if ledger.done(self.conn, self.eng.id, asset, tid):
                    continue
                card = self.kb_index[(tid, ver)]
                pair = Pair(asset, tid, ver)
                if _applicable(card, own) and self._preconditions_met(card, own):
                    pending.append(pair)                   # holds on the asset's own host
                    continue
                if self.board is None:
                    continue                               # coverage path: no board, no chaining
                lateral = self._lateral_facts(asset, card, own)
                if not lateral:
                    continue                               # no cross-host dependency
                merged = {**lateral, **own}
                if not (_applicable(card, merged) and self._preconditions_met(card, merged)):
                    continue                               # the foothold does not unlock it
                if self.eng.lateral_movement:
                    pending.append(pair)                   # lateral chain permitted (§8.1)
                else:
                    self._mark(pair, "blocked_by_policy", detail="blocked_lateral")
        return pending

    def _facts_for(self, asset):
        """The fact view a card is evaluated over, on the asset's own host. On the
        coverage path this is the recon facts; on the objective path it is the
        confirmed board at the asset's host, so a confirmed yield from an earlier card
        is visible to the next. Cross-host foothold facts are added only by
        `_effective_facts`, and only when the engagement permits lateral movement."""
        if self.board is None:
            return self.target_model.get(asset, {})
        return self.board.view(self._scope_of(asset), tier=CONFIRMED)

    def _lateral_facts(self, asset, card, own):
        """Confirmed facts a card references that live on a different in-scope host
        than `asset` and that the asset does not already hold: the foothold, credential
        or session a lateral chain pivots on (§8.1). Host-local recon facts are present
        on every host, so only a capability gained elsewhere ever registers here, which
        is what separates a lateral move from ordinary same-host chaining."""
        refs = _card_identifiers(card)
        if not refs:
            return {}
        host = self._scope_of(asset).get("host")
        out = {}
        for fact in self.board.current():
            if (fact.tier == CONFIRMED and fact.name in refs and fact.name not in own
                    and fact.scope.get("host") not in (None, host)):
                out[fact.name] = fact.value
        return out

    def _effective_facts(self, asset, card):
        """The fact view a card is hunted over: its own-host facts, plus the cross-host
        foothold facts it references when `lateral_movement` is permitted. Mirrors the
        merge `_frontier_pending` used to admit the pair, so a lateral pair that was
        admitted also meets its preconditions when hunted (§8.1, §8.3)."""
        own = self._facts_for(asset)
        if self.board is None or not self.eng.lateral_movement:
            return own
        lateral = self._lateral_facts(asset, card, own)
        return {**lateral, **own} if lateral else own

    def _scope_of(self, asset):
        facts = self.target_model.get(asset, {})
        return {"host": facts.get("host", asset)}

    def _yield(self, pair, card, tier, fid):
        """Write a card's `yields_on_success` facts to the board at `tier`, scoped to
        the pair's host and tagged with the finding that produced them (§5.3)."""
        names = card.get("yields_on_success") or []
        if names:
            self.board.put_many(
                [{"name": n, "scope": self._scope_of(pair.asset)} for n in names],
                tier=tier, produced_by=fid, event_ids=self._found_event_ids(fid))

    # --- operator inner loop (§4.1) -------------------------------------
    def _hunt(self, pair):
        """Run the Operator inner loop on one pair; return the lead's finding id or
        None. Marks the pair's outcome in the ledger either way."""
        card = self.kb_index.get((pair.technique_id, pair.technique_version))
        if card is None:
            self._mark(pair, "not_applicable")
            return None
        facts = self._effective_facts(pair.asset, card)          # own host + any permitted foothold
        card = bind.bind_probe_args(card, facts)                 # route the probe from recon facts
        if card is None:                                         # not routable over this asset
            self._mark(pair, "not_applicable")                   # (e.g. a recon-routed card with
            return None                                          # no discovered endpoint here)
        if not self._preconditions_met(card, facts):
            self._mark(pair, "not_applicable")
            return None
        tier = int(card.get("blast_tier", 0))
        if tier > self.eng.max_blast_tier:
            self._mark(pair, "blocked_by_policy")                # HC-SUB-01 §7 cap
            return None
        if not self._sandbox_proven():
            self._mark(pair, "inconclusive")
            return None

        snap = self.sandbox.snapshot() if tier >= 2 else None    # §4.1 tier>=2 snapshot
        session = self.operator.begin(pair, facts)               # facts scope the hunt
        observations, repro, pe_ids = [], [], []
        denied = invalid = 0
        outcome = "attempted"
        lead_fid = None
        try:
            for step in range(self.budget):
                raw = self.operator.propose_next(session, card,
                                                 roleio.role_context(observations))
                if raw is None:                                  # role gives up
                    break
                turn = roleio.parse_request(raw)                 # harness parses, not the role
                if turn.rejection is not None:                   # unparseable turn (§5.1)
                    invalid += 1
                    observations.append(turn.rejection.as_observation())  # re-prompt (§9)
                    self._record_turn("operator", session, pair, step, raw, turn, None)
                    if invalid >= self.max_invalid:
                        outcome = "inconclusive"
                        break
                    continue
                if not self._sandbox_proven():
                    outcome = "inconclusive"
                    self._record_turn("operator", session, pair, step, raw, turn, None)
                    break
                obs = self.dispatcher.dispatch(
                    turn.request, self._ctx(pair, tier, "operator", "hunting",
                                            snap or GOLDEN, snap is not None))
                observations.append(obs)
                self._record_turn("operator", session, pair, step, raw, turn,
                                  obs.get("probe_event_id"))
                if obs.get("disposition") == "deny":             # a denial is data (§5.2)
                    denied += 1
                    if denied >= self.max_denied:
                        outcome = "inconclusive"                 # pair abandoned (§9)
                        break
                    continue
                pe_ids.append(obs["probe_event_id"])
                repro.append(turn.request)                       # the full request, so a Verifier can reproduce
                signals = evidence.get_signals(self.conn, obs["probe_event_id"])
                if self.signal_evaluator(card, signals):
                    lead_fid = self._emit_lead(pair, card, facts, session.id, repro,
                                               pe_ids, signals.get("confidence"), tier)
                    outcome = "lead"
                    break
        finally:
            if snap is not None:
                self.sandbox.restore(snap)                       # §4.1 restore after tier>=2
        self._mark(pair, outcome)
        return lead_fid

    def _emit_lead(self, pair, card, facts, found_by, repro, pe_ids, confidence, tier):
        fid = "F-" + uuid.uuid4().hex[:12]
        findings.emit_lead(self.conn, fid, self.eng.id, card, pair.asset,
                           found_by=found_by, facts=facts, repro=repro,
                           event_ids=pe_ids, signal_confidence=confidence,
                           blast_tier_used=tier)
        if self.passive_only:
            # sandbox down: found but unverifiable, held for independent validation
            findings.transition(self.conn, fid, "needs_validation", by=found_by,
                                reason="passive-only: sandbox guard proofs did not pass")
        return fid

    # --- verification (§4.2) --------------------------------------------
    def _verify(self, finding_row):
        fid = finding_row["id"]
        pair = Pair(finding_row["asset"], finding_row["technique_id"],
                    finding_row["technique_version"])
        card = self.kb_index.get((pair.technique_id, pair.technique_version))
        tier = int(card.get("blast_tier", 0)) if card else 0

        if not self._sandbox_proven():
            findings.transition(
                self.conn, fid, "needs_validation", by="harness",
                reason="passive-only: sandbox containment was not proven")
            return

        self.sandbox.restore(GOLDEN)                             # §4.2 golden, then fresh
        fresh = self.sandbox.snapshot()
        session = self.verifier.begin()

        # finder != verifier: refuse a shared identity before any confirm (§9),
        # defense in depth over the DB CHECK. Hold the lead, do not reject it.
        if session.id == finding_row["found_by"]:
            findings.transition(
                self.conn, fid, "needs_validation", by=session.id,
                reason="verifier shares the operator session; held for independent verification")
            self._mark(pair, "inconclusive")
            return

        vinput = {"steps": json.loads(finding_row["repro"]) if finding_row["repro"] else [],
                  "evidence": self._found_event_ids(fid)}       # ONLY this crosses over
        observations, pe_ids = [], []
        denied = invalid = 0
        reproduced = False
        for step in range(self.budget):
            raw = self.verifier.propose_next(session, vinput,
                                             roleio.role_context(observations))
            if raw is None:
                break
            turn = roleio.parse_request(raw)                     # harness parses, not the role
            if turn.rejection is not None:                       # unparseable turn (§5.1)
                invalid += 1
                observations.append(turn.rejection.as_observation())  # re-prompt (§9)
                self._record_turn("verifier", session, pair, step, raw, turn, None)
                if invalid >= self.max_invalid:
                    break                                        # falls through to inconclusive
                continue
            if not self._sandbox_proven():
                self._record_turn("verifier", session, pair, step, raw, turn, None)
                findings.transition(
                    self.conn, fid, "needs_validation", by="harness",
                    reason="passive-only: sandbox containment was not proven")
                return
            obs = self.dispatcher.dispatch(
                turn.request, self._ctx(pair, tier, "verifier", "verification", fresh, True))
            observations.append(obs)
            self._record_turn("verifier", session, pair, step, raw, turn,
                              obs.get("probe_event_id"))
            if obs.get("disposition") == "deny":
                denied += 1
                if denied >= self.max_denied:
                    break
                continue
            pe_ids.append(obs["probe_event_id"])
            signals = evidence.get_signals(self.conn, obs["probe_event_id"])
            if self.signal_evaluator(card, signals):
                reproduced = True
                break

        if not self._sandbox_proven():
            findings.transition(
                self.conn, fid, "needs_validation", by="harness",
                reason="passive-only: sandbox containment was not proven")
            return
        if reproduced and session.id != finding_row["found_by"]:
            findings.confirm(self.conn, fid, verified_by=session.id, events=pe_ids)
            self._mark(pair, "confirmed")
        elif getattr(session, "disproved", False):
            findings.reject(self.conn, fid, reason="verifier actively disproved the lead",
                            events=pe_ids)
            self._mark(pair, "rejected")
        else:
            findings.mark_inconclusive(
                self.conn, fid,
                reason="verifier could not reproduce within budget (environment or timing)")
            self._mark(pair, "inconclusive")

    # --- helpers --------------------------------------------------------
    def _preconditions_met(self, card, facts):
        for p in card.get("preconditions") or []:
            try:
                if not predicates.evaluate(p, facts):
                    return False
            except predicates.PredicateError:
                return False
        return True

    def _ctx(self, pair, tier, role, phase, snapshot_id, has_snapshot):
        return ProbeContext(pair_asset=pair.asset, technique_id=pair.technique_id,
                            technique_version=pair.technique_version, blast_tier=tier,
                            role=role, phase=phase, snapshot_id=snapshot_id,
                            has_snapshot=has_snapshot)

    def _found_event_ids(self, finding_id):
        return [r["probe_event_id"] for r in self.conn.execute(
            "SELECT probe_event_id FROM finding_event WHERE finding_id=? AND side='found' ORDER BY probe_event_id",
            (finding_id,))]

    def _mark(self, pair, status, detail=None):
        ledger.mark(self.conn, self.eng.id, pair.asset, pair.technique_id, status, detail=detail)

    def _record_turn(self, role, session, pair, step, raw, turn, probe_event_id):
        """Persist one role proposal for the reasoning view (HC-REPORT-01 §3). Write-only:
        the text is captured for later display and is never read back into any role, which
        leaves the finder-is-not-verifier boundary untouched."""
        reasoning.record(
            self.conn, engagement_id=self.eng.id, role=role, session_id=session.id,
            asset=pair.asset, technique_id=pair.technique_id, step=step, raw=raw,
            parsed=turn.request,
            rejection=turn.rejection.reason if turn.rejection is not None else None,
            probe_event_id=probe_event_id)
