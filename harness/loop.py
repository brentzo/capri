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

from harness import kb as kbmod
from harness import predicates
from harness import report as reportmod
from harness import roleio
from harness.dispatch import ProbeContext
from harness.store import evidence, findings, ledger

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
    __slots__ = ("report", "mode", "valid", "errors")

    def __init__(self, report, mode, valid, errors):
        self.report = report
        self.mode = mode
        self.valid = valid
        self.errors = errors


class DeterministicReporter:
    """Default Reporter: the HC-FIND-01 structured builder is the render. The
    cheap prose Reporter role (Bifrost) can wrap this later without changing the
    ship gate, which stays `validate_report`."""

    def render(self, conn, eng, *, mode, kb_version=None):
        return reportmod.build_report(conn, eng, mode=mode, kb_version=kb_version)


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

    # --- public entry ---------------------------------------------------
    def run(self, target_model):
        """Drive one engagement end to end and return the validated report.

        `target_model` is the recon output: `{asset: facts}`. Resumable - a pair
        the ledger already records (any status but `pending`) is skipped, so a
        killed run re-driven over the same target reaches the same confirmed set
        (HC-AGENT-01 §8)."""
        self.target_model = target_model
        self.passive_only = not self.sandbox.proofs_pass()     # HC-SUB-01 §8
        mode = "passive-only" if self.passive_only else "sandboxed"

        candidates = phase_threat_model(target_model, self.kb_index)
        plan = self.planner.plan(target_model, candidates,
                                 ledger.summary(self.conn, self.eng.id))
        for pair in plan:
            if ledger.done(self.conn, self.eng.id, pair.asset, pair.technique_id):
                continue
            self._hunt(pair)

        if not self.passive_only:
            for row in findings.leads(self.conn, self.eng.id):
                self._verify(row)

        report = self.reporter.render(self.conn, self.eng, mode=mode,
                                      kb_version=self.kb_version)
        status, errs = reportmod.validate_report(report, kbmod.known_pairs(self.kb_index))
        return RunResult(report, mode, status == "ok", errs)

    # --- operator inner loop (§4.1) -------------------------------------
    def _hunt(self, pair):
        card = self.kb_index.get((pair.technique_id, pair.technique_version))
        if card is None:
            self._mark(pair, "not_applicable")
            return
        facts = self.target_model.get(pair.asset, {})
        if not self._preconditions_met(card, facts):
            self._mark(pair, "not_applicable")
            return
        tier = int(card.get("blast_tier", 0))
        if tier > self.eng.max_blast_tier:
            self._mark(pair, "blocked_by_policy")                # HC-SUB-01 §7 cap
            return

        snap = self.sandbox.snapshot() if tier >= 2 else None    # §4.1 tier>=2 snapshot
        session = self.operator.begin(pair, facts)               # recon facts scope the hunt
        observations, repro, pe_ids = [], [], []
        denied = invalid = 0
        outcome = "attempted"
        try:
            for _ in range(self.budget):
                raw = self.operator.propose_next(session, card,
                                                 roleio.role_context(observations))
                if raw is None:                                  # role gives up
                    break
                turn = roleio.parse_request(raw)                 # harness parses, not the role
                if turn.rejection is not None:                   # unparseable turn (§5.1)
                    invalid += 1
                    observations.append(turn.rejection.as_observation())  # re-prompt (§9)
                    if invalid >= self.max_invalid:
                        outcome = "inconclusive"
                        break
                    continue
                obs = self.dispatcher.dispatch(
                    turn.request, self._ctx(pair, tier, "operator", "hunting",
                                            snap or GOLDEN, snap is not None))
                observations.append(obs)
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
                    self._emit_lead(pair, card, facts, session.id, repro, pe_ids,
                                    signals.get("confidence"), tier)
                    outcome = "lead"
                    break
        finally:
            if snap is not None:
                self.sandbox.restore(snap)                       # §4.1 restore after tier>=2
        self._mark(pair, outcome)

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

    # --- verification (§4.2) --------------------------------------------
    def _verify(self, finding_row):
        fid = finding_row["id"]
        pair = Pair(finding_row["asset"], finding_row["technique_id"],
                    finding_row["technique_version"])
        card = self.kb_index.get((pair.technique_id, pair.technique_version))
        tier = int(card.get("blast_tier", 0)) if card else 0

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
        for _ in range(self.budget):
            raw = self.verifier.propose_next(session, vinput,
                                             roleio.role_context(observations))
            if raw is None:
                break
            turn = roleio.parse_request(raw)                     # harness parses, not the role
            if turn.rejection is not None:                       # unparseable turn (§5.1)
                invalid += 1
                observations.append(turn.rejection.as_observation())  # re-prompt (§9)
                if invalid >= self.max_invalid:
                    break                                        # falls through to inconclusive
                continue
            obs = self.dispatcher.dispatch(
                turn.request, self._ctx(pair, tier, "verifier", "verification", fresh, True))
            observations.append(obs)
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

    def _mark(self, pair, status):
        ledger.mark(self.conn, self.eng.id, pair.asset, pair.technique_id, status)
