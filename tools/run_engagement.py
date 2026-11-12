#!/usr/bin/env python3
"""Run one engagement end to end against a live self-hosted range (HC-SUB-01 + HC-AGENT-01).

This is the first wiring of the real `DockerSandbox` into the control loop: parse a
contract, provision a real range, gate on the five-guarantee `proofs_pass`, build the
target model from the pinned targets, and drive the loop with a real HTTP probe adapter
that executes on the attacker container, with the sandbox enforcing scope and the
proofs gating active work.

The Operator and Verifier run on real models through the Bifrost model plane when the
gateway is configured in the environment: the Operator on DeepSeek, the Verifier on
OpenAI, kept on disjoint providers so finder-is-not-verifier holds at the model plane
as well as at the loop and the DB. No role holds a provider key; the per-role virtual
keys are read from the environment and presented only by the transport. With no gateway
configured the run falls back to deterministic stand-ins, so the substrate, dispatch,
probe, and report path can still be exercised on a host without model access.

Skips (exit 0) when Docker is unavailable. Run where Docker is available, with the
Bifrost virtual keys exported from the gateway's own env (never pasted in):
    export HC_VK_OPERATOR=... HC_VK_VERIFIER=...   # from the Bifrost .env, on the host
    sudo -E python3 tools/run_engagement.py
"""
import contextlib
import os
import shutil
import signal
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import capabilities, kb, ratelimit, roleio        # noqa: E402
from harness.bifrost import BifrostTransport                   # noqa: E402
from harness.dispatch import Dispatcher                        # noqa: E402
from harness.loop import Loop                                  # noqa: E402
from harness.modelplane import ModelPlane, VirtualKey          # noqa: E402
from harness.planner import DeterministicPlanner               # noqa: E402
from harness.recon import phase_recon                          # noqa: E402
from harness.mobile.recon import mobile_recon                   # noqa: E402
from harness.mobile.protocol import MOBILE_TOOL                  # noqa: E402
from harness.roles import ModelOperator, ModelVerifier         # noqa: E402
from harness.sandbox.adapters import (                         # noqa: E402
    BflaAdapter, CacheAdapter, ClickjackAdapter, CmdiAdapter, CorsAdapter, CspAdapter,
    CsrfAdapter, DomClobberAdapter, HttpRequestAdapter, HttpxAdapter, IdorAdapter, JwtAdapter,
    NmapAdapter, OpenRedirectAdapter, PathAdapter, ProtoPolluteAdapter, SessAdapter, SqliAdapter,
    SsrfAdapter, SstiAdapter, WsHijackAdapter)
from harness.sandbox.crawler import CrawlerAdapter             # noqa: E402
from harness.sandbox import rangelock                         # noqa: E402
from harness.sandbox.docker import DockerSandbox               # noqa: E402
from harness.mobile.probe import DeepLinkProbe                 # noqa: E402
from harness.sandbox.probe import DockerProbe                  # noqa: E402
from harness.store import blobstore, datadir, db, engagements  # noqa: E402
from harness.substrate import contract                         # noqa: E402

CONTRACT = """
engagement:
  id: eng-live-001
  authorized_by: operator
  window: { start: 2026-11-09T00:00, end: 2030-01-01T00:00 }
  max_blast_tier: 2
scope:
  in_scope_hosts: [t1.sandbox.local]
  in_scope_cidrs: [10.90.0.0/24]
  allowed_ports: { default: [8080] }
policy:
  rate: { max_rps_per_target: 1000, max_actions_per_run: 10000 }
"""

# The live run drives the real materialized knowledge base (HC-KB-01), not hand-written
# demo cards. `kb.load()` reads every technique card; `capabilities.runnable_index` keeps
# only the techniques the harness has a concrete adapter for and attaches each one's probe
# step, so the planner, the deterministic signal rule, and the report validator all see the
# genuine card while the dispatcher runs a real adapter. Cards with no adapter (or a
# model-evaluated signal) still load into the full KB but are not hunted here.
FULL_KB = kb.load()
KB = capabilities.runnable_index(FULL_KB)

# A deliberately vulnerable stand-in app, seeded into the target at provision time so the
# reflected-XSS technique has a real hole to find; it never leaves the egress-denied range.
with open(os.path.join(ROOT, "infra", "sandbox", "vulnweb.py"), encoding="utf-8") as _f:
    VULNWEB = _f.read()

# The in-range out-of-band collaborator (harness infrastructure, never in scope): a target
# can reach it on the internal network so SSRF is confirmed by the hit it records, which
# the harness reads over docker exec; the attacker cannot reach it through the scope guard.
with open(os.path.join(ROOT, "infra", "sandbox", "collaborator.py"), encoding="utf-8") as _f:
    COLLABORATOR = _f.read()


class Operator:
    """Deterministic stand-in Operator: proposes the card's own probe step at the asset's
    pinned address. Used only when no model gateway is configured; with a gateway the
    Bifrost-backed `ModelOperator` runs instead."""

    def begin(self, pair, facts=None):
        facts = facts or {}
        ports = facts.get("open_ports") or []
        return types.SimpleNamespace(step=0, id="live-operator",
                                     addr=facts.get("addr", facts.get("host")),
                                     port=(ports[0] if ports else
                                           (0 if facts.get("asset.type") == "mobile_app" else 8080)))

    def propose_next(self, session, card, role_context):
        if session.step >= 1:
            return None
        session.step += 1
        step = (card.get("probe_steps") or [{}])[0]
        args = {k: v for k, v in step.items() if k not in ("tool", "intent")}
        return roleio.emit({"tool": step.get("tool"), "intent": step.get("intent"),
                            "target": session.addr, "port": session.port, "args": args})


class Verifier:
    """Reproduces from the recorded steps, on a disjoint session."""

    def begin(self):
        return types.SimpleNamespace(step=0, id="live-verifier", disproved=False)

    def propose_next(self, session, vinput, role_context):
        steps = vinput.get("steps") or []
        if session.step >= 1 or not steps:
            return None
        session.step += 1
        last = steps[-1]
        return roleio.emit({"tool": last["tool"], "intent": "reproduce", "target": last["target"],
                            "port": last.get("port", 8080), "args": last.get("args", {})})


# Bifrost model routes, chosen so the operator and verifier sit on disjoint providers
# (the model-plane diversity invariant). The plane passes these verbatim as the model
# field; the per-role virtual key governs that each may reach only its own provider.
OPERATOR_ROUTE = "deepseek/deepseek-chat"
VERIFIER_ROUTE = "openai/gpt-4o-mini"

# Each role answers with one JSON probe, far below this, but a reasoning model spends
# completion tokens thinking first, so the cap leaves it room. Without a cap a provider
# such as OpenRouter reserves its own default (65536) per call and refuses a key whose
# remaining credit cannot cover that reservation.
MAX_OUTPUT_TOKENS = 8192


def build_roles(conn, eng):
    """The Operator and Verifier for this run, on Bifrost when it is configured.

    When the gateway URL and both per-role virtual-key secrets are present in the
    environment, the roles run on real models through the model plane (Operator on
    DeepSeek, Verifier on OpenAI, disjoint providers). The secrets are read from the
    environment only and presented solely by the transport, so no role holds a
    provider key. With no gateway configured the deterministic stand-ins run instead,
    so a host without model access can still exercise the substrate and dispatch path.
    """
    base_url = os.environ.get("HC_BIFROST_URL", "http://127.0.0.1:8099")
    op_secret = os.environ.get("HC_VK_OPERATOR")
    ver_secret = os.environ.get("HC_VK_VERIFIER")
    if not (op_secret and ver_secret):
        return Operator(), Verifier(), ("deterministic stand-ins "
                                        "(run capri setup to configure the model plane)")
    # Routes come from the gateway the user configured (capri setup exports them via
    # `modelplane.py env`), so whichever providers they picked drive the run; the
    # defaults keep the deepseek/openai pairing when the env does not set them.
    op_route = os.environ.get("HC_OPERATOR_ROUTE", OPERATOR_ROUTE)
    ver_route = os.environ.get("HC_VERIFIER_ROUTE", VERIFIER_ROUTE)
    transport = BifrostTransport(base_url, {"vk-operator": op_secret, "vk-verifier": ver_secret})
    # The engagement's model-token budget is a fail-closed cap: the plane stops serving once the
    # run's total spend reaches it (and each role cannot exceed it alone), so a run is bounded
    # rather than open-ended. Cost is counted in tokens (in + out) per call.
    budget = eng.model_budget
    vkeys = [VirtualKey("operator", [op_route], cache=False, fallback="within_set", budget=budget,
                        max_output_tokens=MAX_OUTPUT_TOKENS),
             VirtualKey("verifier", [ver_route], cache=False, fallback="none", budget=budget,
                        max_output_tokens=MAX_OUTPUT_TOKENS)]
    plane = ModelPlane(vkeys, transport, conn, eng.id, engagement_budget=budget)  # diversity asserted
    return (ModelOperator(plane), ModelVerifier(plane),
            f"Bifrost at {base_url}  (operator={op_route}, verifier={ver_route}; "
            f"budget={budget} model tokens)")


def _install_teardown_on_signal():
    """Turn a SIGTERM into a KeyboardInterrupt so the run's ``finally: sb.teardown()``
    still fires on an external kill.

    A supervisor or a wall-clock ``timeout`` sends SIGTERM, whose default disposition
    terminates the process without unwinding ``finally`` - which leaks the range's
    containers and network. SIGINT (Ctrl-C) already raises KeyboardInterrupt, so only
    the external-kill path needed closing. The handler is one-shot: it restores the
    default disposition before raising, so a second signal hard-kills rather than
    interrupting teardown midway.
    """
    if threading.current_thread() is not threading.main_thread():
        return  # signal handlers can only be installed from the main thread

    def _handler(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):
        pass  # some environments disallow it; fall back to the default disposition


_STOP_EXPLANATIONS = {
    "provider_out_of_credit": "its provider account is out of credit; add credit, "
                              "or pick another provider with `capri setup`",
    "provider_unavailable": "its provider could not be reached",
    "budget_exhausted": "it used its token budget",
    "engagement_budget_exhausted": "the engagement used its token budget",
    "rate_limited": "it hit its request rate limit",
}


def model_stop_lines(stops):
    """One line per (role, reason) the model plane stopped a role for, so a run that
    confirmed nothing says why instead of looking like a clean miss."""
    return [f"  model stop: {role} x{count} - {_STOP_EXPLANATIONS.get(reason, reason)}"
            for (role, reason), count in sorted(stops.items())]


def main(progress=None):
    emit = progress or print
    if shutil.which("docker") is None:
        emit("docker not found; skipping live engagement run")
        return 0
    contract_text = CONTRACT
    contract_path = os.environ.get("HC_ENGAGEMENT_CONTRACT")
    if contract_path:
        try:
            with open(contract_path, encoding="utf-8") as contract_file:
                contract_text = contract_file.read()
        except OSError as exc:
            emit(f"cannot read HC_ENGAGEMENT_CONTRACT: {exc}")
            return 1
    eng, errs = contract.parse(contract_text)
    if errs:
        emit(f"contract invalid: {errs}")
        return 1
    sb = DockerSandbox(listener_app=VULNWEB, collaborator_app=COLLABORATOR)
    # Held from before provisioning (which first tears down any same-named range) until
    # after teardown, so a second run never destroys the range of one in progress.
    try:
        lock = rangelock.RangeLock(sb.network).acquire()
    except rangelock.RangeBusy as busy:
        emit(str(busy))
        return 1
    _install_teardown_on_signal()  # a SIGTERM kill still runs the teardown below
    try:
        desc = sb.provision(eng)
        emit(f"provisioned {desc['range_id']}  pinned={desc['pinned_targets']}")
        if not sb.proofs_pass():
            emit("proofs did not pass; the harness would run passive-only. Aborting live run.")
            return 1
        emit("all five guarantees proved; running the engagement under sandbox enforcement")

        if eng.source_root:                                    # the operator has the app's source
            target_model = phase_recon(sb.attacker, eng, source_root=eng.source_root)
            emit(f"recon: source-aware surface from {eng.source_root}")
        else:
            crawler = CrawlerAdapter(sb.attacker, eng.pinned)  # black-box endpoint discovery
            target_model = phase_recon(sb.attacker, eng, crawler=crawler)   # live recon, not hand-built
        emit(f"recon: {target_model}")
        with contextlib.nullcontext(datadir.blob_root()) as root:  # persist, not a temp dir
            conn = db.connect(datadir.db_path())
            mobile_static = None
            if sb.mobile.inventory:
                mobile_model, mobile_static = mobile_recon(conn, eng.id, sb.mobile.inventory)
                target_model.update(mobile_model)
                emit(f"mobile recon: {sb.mobile.inventory['package']} "
                     f"sha256={sb.mobile.inventory['sha256']} "
                     f"links={len(sb.mobile.inventory['deep_links'])} "
                     f"advisories={len(mobile_static['advisory_findings'])}")
            operator, verifier, plane_label = build_roles(conn, eng)
            emit(f"model plane: {plane_label}")
            # The caller-supplied session (if any) rides on every HTTP adapter, so a probe
            # reaches an auth-gated route rather than the login. The non-HTTP probe is exempt.
            sess = eng.session_headers
            adapters = {"probe": DockerProbe(sb.attacker, eng.pinned),
                        "nmap": NmapAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "httpx": HttpxAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "http": HttpRequestAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "sqli": SqliAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "idor": IdorAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "bfla": BflaAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "jwt": JwtAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "ssti": SstiAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "cors": CorsAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "path": PathAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "cmdi": CmdiAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "cache": CacheAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "sess": SessAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "ssrf": SsrfAdapter(sb.attacker, eng.pinned,
                                            collaborator=sb.collaborator,
                                            collab_addr=sb.collab_addr, session_headers=sess),
                        "redirect": OpenRedirectAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "clickjack": ClickjackAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "csrf": CsrfAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "wshijack": WsHijackAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "cspexec": CspAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "domclobber": DomClobberAdapter(sb.attacker, eng.pinned, session_headers=sess),
                        "protopollute": ProtoPolluteAdapter(sb.attacker, eng.pinned, session_headers=sess)}
            if sb.mobile.inventory:
                adapters[MOBILE_TOOL] = DeepLinkProbe(
                    sb.mobile.inventory["package"], sb.mobile.inventory["deep_links"],
                    adb=sb.mobile.adb,
                    collaborator=lambda: sb._run(["docker", "exec", sb.collaborator,
                                                  "cat", "/tmp/hits.log"]).out,
                    collab_addr=sb.collab_addr, expected_source=sb.mobile.ip)
            disp = Dispatcher(conn, blobstore.BlobStore(root), eng, adapters,
                              ratelimit.RateLimiter(1000, now=lambda: 0.0))
            res = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sb,
                       planner=DeterministicPlanner(KB), operator=operator,
                       verifier=verifier, kb_version="live",
                       mobile_static=mobile_static).run(target_model)
            engagements.save(conn, res.report, valid=res.valid)    # persist the run for the dashboard
        emit(f"\nmode: {res.mode}   report valid: {res.valid}")
        emit(f"coverage: {res.report['coverage_summary']}")
        for f in res.report["findings"]:
            emit(f"  CONFIRMED {f['technique_id']} on {f['asset']}  "
                 f"found_by={f['found_by']} verified_by={f['verified_by']} cvss={f['cvss']['band']}")
        if not res.report["findings"]:
            emit("  (no confirmed findings)")
        for line in model_stop_lines(operator.plane.stops):
            emit(line)
        emit(f"saved run {eng.id} -> {datadir.db_path()}")
        return 0 if res.valid else 1
    except KeyboardInterrupt:
        emit("\ninterrupted; tearing down the range")
        return 130
    finally:
        try:
            sb.teardown()
            emit("range torn down")
        finally:
            lock.release()


if __name__ == "__main__":
    sys.exit(main())
