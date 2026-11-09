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

Skips (exit 0) when Docker is unavailable. Run on the range host as root, with the
Bifrost virtual keys exported from the gateway's own env (never pasted in):
    export HC_VK_OPERATOR=... HC_VK_VERIFIER=...   # from the Bifrost .env, on the host
    sudo -E python3 tools/run_engagement.py
"""
import os
import shutil
import sys
import tempfile
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
from harness.roles import ModelOperator, ModelVerifier         # noqa: E402
from harness.sandbox.adapters import (                         # noqa: E402
    BflaAdapter, CmdiAdapter, CorsAdapter, HttpRequestAdapter, HttpxAdapter, IdorAdapter,
    JwtAdapter, NmapAdapter, PathAdapter, SqliAdapter, SstiAdapter)
from harness.sandbox.docker import DockerSandbox               # noqa: E402
from harness.sandbox.probe import DockerProbe                  # noqa: E402
from harness.store import blobstore, db                        # noqa: E402
from harness.substrate import contract                         # noqa: E402

CONTRACT = """
engagement:
  id: eng-live-001
  authorized_by: operator
  window: { start: 2026-11-09T00:00, end: 2030-01-01T00:00 }
  max_blast_tier: 1
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


class Operator:
    """Deterministic stand-in Operator: proposes the card's own probe step at the asset's
    pinned address. Used only when no model gateway is configured; with a gateway the
    Bifrost-backed `ModelOperator` runs instead."""

    def begin(self, pair, facts=None):
        return types.SimpleNamespace(step=0, id="live-operator", addr=(facts or {}).get("addr"))

    def propose_next(self, session, card, role_context):
        if session.step >= 1:
            return None
        session.step += 1
        step = (card.get("probe_steps") or [{}])[0]
        args = {k: v for k, v in step.items() if k not in ("tool", "intent")}
        return roleio.emit({"tool": step.get("tool"), "intent": step.get("intent"),
                            "target": session.addr, "port": 8080, "args": args})


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
                                        "(run tools/setup.py to configure the model plane)")
    # Routes come from the gateway the user configured (tools/setup.py exports them via
    # `modelplane.py env`), so whichever providers they picked drive the run; the
    # defaults keep the deepseek/openai pairing when the env does not set them.
    op_route = os.environ.get("HC_OPERATOR_ROUTE", OPERATOR_ROUTE)
    ver_route = os.environ.get("HC_VERIFIER_ROUTE", VERIFIER_ROUTE)
    transport = BifrostTransport(base_url, {"vk-operator": op_secret, "vk-verifier": ver_secret})
    vkeys = [VirtualKey("operator", [op_route], cache=False, fallback="within_set"),
             VirtualKey("verifier", [ver_route], cache=False, fallback="none")]
    plane = ModelPlane(vkeys, transport, conn, eng.id)       # diversity asserted here
    return (ModelOperator(plane), ModelVerifier(plane),
            f"Bifrost at {base_url}  (operator={op_route}, verifier={ver_route})")


def main():
    if shutil.which("docker") is None:
        print("docker not found; skipping live engagement run")
        return 0
    eng, errs = contract.parse(CONTRACT)
    if errs:
        print("contract invalid:", errs)
        return 1
    sb = DockerSandbox(listener_app=VULNWEB)
    try:
        desc = sb.provision(eng)
        print(f"provisioned {desc['range_id']}  pinned={desc['pinned_targets']}")
        if not sb.proofs_pass():
            print("proofs did not pass; the harness would run passive-only. Aborting live run.")
            return 1
        print("all five guarantees proved; running the engagement under sandbox enforcement")

        target_model = phase_recon(sb.attacker, eng)           # live recon, not hand-built
        print("recon:", target_model)
        with tempfile.TemporaryDirectory() as root:
            conn = db.connect()
            operator, verifier, plane_label = build_roles(conn, eng)
            print("model plane:", plane_label)
            adapters = {"probe": DockerProbe(sb.attacker, eng.pinned),
                        "nmap": NmapAdapter(sb.attacker, eng.pinned),
                        "httpx": HttpxAdapter(sb.attacker, eng.pinned),
                        "http": HttpRequestAdapter(sb.attacker, eng.pinned),
                        "sqli": SqliAdapter(sb.attacker, eng.pinned),
                        "idor": IdorAdapter(sb.attacker, eng.pinned),
                        "bfla": BflaAdapter(sb.attacker, eng.pinned),
                        "jwt": JwtAdapter(sb.attacker, eng.pinned),
                        "ssti": SstiAdapter(sb.attacker, eng.pinned),
                        "cors": CorsAdapter(sb.attacker, eng.pinned),
                        "path": PathAdapter(sb.attacker, eng.pinned),
                        "cmdi": CmdiAdapter(sb.attacker, eng.pinned)}
            disp = Dispatcher(conn, blobstore.BlobStore(root), eng, adapters,
                              ratelimit.RateLimiter(1000, now=lambda: 0.0))
            res = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sb,
                       planner=DeterministicPlanner(KB), operator=operator,
                       verifier=verifier, kb_version="live").run(target_model)
        print(f"\nmode: {res.mode}   report valid: {res.valid}")
        print("coverage:", res.report["coverage_summary"])
        for f in res.report["findings"]:
            print(f"  CONFIRMED {f['technique_id']} on {f['asset']}  "
                  f"found_by={f['found_by']} verified_by={f['verified_by']} cvss={f['cvss']['band']}")
        if not res.report["findings"]:
            print("  (no confirmed findings)")
        return 0 if res.valid else 1
    finally:
        sb.teardown()
        print("range torn down")


if __name__ == "__main__":
    sys.exit(main())
