---
tag: HC-SUB-01
title: Sandbox, scope guard, and engagement contract
status: draft
parent: SPEC.md#3
depends_on: []
depended_on_by: [HC-KB-01, HC-KB-02, HC-KB-03, HC-KB-04, HC-KB-05, HC-KB-06, HC-KB-07, HC-KB-08, HC-KB-09, HC-KB-10, HC-KB-11, HC-MODEL-01, HC-ENRICH-01, HC-AGENT-01, HC-FIND-01, HC-DATA-01, HC-SAFE-01, HC-EVAL-01, HC-MOB-01]
updated: 2026-11-08
---

# HC-SUB-01 - Substrate: sandbox, scope guard, engagement contract

## 1. Purpose

This spec defines the substrate: the layer that makes autonomous exploitation safe by construction.
It is milestone M0, and the project rule is that nothing else starts until it is solid.
Everything above it (the agent, the knowledge base, the findings pipeline) assumes the five guarantees in section 3 hold without exception.

This document is the authority for how scope, isolation, reproducibility, containment, and killability are enforced.
Where it says "enforced," it means in code or configuration at a layer the agent and the target cannot reconfigure, never in a model prompt.

## 2. Substrate threat model

The substrate defends against four failures, in priority order:

1. Out-of-scope reach: the agent or an exploited target touches a host outside the declared scope.
2. Egress and exfiltration: anything inside the sandbox reaches the public internet or the operator's own network.
3. Non-reproducibility: a run cannot be reset to a known state, so findings cannot be independently reproduced and destructive actions cannot be undone.
4. Escape: an exploited target pivots out of the sandbox onto the host or corporate network.

Note that the adversary here is not only the external attacker being simulated.
It is also our own agent, which is an autonomous process issuing exploit traffic and must be contained as if it were hostile.

## 3. The five guarantees

Each guarantee has a mechanism (section 5-7) and a test (section 8).
A guarantee without a passing test is treated as absent, and the harness refuses to leave `passive-only` mode.

| # | Guarantee | Mechanism | Proven by |
|---|-----------|-----------|-----------|
| G1 | Scope: only declared in-scope targets are reachable | Default-deny scope-guard gateway on pinned IPs | Guard-proof self-test |
| G2 | No egress: nothing in the sandbox reaches the internet or operator LAN | Gateway drops all non-range traffic; no upstream DNS | Guard-proof self-test |
| G3 | Reproducibility: any state is resettable to a known snapshot | Clone-per-run, snapshot before destructive, restore after | Snapshot round-trip test |
| G4 | Containment: an exploited target cannot escape the sandbox | microVM isolation, no host networking/shares, isolated L2 segment | Escape-attempt test |
| G5 | Killability: one action freezes everything | Kill switch disables segment ports and snapshot-freezes | Kill-switch drill |

## 4. The engagement contract

A signed, declarative document parsed and validated before any provisioning.
It is the single source of truth for what this run is allowed to do.

### 4.1 Schema

```yaml
engagement:
  id:            eng-2026-11-08-001        # unique, immutable; keys all state
  authorized_by: brent / TICKET-1234        # human or ticket of record
  window:        { start: 2026-11-08T20:00, end: 2026-11-08T23:59 }
  max_blast_tier: 2                          # 0..3, see section 7
  target:                                    # optional: a real app + datastore the range stands up
    build: { context: ., dockerfile: Dockerfile }   # OR image: myapp:local
    port: 3000                               # the app's listen port (joins allowed_ports)
    env:  { DATABASE_URL: postgres://app:app@db:5432/app }
    ready: { path: /healthz, timeout_s: 60 } # polled before proofs/recon
    services:                                # backing services, in-range, reachable by the app only
      - { name: db, engine: postgres, version: "16", init_sql: ./seed.sql }

scope:
  in_scope_hosts:  [app.sandbox.local, api.sandbox.local]
  in_scope_cidrs:  [10.13.0.0/24]
  out_of_scope:    [10.13.0.1]               # always-excluded, overrides in-scope
  allowed_ports:   { default: [80, 443], "10.13.0.0/24": [22, 80, 443, 5432] }

policy:
  allowed_tactics: [recon, initial-access, discovery, credential-access]
  forbidden:       [exfil-to-internet, persistence-survive-reset]
  rate:            { max_rps_per_target: 20, max_actions_per_run: 5000 }
```

### 4.2 Field semantics and validation rules

- `id` is immutable and keys every `probe_event`, snapshot, and audit entry (see HC-DATA-01).
- `out_of_scope` always wins: an address in both lists is out of scope.
- `window` is enforced; the harness refuses to start before `start` and aborts in-flight work at `end`.
- `max_blast_tier` caps the whole run; a technique card above it is skipped as `blocked_by_policy` (see SPEC.md#6.1).
- Validation is fail-closed: a missing, malformed, or contradictory field aborts the run before any VM is provisioned.
- The harness refuses to start if any resolved target IP falls outside `in_scope_cidrs`, or if `in_scope_cidrs` overlaps the operator's own management network.
- `target` is optional; absent, the range runs a bundled listener as before. It declares a real app by exactly one of `image` or `build` (built on the host before the range is sealed), its listen `port`, `env`, a `ready` probe, and a closed set of backing `services` by known `engine` (only `postgres` today), each with optional `init_sql`, `version`, and credentials. We own this surface deliberately: it cannot express a host volume, a published port, or an external network, so a contract cannot describe a target that would breach the range. An unsupported key is rejected, not ignored, so a containment-breaking directive fails loudly.

### 4.3 Target resolution and IP pinning (anti-TOCTOU)

Scope is declared partly by hostname but enforced by IP, which opens a time-of-check/time-of-use gap (DNS rebinding).
Close it at provisioning:

1. Resolve every `in_scope_host` once, through the sandbox resolver only, to a pinned IP set.
2. Record the pinned `host -> IP` map in the engagement state; this is what the scope guard enforces on.
3. The sandbox resolver answers only for pinned in-scope names and refuses everything else; there is no upstream internet DNS.
4. Re-resolution is never implicit; it happens only through a controlled re-pin step that re-runs validation in section 4.2.

## 5. Scope guard

### 5.1 Enforcement point

The scope guard is a default-deny gateway that sits between the sandbox range and everything else.
It runs outside the control of both the target VMs and the attacker VM, on the range gateway (a dedicated firewall VM or host-level nftables/eBPF on the virtual switch uplink).
Nothing inside the range can reconfigure it.

### 5.2 Policy model

- Default deny for all egress leaving the range.
- Allow only flows to pinned in-scope IPs on `allowed_ports`.
- No route to the public internet and no route to the operator LAN exists at all, so there is nothing to misconfigure around.
- Intra-range flows to out-of-scope hosts (for example the gateway itself) are dropped.

### 5.3 Pre-flight re-check (defense in depth)

The gateway is the real enforcement; the harness adds a second, independent check in software.
Before every tool-adapter call, the harness calls `scope.validate(target, port)` against the pinned allowlist and refuses to dispatch a call that would leave scope.
If the two layers ever disagree, that is a stop-the-line bug: the harness halts and logs, because a software check passing while the gateway would deny (or vice versa) means one of them is wrong.

### 5.4 Fail-closed

If the gateway or the sandbox resolver is unhealthy, or the guard-proof self-test (section 8) has not passed in this run, the harness does not execute any active tool call.
It drops to `passive-only` and marks every lead `needs_validation`.

## 6. Sandbox runtime

### 6.1 Topology

```
  operator host (trusted)
    |  control plane: narrow authenticated RPC, host-only link
    v
  [ attacker VM ] ----data plane----> [ target VM(s) ]      all on one
        \______________ isolated L2 range (vswitch/VLAN) ______________/
                                   |
                           [ scope-guard gateway ]  default-deny, no internet/LAN route
```

- The isolated L2 range is the "cyber range": target VMs plus one attacker VM where tool adapters execute.
- The attacker VM has two interfaces: a data interface on the range (subject to the scope guard) and a control interface to the operator host (host-only, policy-restricted).
- The control plane carries only tool-adapter commands and artifact collection; it is not a route to the internet or the operator LAN, and the orchestrator treats everything returning over it as untrusted output.
- A target may depend on backing services (a datastore). Each declared service runs as its own in-range container on its own IP with a network alias the app resolves; the service is reachable by the target over the internal network but is never pinned into the scope guard, so the attacker cannot reach the datastore directly. This models reality: the app is the attack surface, its database is not.

### 6.2 Isolation (G4)

- Target and attacker VMs run as microVMs (Firecracker) or on a hardened hypervisor, with no shared folders, no clipboard, and no host-bridged networking.
- The only path off the range is the scope-guard gateway, which has no onward route.
- An exploited target that pivots to the attacker VM still cannot egress, and the control-plane RPC is authenticated and narrow, so pivoting to the operator host is not a reachable path.

### 6.3 Reproducibility (G3)

- Each run clones target VMs from a versioned golden snapshot, so every run starts identical.
- The harness takes a snapshot before any tier-2 or tier-3 action and restores it after the action completes or aborts.
- `snapshot_id` is recorded on every `probe_event` (see HC-DATA-01), which is what makes a finding replayable by the independent Verifier.
- A target's backing datastore is part of the snapshot, not an unmanaged dependency: its container is committed with the target, so an action that mutates the database is reproduced from the snapshot, and the golden baseline is the post-seed state. For a crash-safe engine (Postgres) the committed data directory is crash-consistent and recovers on restart; a CHECKPOINT before the commit minimizes that recovery. The data directory must sit outside the engine image's declared VOLUME, because `docker commit` does not capture volume contents; Postgres is run with PGDATA pointed into the committable container layer, or a golden committed with the data in the volume would come back empty and silently drop the seed.

### 6.4 Kill switch (G5)

- A single `sandbox.kill()` disables the range's virtual-switch ports (instant network freeze) and snapshot-freezes the VMs for forensics, then restores from golden.
- It is callable by the orchestrator, by a watchdog on budget or rate breach, and by a human out-of-band.

## 7. Blast-tier model

Every technique card declares a `blast_tier`.
The engagement's `max_blast_tier` caps what may run.

| Tier | Name | Permits | Snapshot | Extra authorization |
|------|------|---------|----------|---------------------|
| 0 | Passive | Observation only; no active packets to the target beyond what recon requires | No | No |
| 1 | Active, non-destructive | Active probing that only reads state (port/service scans, read-only injections, auth probes that do not change state) | No | No |
| 2 | State-changing, recoverable | Actions that modify target state but are fully recoverable by snapshot restore (writes, account creation, config change) | Yes, before | No |
| 3 | Destructive or persistent | Actions that would destroy data or establish persistence | Yes, before | Explicit tier-3 flag in the contract, per technique |

Tiers 2 and 3 cannot run unless a live snapshot handle exists; if snapshotting fails, the action is refused.
Tier 3 additionally requires that the contract names it, and it remains fully contained by G1, G2, and G4 regardless.

## 8. Startup self-tests (the proofs)

Before leaving `passive-only`, the harness runs these and aborts fail-closed if any assertion fails.
This operationalizes the rule "prove you cannot reach an out-of-scope host even when you try."

### 8.1 Guard proof (proves G1 and G2)

From the attacker VM, actively attempt and assert:

- a TCP connection to a known-routable internet canary IP is dropped;
- a DNS lookup of a public name is refused (no upstream resolver);
- a connection to an in-range but out-of-scope host is dropped;
- a connection to a pinned in-scope target on an allowed port succeeds.

All four must hold.
A single failure aborts the run and logs which assertion failed.

### 8.2 Snapshot round-trip (proves G3)

Write a marker to a target, snapshot, overwrite the marker, restore, and assert the original marker is back.

### 8.3 Escape-attempt (proves G4)

From the attacker VM, attempt to reach the operator host's management interface and a second, unrelated host network, and assert both are unreachable.

### 8.4 Kill-switch drill (proves G5)

In a provisioning dry-run, invoke `sandbox.kill()` and assert all range ports drop within the target time budget and VMs restore from golden.

## 9. passive-only fallback

If the sandbox is not provisioned, or any section-8 proof has not passed in the current run, the harness operates in `passive-only`:

- no active (tier >= 1) tool call executes;
- every lead is recorded as `needs_validation` and never promoted to `confirmed`;
- the report states plainly that it ran without an enforced sandbox.

## 10. Interfaces exposed to the orchestrator

```
sandbox.provision(engagement)        -> { range_id, attacker_vm, golden_snapshot_id, pinned_targets }
sandbox.snapshot()                   -> snapshot_id
sandbox.restore(snapshot_id)         -> ok
sandbox.guard_proof()                -> pass | fail(details)   # G1/G2 only (the §8.1 guard proof)
sandbox.proofs_pass()                -> pass | fail(details)   # aggregate G1-G5; runs the §8.1-8.4 self-tests
sandbox.kill()                       -> ok
scope.validate(target, port)         -> allow | deny(reason)
blast.gate(technique_tier, has_snap) -> allow | deny(reason)
```

Tool adapters (HC-AGENT-01) must call `scope.validate` and `blast.gate` before executing on the attacker VM; the adapter layer is where these are wired, but the gateway in section 5 remains the real enforcement.

The engagement-contract parser, `scope.validate`, and `blast.gate` are implemented as pure-standard-library, fail-closed code in `harness/substrate/` (contract.py, scope.py, blast.py), with adversarial tests in `tests/test_substrate.py` run in CI; `python3 -m harness.substrate.contract <file>` validates a contract from the command line.

The §10 interface and the first provisioning backend are implemented in `harness/sandbox/`.
`Sandbox` (base.py) is the backend-agnostic interface the control loop drives, and `PassiveOnlySandbox` is the safe default whose proofs all fail, so a harness with no range stays in passive-only (§9).
`DockerSandbox` (docker.py) is the first self-hostable backend and needs no nested virtualization, so it runs on commodity Linux hosts and Docker Desktop on Windows/macOS.
Before creating a range, `provision` checks that the attacker image exists and reports its build command if it is missing.
`provision` first tears down any range of the same name, so a range a crashed run left behind is cleaned up; the callers that drive a live range (`tools/run_engagement.py`, `tools/sandbox_selftest.py`) therefore hold `rangelock.RangeLock` from before provisioning until after teardown, an OS file lock the OS drops when the holder exits, so a second run is refused with a clear message instead of destroying the range of a run in progress, and a crashed run never blocks the next one.
It provisions one egress-denied Docker network (`--internal`, so the range has no route off the host by construction, which is G2) holding a target container per in-scope host and one attacker container where tool adapters run; a short-lived `hc-guard:golden` helper joins the attacker's network namespace with all capabilities dropped except `NET_ADMIN`, installs the nftables rules from stdin, then exits.
The rules default-deny egress and allow only the pinned in-scope IPs on their allowed ports, built from the same `scope.ports_for` policy the pre-flight check enforces.
The attacker runs with no `NET_ADMIN` and no network tooling, so the agent can neither reach an out-of-scope host nor reconfigure the guard (§2: the agent itself is in the threat model).
`guard_proof` runs the four §8.1 assertions from inside the attacker container (internet dropped, public DNS refused, in-range out-of-scope dropped, pinned in-scope allowed).
Reproducibility (G3) is `snapshot`/`restore`: `snapshot` commits every target container to an image, and `restore` recreates each target from its image at the same pinned IP, leaving the attacker and the scope guard untouched; `snapshot_round_trip` proves it per §8.2 by writing a marker, snapshotting, overwriting the marker, restoring, and asserting the original is back.
Containment (G4) is `escape_attempt`: from the attacker container it probes the operator host's management interface (discovered), the range gateway (the host's own interface on the range), and a second unrelated host network, and asserts all three unreachable per §8.3; the range gateway is the real escape path and is closed only by the scope guard, not by the internal network alone.
As the §6.2 isolation mechanism, `provision` runs every range container under the gVisor `runsc` runtime when the host offers it, auto-detected, so a container escape is contained in a user-space kernel rather than the host kernel; no nested virtualization is needed, and `escape_attempt` reports the active runtime so an operator knows whether kernel-escape hardening backs the network containment.
Killability (G5) is `kill`: one action pauses every range container at once (an instant freeze via the cgroup freezer), commits each frozen container for forensics, and restores the targets from the golden image, leaving the attacker frozen for analysis; `kill_switch_drill` proves it per §8.4 by writing a marker, invoking the kill switch, and asserting the freeze lands within a time budget and the target is wiped back to golden, then reviving the attacker so the proven range stays usable.
`kill` is the emergency kill switch and is distinct from `teardown`, which destroys the range entirely and doubles as pre-provision cleanup.
`proofs_pass` runs all five drills and returns `True` only when every guarantee holds, at which point the harness may leave passive-only; a single failed proof returns `False` and keeps it passive-only, and because each drill leaves the range usable a passing run hands back a range ready for the engagement.
Every Docker call goes through an injected runner, so the provisioning and proof logic is unit-tested with no Docker present (`tests/test_sandbox.py`, in CI), and the full five-guarantee path is proven end to end against a real range by `tools/sandbox_selftest.py`, with the required images and host-side notes in `infra/sandbox/`.
`restore` also serves the Verifier's per-run golden baseline (§4.2), so the backend drives a full engagement end to end: `tools/run_engagement.py` parses a contract, provisions the range, gates on `proofs_pass`, and runs the control loop with the live HTTP probe adapter `harness/sandbox/probe.py:DockerProbe`, which executes on the attacker container and reports the raw signals the harness triages into a lead; a run against a real range confirms an exposed-service finding with finder and verifier disjoint and produces a validated report, all under sandbox enforcement.
A separate no-route gateway host further hardens G4, and a managed or cloud-provisioned range is an optional backend behind this same interface too, never a prerequisite for self-hosting.

The optional `engagement.target` block lets a user stand up their own app and its datastore, which is what makes the harness runnable against anyone's app rather than only the bundled stdlib practice targets. Its contract surface is parsed and validated in `harness/substrate/contract.py` (`_validate_target`/`_normalize_target`), fail-closed and with unsupported keys rejected. The first increment runs the backing services: `DockerSandbox._bring_up_services` pulls each declared engine's image on the host before the range is sealed (§13), runs it in-range on its own IP with a `--network-alias`, waits on `pg_isready`, and applies `init_sql` with `psql -v ON_ERROR_STOP=1`; the sidecar is never added to the pinned allow list and is swept on teardown. The second increment runs the app itself: `_prepare_app_image` builds the declared `build` context or pulls the declared `image` on the host before the range is sealed, and the target then runs that image with the engagement `env` injected in place of the bundled stdlib listener; the declared `port` is added to the allowed ports so the software pre-check and the guard are built from one policy and agree (§5.3); after the guard is installed the harness polls the app's `ready` health path from the attacker over the real in-range path before the range is used, and restore and the kill switch recreate the app from its own image. A bundled Node-plus-Postgres practice target under `infra/sandbox/nodepg/` exercises this on a genuine app image, not a stdlib stand-in. The third increment makes the datastore part of reproducibility: `snapshot` commits each service container as well as each target (a `CHECKPOINT` first so the committed data dir needs little WAL replay), `restore` recreates the services from the snapshot or from a per-service golden image committed right after seeding, and the kill switch freezes and restores the services with the rest of the range, so G3 and G5 now reproduce a mutating action's database state and not only the app's filesystem. The first live run against the bundled Node-plus-Postgres target exposed that this only appeared to hold: the Postgres image declares its data directory a VOLUME, which `docker commit` skips, so every restore and kill brought the datastore back empty and the app answered every query with a relation-does-not-exist error; the fix points PGDATA into the committable container layer so the seeded database actually travels with the golden and the snapshot, which the injected-runner test cannot model (it does not know Docker's volume semantics) and only an end-to-end run surfaces. Covered by `tests/test_substrate.py` (the target contract) and `tests/test_sandbox.py` (the Postgres bring-up and seed, the app image running with its env, the Dockerfile build, the port agreement, the five guarantees holding for an app-plus-service target, the datastore surviving snapshot/restore and the kill switch, and the data directory sitting outside the image VOLUME so the commit captures it, all via the injected runner).

The first run against a real, non-bundled app, a React Router dashboard, flushed out two more assumptions that held only for the lightweight bundled targets. First, the snapshot proof wrote its marker into the target with `docker exec sh -c`, but a production image is routinely distroless (no shell), and the host ran Docker from a snap whose confined daemon cannot read the host `/tmp` a temp-file `docker cp` would stage through; the marker now moves as a tar stream on `docker cp` stdin and stdout, which needs neither a shell in the target nor a host path the daemon can reach. Second, a proof drill (the G3 restore and the G5 kill) recreates the app container, a fresh process that has to boot again, but only the datastore was re-waited after a drill, so recon raced a heavy app that had passed readiness at provision and then been recreated by a drill, and found its port closed; `restore` and the kill-switch drill now re-poll the app's health path after recreating an app target, the app analogue of the service re-wait, so a passing proof hands recon a range that is actually up. With both fixes the dashboard provisions, proves all five guarantees on a distroless image, and its full source-aware surface, every route with its auth and sink metadata, is enumerated and probed. Covered by `tests/test_sandbox.py` (the marker write and read staying shell-free and host-temp-free, and `restore` polling a recreated app's health after it comes back), green in make check.

The control loop runs `sandbox.proofs_pass()` once at startup, then checks `sandbox.guard_proof()` before every dispatch and before confirming a finding; a failed or raised check halts hunting and verification, records the failure in the audit log, and leaves outstanding leads at `needs_validation`.
The passive-only report explains that containment was not proven throughout the run and omits previously confirmed findings; those records remain in the store.

## 11. Failure modes

| Condition | Response |
|-----------|----------|
| Contract invalid or contradictory | Abort before provisioning; log; no VM created |
| Target resolves out of scope | Abort; refuse to start |
| Guard-proof fails | Abort; drop to passive-only; log failing assertion |
| Gateway or resolver unhealthy mid-run | Halt active work; passive-only; alert |
| Snapshot fails before a tier-2/3 action | Refuse the action; continue with lower-tier work |
| Rate or budget breach | Watchdog triggers kill switch; snapshot-freeze for forensics |
| Window `end` reached | Abort in-flight work; restore; finalize report |

## 12. Acceptance criteria (M0 done)

- A contract with an out-of-scope target is rejected before any VM is provisioned.
- All four guard-proof assertions pass on a provisioned range, and flipping any scope rule flips the matching assertion.
- Snapshot round-trip restores a known-good state deterministically.
- The escape-attempt test confirms the operator host is unreachable from the attacker VM.
- The kill switch freezes the range within its time budget and restores from golden.
- With the sandbox torn down, the harness runs and stays in passive-only with all leads `needs_validation`.

## 13. Open questions

- Provisioning dependencies: some golden images need package installs that require internet; resolve by building golden images in a separate, pre-lockdown bake step, never during a live engagement. Resolved for the target app and its backing services: `engagement.target` images are built or pulled on the host before the range is sealed, and the egress-denied range only ever runs the already-built images.
- Multi-host and segmented ranges: whether lateral movement across sub-segments is in scope for v1, or deferred.
- IPv6: the scope guard must deny IPv6 egress explicitly, not only IPv4, or disable IPv6 on the range entirely (leaning toward disable for v1).
- Realistic data: if a target ever mirrors production-like data, decide retention and redaction here in coordination with HC-DATA-01's PII tagging.
