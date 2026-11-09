# Capri

An autonomous penetration-testing agent for authorized, scoped engagements inside an isolated lab.

Capri drives an LLM agent through a real pentest against a disposable sandbox target: it explores the target with real security tools, interprets what comes back, decides what to try next, chains steps toward an objective, and produces a verified report with findings, evidence, severity, and remediation.

The one idea that governs everything else: **the harness is code, the agent is prompted.**
Anything that must be reliable, auditable, or safety-critical lives in deterministic code and is never left to model judgment.
The agent decides what to try and why; the harness decides what is allowed to actually run.

> This repository is the harness, the deterministic brain of the system.
> The sandbox (microVMs plus the scope-guard gateway) and the model gateway are infrastructure you point it at, not code that ships here.
> Everything in this repo runs with zero third-party dependencies, and the whole decision layer is exercised end to end against stubbed infrastructure, so you can read it, test it, and run it in under a minute before standing up a lab.

---

## Why it is built this way

- **Scope is enforced in the network layer, not the prompt.**
  A model instruction is a suggestion; a dropped packet is a guarantee.
  The harness re-checks every proposed action against a default-deny, IP-pinned scope guard, and a live engagement runs behind a gateway with no route to the internet or the operator network at all.
- **Finder is never verifier.**
  A finding is a hypothesis until a second, independent agent on a different model provider reproduces its success signal from the repro steps alone, in a fresh snapshot.
  This is enforced at the loop, at the model plane, and as a database constraint.
- **Objective-driven, not just coverage.**
  An engagement can declare a goal; the agent chains techniques toward it through a live blackboard of verified facts, and the report states whether the objective was met and by what attack path.
- **Grounded in real attacker knowledge.**
  107 machine-readable technique cards across 10 target classes, each mapped to MITRE ATT&CK, OWASP, CWE, and CVSS, drive the hunt; new knowledge is a new card, never a change to the harness.
- **Safe by construction.**
  Every technique is tagged by how destructive it is, state-changing steps require a snapshot, destructive steps additionally require explicit authorization, and without a proven sandbox the system drops to a read-only `passive-only` mode that confirms nothing.
- **Deterministic, resumable, auditable.**
  Every action is an append-only event in a hash-chained log, and a killed run resumes from its ledger and reaches the same confirmed set.
- **Zero third-party dependencies.**
  Python 3.12 standard library only.
  SQLite stands in for the production Postgres, and a content-addressed filesystem blob store stands in for object storage, so nothing extra has to run.

---

## How it works

```
   operator host (trusted)                      model plane
  +--------------------------+                 +---------------------------+
  |        HARNESS           |   per-role      |  Bifrost gateway          |
  |  (this repository)       |<--virtual-keys->|  Planner / Operator /     |
  |                          |                 |  Verifier / Reporter      |
  |  plan -> hunt -> verify  |                 |  (disjoint providers)     |
  |       -> report          |                 +---------------------------+
  |                          |
  |  every proposed action   |   control plane (narrow, authenticated)
  |  passes dispatch():      |---------------------------+
  |  scope -> blast -> rate  |                           v
  +--------------------------+                 +---------------------------+
                                               |  attacker VM (tool        |
                                               |  adapters: nmap, httpx,   |
                                               |  ffuf, sqlmap, nuclei...) |
                                               +------------+--------------+
                                                            | data plane
                                   isolated L2 range        v
                                  +----------------[ scope-guard gateway ]----+
                                  |  default-deny, no internet / no LAN route |
                                  |     target VM(s)   <--- cloned from a     |
                                  |                         golden snapshot   |
                                  +-------------------------------------------+
```

A run moves through four phases, driven by four isolated agent roles that each hold a separate model session and can only ever propose:

1. **Plan.**
   Recon builds a target model; the harness matches each asset against the applicable technique cards; the Planner orders them (objective-advancing first, then by severity and blast tier).
2. **Hunt.**
   The Operator proposes probes one at a time.
   The harness disposes each through `dispatch()`, the single chokepoint where the scope, blast-tier, and rate guards run before anything touches the target.
   A deterministic success signal, not the model, decides when a lead is real.
3. **Verify.**
   A Verifier on a different provider reproduces the lead from its repro steps alone, in a fresh snapshot.
   Only then does the lead become a confirmed finding, and only then do its facts enter the blackboard to unlock the next step of a chain.
4. **Report.**
   The Reporter renders a target-neutral report that must pass a zero-dependency schema gate before it ships: every finding independently verified, every vulnerability carrying CVSS and CWE, and an objective outcome with the attack path when a goal was set.

Untrusted input (target responses, enrichment data) only ever enters a role's context as clearly delimited data, never as instructions, so an injected instruction in a target response cannot widen scope, raise a tier, or reach a new host.

---

## Repository layout

| Path | What lives there |
|------|------------------|
| `SPEC.md` | The living design spec and decision log; the overview that ties everything together. |
| `docs/specs/` | The component specs (`HC-*`), the source of truth each file goes deep on. |
| `docs/requirements/` | Business requirements as user stories plus generated Gherkin scenarios. |
| `harness/` | The running system: the control loop, roles, dispatch chokepoint, model plane, blackboard, findings, report, and the SQLite + blob store. |
| `harness/substrate/` | The safety-critical layer: the engagement-contract parser, scope guard, and blast-tier gate. |
| `kb/` | The 107 materialized technique cards, grouped by target class. Generated from the specs. |
| `eval/` | Ground-truth manifests for the evaluation harness. Generated from the specs. |
| `tools/` | The zero-dependency KB validator, materializer, and feature generator. |
| `tests/` | Adversarial self-tests (15 suites), one `main()` per file, run in CI. |

`kb/`, `eval/`, and `docs/requirements/features/` are generated.
The specs under `docs/specs/` are authoritative; regenerate with `make materialize` / `make features` rather than hand-editing a generated file.

---

## Requirements

- Python 3.12
- `make` and `git`
- No third-party packages, no services, nothing to `pip install`.

A full live engagement additionally needs infrastructure you host yourself; see [Running a live engagement](#running-a-live-engagement).

---

## Quickstart (zero install, under a minute)

```bash
git clone <this-repo> capri && cd capri

# Run everything CI runs: the strict KB validator plus all 15 test suites.
make check

# Validate the example engagement contract from the command line.
make contract

# Regenerate the technique-card tree and eval manifests from the specs.
make materialize
```

`make check` exercises the entire decision layer end to end, the control loop, the propose-and-dispose guards, finder-is-not-verifier, objective chaining, the evidence store, and the report ship-gate, all driven against stubbed roles, tools, and sandbox.
Nothing in this step touches a network or a real target.

Validate any contract you write:

```bash
python3 -m harness.substrate.contract path/to/engagement.yaml
```

Validation is fail-closed: a missing, malformed, or contradictory field is rejected before anything could be provisioned.

---

## The engagement contract

A run is defined by one signed, declarative contract, the single source of truth for what it may do.
A starter is in [`harness/substrate/examples/engagement.example.yaml`](harness/substrate/examples/engagement.example.yaml).

```yaml
engagement:
  id: eng-2026-11-08-001                  # unique, immutable; keys all state
  authorized_by: you / TICKET-1234        # human or ticket of record
  window: { start: 2026-11-08T20:00, end: 2026-11-08T23:59 }
  max_blast_tier: 2                        # 0..3; caps how destructive the run may be

scope:
  in_scope_hosts: [app.sandbox.local, api.sandbox.local]
  in_scope_cidrs: [10.13.0.0/24]
  out_of_scope: [10.13.0.1]                # always wins over in-scope
  allowed_ports: { default: [80, 443], "10.13.0.0/24": [22, 80, 443, 5432] }

policy:
  allowed_tactics: [recon, initial-access, discovery, credential-access]
  forbidden: [exfil-to-internet, persistence-survive-reset]
  rate: { max_rps_per_target: 20, max_actions_per_run: 5000 }
  lateral_movement: false                  # gate movement between in-scope hosts

# Optional. Absent means a pure-coverage run; present means pursue and prove a goal.
objective:
  id: obj-flag-on-db
  description: "Read the planted secret at /flag.txt on the database host."
  type: canary                             # capability | canary | reach
  target: db.sandbox.local                 # must already be an in-scope host
  success: "exists(flag.captured) && flag.host == 'db.sandbox.local'"
  proof: { kind: canary, location: "/flag.txt", sha256: "<hash of the planted secret>" }
  on_success: stop
```

The objective is proven deterministically by the harness (a canary hash match or an in-sandbox marker), never by the agent claiming success.
A foothold on one host unlocks techniques against hosts that are already in scope; it never widens scope.

---

## Running a live engagement

The harness is designed around injected seams, so the infrastructure is swappable and never ships in this repo.
To run against a real target you provide three things:

1. **An isolated sandbox lab** that satisfies the five substrate guarantees (scope, no egress, reproducibility, containment, killability).
   The reference target is Firecracker microVMs on an isolated L2 segment, behind an nftables or eBPF scope-guard gateway with no route off the range, with snapshot and restore.
   See [`docs/specs/HC-SUB-01.md`](docs/specs/HC-SUB-01.md).
2. **A Bifrost model gateway** with one virtual key per role, where the Operator and Verifier keys resolve to disjoint providers.
   No role ever holds a provider credential.
   See [`docs/specs/HC-MODEL-01.md`](docs/specs/HC-MODEL-01.md).
3. **Real tool adapters** behind the allow-listed `dispatch()` interface (nmap, httpx, ffuf, sqlmap, nuclei, a headless browser), plus optionally the Tavily enrichment service, which runs outside the sandbox and is advisory only.

Until all five sandbox self-tests pass, the harness refuses to leave `passive-only` mode: no active probe runs, and every lead is held unverified.
That is the safe default, by design.

The harness logic for all of the above is already here and tested; what you add is the infrastructure it drives.
Start from [`harness/README.md`](harness/README.md) for the module-by-module map, and [`SPEC.md`](SPEC.md) for the full architecture and build roadmap.

---

## Safety and authorization

This is a tool for authorized, scoped security testing inside an isolated laboratory, and nothing else.

- It is built to make out-of-scope activity impossible, not merely discouraged: scope is enforced at the network layer, the sandbox has no route to the public internet or any real network, and any out-of-scope reach fails the run.
- Run it only against targets you own or are explicitly authorized to test, inside an environment with no path to real-world systems.
- The engagement contract records who authorized the run and the window it is valid for, and the harness will not start outside that window or against a target that resolves out of scope.

Do not point this at systems you are not authorized to test.

---

## Development

- `make check` must be green before you commit; it is exactly what CI runs.
- The specs under `docs/specs/` are the source of truth.
  `make materialize` regenerates `kb/` and `eval/`, and `make features` regenerates the Gherkin features; CI fails if either tree drifts from the specs, so regenerate and commit rather than hand-editing a generated file.
- Tests live in `tests/`, one suite per file with a `main()` that prints `ok` / `FAIL` lines and an `N/N passed` total.
  A new suite is wired into both the `test:` target in the `Makefile` and the workflow in `.github/workflows/validate.yml`.

---

## Where to read next

- [`SPEC.md`](SPEC.md) - the architecture, the design principles, and the dated decision log.
- [`docs/specs/INDEX.md`](docs/specs/INDEX.md) - the registry of component specs and how they depend on each other.
- [`harness/README.md`](harness/README.md) - the running system, module by module.
