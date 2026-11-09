# Capri

Autonomous penetration-testing agent for authorized, scoped engagements in an isolated lab.

Capri drives an LLM agent through a real pentest against a disposable sandbox target: it recons with real tools, decides what to try next, chains steps toward an objective, and produces an independently verified report with evidence, severity, and remediation.

The governing rule is **the harness is code, the agent is prompted**: safety-critical logic is deterministic, and the model only proposes what to try, never what runs.

This repository is the harness. The sandbox and model gateway are infrastructure you point it at. It has zero third-party dependencies, and the whole decision layer is tested against stubbed infrastructure, so `make check` runs in seconds.

## Highlights

- **Scope enforced in the network layer.** Default-deny and IP-pinned; the lab has no route to the internet or any real network, and out-of-scope reach fails the run.
- **Finder is never verifier.** A lead is confirmed only when a second agent on a different provider reproduces it from the repro steps alone, in a fresh snapshot. Enforced at the loop, the model plane, and the database.
- **Objective-driven.** An engagement can declare a goal; the agent chains techniques toward it through a blackboard of verified facts, and the report shows the attack path.
- **Grounded.** 107 technique cards across 10 classes, each mapped to ATT&CK, OWASP, CWE, and CVSS. New knowledge is a new card, not a code change.
- **Safe by construction.** Destructive steps are tiered, snapshotted, and authorized; without a proven sandbox the system stays in read-only `passive-only` mode.
- **Deterministic and resumable.** An append-only, hash-chained audit log means a killed run resumes from its ledger to the same result.

## Architecture

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

Four phases, run by four isolated roles that can only propose:

1. **Plan** - recon builds a target model; the harness matches applicable cards; the Planner orders them.
2. **Hunt** - the Operator proposes probes; `dispatch()` runs the scope, blast-tier, and rate guards before anything touches the target; a deterministic signal, not the model, decides when a lead is real.
3. **Verify** - a Verifier on a different provider reproduces the lead in a fresh snapshot; only then is it confirmed and its facts unlock the next step.
4. **Report** - a schema gate blocks the report unless every finding is independently verified and carries CVSS and CWE.

Untrusted target output enters a role's context only as delimited data, never as instructions.

## Repository layout

| Path | What lives there |
|------|------------------|
| `SPEC.md` | The design spec and dated decision log. |
| `docs/specs/` | The component specs (`HC-*`), the source of truth. |
| `harness/` | The running system: control loop, roles, dispatch, model plane, blackboard, findings, report, and the SQLite + blob store. |
| `harness/substrate/` | The safety-critical layer: contract parser, scope guard, blast-tier gate. |
| `kb/` | The 107 technique cards, by target class. Generated. |
| `eval/` | Ground-truth manifests for the eval harness. Generated. |
| `tools/` | The KB validator, materializer, and feature generator. |
| `tests/` | 17 self-test suites, run in CI. |

`kb/`, `eval/`, and `docs/requirements/features/` are generated from the specs; run `make materialize` / `make features` instead of editing them by hand.

## Quickstart

Needs Python 3.12, `make`, and `git`. Nothing to install.

```bash
git clone <this-repo> capri && cd capri

make check      # the strict KB validator plus all 17 test suites (what CI runs)
make contract   # validate the example engagement contract
make materialize # regenerate the card tree and eval manifests from the specs
```

`make check` exercises the full decision layer against stubbed roles, tools, and sandbox, and touches no network. Validate a contract of your own with:

```bash
python3 -m harness.substrate.contract path/to/engagement.yaml
```

Validation is fail-closed: a missing, malformed, or contradictory field is rejected before anything is provisioned.

## The engagement contract

One declarative contract is the single source of truth for what a run may do. Starter: [`harness/substrate/examples/engagement.example.yaml`](harness/substrate/examples/engagement.example.yaml).

```yaml
engagement:
  id: eng-2026-11-08-001
  authorized_by: you / TICKET-1234
  window: { start: 2026-11-08T20:00, end: 2026-11-08T23:59 }
  max_blast_tier: 2                   # 0..3; caps how destructive the run may be

scope:
  in_scope_hosts: [app.sandbox.local, api.sandbox.local]
  in_scope_cidrs: [10.13.0.0/24]
  out_of_scope: [10.13.0.1]           # always wins over in-scope
  allowed_ports: { default: [80, 443], "10.13.0.0/24": [22, 80, 443, 5432] }

policy:
  rate: { max_rps_per_target: 20, max_actions_per_run: 5000 }
  lateral_movement: false             # gate movement between in-scope hosts

objective:                            # optional; omit for a pure-coverage run
  id: obj-flag-on-db
  type: canary                        # capability | canary | reach
  target: db.sandbox.local            # must already be in scope
  success: "exists(flag.captured) && flag.host == 'db.sandbox.local'"
  proof: { kind: canary, location: "/flag.txt", sha256: "<hash of the planted secret>" }
  on_success: stop
```

The objective is proven by the harness (a canary hash match or an in-sandbox marker), never by the agent claiming success. A foothold unlocks techniques against hosts already in scope; it never widens scope.

## Running a live engagement

The harness runs against injected seams, so you supply three things:

1. **An isolated sandbox lab** meeting the five substrate guarantees (scope, no egress, reproducibility, containment, killability). The self-hostable reference backend is Docker plus an nftables scope guard, with no nested virtualization, so it runs on any Linux host or inside Docker Desktop on macOS/Windows; prove all five guarantees on your host with `python3 tools/sandbox_selftest.py` (host notes in [`infra/sandbox/`](infra/sandbox/)). Firecracker microVMs plug in behind the same interface for stronger isolation. See [`docs/specs/HC-SUB-01.md`](docs/specs/HC-SUB-01.md).
2. **A Bifrost model gateway** with one virtual key per role, the Operator and Verifier on disjoint providers, and no provider credential in any role. One command stands it up, no cloud account:

   ```bash
   python3 tools/modelplane.py up      # generate config, mint virtual keys, run the gateway
   python3 tools/modelplane.py keys    # paste your own provider API keys (hidden input)
   ```

   Then `eval "$(python3 tools/modelplane.py env)"` exports the handles a run reads. Walkthrough in [`infra/modelplane/README.md`](infra/modelplane/README.md); design in [`docs/specs/HC-MODEL-01.md`](docs/specs/HC-MODEL-01.md).
3. **Tool adapters** behind the allow-listed `dispatch()` interface (nmap, httpx, ffuf, sqlmap, nuclei, a headless browser), optionally with the Tavily enrichment service.

Until the five sandbox self-tests pass, the harness stays in `passive-only`: no active probe runs and every lead is held unverified.

## Safety

Capri is for authorized, scoped testing inside an isolated lab, and nothing else. Scope is enforced at the network layer, the sandbox has no route to any real network, and the contract records who authorized the run and when. Do not point it at systems you are not authorized to test.

## Development

- `make check` is the pre-commit gate and exactly what CI runs.
- The specs under `docs/specs/` are the source of truth; CI fails if `kb/` or the features drift, so regenerate and commit.
- Tests are one suite per file with a `main()`; wire a new one into both the `test:` target and `.github/workflows/validate.yml`.

## Read next

- [`SPEC.md`](SPEC.md) - architecture, design principles, decision log.
- [`docs/specs/INDEX.md`](docs/specs/INDEX.md) - the component-spec registry.
- [`harness/README.md`](harness/README.md) - the running system, module by module.
