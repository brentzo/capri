# Capri

Autonomous penetration-testing agent for authorized, scoped engagements in an isolated lab.

Capri drives an LLM agent through a real pentest against a disposable sandbox target: it recons with real tools, decides what to try next, chains steps toward an objective, and produces an independently verified report with evidence, severity, and remediation.

The governing rule is **the harness is code, the agent is prompted**: safety-critical logic is deterministic, and the model only proposes what to try, never what runs.

This repository holds the whole system: the dependency-free Python harness, plus self-hostable backends for the two things it drives - an isolated Docker sandbox range and a Bifrost model gateway you bring up on your own machine.
The harness core and its test suite use only the Python standard library, and its decision layer is tested against stubbed infrastructure, so `make check` runs in seconds without Docker or a network.
The CLI's styled terminal UI uses Textual and Rich, pinned in `pyproject.toml` and `uv.lock`.

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
| `capri` | The CLI a self-hoster runs: `capri setup` (pick models, start the gateway), `capri run` (run an engagement). |
| `SPEC.md` | The design spec and dated decision log. |
| `docs/specs/` | The component specs (`HC-*`), the source of truth. |
| `harness/` | The running system: control loop, roles, dispatch, model plane, blackboard, recon, findings, report, and the SQLite + blob store. |
| `harness/substrate/` | The safety-critical layer: contract parser, scope guard, blast-tier gate. |
| `harness/sandbox/` | The sandbox backends: the interface, the passive-only default, and the self-hostable Docker range with its live tool adapters. |
| `infra/` | Host-side setup for the two self-hosted backends: the Docker sandbox range and the Bifrost model gateway. |
| `kb/` | The 107 technique cards, by target class. Generated. |
| `eval/` | Ground-truth manifests for the eval harness. Generated. |
| `tools/` | KB build tooling (validator, materializer) plus the live-engagement runner and the model-plane setup. |
| `tests/` | Self-test suites, run in CI. |

`kb/`, `eval/`, and `docs/requirements/features/` are generated from the specs; run `make materialize` / `make features` instead of editing them by hand.

## Quickstart

Needs Python 3.12, `uv`, `make`, and `git`.

```bash
git clone git@github.com:brentzo/capri.git && cd capri

make check      # the strict KB validator plus all self-test suites (what CI runs)
uv sync         # install the pinned CLI UI dependencies
make contract   # validate the example engagement contract
make materialize # regenerate the card tree and eval manifests from the specs
```

`make check` exercises the full decision layer against stubbed roles, tools, and sandbox, and touches no network. Validate a contract of your own with:

```bash
python3 -m harness.substrate.contract path/to/engagement.yaml
```

Validation is fail-closed: a missing, malformed, or contradictory field is rejected before anything is provisioned.

## The engagement contract

One declarative contract is the single source of truth for what a run may do. Start from [the example engagement contract](harness/substrate/examples/engagement.example.yaml).

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

A live engagement needs three things, all self-hostable on your own machine:

1. **An isolated sandbox lab** meeting the five substrate guarantees (scope, no egress, reproducibility, containment, killability). The self-hostable reference backend is Docker plus an nftables scope guard, with no nested virtualization, so it runs on any Linux host or inside Docker Desktop on macOS/Windows; prove all five guarantees on your host with `python3 tools/sandbox_selftest.py` (see the [sandbox host notes](infra/sandbox/)). Firecracker microVMs plug in behind the same interface for stronger isolation. See the [sandbox substrate spec](docs/specs/HC-SUB-01.md).
2. **A Bifrost model gateway** with one virtual key per role, the Operator and Verifier on disjoint providers, and no provider credential in any role. Set it up on your own machine, no cloud account:

   ```bash
   make install     # once: puts the `capri` command on your PATH
   capri setup      # a terminal UI: pick your Operator and Verifier models, drop in keys, start the gateway
   capri run        # run an engagement with the models you chose
   ```

   In Windows PowerShell, from the repository folder, run `python .\capri setup`
   and `python .\capri run` if `capri` is not installed on your `PATH`.
   Those commands use the repo's locked `uv` environment; add `--plain` to setup for line-by-line prompts.

   `capri setup` offers a catalog of providers (OpenAI, Anthropic, Gemini, DeepSeek, and more) and keeps the two roles on different providers; the gateway (Bifrost) runs on `127.0.0.1` and never appears. See the [gateway setup walkthrough](infra/modelplane/README.md) and the [model-plane spec](docs/specs/HC-MODEL-01.md).

For a local, read-only source assessment of any project, install Semgrep locally and run:

```powershell
python .\capri source --project C:\path\to\project
```

This uses Capri's local rule pack with metrics and version checks disabled, does not execute the project or contact a model provider, and writes a snippet-free report under `~/.capri/reports/`.
This command assesses source only; it does not run the app or its backing services.
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
