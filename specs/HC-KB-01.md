---
tag: HC-KB-01
title: Technique-card schema and knowledge base structure
status: draft
parent: SPEC.md#7
depends_on: [HC-SUB-01]
depended_on_by: [HC-KB-02, HC-KB-03, HC-KB-04, HC-KB-05, HC-KB-06, HC-KB-07, HC-KB-08, HC-KB-09, HC-KB-10, HC-KB-11, HC-MODEL-02, HC-ENRICH-01, HC-AGENT-01, HC-FIND-01, HC-DATA-01, HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-01 - Technique-card schema and knowledge base structure

## 1. Purpose

This spec defines the technique card: the atomic, machine-readable, versioned unit of attacker knowledge that drives the hunting loop, and the structure, grounding, versioning, and validation of the knowledge base they live in.

The point of the card is to make the agent grounded in curated, real-adversary TTPs rather than improvising.
A card is data the loop reads field by field, not prose the model interprets.
This is also the separation that lets the system grow: new knowledge is a new card (a git diff), never a change to the harness.

## 2. Design goals

- Cards are data: the loop evaluates typed fields (applicability, probe steps, success signal), it does not read paragraphs.
- Deterministic first: a card expresses its success signal so the harness can evaluate it in code, and it reaches for a Laya classifier (HC-MODEL-02) only for a genuinely fuzzy judgment.
- Grounded: every card maps to public, authoritative, real-adversary catalogs (ATT&CK, ATLAS, OWASP, CWE, CAPEC, CVSS).
- Composable: a card declares what facts it needs and what it yields, so cards chain explicitly through a shared blackboard rather than through a model's imagination.
- Safe by construction: a card declares its blast tier (HC-SUB-01) and its cleanup, and the validator refuses an unsafe or incomplete card.
- Reviewable and versioned: each card carries a semver, and a finding always pins the exact card version that produced it.

## 3. Card schema

The canonical template, with every field and its meaning:

```yaml
id:         KB-WEB-INJ-SQLI-001        # stable handle; KB-<CLASS>-<FAMILY>-<nnn>
title:      Error-based SQL injection in a query parameter
version:    1.2.0                       # semver; pinned into every probe_event
status:     active                      # draft | active | deprecated
supersedes: null                        # card id this replaces, if any

taxonomy:
  attack: { tactic: TA0001, technique: T1190 }   # MITRE ATT&CK (web and infra classes)
  atlas:  [AML.T0051]                              # MITRE ATLAS; AI/LLM classes where ATT&CK has no equivalent (optional)
  owasp:  [WSTG-INPV-05]                           # OWASP WSTG / ASVS / Top 10 / LLM Top 10
  cwe:    [CWE-89]                                 # MITRE CWE
  capec:  [CAPEC-66]                               # optional

applicability:                          # predicate DSL over the target model; all must hold
  - asset.type == "http_endpoint"
  - exists(asset.params)
  - asset.params.length > 0
preconditions:      [ reachable ]        # runtime facts; some are yielded by other cards
yields_on_success:  [ db_read ]          # facts written to the blackboard for chaining

inputs:
  param: "{asset.params[*]}"            # the Operator iterates these

blast_tier: 1                            # HC-SUB-01 §7
cleanup:    none                         # required (non-empty) when blast_tier >= 2

probe_steps:                             # ordered; each is a normalized dispatch() request
  - { tool: httpx,            intent: baseline,       args: { path: "{asset.path}", param: "{param}" } }
  - { tool: custom.sqli_probe, intent: error_payloads, args: { param: "{param}", set: error_based } }

success_signal:
  type:      response_diff               # see §5 for the type set
  evaluator: deterministic               # deterministic | laya:<decision_point>
  assert:    "db_error_fingerprint(resp) OR boolean_oracle_divergence(baseline, resp)"
  confidence_floor: 0.0                   # deterministic evaluators return 1.0 or 0.0

severity_rubric:
  base: high
  raise_if: [ { when: "yields.writable", to: critical } ]   # list of {when, to}; evaluated in order
  lower_if: [ { when: "asset.read_only", to: medium } ]      # symmetric; same {when, to} shape
  cvss_base_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N"

false_positive_notes:
  - "WAF block pages can echo the payload without executing it; require the oracle, not mere reflection."

test_fixture:                            # HC-EVAL-01
  fires_on:      seed/web-juiceshop/sqli-login
  does_not_fire: seed/web-juiceshop/sqli-patched

references:
  - https://owasp.org/www-project-web-security-testing-guide/
  - https://attack.mitre.org/techniques/T1190/
```

### 3.1 Naming

`KB-<CLASS>-<FAMILY>-<nnn>`.
`CLASS` is the target class abbreviation (section 7): `WEB`, `CLIENT`, `AILLM`, `CLOUD`, `SUPPLY`, `RPC`, `DOS`, `DATA`, `BIN`, `MOBILE`.
`FAMILY` is a short grouping within the class (`INJ`, `AUTH`, `SESS`, ...), and `nnn` is sequential.
The id is permanent, and a behavioral change bumps the version, not the id.

## 4. The applicability predicate DSL

Applicability and the `when` clauses in the rubric are a small, safe expression language evaluated by the harness over the target model.
It is deliberately not general code: that keeps cards auditable and keeps an untrusted or mistaken card from executing logic.

- Operands: fields of the target model (`asset.type`, `asset.params`, `service.version`, `tech.framework`, blackboard facts).
- Operators: `==`, `!=`, `in`, `exists(x)`, `matches(x, /regex/)`, `>`, `<`, `&&`, `||`, `!`.
- No function calls beyond the small allowlisted set above, no loops, no side effects.
- An unparseable predicate fails validation (section 9), so it can never reach a run.

## 5. The success-signal model

This is where "grounded" meets "reliable."
Every signal declares a `type`, an `evaluator`, and an `assert`, and returns `{hit: bool, confidence: float}`.

| Type | Meaning | Typical evaluator |
|------|---------|-------------------|
| `status_match` | HTTP status / response code pattern | deterministic |
| `content_match` | A known fingerprint or regex is present (e.g. a DB error signature) | deterministic |
| `response_diff` | Baseline vs probe response differ in a defined way | deterministic, or `laya:` when "differ meaningfully" is fuzzy |
| `differential` | A true/false oracle diverges across a payload pair | deterministic |
| `timing_oracle` | A statistically significant timing delta (blind injection) | deterministic (with a stats test) |
| `state_change` | An observed side effect (row created, file written); usually tier >= 2 | deterministic |
| `oob_callback` | An out-of-band interaction is received | deterministic, in-sandbox collaborator only |

Rules:

- Deterministic first: a signal uses a deterministic evaluator unless the phenomenon is inherently a judgment call, in which case it names a Laya decision point (`evaluator: laya:success_signal`) per HC-MODEL-02.
- The returned `confidence` feeds the HC-FIND-01 gate: below the configured floor a signal is not emitted as a lead at all, and every emitted lead is independently verified regardless of confidence (HC-FIND-01 is the authority on this); a deterministic evaluator returns 1.0 or 0.0.
- `oob_callback` must terminate at an in-sandbox collaborator service (a DNS/HTTP listener on the range), never an internet host, which keeps the egress-denied guarantee (HC-SUB-01 G2) intact. A card that names an external collaborator fails validation.

## 6. Chaining through the blackboard

Cards compose through facts, not through a model planning freely.

- `preconditions` are facts a card needs before it runs (for example `authenticated_session`).
- `yields_on_success` are facts a card writes to the target model (the shared blackboard) when its signal fires (for example `credential`, `session_token`, `rce_foothold`).
- The Planner and Operator (HC-AGENT-01) sequence cards by matching yields to preconditions, so a credential-access card that yields `credential` unlocks a lateral card that requires one.
- v1 keeps chaining shallow and explicit: declared yields and preconditions only, no automatic deep attack-path search, which stays auditable and cheap.

## 7. Knowledge base structure

One card per YAML file, grouped by target class, with a per-class index; this mirrors the ten classes in SPEC.md#7.3.

```
kb/
  web-protocol-auth/     # WEB     HTTP framing, caching, injection, authn/session
  client-side/           # CLIENT  DOM injection, messaging, UI redress, prototype pollution
  ai-llm/                # AILLM   prompt injection, tool/agent abuse, output handling
  cloud-deployment/      # CLOUD   IAM, IaC, containers, serverless
  supply-chain/          # SUPPLY  dependencies, CI, signing, updates, plugins
  rpc-messaging/         # RPC     RPC, serialization, queues, webhooks
  resource-exhaustion/   # DOS     availability and resource limits
  data-isolation/        # DATA    tenant isolation, backups, deletion
  memory-binary/         # BIN     native code, kernels
  mobile-local-ipc/      # MOBILE  native apps, deep links, local IPC
  _index/                # generated per-class and global indexes
```

## 8. Versioning and governance

- Semver per card: major = a change to the assert or behavior that can change findings; minor = added payloads or steps; patch = metadata only.
- The KB is git-versioned, and every `probe_event` pins `technique_id` plus `technique_version` (HC-DATA-01), so a historical finding is always interpretable against the exact card that produced it.
- A change that raises `blast_tier`, adds a tier >= 2 step, or weakens a success signal requires explicit review before the card returns to `active`.
- Deprecation sets `status: deprecated` and names a `supersedes` successor; deprecated cards never run but remain for interpreting old findings.

## 9. Validation

A zero-dependency validator, runnable in CI, gates every card; an `active` card that fails does not load.
It checks:

- schema conformance and required fields present;
- taxonomy references resolve to valid ATT&CK, ATLAS, CWE, and (if present) CAPEC identifiers;
- the applicability predicate and every `when` clause parse under the section-4 DSL;
- `success_signal.evaluator` is a known deterministic evaluator or a declared Laya decision point;
- `blast_tier` is present, and `cleanup` is non-empty when the tier is >= 2;
- any `oob_callback` names an in-sandbox collaborator, never an external host;
- `references` is non-empty, and `test_fixture.fires_on` and `does_not_fire` are present for active cards.

The reference implementation lives in `tools/validate_kb.py` (pure standard library), with the bundled identifier reference in `tools/taxonomy.py` and adversarial tests in `tests/test_validator.py`, and it runs in CI on every change (`tools/README.md`).
Taxonomy ids that are well-formed but not yet confirmed against their upstream catalog are reported as UNRESOLVED, which is how a `# verify` marker is discharged: confirm the id and add it to the reference, or correct the card.

## 10. How the loop consumes a card

Recap of the HC-AGENT-01 contract, for completeness:

- `kb.get(id)` returns the card; `preconditions_met(card, asset)` evaluates applicability (section 4) and preconditions against the blackboard.
- `probe_steps` are rendered (parameters substituted) into `dispatch()` requests, one per step.
- `success_signal` drives `signal_hit`, deterministic in code or delegated to Laya, returning `{hit, confidence}`.
- On a hit, the Operator emits a lead whose `repro` is the executed steps and whose `evidence` is the probe_event URIs; `severity_rubric` sets the finding's CWE and CVSS (HC-FIND-01).
- On success, `yields_on_success` facts are written to the blackboard for downstream cards.

## 11. Grounding sources

- MITRE ATT&CK: tactics and techniques observed in the wild.
- MITRE ATLAS: the adversarial-ML threat matrix, grounding the AI and LLM classes where ATT&CK has no equivalent.
- OWASP WSTG, ASVS, Top 10, and LLM Top 10.
- MITRE CWE: the weakness taxonomy for findings.
- MITRE CAPEC: optional attack-pattern cross-reference.
- CVSS v4: severity vectors.

## 12. Acceptance criteria

- A malformed card, an unresolved taxonomy reference, an unparseable predicate, a tier >= 2 card with empty cleanup, or an external `oob_callback` all fail validation and cannot load.
- A valid active card runs end to end in the HC-AGENT-01 loop: applicability gates it, probe steps dispatch, the success signal returns `{hit, confidence}`, and a hit yields a lead with repro and evidence.
- Each active card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- A finding records the card version, and re-reading it against a later KB still resolves to the producing card.

## 13. Open questions

- Predicate DSL surface: how rich to make `matches`/version-range comparisons before it becomes code we must sandbox; leaning minimal for v1.
- Whether `timing_oracle` needs a shared statistical helper in the harness so cards do not each reinvent the significance test (likely yes).
- Payload sets: keep inline in the card, or factor shared payload libraries referenced by name (leaning referenced, so a payload fix updates many cards at once, but that complicates version pinning).
- Confidence semantics for Laya evaluators once HC-MODEL-02 calibration data exists.
