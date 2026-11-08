---
tag: HC-KB-02
title: Web and auth technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-02 - Web and auth technique-card starter set

## 1. Purpose

This is the first concrete card set: fifteen cards for the `web-protocol-auth` class, authored against the HC-KB-01 schema.
It is enough to exercise the full HC-AGENT-01 loop end to end against seeded targets, and it is the pattern every later class copies.

Each card ships as its own YAML file under `kb/web-protocol-auth/` (HC-KB-01 §7).
The blocks below are condensed to the meaningful fields; the omitted fields (`status: active`, per-card `references`, `inputs` templating, full `cvss_base_vector`) follow the HC-KB-01 template.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Coverage map

| Card | Family | CWE | OWASP | ATT&CK | Tier | Signal | Yields |
|------|--------|-----|-------|--------|------|--------|--------|
| KB-WEB-INJ-SQLI-001 | Injection | CWE-89 | WSTG-INPV-05 | T1190 | 1 | response_diff | db_read |
| KB-WEB-INJ-SQLI-002 | Injection | CWE-89 | WSTG-INPV-05 | T1190 | 1 | timing_oracle | db_read |
| KB-WEB-INJ-XSS-001  | Injection | CWE-79 | WSTG-INPV-01 | T1190 | 1 | content_match | client_exec |
| KB-WEB-INJ-XSS-002  | Injection | CWE-79 | WSTG-INPV-02 | T1190 | 2 | content_match | client_exec |
| KB-WEB-INJ-CMDI-001 | Injection | CWE-78 | WSTG-INPV-12 | T1190 | 1 | timing_oracle / oob_callback | rce_foothold |
| KB-WEB-INJ-SSTI-001 | Injection | CWE-1336 | WSTG-INPV-18 | T1190 | 1 | differential | rce_foothold |
| KB-WEB-INJ-PATH-001 | Injection | CWE-22 | WSTG-ATHZ-01 | T1190 | 1 | content_match | file_read |
| KB-WEB-INJ-SSRF-001 | Injection | CWE-918 | WSTG-INPV-19 | T1190 | 1 | oob_callback | internal_reach |
| KB-WEB-AUTH-IDOR-001 | Authz | CWE-639 | API1:2023 (BOLA) | T1190 # verify | 1 | differential | cross_object_read |
| KB-WEB-AUTH-BFLA-001 | Authz | CWE-285 | API5:2023 (BFLA) | T1190 # verify | 1 | status_match | priv_function_access |
| KB-WEB-AUTH-JWT-001 | Authn | CWE-347 | WSTG-SESS-10 | T1550.001 | 1 | status_match | authenticated_session |
| KB-WEB-AUTH-BRUTE-001 | Authn | CWE-307 | WSTG-ATHN-03 | T1110.004 | 2 | differential | credential |
| KB-WEB-SESS-FIX-001 | Session | CWE-384 | WSTG-SESS-03 | T1539 # verify | 2 | differential | session_hijack |
| KB-WEB-PROTO-CORS-001 | Protocol | CWE-942 | WSTG-CLNT-07 | T1190 # verify | 1 | content_match | cross_origin_read |
| KB-WEB-CACHE-POISON-001 | Caching | CWE-444 # verify | WSTG-INPV-??  # verify | T1190 # verify | 2 | response_diff | cache_control |

Tier distribution: eleven tier-1 (read-only probing) and four tier-2 (state-changing, snapshot required before the step): stored XSS, credential stuffing, session fixation, cache poisoning.

## 3. Cards

### 3.1 Injection family

```yaml
id: KB-WEB-INJ-SQLI-001
title: Error/boolean-based SQL injection in a query parameter
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-05], cwe: [CWE-89] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ db_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx,             intent: baseline }
  - { tool: custom.sqli_probe, intent: error_and_boolean }
success_signal: { type: response_diff, evaluator: deterministic,
                  assert: "db_error_fingerprint(resp) OR boolean_oracle_divergence(baseline, resp)" }
severity_rubric: { base: high, raise_if: [ { when: "asset.writable", to: critical } ] }
```

```yaml
id: KB-WEB-INJ-SQLI-002
title: Time-based blind SQL injection
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-05], cwe: [CWE-89] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ db_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.sqli_probe, intent: time_payloads, args: { delay_s: 5, trials: 5 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "significant_delay(delay_s=5, trials=5, p<0.01)" }
severity_rubric: { base: high }
false_positive_notes: [ "Network jitter; require a stats test across trials, not a single slow response." ]
```

```yaml
id: KB-WEB-INJ-XSS-001
title: Reflected cross-site scripting in a parameter
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-01], cwe: [CWE-79] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ client_exec ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.xss_probe,   intent: reflect_marker }
  - { tool: browser.playwright, intent: observe_execution }   # did the marker script run in a real DOM
success_signal: { type: content_match, evaluator: "laya:success_signal",
                  assert: "marker executed in DOM, not merely reflected" }
severity_rubric: { base: medium, raise_if: [ { when: "asset.auth_context", to: high } ] }
false_positive_notes: [ "Reflection without execution is not XSS; confirm execution in a browser context." ]
```

```yaml
id: KB-WEB-INJ-XSS-002
title: Stored cross-site scripting
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-02], cwe: [CWE-79] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.persists_input == true' ]
preconditions: [ reachable ]
yields_on_success: [ client_exec ]
blast_tier: 2                      # persists a payload other requests will render
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.xss_probe,   intent: store_marker }
  - { tool: browser.playwright, intent: observe_execution_on_render }
success_signal: { type: content_match, evaluator: "laya:success_signal",
                  assert: "stored marker executes when the sink page is rendered" }
severity_rubric: { base: high }
```

```yaml
id: KB-WEB-INJ-CMDI-001
title: OS command injection
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-12], cwe: [CWE-78] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ rce_foothold ]
blast_tier: 1                      # read-only proof: timing or OOB, no destructive command
cleanup: none
probe_steps:
  - { tool: custom.cmdi_probe, intent: sleep_and_oob, args: { delay_s: 5, collaborator: range-oob } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "significant_delay(5) OR oob_received(collaborator=range-oob)" }
severity_rubric: { base: critical }
# collaborator MUST be the in-sandbox listener; external would fail HC-KB-01 validation
```

```yaml
id: KB-WEB-INJ-SSTI-001
title: Server-side template injection
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-18], cwe: [CWE-1336] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ rce_foothold ]
blast_tier: 1                      # arithmetic-eval proof only, no code exec in the probe
cleanup: none
probe_steps:
  - { tool: custom.ssti_probe, intent: arithmetic_eval, args: { expr: "{{7*7}}", expect: "49" } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "response_contains('49') AND NOT response_contains('{{7*7}}')" }
severity_rubric: { base: critical }
```

```yaml
id: KB-WEB-INJ-PATH-001
title: Path traversal / local file read
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-ATHZ-01], cwe: [CWE-22] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.params matches /file|path|name|template/' ]
preconditions: [ reachable ]
yields_on_success: [ file_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.path_probe, intent: traversal_markers }   # seeded canary file on the range target
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "response_contains(range_canary_marker)" }
severity_rubric: { base: high }
```

```yaml
id: KB-WEB-INJ-SSRF-001
title: Server-side request forgery
taxonomy: { attack: {technique: T1190}, owasp: [WSTG-INPV-19], cwe: [CWE-918] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.params matches /url|uri|callback|dest|next/' ]
preconditions: [ reachable ]
yields_on_success: [ internal_reach ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.ssrf_probe, intent: fetch_collaborator, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=target)" }
severity_rubric: { base: high, raise_if: [ { when: "yields.internal_reach", to: critical } ] }
```

### 3.2 Authorization family

```yaml
id: KB-WEB-AUTH-IDOR-001
title: Insecure direct object reference / broken object-level authorization
taxonomy: { owasp: [API1:2023], cwe: [CWE-639] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.params matches /id|uuid|account|order/' ]
preconditions: [ reachable, authenticated_session ]     # needs a baseline object to pivot from
yields_on_success: [ cross_object_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.authz_probe, intent: swap_object_id, args: { from: session_a, to: object_b } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "session_a reads object_b's data (status 200 AND foreign-owner marker)" }
severity_rubric: { base: high }
```

```yaml
id: KB-WEB-AUTH-BFLA-001
title: Broken function-level authorization (forced browsing to privileged function)
taxonomy: { owasp: [API5:2023], cwe: [CWE-285] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.privileged_siblings)' ]
preconditions: [ reachable, authenticated_session ]     # low-privilege session
yields_on_success: [ priv_function_access ]
blast_tier: 1                      # read/invoke a privileged GET only; state-changing calls are tier 2
cleanup: none
probe_steps:
  - { tool: custom.authz_probe, intent: low_priv_calls_admin_endpoint }
success_signal: { type: status_match, evaluator: deterministic,
                  assert: "privileged endpoint returns 2xx for a low-privilege session" }
severity_rubric: { base: high }
```

### 3.3 Authentication and session family

```yaml
id: KB-WEB-AUTH-JWT-001
title: JWT algorithm confusion / unverified signature
taxonomy: { attack: {technique: T1550.001}, owasp: [WSTG-SESS-10], cwe: [CWE-347] }
applicability: [ 'asset.auth == "jwt"' ]
preconditions: [ reachable, authenticated_session ]     # need a sample token to tamper
yields_on_success: [ authenticated_session, privilege_escalation ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.jwt_probe, intent: alg_none_and_hs_rs_confusion }
success_signal: { type: status_match, evaluator: deterministic,
                  assert: "a tampered/forged token is accepted (2xx on an authenticated endpoint)" }
severity_rubric: { base: critical }
```

```yaml
id: KB-WEB-AUTH-BRUTE-001
title: Missing rate limit on login / credential stuffing
taxonomy: { attack: {technique: T1110.004}, owasp: [WSTG-ATHN-03], cwe: [CWE-307] }
applicability: [ 'asset.type == "login_endpoint"' ]
preconditions: [ reachable, login_endpoint ]
yields_on_success: [ credential ]
blast_tier: 2                      # repeated auth attempts can lock accounts
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.auth_probe, intent: rate_probe, args: { attempts: 50, window_s: 10 } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "no lockout/throttle/captcha after N failed attempts" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.credential", to: high } ] }
```

```yaml
id: KB-WEB-SESS-FIX-001
title: Session fixation (session id not rotated on authentication)
taxonomy: { attack: {technique: T1539}, owasp: [WSTG-SESS-03], cwe: [CWE-384] }
applicability: [ 'asset.type == "login_endpoint"', 'asset.session_cookie exists' ]
preconditions: [ reachable, login_endpoint ]
yields_on_success: [ session_hijack ]
blast_tier: 2                      # performs an authentication
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.sess_probe, intent: set_preauth_id_then_login }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "pre-auth session id remains valid and authenticated after login" }
severity_rubric: { base: high }
```

### 3.4 Protocol and caching family

```yaml
id: KB-WEB-PROTO-CORS-001
title: CORS misconfiguration (reflected origin with credentials)
taxonomy: { owasp: [WSTG-CLNT-07], cwe: [CWE-942] }
applicability: [ 'asset.type == "http_endpoint"' ]
preconditions: [ reachable ]
yields_on_success: [ cross_origin_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx, intent: cors_reflect, args: { origin: "https://evil.range.local" } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "ACAO reflects attacker origin AND ACA-Credentials: true" }
severity_rubric: { base: medium, raise_if: [ { when: "asset.auth_context", to: high } ] }
```

```yaml
id: KB-WEB-CACHE-POISON-001
title: Web cache poisoning via unkeyed input
taxonomy: { cwe: [CWE-444] }   # verify mapping at authoring time
applicability: [ 'asset.cacheable == true' ]
preconditions: [ reachable, cacheable_endpoint ]
yields_on_success: [ cache_control ]
blast_tier: 2                      # poisons a shared cache that affects other requests
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.cache_probe, intent: unkeyed_header_inject }
  - { tool: custom.cache_probe, intent: confirm_served_from_cache }
success_signal: { type: response_diff, evaluator: deterministic,
                  assert: "injected payload served to a second, clean request from cache" }
severity_rubric: { base: high }
```

## 4. Chaining in this set

The blackboard (HC-KB-01 §6) lets these compose:

- `KB-WEB-AUTH-BRUTE-001` yields `credential`, which an authenticated login turns into `authenticated_session`.
- `authenticated_session` is a precondition of the authz and JWT cards (`IDOR-001`, `BFLA-001`, `JWT-001`), so they only run once auth exists.
- `KB-WEB-INJ-SQLI-001` yields `db_read`, which can surface credentials and feed the same auth chain.
- `KB-WEB-AUTH-JWT-001` yields `privilege_escalation`, which later classes (cloud, data-isolation) will consume.

This keeps the agent's sequencing explicit and auditable rather than letting it free-plan an attack path.

## 5. Seed targets and fixtures

Each card names a `test_fixture.fires_on` and a `does_not_fire` (HC-KB-01 §3, HC-EVAL-01).
v1 stands up deliberately vulnerable, locally hosted targets on the range (for example a Juice-Shop-style app and a DVWA-style app, both self-hosted, no internet), with a patched variant per card for the negative fixture.
The in-sandbox OOB collaborator (`range-oob`) is a DNS/HTTP listener on the range used by the SSRF and command-injection cards; it never egresses.

## 6. Backlog (deferred from this set)

- HTTP request smuggling (CL.TE / TE.CL) - high blast and framing-dependent; its own careful card.
- Open redirect, host-header injection in password-reset links, SSTI engine-specific escapes, XXE, NoSQL injection, GraphQL introspection/abuse, mass assignment.

## 7. Acceptance criteria

- All fifteen cards pass the HC-KB-01 validator, including taxonomy resolution of every non-`# verify` id and the clearing of each `# verify` placeholder.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- The four tier-2 cards refuse to run without a live snapshot, and restore cleanly after.
- The brute-force and cache cards never cause a scope or egress violation, confirmed by the audit log.
- The chain in section 4 executes: a confirmed `credential` enables the authz cards that require `authenticated_session`.

## 8. Open questions

- XSS execution confirmation leans on Laya (`laya:success_signal`) plus a real browser; decide the deterministic fallback when Laya is unavailable (likely a headless-DOM execution assertion).
- Whether IDOR/BFLA need the harness to provision two seeded accounts (A and B) as a standard range fixture; leaning yes, as a reusable fixture.
- Cache-poisoning and request-smuggling interact; sequence smuggling (backlog) after this set stabilizes.
- Confirm the `# verify` taxonomy ids (cache poisoning CWE, several ATT&CK mappings for authz/protocol) during card authoring.
