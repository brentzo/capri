---
tag: HC-KB-04
title: Client-side technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-04 - Client-side technique-card starter set

## 1. Purpose

The third concrete card set: ten cards for the `client-side` class, authored against the HC-KB-01 schema.
It covers weaknesses that live in the browser (the DOM, cross-document messaging, UI redress, client storage), which the web class (HC-KB-02) deliberately left to the server side.
It leans on the Playwright browser adapter already specified in HC-AGENT-01 §5.3.

Each card ships as its own YAML file under `kb/client-side/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Determinism for a browser target

Client-side success is proven in a real browser, not inferred from a response body:

- Script execution is asserted in a headless DOM (Playwright): a planted marker runs, it is not merely reflected as text, the same proof HC-KB-02 uses for XSS.
- Header-level weaknesses (clickjacking, weak CSP, open redirect) are deterministic parses of response headers plus a framability or redirect observation.
- Cross-origin trust failures (postMessage, WebSocket, CORS) are proven by driving a message or handshake from a controlled untrusted origin on the range and observing the target act on it.

Only the execution judgment itself ("did the marker truly execute versus render") uses `laya:success_signal`, with a headless-DOM assertion as the deterministic fallback (HC-KB-02 §8); every lead is independently verified regardless (HC-FIND-01).

## 3. Coverage map

| Card | Family | CWE | OWASP | ATT&CK | Tier | Signal | Yields |
|------|--------|-----|-------|--------|------|--------|--------|
| KB-CLIENT-DOM-XSS-001 | DOM injection | CWE-79 | WSTG-CLNT-01 | T1059.007 # verify | 1 | content_match | client_exec |
| KB-CLIENT-DOM-CLOBBER-001 | DOM injection | CWE-79 | WSTG-CLNT-01 # verify | - | 1 | differential | dom_override |
| KB-CLIENT-PROTO-POLLUTE-001 | Prototype pollution | CWE-1321 | WSTG-CLNT-13 # verify | - | 1 | differential | proto_pollution |
| KB-CLIENT-MSG-POSTMSG-001 | Cross-document messaging | CWE-345 | WSTG-CLNT-11 # verify | - | 1 | differential | cross_origin_exec |
| KB-CLIENT-REDRESS-CLICKJACK-001 | UI redress | CWE-1021 | WSTG-CLNT-09 | - | 1 | content_match | ui_redress |
| KB-CLIENT-REDIRECT-OPEN-001 | Redirection | CWE-601 | WSTG-CLNT-04 | - | 1 | status_match | open_redirect |
| KB-CLIENT-CSRF-001 | Request forgery | CWE-352 | WSTG-SESS-05 | - | 2 | differential | csrf_action |
| KB-CLIENT-STORAGE-TOKEN-001 | Client storage | CWE-922 # verify | WSTG-CLNT-12 # verify | - | 1 | content_match | token_exposure |
| KB-CLIENT-WS-HIJACK-001 | WebSocket | CWE-345 | WSTG-CLNT-10 # verify | - | 1 | differential | cross_origin_read |
| KB-CLIENT-CSP-WEAK-001 | Policy | CWE-693 | WSTG-CLNT-12 # verify | - | 1 | content_match | csp_weak |

Tier distribution: nine tier-1 (read-only probing and observation) and one tier-2, CSRF, which performs a state-changing cross-origin request and so snapshots first.

## 4. Cards

### 4.1 DOM injection family

```yaml
id: KB-CLIENT-DOM-XSS-001
title: DOM-based cross-site scripting via a dangerous sink
taxonomy: { attack: {technique: T1059.007}, owasp: [WSTG-CLNT-01], cwe: [CWE-79] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.renders_html == true' ]
preconditions: [ reachable ]
yields_on_success: [ client_exec ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.client_probe, intent: seed_marker_into_source }   # URL fragment / param that reaches a sink
  - { tool: browser.playwright, intent: observe_execution }
success_signal: { type: content_match, evaluator: "laya:success_signal",
                  assert: "marker executed in DOM via a client-side sink, not server-reflected" }
severity_rubric: { base: high, raise_if: [ { when: "yields.token_exposure", to: critical } ] }
false_positive_notes: [ "Distinguish a DOM sink from a server reflection; the payload must never reach the server, as in KB-WEB-INJ-XSS-001." ]
```

```yaml
id: KB-CLIENT-DOM-CLOBBER-001
title: DOM clobbering overrides a script-referenced global
taxonomy: { owasp: [WSTG-CLNT-01], cwe: [CWE-79] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.allows_named_markup == true' ]
preconditions: [ reachable ]
yields_on_success: [ dom_override ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.client_probe, intent: inject_named_elements }     # id/name collides with a global the code reads
  - { tool: browser.playwright, intent: observe_overridden_reference }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "a script-read global resolves to the injected element instead of its intended value" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.client_exec", to: high } ] }
```

```yaml
id: KB-CLIENT-PROTO-POLLUTE-001
title: Client-side prototype pollution via unsafe merge
taxonomy: { owasp: [WSTG-CLNT-13], cwe: [CWE-1321] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.renders_html == true' ]
preconditions: [ reachable ]
yields_on_success: [ proto_pollution ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.client_probe, intent: pollute_proto_via_query, args: { path: "__proto__.marker", value: polluted } }
  - { tool: browser.playwright, intent: observe_gadget }             # a known sink reads Object.prototype.marker
success_signal: { type: differential, evaluator: deterministic,
                  assert: "Object.prototype.marker is set AND a page gadget observably consumes it" }
severity_rubric: { base: high }
false_positive_notes: [ "Pollution without a reachable gadget is a hardening note; require an observed gadget to call it a finding." ]
```

### 4.2 Cross-origin trust family

```yaml
id: KB-CLIENT-MSG-POSTMSG-001
title: postMessage handler without an origin check
taxonomy: { owasp: [WSTG-CLNT-11], cwe: [CWE-345] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_message_listener == true' ]
preconditions: [ reachable ]
yields_on_success: [ cross_origin_exec ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: browser.playwright, intent: post_message_from_foreign_origin, args: { origin: "https://evil.range.local" } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "the handler acts on a message from an untrusted origin (state change or sink reached)" }
severity_rubric: { base: high }
```

```yaml
id: KB-CLIENT-WS-HIJACK-001
title: Cross-site WebSocket hijacking (handshake origin not validated)
taxonomy: { owasp: [WSTG-CLNT-10], cwe: [CWE-345] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_websocket == true' ]
preconditions: [ reachable ]
yields_on_success: [ cross_origin_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.client_probe, intent: ws_handshake_foreign_origin, args: { origin: "https://evil.range.local" } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "the socket is established for a foreign Origin and returns session-bound data" }
severity_rubric: { base: high }
```

### 4.3 UI redress and redirection family

```yaml
id: KB-CLIENT-REDRESS-CLICKJACK-001
title: Clickjacking on a sensitive action (missing frame-ancestors / XFO)
taxonomy: { owasp: [WSTG-CLNT-09], cwe: [CWE-1021] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_state_changing_action == true' ]
preconditions: [ reachable ]
yields_on_success: [ ui_redress ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx, intent: fetch_headers }
  - { tool: browser.playwright, intent: frame_and_target_action }    # can the action be reached inside a frame
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "no frame-ancestors/X-Frame-Options AND the action is operable inside a cross-origin frame" }
severity_rubric: { base: medium, raise_if: [ { when: "asset.auth_context", to: high } ] }
```

```yaml
id: KB-CLIENT-REDIRECT-OPEN-001
title: Open redirect via an unvalidated redirect parameter
taxonomy: { owasp: [WSTG-CLNT-04], cwe: [CWE-601] }
applicability: [ 'asset.type == "http_endpoint"', 'matches(asset.params, /url|next|dest|return|redirect/)' ]
preconditions: [ reachable ]
yields_on_success: [ open_redirect ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx, intent: redirect_to_foreign_origin, args: { value: "https://evil.range.local" } }
success_signal: { type: status_match, evaluator: deterministic,
                  assert: "a 3xx Location or a client-side redirect points to the attacker-controlled origin" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.token_exposure", to: high } ] }
false_positive_notes: [ "A redirect confined to the same origin or an allowlist is not open; require the foreign origin to be honored." ]
```

### 4.4 Request forgery and storage family

```yaml
id: KB-CLIENT-CSRF-001
title: Cross-site request forgery on a state-changing endpoint
taxonomy: { owasp: [WSTG-SESS-05], cwe: [CWE-352] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_state_changing_action == true' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ csrf_action ]
blast_tier: 2                      # performs a state-changing request cross-origin
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.client_probe, intent: forge_cross_origin_request }   # no token, rely on ambient cookies
  - { tool: custom.client_probe, intent: confirm_state_marker }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "the state change completes without an anti-CSRF token and without SameSite protection" }
severity_rubric: { base: high }
```

```yaml
id: KB-CLIENT-STORAGE-TOKEN-001
title: Sensitive token or PII in web storage reachable by script
taxonomy: { owasp: [WSTG-CLNT-12], cwe: [CWE-922] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.uses_web_storage == true' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ token_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: browser.playwright, intent: read_local_and_session_storage }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a session token or PII canary is present in localStorage/sessionStorage" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.client_exec", to: high } ] }
false_positive_notes: [ "Severity depends on an execution path to read it; pair with DOM-XSS to demonstrate theft." ]
```

### 4.5 Policy family

```yaml
id: KB-CLIENT-CSP-WEAK-001
title: Missing or bypassable Content-Security-Policy
taxonomy: { owasp: [WSTG-CLNT-12], cwe: [CWE-693] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.renders_html == true' ]
preconditions: [ reachable ]
yields_on_success: [ csp_weak ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx, intent: fetch_csp_header }
  - { tool: browser.playwright, intent: attempt_inline_marker }      # does injected inline script run under the CSP
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "CSP is absent or allows unsafe-inline AND an injected inline marker executes" }
severity_rubric: { base: low, raise_if: [ { when: "yields.client_exec", to: medium } ] }
false_positive_notes: [ "On its own a weak CSP is a hardening note; it becomes a finding only when it lets a marker execute." ]
```

## 5. Chaining in this set

- `KB-CLIENT-PROTO-POLLUTE-001` yields `proto_pollution`, whose gadget can reach a script sink and drive `KB-CLIENT-DOM-XSS-001` (`client_exec`).
- `KB-CLIENT-MSG-POSTMSG-001` yields `cross_origin_exec`, another route into `client_exec` when direct DOM injection is filtered.
- `KB-CLIENT-DOM-XSS-001` yields `client_exec`, which turns `KB-CLIENT-STORAGE-TOKEN-001`'s `token_exposure` into demonstrable token theft (the storage card's severity raise).
- `KB-CLIENT-REDIRECT-OPEN-001` yields `open_redirect`, a step in an OAuth-token or credential-phishing chain, raised when paired with `token_exposure`.
- `KB-CLIENT-CSRF-001` consumes `authenticated_session` from the HC-KB-02 auth chain, so a confirmed session unlocks the forged state change.

## 6. Seed targets and fixtures

v1 stands up a deliberately vulnerable single-page app on the range (no internet), reusing the Juice-Shop-style and DVWA-style client surfaces (HC-KB-02 §5) plus purpose-built micro-pages per card: a fragment-to-sink page, a named-markup page, an unsafe client-side merge, a no-origin-check postMessage listener, a framable sensitive action, an open-redirect endpoint, a CSRF-vulnerable form, tokens written to localStorage, a WebSocket endpoint that ignores Origin, and a page with no CSP.
Each card's `does_not_fire` fixture applies the correct control: an allowlist origin check, frame-ancestors/XFO, SameSite plus an anti-CSRF token, HttpOnly cookies instead of web storage, and a strict nonce-based CSP.
A controlled attacker origin (`evil.range.local`) is a second vhost on the range used by the postMessage, WebSocket, clickjacking, and redirect cards; it never egresses.
Probing runs through `browser.playwright` and `custom.client_probe`; both are reviewed allowlist adapters (HC-AGENT-01 §5.3), never a general browser-exec primitive.

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including WSTG and CWE resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01, with execution asserted in a real headless DOM.
- The CSRF card refuses to run without a live snapshot and restores cleanly.
- No card causes a scope or egress violation; the attacker-origin interactions stay within the range, confirmed by the audit log.
- The chain in section 5 executes: prototype pollution or postMessage reaches `client_exec`, which demonstrates web-storage token theft.
- Header and framability signals are evaluated deterministically by the harness; only DOM-execution judgment uses `laya:success_signal`, with a headless-DOM fallback.

## 8. Open questions

- DOM-execution confirmation reuses the HC-KB-02 XSS pattern; decide whether the headless-DOM assertion fully replaces `laya:success_signal` here, since client-side sinks are often cleaner to assert than reflected XSS.
- Whether the attacker-origin vhost (`evil.range.local`) and a reusable CSRF/clickjacking harness page should be standard range fixtures alongside the two seeded accounts and `range-oob`.
- SameSite default behavior varies by browser; pin the Playwright browser and version so CSRF fixtures are deterministic.
- How much client-side state (service workers, IndexedDB) to model before this class needs richer target metadata.

## 9. Backlog (deferred from this set)

- Service-worker and cache poisoning on the client, and IndexedDB exposure.
- Tabnabbing and `window.opener` abuse via `target=_blank`.
- CSS injection and style-based data exfiltration.
- Client-side request smuggling and browser-parser differentials, sequenced after the server-side smuggling card (HC-KB-02 backlog).
- WebRTC IP/leak probes, deferred because they interact with the egress-denied topology and need careful in-range framing.
