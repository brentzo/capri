---
tag: HC-KB-11
title: Mobile and local-IPC technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01, HC-MOB-01]
updated: 2026-11-08
---

# HC-KB-11 - Mobile and local-IPC technique-card starter set

## 1. Purpose

Ten cards for the `mobile-local-ipc` class, authored against the HC-KB-01 schema, completing the ten-class knowledge base (HC-KB-01 §7).
It covers mobile-app and local inter-process surfaces: deep links, exported components, intent redirection, local storage, the WebView bridge, cleartext traffic, local IPC sockets, backups, content-provider injection, and tapjacking.

Each card ships as its own YAML file under `kb/mobile-local-ipc/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Scope and determinism for a mobile and local-IPC target

- The target is an instrumented app in an emulator plus its exposed local surfaces, modeled on the range (no internet); cards that require the instrumented-app fixture are called out in section 6.
- Component and link abuse is proven by a deterministic `oob_callback` or an observed component invocation: a deep link, forwarded intent, or WebView bridge call reaches `range-oob`, or an unauthorized caller drives a component the harness observes.
- Local data exposure is a planted canary read from storage, a backup, a content provider, or the cleartext wire via the range proxy, a deterministic `content_match`.
- The class uses no `laya:` evaluator; every signal is a canary, an OOB callback, an observed invocation, or a deterministic oracle.
- The one state-changing card (an unauthorized caller invoking a privileged exported component) is tier 2 and snapshots first.

## 3. Coverage map

| Card | Family | CWE | OWASP Mobile | Tier | Signal | Yields |
|------|--------|-----|--------------|------|--------|--------|
| KB-MOBILE-LINK-DEEPLINK-001 | Link handling | CWE-939 | M4:2024 # verify | 1 | oob_callback | deeplink_abuse |
| KB-MOBILE-LINK-INTENT-001 | Link handling | CWE-927 | M8:2024 # verify | 1 | oob_callback | intent_redirect |
| KB-MOBILE-COMP-EXPORTED-001 | Component | CWE-926 | M8:2024 # verify | 2 | state_change | component_abuse |
| KB-MOBILE-COMP-PROVIDER-SQLI-001 | Component | CWE-89 | M4:2024 # verify | 1 | content_match | db_read |
| KB-MOBILE-IPC-SOCKET-001 | Local IPC | CWE-306 | M8:2024 # verify | 1 | content_match | local_ipc_access |
| KB-MOBILE-IPC-WEBVIEW-001 | Local IPC | CWE-749 | M4:2024 # verify | 1 | oob_callback | bridge_exec |
| KB-MOBILE-STORAGE-LOCAL-001 | Storage | CWE-312 | M9:2024 # verify | 1 | content_match | token_exposure |
| KB-MOBILE-STORAGE-BACKUP-001 | Storage | CWE-530 | M9:2024 # verify | 1 | content_match | data_exposure |
| KB-MOBILE-NET-CLEARTEXT-001 | Network | CWE-319 | M5:2024 # verify | 1 | content_match | traffic_intercept |
| KB-MOBILE-REDRESS-TAPJACK-001 | UI redress | CWE-1021 | M8:2024 # verify | 1 | content_match | ui_redress |

Tier distribution: nine tier-1 (read-only probing and observation) and one tier-2, the privileged exported-component invocation, which changes state and so snapshots first.

## 4. Cards

### 4.1 Link-handling family

```yaml
id: KB-MOBILE-LINK-DEEPLINK-001
title: Deep link reaches a sensitive action without validation
taxonomy: { owasp: [M4:2024], cwe: [CWE-939] }
applicability: [ 'asset.type == "mobile_app"', 'asset.has_deep_link == true' ]
preconditions: [ reachable, mobile_app, has_deep_link ]
yields_on_success: [ deeplink_abuse ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: invoke_deeplink, args: { action: fetch, collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=app) driven by an unvalidated deep link" }
severity_rubric: { base: high }
```

```yaml
id: KB-MOBILE-LINK-INTENT-001
title: Intent redirection (confused deputy via a forwarded intent)
taxonomy: { owasp: [M8:2024], cwe: [CWE-927, CWE-441] }
applicability: [ 'asset.type == "mobile_app"' ]
preconditions: [ reachable, mobile_app ]
yields_on_success: [ intent_redirect ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: supply_redirected_intent, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "the app forwards an attacker-supplied intent that reaches range-oob" }
severity_rubric: { base: high }
```

### 4.2 Component family

```yaml
id: KB-MOBILE-COMP-EXPORTED-001
title: Exported component invokable by an unauthorized caller
taxonomy: { owasp: [M8:2024], cwe: [CWE-926, CWE-862] }
applicability: [ 'asset.type == "mobile_app"', 'exists(asset.exported_components)' ]
preconditions: [ reachable, mobile_app, exported_component ]
yields_on_success: [ component_abuse ]
blast_tier: 2                      # drives a privileged, state-changing component
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.mobile_probe, intent: invoke_exported_component, args: { marker: exported_canary } }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "an unauthorized caller drives the component to set exported_canary" }
severity_rubric: { base: high }
```

```yaml
id: KB-MOBILE-COMP-PROVIDER-SQLI-001
title: Content-provider SQL injection
taxonomy: { owasp: [M4:2024], cwe: [CWE-89] }
applicability: [ 'asset.type == "mobile_app"', 'exists(asset.exported_components)' ]
preconditions: [ reachable, mobile_app, exported_component ]
yields_on_success: [ db_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: provider_injection, args: { oracle: true } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "db_error_fingerprint(resp) OR boolean_oracle_divergence(baseline, resp) via the provider" }
severity_rubric: { base: high }
```

### 4.3 Local-IPC family

```yaml
id: KB-MOBILE-IPC-SOCKET-001
title: Unauthenticated local IPC socket
taxonomy: { owasp: [M8:2024], cwe: [CWE-306, CWE-200] }
applicability: [ 'asset.type == "local_ipc"' ]
preconditions: [ reachable, local_ipc ]
yields_on_success: [ local_ipc_access ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.ipc_probe, intent: connect_local_socket, args: { canary: ipc_canary } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an unauthenticated local socket (unix/abstract/localhost) returns ipc_canary" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.db_read", to: high } ] }
```

```yaml
id: KB-MOBILE-IPC-WEBVIEW-001
title: WebView JavaScript bridge exposes native methods
taxonomy: { owasp: [M4:2024], cwe: [CWE-749] }
applicability: [ 'asset.type == "mobile_app"', 'asset.has_webview_bridge == true' ]
preconditions: [ reachable, mobile_app ]
yields_on_success: [ bridge_exec ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: load_untrusted_content_and_call_bridge, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "web content loaded in the WebView calls a native bridge method that reaches range-oob" }
severity_rubric: { base: high }
```

### 4.4 Storage family

```yaml
id: KB-MOBILE-STORAGE-LOCAL-001
title: Sensitive data in insecure local storage
taxonomy: { owasp: [M9:2024], cwe: [CWE-312, CWE-922] }
applicability: [ 'asset.type == "mobile_app"' ]
preconditions: [ reachable, mobile_app ]
yields_on_success: [ token_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: read_app_local_storage }   # shared prefs / unencrypted db / world-readable file
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a token or PII storage_canary is present unencrypted in app-local storage" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.traffic_intercept", to: high } ] }
```

```yaml
id: KB-MOBILE-STORAGE-BACKUP-001
title: App data extractable via backup
taxonomy: { owasp: [M9:2024], cwe: [CWE-530, CWE-312] }
applicability: [ 'asset.type == "mobile_app"', 'asset.backup_allowed == true' ]
preconditions: [ reachable, mobile_app ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: extract_app_backup }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an app backup is extractable and carries the backup_canary" }
severity_rubric: { base: medium }
```

### 4.5 Network and UI-redress family

```yaml
id: KB-MOBILE-NET-CLEARTEXT-001
title: Cleartext traffic or missing TLS validation
taxonomy: { owasp: [M5:2024], cwe: [CWE-319] }
applicability: [ 'asset.type == "mobile_app"' ]
preconditions: [ reachable, mobile_app ]
yields_on_success: [ traffic_intercept ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: observe_traffic_via_range_proxy, args: { canary: wire_canary } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a sensitive wire_canary is sent in cleartext or the app accepts a range-proxy certificate" }
severity_rubric: { base: high }
false_positive_notes: [ "Interception happens only through the in-range proxy; there is no internet path, so this never leaves scope." ]
```

```yaml
id: KB-MOBILE-REDRESS-TAPJACK-001
title: Tapjacking on a sensitive action (overlay permitted)
taxonomy: { owasp: [M8:2024], cwe: [CWE-1021] }
applicability: [ 'asset.type == "mobile_app"', 'asset.has_sensitive_action == true' ]
preconditions: [ reachable, mobile_app ]
yields_on_success: [ ui_redress ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.mobile_probe, intent: overlay_and_target_action }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "the sensitive action lacks overlay protection and is operable beneath an overlay" }
severity_rubric: { base: medium, raise_if: [ { when: "asset.auth_context", to: high } ] }
```

## 5. Chaining in this set

- `KB-MOBILE-LINK-DEEPLINK-001` and `KB-MOBILE-LINK-INTENT-001` yield link and intent abuse that reach `KB-MOBILE-IPC-WEBVIEW-001`'s `bridge_exec` and `KB-MOBILE-COMP-EXPORTED-001`'s `component_abuse`, the mobile analog of the client-side injection-to-execution chain.
- `KB-MOBILE-STORAGE-LOCAL-001` yields `token_exposure` and `KB-MOBILE-NET-CLEARTEXT-001` yields `traffic_intercept`, which together demonstrate session theft and feed the HC-KB-02 auth chain (a stolen token becomes an `authenticated_session`).
- `KB-MOBILE-COMP-PROVIDER-SQLI-001` yields `db_read`, the same fact the web SQLi card produces, so the mobile backend and the web backend share a credential chain.
- `KB-MOBILE-IPC-SOCKET-001` yields `local_ipc_access`, a lateral foothold that raises when it reaches a database or privileged service.

## 6. Seed targets and fixtures

v1 stands up an instrumented mobile app in an emulator plus its local surfaces on the range (no internet): a deep-link handler and an intent forwarder that reach `range-oob`, a privileged exported component with an `exported_canary`, an injectable content provider, an unauthenticated local IPC socket with an `ipc_canary`, a WebView with an over-exposed native bridge, insecure local storage and an extractable backup carrying canaries, an app that sends a `wire_canary` in cleartext through the range proxy, and a sensitive action with no overlay protection.
The content-provider, socket, backup, and cleartext cards can run against the local surfaces directly; the deep-link, intent, exported-component, WebView, storage, and tapjacking cards require the instrumented-app emulator fixture.
Each `does_not_fire` fixture applies the control: validated deep links, explicit intents, non-exported or permission-guarded components, parameterized provider queries, authenticated IPC, a restricted bridge allowlist, encrypted storage with backups disabled, TLS with pinning, and overlay protection on sensitive actions.
Probing uses `custom.mobile_probe` and `custom.ipc_probe`, reviewed allowlist adapters (HC-AGENT-01 §5.3); all link, intent, bridge, and traffic proofs stay range-local and terminate at `range-oob` or the range proxy.

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including taxonomy resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- The exported-component card refuses to run without a live snapshot and restores cleanly.
- No card causes a scope or egress violation; link, intent, bridge, and traffic proofs stay range-local and terminate at `range-oob` or the range proxy, confirmed by the audit log.
- The chain in section 5 executes: a deep link reaches the WebView bridge, and local-storage plus cleartext interception demonstrate session theft into the auth chain.
- All signals are deterministic; the class uses no `laya:` evaluator.

## 8. Open questions

- Emulator fidelity and cost: how much of the instrumented-app surface to model in an emulator versus a lighter local-service stand-in, given the emulator fixture is heavier than the rest of the KB.
- Platform coverage: the cards are written platform-neutrally, but a fixture must pick a concrete platform (Android-style components, iOS-style URL schemes) and the taxonomy should follow.
- Whether mobile deserves OWASP MASVS/MASTG as a first-class grounding source in the HC-KB-01 taxonomy alongside WSTG, once this class stabilizes.
- How local-IPC cards generalize to desktop and host-local services, which share the unauthenticated-socket and bridge patterns but are not strictly mobile.

## 9. Backlog (deferred from this set)

- Runtime manipulation and anti-tampering bypass (hooking, repackaging), which overlap the binary class and need an instrumented runtime.
- Biometric and keystore misuse, and secure-enclave assumptions.
- Push-notification and deep-link token leakage across the app lifecycle.
- Accessibility-service abuse as a privilege and overlay vector.
- Cross-app content sharing and clipboard exposure as dedicated cards once the emulator fixture is standardized.
