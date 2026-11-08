---
tag: HC-KB-10
title: Memory and binary technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-10 - Memory and binary technique-card starter set

## 1. Purpose

Ten cards for the `memory-binary` class, authored against the HC-KB-01 schema.
It covers memory-safety defects in native network services and binaries: overflows, use-after-free, type confusion, out-of-bounds reads, format strings, null dereference, races, and argument injection.

Each card ships as its own YAML file under `kb/memory-binary/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Scope and determinism for a binary target (read first)

This class is deliberately scoped to confirming a memory-safety defect, not to developing a weaponized exploit:

- The target is a native service on the range, built in the eval fixture with sanitizers (ASan, UBSan). A memory error produces a deterministic diagnostic (`heap-buffer-overflow`, `use-after-free`, ...), which the harness matches as a `state_change` signal, the same way a canary proves a leak elsewhere.
- A crash is observed deterministically as the service process dying and being restarted by the supervisor, again a `state_change`.
- Information leaks are proven by a planted canary in adjacent memory: an out-of-bounds read or a format string that returns the `mem_canary` is a deterministic `content_match`.
- The finding is "this input corrupts memory / crashes / leaks," proven by the sanitizer, crash, or canary. The agent does not build a ROP chain, shellcode, or a reliable control-flow hijack; weaponization to full code execution is out of scope for v1 and is a deferred, separately gated capability (section 9).
- These cards crash or corrupt the target, so the memory-corruption and crash cards are tier 2 and snapshot first; the defect stays contained by HC-SUB-01 G4.

## 3. Coverage map

| Card | Family | CWE | ATT&CK | Tier | Signal | Yields |
|------|--------|-----|--------|------|--------|--------|
| KB-BIN-OVERFLOW-STACK-001 | Overflow | CWE-121 | T1203 # verify | 2 | state_change | memory_corruption |
| KB-BIN-OVERFLOW-HEAP-001 | Overflow | CWE-122 | T1203 # verify | 2 | state_change | memory_corruption |
| KB-BIN-OVERFLOW-INT-001 | Overflow | CWE-190 | T1203 # verify | 2 | state_change | memory_corruption |
| KB-BIN-UAF-001 | Lifetime | CWE-416 | T1203 # verify | 2 | state_change | memory_corruption |
| KB-BIN-TYPECONF-001 | Lifetime | CWE-843 | T1203 # verify | 2 | state_change | memory_corruption |
| KB-BIN-OOBREAD-001 | Disclosure | CWE-125 | T1203 # verify | 1 | content_match | info_leak |
| KB-BIN-FORMATSTR-001 | Disclosure | CWE-134 | T1203 # verify | 1 | content_match | info_leak |
| KB-BIN-NULLDEREF-001 | Availability | CWE-476 | T1499.004 # verify | 2 | state_change | service_crash |
| KB-BIN-RACE-TOCTOU-001 | Concurrency | CWE-367 | T1203 # verify | 2 | differential | race_corruption |
| KB-BIN-ARGV-INJECT-001 | Process | CWE-88 | T1059 # verify | 1 | oob_callback | rce_foothold |

Tier distribution: three tier-1 (read-only leak and argument-injection proofs) and seven tier-2 (memory corruption or crash, snapshot required).

## 4. Cards

### 4.1 Overflow family

```yaml
id: KB-BIN-OVERFLOW-STACK-001
title: Stack buffer overflow in a native service
taxonomy: { attack: {technique: T1203}, cwe: [CWE-121, CWE-787] }
applicability: [ 'asset.type == "native_service"' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ memory_corruption ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: oversized_field, args: { field: name, len: 4096 } }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "sanitizer reports stack-buffer-overflow OR the service crashes and restarts" }
severity_rubric: { base: high, raise_if: [ { when: "yields.rce_foothold", to: critical } ] }
false_positive_notes: [ "A graceful input-length rejection is not a finding; require a sanitizer diagnostic or an observed crash." ]
```

```yaml
id: KB-BIN-OVERFLOW-HEAP-001
title: Heap buffer overflow
taxonomy: { attack: {technique: T1203}, cwe: [CWE-122, CWE-787] }
applicability: [ 'asset.type == "native_service"' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ memory_corruption ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: heap_overflow_input }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "sanitizer reports heap-buffer-overflow OR the service crashes" }
severity_rubric: { base: high }
```

```yaml
id: KB-BIN-OVERFLOW-INT-001
title: Integer overflow leads to undersized allocation
taxonomy: { attack: {technique: T1203}, cwe: [CWE-190] }
applicability: [ 'asset.type == "native_service"', 'asset.reads_size_field == true' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ memory_corruption ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: wraparound_size_then_write }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "a wrapped size produces an undersized buffer and sanitizer reports an overflow" }
severity_rubric: { base: high }
```

### 4.2 Lifetime family

```yaml
id: KB-BIN-UAF-001
title: Use-after-free
taxonomy: { attack: {technique: T1203}, cwe: [CWE-416] }
applicability: [ 'asset.type == "native_service"' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ memory_corruption ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: free_then_reuse_sequence }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "sanitizer reports heap-use-after-free on the reuse step" }
severity_rubric: { base: high }
```

```yaml
id: KB-BIN-TYPECONF-001
title: Type confusion in a native parser
taxonomy: { attack: {technique: T1203}, cwe: [CWE-843] }
applicability: [ 'asset.type == "native_service"', 'asset.parses_tagged_union == true' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ memory_corruption ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: mismatched_type_tag }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "a confused type is dereferenced and sanitizer reports an invalid access" }
severity_rubric: { base: high }
```

### 4.3 Disclosure family

```yaml
id: KB-BIN-OOBREAD-001
title: Out-of-bounds read discloses adjacent memory
taxonomy: { attack: {technique: T1203}, cwe: [CWE-125] }
applicability: [ 'asset.type == "native_service"' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ info_leak ]
blast_tier: 1                      # read-only over-read, no corruption
cleanup: none
probe_steps:
  - { tool: custom.bin_probe, intent: over_read_length, args: { declared_len: 65535 } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "the response returns the adjacent mem_canary beyond the intended bounds" }
severity_rubric: { base: high }
```

```yaml
id: KB-BIN-FORMATSTR-001
title: Format-string information leak
taxonomy: { attack: {technique: T1203}, cwe: [CWE-134] }
applicability: [ 'asset.type == "native_service"', 'asset.reflects_user_format == true' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ info_leak ]
blast_tier: 1                      # read-only leak via conversion specifiers, no %n write
cleanup: none
probe_steps:
  - { tool: custom.bin_probe, intent: conversion_specifier_leak }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "format specifiers return stack memory containing the mem_canary" }
severity_rubric: { base: high }
false_positive_notes: [ "The probe uses read specifiers only; a %n write path would be a separate, higher-tier card." ]
```

### 4.4 Availability and concurrency family

```yaml
id: KB-BIN-NULLDEREF-001
title: Null or invalid pointer dereference crash
taxonomy: { attack: {technique: T1499.004}, cwe: [CWE-476] }
applicability: [ 'asset.type == "native_service"' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ service_crash ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: trigger_null_path }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "the input drives a null/invalid dereference and the service crashes and restarts" }
severity_rubric: { base: medium }
```

```yaml
id: KB-BIN-RACE-TOCTOU-001
title: Time-of-check to time-of-use race (double fetch)
taxonomy: { attack: {technique: T1203}, cwe: [CWE-367, CWE-362] }
applicability: [ 'asset.type == "native_service"', 'asset.double_fetches == true' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ race_corruption ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.bin_probe, intent: concurrent_mutate_between_check_and_use, args: { trials: 100 } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "across trials a value validated at check differs at use, with a sanitizer or state divergence" }
severity_rubric: { base: high }
false_positive_notes: [ "Require a reproducible divergence across trials, not a single racy sample." ]
```

### 4.5 Process family

```yaml
id: KB-BIN-ARGV-INJECT-001
title: Argument or environment injection into a native subprocess
taxonomy: { attack: {technique: T1059}, cwe: [CWE-88] }
applicability: [ 'asset.type == "native_service"', 'asset.spawns_subprocess == true' ]
preconditions: [ reachable, native_service ]
yields_on_success: [ rce_foothold ]
blast_tier: 1                      # read-only proof: injected arg drives an OOB callback
cleanup: none
probe_steps:
  - { tool: custom.bin_probe, intent: inject_argument, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=subprocess)" }
severity_rubric: { base: critical }
# collaborator MUST be the in-sandbox listener; external would fail HC-KB-01 validation
```

## 5. Chaining in this set

- The overflow, use-after-free, and type-confusion cards yield `memory_corruption`, which is the precursor to `rce_foothold`; v1 stops at confirming corruption, so the chain to execution is noted but not walked (section 2, section 9).
- `KB-BIN-ARGV-INJECT-001` yields `rce_foothold` directly and deterministically, feeding the HC-KB-05 container-escape chain the same way the web command-injection card does.
- `KB-BIN-OOBREAD-001` and `KB-BIN-FORMATSTR-001` yield `info_leak`, which can disclose addresses or secrets that raise the severity of a co-located corruption finding (defeating ASLR is the classic pairing, left as a deferred escalation).

## 6. Seed targets and fixtures

v1 stands up purpose-built native services on the range (no internet), each compiled twice: a vulnerable build with the defect and sanitizers enabled, and a patched build for the negative fixture.
The vulnerable builds plant a `mem_canary` adjacent to the over-readable buffer and the format-string stack frame, and the argument-injection service spawns a subprocess reachable to `range-oob`.
Each `does_not_fire` fixture applies the control: bounds checks, safe allocators and lifetime discipline, validated type tags, fixed format strings, null checks, atomic check-and-use, and argument escaping or an allowlist.
The eval fixture runs these services under a supervisor that records crashes and sanitizer diagnostics, which is what makes the `state_change` signal deterministic.
Probing uses `custom.bin_probe` and `nmap`, reviewed allowlist adapters (HC-AGENT-01 §5.3); the argument-injection proof terminates only at `range-oob`.

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including taxonomy resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01, with the sanitizer or crash supervisor providing the signal.
- The seven tier-2 cards refuse to run without a live snapshot and restore the crashed or corrupted service cleanly.
- No card attempts weaponized control-flow hijack; a confirmed finding is a sanitizer diagnostic, a crash, or a canary leak, never a shell.
- No card causes a scope or escape violation; the corruption stays contained by HC-SUB-01 G4 and the argument-injection OOB terminates at `range-oob`, confirmed by the audit log.
- All signals are deterministic; the class uses no `laya:` evaluator.

## 8. Open questions

- Sanitizer dependence: production targets are rarely sanitizer-built, so decide how to confirm memory safety on a stripped release binary (crash-only oracle, lighter instrumentation, or a core-dump analysis step).
- Whether a crash-only signal is strong enough to call a finding without a sanitizer, given a crash may be a benign assertion rather than memory unsafety.
- Fuzzing integration: whether the Operator drives a coverage-guided fuzzer as a probe step for these cards, and how to keep that within the per-pair budget.
- How to express binary-defect severity in CVSS when exploitability (the step v1 does not take) dominates the real score.

## 9. Backlog (deferred from this set)

- Exploit development to control-flow hijack (ROP, shellcode, heap grooming), a separately gated capability well beyond authorized-finding confirmation.
- Kernel and driver memory safety, needing a different target model than a userspace network service.
- Information-leak-to-corruption chaining (ASLR/stack-canary defeat) as an explicit escalation once single-defect confirmation is stable.
- Uninitialized-memory disclosure and double-free as distinct cards.
- Speculative-execution and microarchitectural side channels, out of scope for a network-reachable black-box agent.
