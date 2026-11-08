---
tag: HC-MODEL-02
title: Laya decision layer and fine-tuning pipeline
status: draft
parent: SPEC.md#5.2, SPEC.md#10
depends_on: [HC-MODEL-01, HC-DATA-01, HC-EVAL-01, HC-KB-01]
depended_on_by: [HC-AGENT-01, HC-FIND-01]
updated: 2026-11-08
---

# HC-MODEL-02 - Laya decision layer and fine-tuning pipeline

## 1. Purpose

This spec defines the in-loop decision layer: what classification decisions Laya serves, how it is deployed off the Bifrost plane, the decision-point catalog, the zero-shot-first approach, the self-labeling flywheel, the targeted LoRA pipeline, and the calibration discipline that gates it.

Laya is a non-generative System One decision model: it emits a typed value plus a calibrated confidence, fast and cheap, and it cannot hallucinate free text.
It complements the LLM, it does not replace it; the LLM defines the decision, Laya executes the repeated structured part.

## 2. Why Laya, and where it sits

- Open-weights, self-hostable (Apache 2.0, ModernBERT-large English checkpoint), so it runs air-gapped inside the trust boundary and can be fine-tuned locally on sensitive evidence; hosted Jev can do neither, which is why Laya is the in-loop choice (SPEC.md#5.2).
- It sits on the raw-target-output boundary for success-signal triage, which shrinks the prompt-injection surface: a classifier emits a label, not an action, so attacker-influenced content cannot steer it.
- It is a local sidecar called directly by the harness over local RPC, off the Bifrost plane (HC-MODEL-01), because classify-not-chat I/O does not fit chat-completions.

```
harness ──local RPC──> Laya sidecar (self-hosted, no egress)
          classify(decision_point, input) -> { value, confidence, model_version }
```

"Laya" is really a family of small per-decision LoRA heads on one shared base; each decision point (section 3) is its own head.

## 3. Decision-point catalog

The finite set of classification tasks, each with a deterministic fallback so the system degrades gracefully.

| Decision point | Input | Output | Used by | Deterministic fallback |
|----------------|-------|--------|---------|------------------------|
| `success_signal` | baseline + probe response (parsed + raw) | hit / miss / ambiguous + confidence | HC-AGENT-01 signal_hit, HC-KB-01 `laya:` evaluators | the card's deterministic evaluator, or a headless-DOM assertion for XSS |
| `applicability` | card context + asset features | applicable / not + confidence | HC-AGENT-01 threat-model, HC-KB-01 §4 | the DSL predicate (most cases are already deterministic) |
| `severity_bucket` | finding evidence | info/low/med/high/crit + confidence | HC-FIND-01 §5 | the card `severity_rubric` |
| `lead_priority` | (asset, technique) features | score | HC-AGENT-01 Planner ordering | a static heuristic |

Deterministic-first rule holds: a decision point uses Laya only for the genuinely fuzzy cases; anything a rule can decide stays a rule (HC-KB-01 §5).

## 4. Zero-shot first

- Start with zero-shot classification against each decision point's label schema; decision models do this natively.
- Improve it without touching weights by curating the label definitions and a few exemplars per schema, the decision-model equivalent of prompt engineering.
- Establish a baseline against the HC-EVAL-01 seeded suite before any fine-tuning, because that baseline is what tells you whether fine-tuning is even worth the maintenance.

## 5. The self-labeling flywheel

- The independent Verifier produces a ground-truth label for every lead as a byproduct of the confirm/reject lifecycle (HC-FIND-01), written to HC-DATA-01 as `source: verifier, tier: silver`.
- Audits add `tier: gold` labels.
- Laya's own predictions are never written as labels (HC-DATA-01 §4.3), so the model cannot train on its own output.
- The training set is the HC-DATA-01 corpus export: train split, non-`eval_seed`, latest label, gold over silver.

## 6. Targeted fine-tuning pipeline

Fine-tune only where the baseline underperforms, per decision point, never one mega-model.

```
1. export    corpus.export(decision_point, split='train')          # HC-DATA-01, eval quarantined
2. train     LoRA adapter on the shared base (single GPU)
3. evaluate  eval.decision_model(decision_point) on eval_seed test # HC-EVAL-01, provably unseen
4. calibrate measure ECE / reliability diagram on the held-out set
5. gate      promote only if accuracy improved AND calibration held; else reject or recalibrate
6. version   record adapter version; model_version lands on predictions and labels; rollback available
```

Hygiene, enforced structurally:

- Never train on the eval targets: the HC-DATA-01 `provenance = eval_seed` quarantine makes the HC-EVAL-01 targets an unseen test set by construction.
- Small per-decision LoRA adapters keep each classifier simple, auditable, and independently versioned.

## 7. Calibration discipline

Calibration is the deliverable, not raw accuracy, because the verdict gate thresholds on confidence (HC-FIND-01).

- Measure ECE and a reliability diagram on the held-out test set after every fine-tune.
- A fine-tune that improves accuracy but degrades calibration is a regression and does not promote.
- If calibration degrades, apply post-hoc recalibration (temperature or Platt scaling); if that does not restore it, keep the gate deterministic and demote Laya to an advisory ranker (section 9).

## 8. How confidence is used (and never misused)

- `success_signal` confidence at or above the card floor emits a lead; below it, the signal is logged as a `weak_signal` and is not a finding (HC-KB-01 §5, HC-FIND-01 §2).
- Confirmation always requires the independent Verifier; Laya confidence never confirms a finding on its own (HC-FIND-01 universal verification).
- So Laya gates emission and prioritization, never the final verdict.

## 9. Degraded mode and the advisory-ranker fallback

- If the Laya sidecar is unavailable, deterministic evaluators run normally, and a card whose only evaluator is `laya:` with no deterministic fallback keeps its leads at `needs_validation` rather than ever silently confirming.
- If the bake-off (section 10) shows Laya is not reliably calibrated on our data, the emission and confirm gates stay deterministic and Laya is used only to rank and prioritize, never to decide.
- Either way the system remains correct, just less efficient, which is the point of keeping the deterministic path authoritative.

## 10. Bake-off (go / no-go before Laya drives the gate)

- Measure `success_signal` accuracy and calibration against the HC-EVAL-01 manifest-derived labels; this is the EVAL-01 "decision-model quality" metric.
- Go: calibrated and accurate, Laya drives the emission gate.
- No-go: Laya is advisory only (section 9) until a later fine-tune passes.
- Re-run the bake-off after every adapter promotion.

## 11. Feedback-loop safety

- The primary loop is already broken because the silver labels come from the independent Verifier, not from Laya.
- To guard the Verifier itself from drifting, a fraction of Laya-gated decisions is sampled into a held-out audit stream (human or stronger-LLM), producing gold labels that periodically re-anchor both Laya and the Verifier.

## 12. Interfaces

```
decide.classify(decision_point, input)        -> { value, confidence, model_version }
decide.batch(decision_point, inputs[])        -> [...]
train.lora(decision_point, corpus)            -> adapter_version
eval.decision_model(decision_point)           -> { accuracy, ece, reliability }   # via HC-EVAL-01
model.promote(decision_point, adapter_version) / model.rollback(decision_point)
```

## 13. Acceptance criteria

- Laya runs as a local sidecar with no egress; a classify call never leaves the trust boundary.
- A zero-shot baseline is measured before any fine-tune.
- Fine-tuning uses only train-split, non-`eval_seed` corpus, and the HC-EVAL-01 test set is provably unseen.
- A calibration regression blocks promotion even when accuracy improves.
- Laya confidence never yields a `confirmed` finding without the Verifier.
- With Laya down, deterministic evaluators run and laya-only signals keep their leads at `needs_validation`.
- No Laya prediction is ever written as a training label.

## 14. Open questions

- Per-decision heads versus a shared multi-head architecture on the base.
- How much audit sampling is enough to catch Verifier drift without excessive cost.
- A calibration regression test in CI, tied to the HC-EVAL-01 suite.
- Whether any decision point ever needs the multilingual checkpoint; current inputs are technical English, so ModernBERT-large stands.
