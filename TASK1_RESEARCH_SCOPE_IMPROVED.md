# Task 1 — Research Scope: Inline Edge AI Guardrails

## Scope and assumptions

- **Output:** ALLOW / BLOCK / ESCALATE, separate injection, unsafe-content, and leakage labels, rule spans/flagged windows, and per-detector coverage.
- **Deployment:** Offline laptop CPU POC; declare hardware and latency/RAM budgets. Mobile feasibility requires separate validation.
- **Boundaries:** Inspect user/retrieved inputs, proposed tool arguments, tool results, and final outputs before consumption. Trust application-provided provenance/permissions, never text-declared authority. Tool authorization remains independent.
- **POC scope:** Injection, hate/abuse/profanity, and selected secret patterns. Other harmful-content categories remain explicit coverage gaps.

## Two-layer technical direction

| Component | Proposed approach and rationale | Main limitation |
|---|---|---|
| **1: Rules** | Scan all accepted text with bounded patterns for role spoofing, overrides, exfiltration cues, and secrets. Preserve original spans; inspect a normalized view and bounded decoded candidates. | Keywords are evidence, not automatic blocks; quotations and legitimate instructions create false positives. |
| **2: ML** | Evaluate [Prompt Guard 2 86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) for multilingual instruction-override detection and [TextDetox multilingual BERT](https://huggingface.co/textdetox/bert-multilingual-toxicity-classifier) for toxicity. Benchmark CPU inference and INT8 against unquantized quality. | Injection differs from toxicity; cue-free goal hijacking may evade override detection. Target-language reliability and edge feasibility need validation. |
| **Routing** | Tokenizer-specific overlapping windows; prioritize rule spans and lower-trust sources. Reserve random-window sampling budget for rule-silent attacks. Cache scores by exact model input and model/tokenizer/preprocessing versions; recompute policy using current context. | Sampling can still miss attacks; overlap cannot resolve arbitrarily distributed instructions. |
| **Enforcement** | Use per-risk thresholds with provenance and interaction type; retain strongest evidence without averaging away localized attacks. Return incomplete/unsupported status on timeout, skipped coverage, or missing detectors; hold sensitive actions for escalation. | Scores are not calibrated probabilities. Reduced coverage requires an explicit application policy, never an implicit safe verdict. |

## Research questions and experiments

1. **Security–compute frontier:** How much recall survives selective routing? Compare rules-only, full-ML, rules+full-ML, and rules+selective-ML on identical held-out inputs. Full-ML scans every window. For routing ablation, freeze models, rules, aggregation, coverage policy, and validation-selected thresholds (provisional document-level FPR target ≤1%). Ablate sampling; report achieved FPR and escalation separately.
2. **Long-document robustness:** Vary length, injection position, chunk boundaries, paraphrasing, Unicode/encoding, distributed instructions, and cue-free goal hijacking. Flood rule hits before payloads to test budget exhaustion. Measure misses and document-level false positives as window count grows.
3. **Multilingual reliability:** Evaluate English, Hebrew, Arabic, and code-switching using native examples, translations, benign attack quotations, and legitimate imperative requests. Group documents and translated/paraphrased variants before splitting; hold out attack families. Inspect calibration and unsupported-language behavior.
4. **Agent safety:** Replay benign/malicious workflows across interception points. Measure attack success, unauthorized actions, false blocks, escalation rate, and legitimate-task completion; trusted provenance must not exempt unsafe content.

## Decision criterion

Measure recall/FPR by language/risk, cold/warm end-to-end p50/p95 latency, peak RAM, ML windows, and unique-token coverage. Adopt selective routing only when paired recall-loss confidence bounds meet a predeclared tolerance, latency/RAM budgets hold, and cost decreases without unacceptable task-completion loss; otherwise require fuller scanning or narrow supported scope.
