> Supporting copy of [canonical Task 1 in SUBMISSION.md](../SUBMISSION.md#task-1--research-scope-inline-edge-ai-guardrails). SUBMISSION.md is the authoritative submission.

# Task 1 — Research Scope: Inline Edge AI Guardrails

## Scope and assumptions

- **Output:** ALLOW / BLOCK / ESCALATE, injection/toxicity/synthetic-secret evidence, flagged windows, and per-detector coverage.
- **Deployment:** Offline laptop CPU POC. Declare latency/RAM budgets; validate mobile feasibility separately.
- **Boundaries:** Inspect inputs, tool arguments/results, and outputs. Trust application-provided provenance, never text-declared authority. Tool authorization remains independent.
- **Coverage:** Injection, hate/abuse/profanity, and configured secrets; other safety categories remain gaps.

## Two-layer technical direction

| Component | Proposed approach and rationale | Limitation |
|---|---|---|
| **Rules** | Scan accepted text with bounded override, role-spoofing, exfiltration, and secret patterns. Retain raw/normalized spans. Combine lower-trust provenance, nearby authority/exfiltration cues, and sensitive-action context for narrow enforcement. Investigate bounded decoding separately. | Quoted attacks can match; contextual rules need benign-lookalike evaluation. |
| **ML** | Start with accessible [DeBERTa injection](https://huggingface.co/deepset/deberta-v3-base-injection) and multilingual [TextDetox BERT](https://huggingface.co/textdetox/bert-multilingual-toxicity-classifier). Compare multilingual [Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) when access permits. Benchmark CPU FP32 and INT8 separately. | The accessible injection candidate lists English/German; Hebrew/Arabic quality is unsupported. Toxicity cannot substitute for injection detection. |
| **Routing** | Tokenizer-specific overlapping windows; prioritize rule spans with reserved random exploration. Cache exact model inputs with model/tokenizer/preprocessing identity; recompute contextual policy. Investigate source-aware prioritization separately. | Selective scanning is triage: nonflagged partial coverage escalates. Fuller follow-up scanning may reduce review burden, at additional cost. |
| **Enforcement** | Preserve maximum risk evidence with provisional per-risk thresholds. Missing models, unsupported inputs, timeouts, and skipped windows cannot justify ALLOW. Hold sensitive actions on escalation. | Scores are uncalibrated; text classification does not enforce tool permissions. |

## Research questions and experiments

1. **Security–compute frontier:** Compare rules-only, full-ML, rules+full-ML, and rules+selective-ML on identical held-out inputs. Freeze models, rules, aggregation, coverage policy, and validation-selected thresholds for routing ablation; target document-level FPR ≤1% provisionally. Ablate sampling. Measure triage plus follow-up/review cost, escalation, and completion.
2. **Long-document robustness:** Vary length, payload position, chunk boundaries, paraphrases, Unicode/encoding, distributed instructions, and cue-free hijacking. Flood rule cues before payloads; measure misses and document FPR as windows increase.
3. **Multilingual reliability:** Evaluate native English, Hebrew, Arabic, and code-switching alongside reviewed translations. Include benign attack quotations and legitimate imperatives. Group originals/translations/paraphrases before splitting; hold out attack families. Assess calibration and unsupported-language behavior.
4. **Agent safety:** Replay workflows at each boundary. Measure attacker-objective success, unauthorized actions, false blocks, escalation, and legitimate completion against an unguarded baseline with identical permissions.

## Decision criterion

Report per-language/risk recall/FPR, paired recall-loss confidence bounds, cold/warm p50/p95 latency, peak RAM, inference calls, and unique-token coverage. Adopt selective triage only if total cost decreases within predeclared quality, runtime, and completion tolerances; otherwise increase coverage or narrow scope.
