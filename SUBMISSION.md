# AI Security Researcher — Submission

Research scope, implemented POC, and proposed evaluation strategy. Quality experiments and mobile validation are not claimed.

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

# Task 2 — POC Implementation

The POC returns ALLOW, BLOCK, or ESCALATE with rule findings, per-risk classifier scores, flagged windows, coverage, and execution metadata. The code is in [poc/src/edge_guard](poc/src/edge_guard); complete setup instructions and JSON examples are in [poc/README.md](poc/README.md).

## Run

From the repository root, with Python 3.12+ and `uv` installed:

```sh
cd poc
uv sync --extra test
uv run edge-guard demo
uv run pytest
```

The deterministic demo explicitly uses mocks. For real pretrained CPU inference:

```sh
uv sync --extra ml --extra test
uv run edge-guard provision --model textdetox --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run edge-guard smoke --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run python scripts/validate_local.py
```

Provisioning is the explicit network step. Runtime loads local files only. Dependencies are locked in `poc/uv.lock`; provisioning records resolved model revisions. Prompt Guard support requires separately approved gated access and `edge-guard provision --model prompt_guard`.

## Design choices and trade-offs

| Mechanism | Implementation and rationale | Limitation |
|---|---|---|
| Rules | Bounded English/Hebrew/Arabic override cues, role spoofing, exfiltration cues, and exact configured synthetic-secret matching. Raw and NFKC findings retain their view-specific offsets. | Injection cues are evidence, not automatic blocks; normalization does not solve all obfuscation. |
| ML | Real TextDetox multilingual BERT sequence classifier for neutral/toxic text; optional Prompt Guard multilingual DeBERTa benign/malicious classifier for explicit overrides. CPU FP32, evaluation/inference mode, checked class polarity and output shape. | Toxicity is a limited safety category; injection weights were not provisioned. Target-language quality is unvalidated. |
| Long documents | Tokenizer-specific windows up to 512 total tokens with 64-token overlap. Full scanning defaults to eight windows per detector; over-cap documents escalate before classifier inference. | Explicit coverage limits bound work but restrict supported document length. |
| Selective routing | Experimental rule-prioritized selection reserves two slots for seeded random remaining windows, under the same eight-window budget. | Random exploration gives rule-silent attacks a chance of inspection, not guaranteed detection. Partial coverage escalates. |
| Agent reuse | A bounded 128-entry LRU caches exact model inputs and model/tokenizer/preprocessing identities; current boundary policy is reevaluated. | Only identical inputs benefit; source-specific trust policy and actual action execution are deferred. |
| Enforcement | Maximum per-risk score preserves localized signals. Real scores ≥0.5 or outgoing `DEMO_SECRET_DO_NOT_EXPORT` can BLOCK. Otherwise incomplete required checks ESCALATE; complete checks below threshold ALLOW. | Thresholds are provisional, not calibrated or validated against the proposed FPR target. The secret rule is deliberately narrow. |

Default required risks are injection and toxicity. Therefore TextDetox alone does not authorize an interaction when injection coverage is absent. Mock predictions produce a separate `simulated_decision` and never authorize an operational ALLOW. The exact synthetic-secret rule may independently BLOCK during mock execution.

An input cap of 65,536 characters precedes rules/tokenization. A cooperative 30-second scan deadline excludes model loading and can overrun during synchronous inference. Hard RAM enforcement, cancellation, encoded-payload decoding, quantization, and mobile deployment are deferred.

## Execution evidence

The saved [validation artifacts](poc/validation/) distinguish offline behavioral tests, mock fixtures, real-model execution, and integration. Real integration shows rule findings and TextDetox scores in the same request, outgoing rule blocking, a real ML-triggered toxicity block, cache reuse, selective partial-coverage escalation, and multilingual tokenizer offsets/tail preservation. The TextDetox run is pinned to revision `8fe5526e9c6b69cf1a615104a2ad037fb266c670`.

These checks establish execution and policy behavior; they do not measure recall, false positives, calibration, multilingual detection quality, or deployment performance. See [design details](poc/DESIGN.md) and [the specialist discussion](poc/DISCUSSION.md).

# Task 3 — Evaluation Plan

The evaluation should determine whether the two-layer guardrail detects supported risks with acceptable false positives and coverage while reducing CPU cost. The POC's fixtures and smoke tests establish control flow and model execution only; they provide no measured detector efficacy, calibration, or multilingual reliability.

## Methodology

Build a versioned corpus with separate injection, toxicity, and selected-secret labels; source provenance, interception boundary, language, and attack family; and adjudicated document/workflow outcomes. Injection labels concern malicious instruction redirection, not merely imperative wording. Toxicity is a limited unsafe-content category; selected-secret results must not be generalized to arbitrary confidential data. Use native English, Hebrew, and Arabic examples plus code-switching and translations, reviewed by competent annotators. Include disagreements and label uncertainty rather than turning model predictions into ground truth.

Include representative benign traffic, legitimate instructions, quoted attack explanations, security discussions, and toxic material quoted for moderation. Construct adversarial documents varying length, payload position, chunk boundaries, paraphrases, Unicode, encoding, distributed instructions, cue-free goal hijacking, and benign rule-hit flooding. Evaluate unsupported encodings/categories explicitly; the current POC does not decode arbitrary encodings.

Group original documents, translations, and paraphrased variants before development/validation/test splitting. Hold out attack families and preserve a final untouched test set. Development tunes rules and pipeline behavior, not model weights. Record freshly authored examples and source provenance; these splits do not rule out pretrained-model exposure. Maintain distinct representative-prevalence and adversarial stress sets; a balanced attack corpus alone does not estimate operational alert burden.

Compare four baselines on identical documents and workflows: rules only, full ML, rules plus full ML, and rules plus selective ML. Predeclare rules-only cue positives for detector metrics separately from operational escalation. Use real, pinned models for detector-quality comparisons. Full ML means every tokenizer-specific window; ensure caps permit that baseline or report the document outside supported coverage. Do not compare selective scans against a silently truncated baseline.

Choose detector/policy thresholds on validation data at the provisional ≤1% document-level FPR target. For routing ablations, freeze models, rules, thresholds, aggregation, and coverage policy; vary only routing/sampling. Repeat selective routing with declared seeds. The held-out test reports achieved FPR rather than assuming the target was met. Evaluate INT8 versus full precision separately after establishing the real-model baseline.

## Metrics and acceptance

| Decision | Metrics and interpretation |
|---|---|
| Detection quality | Document-level precision, recall, FPR, and confusion matrices by risk/language, document length, and attack family; precision-recall curves where useful. Report detector and final-policy outcomes separately. |
| Uncertainty | Confidence intervals for achieved FPR and paired full-versus-selective recall loss. Resample independent document/workflow groups, not overlapping windows or translations. Insufficient benign sample counts cannot establish a low FPR, even with zero observed false positives. |
| Coverage and usefulness | Per-detector windows/unique tokens scanned, unavailable/unsupported cases, timeout and escalation rates, false blocks, and task completion. Escalation is an explicit third outcome, not counted as successful attack detection or harmless passage. |
| Agent protection | Replay benign/malicious workflows across input, tool-call, tool-result, and output boundaries. Independently judge attacker-objective success, unauthorized actions, prevented outgoing synthetic-secret export, legitimate-task completion, and review burden. Tool authorization remains independent. |
| Runtime and resources | On declared CPU/OS/thread settings, measure cold startup separately from warm end-to-end p50/p95 scan latency, peak RAM, inference calls, cache hits, ML windows, and token coverage. Include long documents, repeated agent content, cache misses, caps, and deadline overruns. Use repeated representative runs; a single smoke duration is not a percentile or SLA. |

Predeclare acceptable recall loss, latency/RAM budgets, and task-completion degradation before test inspection. Adopt selective routing only if paired recall-loss confidence bounds pass, budgets hold, cost decreases, and utility remains acceptable. If evidence is insufficient or target-language performance fails, require fuller scanning, increase the declared budget, or narrow supported scope.

## Expected challenges and failure analysis

Model scores are not calibrated probabilities; language-specific score distributions and increasing window counts can change document FPR. Report calibration diagnostics without implying an unvalidated score means a probability. Translation leakage, ambiguous malicious intent, and realistic prevalence complicate evaluation. Sampling introduces variability and can miss attacks; adversaries may consume routing budgets. Preserve examples of misses and false blocks with risk/language/boundary context and model/version metadata.

Test missing models, malformed configuration, over-limit documents, cooperative deadline overruns, and partial coverage separately from efficacy. Operational ALLOW must not arise from required missing/mock/incomplete checks. Laptop CPU results do not establish mobile feasibility; validate each additional deployment target independently.
