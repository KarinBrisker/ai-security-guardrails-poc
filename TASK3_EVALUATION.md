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
