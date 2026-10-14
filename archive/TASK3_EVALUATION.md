> Supporting copy of [canonical Task 3 in SUBMISSION.md](../SUBMISSION.md#task-3--evaluation-strategy-and-trade-offs). SUBMISSION.md is the authoritative submission.

# Task 3 — Evaluation Strategy and Trade-offs

**Goal:** Measure detection quality, multilingual/adversarial reliability, and CPU cost without mistaking abstention for security. Existing tests and smoke runs establish execution, not efficacy. This is a proposed evaluation; no quality results are claimed.

## Methodology and comparisons

- **Stage 1:** Evaluate real TextDetox toxicity detection and configured-secret boundary behavior. Evaluate isolated injection cues and contextual rule decisions separately. Rules-only toxicity is unsupported. Real DeBERTa injection and joint execution are available; multilingual injection evaluation still requires an appropriate validated candidate. Agent replay requires a future harness.
- **Ground truth:** Version documents with risk, language, attack family, provenance, and interception boundary. Native-language reviewers adjudicate content/attack labels separately from expected policy disposition: toxic quotations can be toxicity-positive yet legitimate moderation input. Record ambiguity and disagreements.
- **Data:** Use native English, Hebrew, Arabic, and code-switched text, plus reviewed translations. Include legitimate instructions, security quotations, and representative benign traffic. Separate realistic-prevalence and adversarial sets. Group originals/translations/paraphrases before development/validation/test splitting; hold out attack families. Pretraining exposure remains possible.
- **Baselines:** Compare rules-only, full-ML, rules+full-ML, and rules+selective-ML by supported risk. Predeclare rules-only injection flags as matched cues. Full-ML must scan every window with sufficient reference budget; evaluate deployment caps separately. Never substitute mocks for quality measurements.
- **Thresholds:** A proposed offline score-analysis harness selects thresholds on validation data targeting ≤1% document-level FPR. The current POC uses fixed 0.5 thresholds. Freeze models, rules, aggregation, thresholds, and coverage policy for paired routing comparisons; vary only routing/budget and declared sampling seeds. Report achieved held-out FPR. Evaluate INT8 separately later.

## Effectiveness and operational utility

| Metric | Definition and interpretation |
|---|---|
| Detection recall / FPR | Per risk: flagged positives / all attempted risk-positive documents; flagged negatives / all attempted risk-negative documents. Define ML flags by threshold and rules-only flags by the declared cue definition. Report precision at representative prevalence. |
| Coverage | Count flagged, complete nonflagged, and unassessed outcomes. Partial positive scans count as flags; partial/missing nonflags remain unassessed, never true negatives. Report windows, unique-token coverage, and decision coverage (ALLOW/BLOCK / all attempts) alongside FPR; skipping inspection can reduce apparent false positives. |
| Policy utility | False blocks / all legitimate attempts; automatic completion / all legitimate attempts. Report escalation and review-assisted completion separately under fixed review handling, including review time/cost. |
| Uncertainty | Use 95% exact binomial intervals on independent documents for rare FPR, including zero observed false positives; paired group-bootstrap intervals for recall loss. Resample original document/workflow groups, not correlated windows/translations. |
| Agent protection | Future guarded versus unguarded replay with identical agent settings and tool authorization: attacker-objective success, unauthorized actions, outgoing-secret export, and legitimate-task completion. ESCALATE is pending/interrupted work, not demonstrated attack resolution. |

## Robustness and multilingual support

Report metrics by risk, language, code-switching, boundary, attack family, and length; separate native from translated examples. Test injections at beginning/middle/end and across windows; paraphrases, Unicode/encoding, distributed instructions, cue-free goal hijacking, and suspicious-decoy flooding. Include benign lookalikes. Mark unsupported encodings/categories explicitly. Inspect per-language calibration; scores are not validated probabilities.

Add adaptive attacks against the frozen guard, declaring query budget and success-only versus score feedback. Future replay separates explicit tasks from open-ended delegation. [AutoDojo](https://arxiv.org/abs/2606.15057) motivates adaptive evaluation; [LongPIBench](https://arxiv.org/abs/2608.28411) motivates long-context stress. As a future broader-safety comparator, evaluate [Qwen3Guard-Gen-0.6B](https://huggingface.co/Qwen/Qwen3Guard-Gen-0.6B) on shared risk labels and identical hardware; advertised multilingual support is not target-language evidence.

## Performance and acceptance

On named hardware with pinned models, CPU/OS/thread settings, measure cold startup separately from repeated warm end-to-end p50/p95 latency, peak RAM, inference calls, cache hits, and coverage. Include cache misses/reuse, long documents, input/window caps, missing models, errors, and cooperative deadline overruns. Preserve configurations and per-run outputs. Single smoke durations are not percentile estimates or SLAs; laptop results do not establish mobile feasibility.

Predeclare recall-loss tolerance, latency/RAM budgets, and acceptable completion/review burden. Adopt selective triage only if paired recall-loss bounds pass, combined scan/follow-up/review cost decreases, and utility remains acceptable. Nonflagged partial coverage for required risks escalates unless another check blocks; scan-time savings alone cannot justify adoption. Otherwise increase coverage/budget or narrow supported scope.

Method references: [exact binomial intervals](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats._result_classes.BinomTestResult.proportion_ci.html); [AgentDojo workflow evaluation](https://arxiv.org/abs/2406.13352).
