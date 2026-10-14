> Historical research notes from the initial scope review. Word counts and model status below describe that revision. Read [SUBMISSION.md](../SUBMISSION.md) for the current authoritative submission.

# Part 1 review

The original is a sound research scope: it satisfies the two-layer requirement, covers all four interception points, separates risk labels, and considers multilingual robustness and edge performance. Its 447 whitespace-delimited words fit the assignment's 500-word maximum (PDF, Task 1, pages 1–2). The main opportunity is to make the POC choices and research decisions more concrete.

| Finding in the original | Why it matters | Revision |
|---|---|---|
| “Compact pretrained text classifiers” leaves model choice and safety scope open (line 15). | Feasibility and language coverage depend on actual models; toxicity does not establish general harmful-request detection. | Name injection and toxicity candidates; scope safety to hate/abuse/profanity and leakage to selected secret patterns. Mark unsupported categories explicitly. |
| Selective ML prioritizes suspicious spans (line 16). | Rule-silent attacks can evade both layers when rules also determine what ML sees. | Reserve budget for random remaining windows, ablate sampling, and acknowledge residual misses. |
| Agent-loop efficiency is asserted without a reuse mechanism (line 16). | Repeated retrieval/tool content can incur repeated inference. | Cache unchanged chunk scores by model/version; recompute context-dependent policy. |
| “Never assume unscanned content is safe” lacks an operational fallback (line 17). | A timeout or absent detector needs an explicit status and policy; escalation must not count as successful detection. | Return incomplete/unsupported coverage, hold sensitive actions, and report escalation separately. |
| Baselines and fixed FPR are underspecified (lines 21, 28). | Comparing a hybrid against ML alone confounds rule benefits with routing effects; chunk-level FPR hides document-length effects. | Add rules+full-ML, specify document-level FPR, and separate validation threshold selection from held-out evaluation. |

Verified model facts:

- Meta's [Prompt Guard 2 model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) describes a multilingual 86M backbone, a smaller 22M variant, and 512-token windows. Its listed evaluation languages omit Hebrew and Arabic; the 22M variant lacks multilingual pretraining. These are candidate models, not proof of target-language reliability or edge latency.
- The [TextDetox multilingual BERT model card](https://huggingface.co/textdetox/bert-multilingual-toxicity-classifier) describes a multilingual BERT binary toxicity classifier and lists evaluations for English, Hebrew, and Arabic. Its published language results vary substantially. This provides a concrete multilingual safety research candidate, not evidence of acceptable deployment accuracy, calibration, or CPU latency. It replaces the earlier English-only Granite HAP candidate.

The revised scope's ≤1% document-level FPR target is a proposed experimental operating point, not an assignment requirement or measured result. Thresholds are selected on validation data; achieved held-out FPR must be reported rather than assumed. Budget sweeps and recall-loss tolerance are research choices; deployment budgets and acceptable tolerance must be declared before experiments. Laptop validation does not establish mobile feasibility.

[Revised Part 1](TASK1_RESEARCH_SCOPE_IMPROVED.md) contains 499 whitespace-delimited words after the specialist review, including Markdown table syntax and links. No experiments were run; the assignment explicitly allows a proposed evaluation strategy. Original files were preserved.

## Verification against the assignment

Reference: `AI Security Researcher.pdf`, Task 1, pages 1–2; scenario, page 1; experiment exemption, page 3.

| Requirement | Evidence in the revised scope | Assessment |
|---|---|---|
| Maximum 500 words, Markdown, concise bullets/table | 499 whitespace-delimited words; bullets and a three-column table | Fits |
| Rule-based and ML-based text detection | Explicit patterns, normalization, decoding; pretrained injection and toxicity classifiers | Fits |
| Prompt injection and unsafe content across languages | Separate classifiers; English/Hebrew/Arabic evaluation; multilingual toxicity candidate | Fits as research scope; reliability remains unproven |
| Research questions, rationale, POC directions | Four testable questions; proposed routing, enforcement, baselines, and limitations | Fits |
| Low latency for long documents and agent workflows | Window selection, sampling, caching, full-window baseline, latency/RAM metrics | Fits as proposal; savings require measurements |
| Edge constraints and inline input/tool/output inspection | Offline CPU laptop POC, mobile validation caveat, all interception boundaries | Fits as proposal; no mobile deployment claim |

Verification also corrected cache identity to include the exact model input and model/tokenizer/preprocessing versions. Only context-independent inference scores are reusable; policy is recomputed. Full-ML now explicitly means scanning all windows, not exceeding the classifier's context limit.

Part 1 is ready as a research proposal. This does not satisfy the separate Task 2 implementation or Task 3 evaluation-plan deliverables, and it does not demonstrate detection quality or runtime performance. If gated model access or integration blocks Task 2, the assignment permits an abstract interface/mock with the architecture described; mocked predictions must not be reported as measured detector performance.

The subsequent [specialist discussion](RESEARCH_DISCUSSION.md) tightened the output contract, adversarial tests, split hygiene, controlled routing comparison, and adoption criteria. The optional 22M comparison and caching ablation were removed to preserve the word limit.
