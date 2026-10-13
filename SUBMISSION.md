# AI Security Researcher — Submission

Research scope, implemented POC, and proposed evaluation strategy. Quality experiments and mobile validation are not claimed.

# Task 1 — Research Scope: Inline Edge AI Guardrails

## Scope and assumptions

- **Output:** ALLOW / BLOCK / ESCALATE, injection/toxicity/leakage evidence, flagged windows, and per-detector coverage.
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
uv run edge-guard provision --model all --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run edge-guard smoke --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run python scripts/validate_local.py
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run python scripts/validate_injection.py
```

Provisioning is the explicit network step. Runtime loads local files only. Dependencies are locked in `poc/uv.lock`; provisioning records resolved model revisions. The default injection model is ungated DeBERTa. Optional Prompt Guard requires gated access and `edge-guard provision --model prompt_guard`; its execution remains unverified.

## Design choices and trade-offs

| Mechanism | Implementation and rationale | Limitation |
|---|---|---|
| Rules | Bounded English/Hebrew/Arabic override cues, role spoofing, exfiltration cues, and exact configured synthetic-secret matching. Raw and NFKC findings retain their view-specific offsets. | Isolated cues remain evidence. Lower-trust role spoofing followed within 256 characters by an exfiltration cue blocks before a sensitive action; quoted attacks can still trigger it. |
| ML | Real TextDetox multilingual BERT and ungated DeBERTa injection classifier (LEGIT/INJECTION); optional Prompt Guard adapter. CPU FP32, evaluation/inference mode, checked class polarity and output shape. | DeBERTa lists English/German; non-Latin injection inputs escalate through a conservative script gate. This is not language identification; other Latin-script languages are unvalidated. Prompt Guard weights remain untested. |
| Long documents | Tokenizer-specific windows up to 512 total tokens with 64-token overlap. Full scanning defaults to eight windows per detector; over-cap documents escalate before classifier inference. | Explicit coverage limits bound work but restrict supported document length. |
| Selective routing | Experimental rule-prioritized selection reserves two slots for seeded random remaining windows, under the same eight-window budget. | Triage reduces initial inference work, not total decision cost by itself. Partial nonflags escalate. A toxicity-only follow-up demo reuses scores and requires complete coverage before ALLOW; it makes no injection-safety claim. |
| Agent reuse | A bounded 128-entry LRU caches exact model inputs and model/tokenizer/preprocessing identities; current boundary policy is reevaluated. | Only identical inputs benefit. A narrow source-aware blocking rule is implemented; source-aware window prioritization and action execution remain deferred. |
| Enforcement | Maximum per-risk score preserves localized signals. Real scores ≥0.5, the contextual injection rule, or outgoing `DEMO_SECRET_DO_NOT_EXPORT` can BLOCK. Otherwise incomplete required checks ESCALATE; complete checks below threshold ALLOW. | Thresholds are provisional, not calibrated or validated against the proposed FPR target. The secret rule is deliberately narrow. |

Default required risks are injection and toxicity. Therefore TextDetox alone does not authorize an interaction when injection coverage is absent. Mock predictions produce a separate `simulated_decision` and never authorize an operational ALLOW. The synthetic-secret and contextual injection rules may independently BLOCK during mock execution.

An input cap of 65,536 characters precedes rules/tokenization. A cooperative 30-second scan deadline excludes model loading and can overrun during synchronous inference. Hard RAM enforcement, cancellation, encoded-payload decoding, quantization, and mobile deployment are deferred. Windows follow the classifier limits; overlap trades local boundary context against repeated inference; caps bound work/state. The 30-second development guard is not a real-time target. Nonblank input discarded by the tokenizer is unassessed and escalates.

## Execution evidence

The saved [validation artifacts](poc/validation/) distinguish offline behavioral tests, mock fixtures, real-model execution, and integration. Separate real runs cover TextDetox-only integration and joint injection/toxicity execution. Joint cases demonstrate ML injection blocking alongside rule evidence, cue-free injection scoring, contextual blocking without ML, cache reuse, and toxicity-scoped selective triage followed by complete scanning. The injection model also blocks a benign quoted attack and repeated benign questions; these observed false positives remain in the saved evidence. No joint low-latency ALLOW benefit is claimed. The TextDetox run is pinned to revision `8fe5526e9c6b69cf1a615104a2ad037fb266c670`.

These checks establish execution and policy behavior; they do not estimate recall, population FPR, calibration, multilingual detection quality, or deployment performance. See [design details](poc/DESIGN.md) and [the specialist discussion](poc/DISCUSSION.md).

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
