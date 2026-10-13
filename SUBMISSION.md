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

# Task 3 — Evaluation Strategy and Trade-offs

**Goal:** Measure detection quality, multilingual/adversarial reliability, and CPU cost without mistaking abstention for security. Existing tests and smoke runs establish execution, not efficacy. This is a proposed evaluation; no quality results are claimed.

## Methodology and comparisons

- **Stage 1:** Evaluate real TextDetox toxicity detection and configured-secret boundary behavior. Assess injection rules as cues separately. Rules-only toxicity is unsupported; real injection and joint efficacy await Prompt Guard weights. Agent replay requires a future harness.
- **Ground truth:** Version documents with risk, language, attack family, provenance, and interception boundary. Native-language reviewers adjudicate content/attack labels separately from expected policy disposition: toxic quotations can be toxicity-positive yet legitimate moderation input. Record ambiguity and disagreements.
- **Data:** Use native English, Hebrew, Arabic, and code-switched text, plus reviewed translations. Include legitimate instructions, security quotations, and representative benign traffic. Separate realistic-prevalence and adversarial sets. Group originals/translations/paraphrases before development/validation/test splitting; hold out attack families. Pretraining exposure remains possible.
- **Baselines:** Compare rules-only, full-ML, rules+full-ML, and rules+selective-ML by supported risk. Predeclare rules-only injection flags as matched cues. Full-ML must scan every window with sufficient reference budget; evaluate deployment caps separately. Never substitute mocks for quality measurements.
- **Thresholds:** A proposed offline score-analysis harness selects thresholds on validation data targeting ≤1% document-level FPR. The current POC uses fixed 0.5 thresholds. Freeze models, rules, aggregation, thresholds, and coverage policy for paired routing comparisons; vary only routing/budget and declared sampling seeds. Report achieved held-out FPR. Evaluate INT8 separately later.

## Effectiveness and operational utility

| Metric | Definition and interpretation |
|---|---|
| Detection recall / FPR | Per risk: flagged positives / all attempted risk-positive documents; flagged negatives / all attempted risk-negative documents. Define ML flags by threshold and rules-only flags by the declared cue definition. Report precision at representative prevalence. |
| Coverage | Count flagged, complete nonflagged, and unassessed outcomes. Partial positive scans count as flags; partial/missing nonflags remain unassessed, never true negatives. Report windows, unique-token coverage, and escalation alongside FPR; skipping inspection can reduce apparent false positives. |
| Policy utility | False blocks / all legitimate attempts; automatic completion / all legitimate attempts. Report escalation and review-assisted completion separately under fixed review handling, including review time/cost. |
| Uncertainty | Use 95% exact binomial intervals on independent documents for rare FPR, including zero observed false positives; paired group-bootstrap intervals for recall loss. Resample original document/workflow groups, not correlated windows/translations. |
| Agent protection | Future guarded versus unguarded replay with identical agent settings and tool authorization: attacker-objective success, unauthorized actions, outgoing-secret export, and legitimate-task completion. ESCALATE is pending/interrupted work, not demonstrated attack resolution. |

## Robustness and multilingual support

Report metrics by risk, language, code-switching, boundary, attack family, and length; separate native from translated examples. Test injections at beginning/middle/end and across windows; paraphrases, Unicode/encoding, distributed instructions, cue-free goal hijacking, and suspicious-decoy flooding. Include benign lookalikes. Mark unsupported encodings/categories explicitly. Inspect per-language calibration; scores are not validated probabilities.

## Performance and acceptance

On named hardware with pinned models, CPU/OS/thread settings, measure cold startup separately from repeated warm end-to-end p50/p95 latency, peak RAM, inference calls, cache hits, and coverage. Include cache misses/reuse, long documents, input/window caps, missing models, errors, and cooperative deadline overruns. Preserve configurations and per-run outputs. Single smoke durations are not percentile estimates or SLAs; laptop results do not establish mobile feasibility.

Predeclare recall-loss tolerance, latency/RAM budgets, and acceptable completion/review burden. Adopt selective routing only if paired recall-loss bounds pass, cost decreases, and utility remains acceptable. Nonflagged partial coverage for required risks escalates unless another check blocks; scan-time savings alone cannot justify adoption. Otherwise increase coverage/budget or narrow supported scope.

Method references: [exact binomial intervals](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats._result_classes.BinomTestResult.proportion_ci.html); [AgentDojo workflow evaluation](https://arxiv.org/abs/2406.13352).
