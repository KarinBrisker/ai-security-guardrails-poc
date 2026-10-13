# Implementation decisions

The manager, security researcher, and data scientist reviewed the research scope together, then narrowed Task 2 to a runnable CPU proof of concept. This records the discussion and resulting design choices; it does not report detector experiments.

| Question raised | Resolution | Why it matters |
|---|---|---|
| Can the model return exact evidence spans? | Return rule spans or flagged model windows. | Sequence classifiers do not supply validated token-level explanations. |
| Is selective scanning a security guarantee? | Make full scanning the default; label selective scanning experimental and incomplete unless every window is covered. | Cue-free attacks and floods of suspicious cues can defeat routing assumptions. |
| Should each routing configuration retune thresholds? | Freeze thresholds for the proposed routing ablation; retain achieved FPR and paired recall-loss bounds as future evaluation requirements. | Separately tuned thresholds would mix routing and threshold effects. |
| Can translated examples cross train/test boundaries? | Group documents, translations, and paraphrased variants before splitting in future evaluation. | Related examples can inflate measured generalization. |
| Can a missing injection model still produce ALLOW? | Require injection and toxicity coverage by default; unavailable required detectors cause operational ESCALATE. | A real toxicity result does not establish injection safety. |
| How can mocks demonstrate ALLOW/BLOCK? | Expose a separate simulated decision while preserving operational ESCALATE for mock coverage. | The demo exercises control flow without claiming security validation. |
| How should bounded full scanning handle a long document? | Preflight window count and escalate before ML when over the cap. | Partially scanning a document must not be presented as the full-scan baseline. |
| Should a deadline interrupt inference? | Use a cooperative soft deadline and report overruns; defer process isolation. | A synchronous CPU inference can finish after the deadline. |
| Which secrets can demonstrate reliable leakage blocking? | Use the configured synthetic literal `DEMO_SECRET_DO_NOT_EXPORT` at outgoing boundaries. General patterns remain suspicion cues. | The POC can demonstrate policy without claiming comprehensive secret detection. |
| Does Task 2 need every research experiment? | Implement adapters, rules, routing, policy, caching, and a small offline demonstration. Defer corpus evaluation, calibration, quantization, mobile validation, recursive decoding, and hard runtime isolation. | Keeps the deliverable runnable and its claims proportionate to the evidence. |

The user selected a real accessible toxicity model with an explicit mock pathway. Prompt Guard integration remains an adapter for locally provisioned gated artifacts; access is not assumed.

Proposed default thresholds and runtime caps are demonstration controls, not validated operating points or deployment recommendations. Tests of scheduler and policy behavior are distinct from detector-quality evaluation.

## Task 3 review

The same specialists exchanged critiques of the evaluation plan. They agreed to stage real toxicity/secret evaluation before unavailable injection/joint evaluation; separate risk labels from expected policy outcomes; retain all attempted documents in recall/FPR denominators while reporting unassessed coverage; and distinguish automatic completion from completion after review. The manager also required a future unguarded agent baseline with identical tool authorization, so protection is not mistakenly attributed to the scanner. Threshold sweeps and workflow replay are proposed evaluation components, not features already implemented. Zero observed false positives require rare-event confidence bounds rather than a zero-width bootstrap interval. These decisions are incorporated in the standalone and combined Task 3 plans.
