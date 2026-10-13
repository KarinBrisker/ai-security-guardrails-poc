# Inline edge guardrail POC

The scanner produces an operational ALLOW, BLOCK, or ESCALATE decision, separate injection/toxicity/leakage results, rule evidence, flagged model windows, and coverage metadata. Mock execution additionally reports a simulated decision. This is a synchronous CPU text scanner with application-supplied boundary and provenance, not an agent authorization service.

## Detection and enforcement

1. Validate the envelope and reject over-limit inputs explicitly. Text cannot grant itself authority or change the application-provided boundary.
2. Apply bounded English, Hebrew, and Arabic override cues, role markers, exfiltration cues, and the configured synthetic secret. Scan raw and NFKC-normalized views; normalized offsets refer to that view. Injection cues are evidence rather than automatic blocks. Recursive decoding is deferred.
3. Tokenize separately for each model. Window length includes special tokens; overlapping windows retain the document tail. Never treat truncation as complete coverage.
4. Full mode scans every window within the configured cap. If the cap is exceeded, preflight prevents classifier inference and records incomplete coverage. Experimental selective mode reserves random exploration capacity in addition to prioritizing windows overlapping raw rule findings; it does not establish full coverage unless all windows are selected. Normalized-only cues do not drive raw-window priority because their offsets are in another view.
5. Aggregate the strongest risk evidence rather than averaging away a localized attack. A positive, valid real detection can BLOCK even when other coverage is incomplete. Otherwise required missing, mock, timed-out, or incomplete detection produces ESCALATE. ALLOW requires complete required real-detector coverage below the provisional thresholds.

The exact literal `DEMO_SECRET_DO_NOT_EXPORT` demonstrates outgoing leakage blocking at `tool_call` and `output` boundaries. Its presence in incoming material is evidence. This is a deliberately narrow selected-secret contract, not general data-loss prevention. `source` and `sensitive_action` are preserved metadata; source-specific trust policy/routing and an action executor are deferred. The caller holds sensitive actions on escalation and retains independent tool authorization.

## Backends and coverage

TextDetox is the accessible real toxicity candidate. Its adapter uses the known neutral/toxic label mapping and verifies the expected classifier output shape. Prompt Guard is a separate injection adapter for locally supplied gated artifacts; an unavailable model is reported explicitly. Loading models is separate from scanning; real scans must not silently download artifacts.

TextDetox uses a pretrained multilingual BERT encoder fine-tuned for binary toxicity classification, with a sequence-classification head producing neutral/toxic logits. Prompt Guard 2 86M uses a multilingual DeBERTa encoder and binary benign/malicious classification targeting instruction overrides. Both process bounded text windows rather than generating text. The adapters apply softmax and retain the configured positive-class score. Training and fine-tuning are outside this POC. See the [TextDetox model card](https://huggingface.co/textdetox/bert-multilingual-toxicity-classifier) and [Prompt Guard model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M).

Mock scores exercise routing and policy control flow. They cannot support accuracy, calibration, language-coverage, or security claims. Absent an independent real blocking finding, the operational verdict remains ESCALATE when required coverage is mocked; `simulated_decision` demonstrates the counterfactual policy branch.

Coverage is per detector, not inferred from total characters or cache hits. Tokenizers can create different windows. A cached score is valid only for the exact model input and relevant model/tokenizer/preprocessing/backend versions; the current boundary and policy are reevaluated. Cache entries are bounded and process-local, with no persistent raw-text logs.

## Bounded execution

Demo controls are a 64Ki-character pretokenization cap, windows of at most 512 total model tokens, overlap of 64 tokens, up to eight selected windows per detector, batch size 1 CPU inference, a 128-entry LRU, and a cooperative 30-second scan deadline excluding model startup. Input, selection, cache, and deadline limits are demonstration choices rather than measured deployment budgets; tokenizer window settings are adapter-specific.

Deadline checks happen between synchronous inference calls. A call can overrun the deadline; elapsed time and incomplete coverage must make that visible. Hard cancellation, per-request process isolation, and hard RAM enforcement are deferred. Cold model load and warm scan timing are distinct.

## Validation and remaining research

Offline tests use injected detector scores and a fake clock to verify meaningful safety invariants: quote cues do not automatically block; text does not change provenance; missing/mock/partial coverage cannot authorize; full windows retain a tail payload; selective routing cannot claim unscanned coverage; localized evidence is preserved; cached inference does not freeze policy. Optional real-model smoke checks loading, output shape, and finite scores, not detector efficacy.

No results here establish the research proposal's provisional ≤1% document-level FPR target, acceptable recall loss, or edge feasibility. A subsequent evaluation must use grouped documents/translations/variants, held-out attack families, per-language/risk metrics, paired routing comparisons, and agent attack-success/task-completion measurements. Cue-free hijacking, budget flooding, encoded attacks, other unsafe-content categories, and mobile operation remain explicit research gaps.
