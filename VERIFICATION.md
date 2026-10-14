# Verification record

The current submission is [SUBMISSION.md](SUBMISSION.md). The revision checks below supersede initial model-execution, word-count, and source-policy limitations. Earlier checks are retained as historical evidence.

Reviewed 2026-10-13 against the original `AI Security Researcher.pdf`, all three submission sections, scanner code, documented commands, and persisted execution checks. The security researcher and research manager performed independent reviews; the scientist reviewed the literature alignment.

## Requirement coverage

| Assignment requirement | Evidence | Assessment |
|---|---|---|
| Task 1: maximum 500 words, questions/rationale/technical directions | Revised embedded scope is 434 whitespace-delimited words, with four questions and a two-layer comparison table | Meets |
| Task 1: multilingual risks, robustness, long-document/agent efficiency | Separate injection/toxicity scope, target-language tests, boundary attacks, sampling/caching, resource metrics | Meets as research proposal |
| Task 2: selected rule-based detection | Bounded multilingual cues, contextual role/exfiltration blocking, synthetic-secret rule, raw/NFKC evidence | Meets |
| Task 2: pretrained model or explicit mock/interface with architecture | Real TextDetox and ungated DeBERTa injection CPU inference; optional Prompt Guard adapter; explicit fixture-only mocks; architecture documented | Meets; both real classifiers executed |
| Task 2: integrated pipeline beyond pattern matching/predict | Token-aware windows, reserved random exploration, coverage policy, strongest-score aggregation, cache reuse with current policy | Meets |
| Task 2: code, run instructions, brief design/trade-offs | Source, locked dependencies, CLI instructions, design document, combined Task 2 section | Meets |
| Task 3: methodology, metrics, multilingual/adversarial robustness, performance, challenges | Standalone and identical embedded evaluation plan; independent risk/policy labels, coverage, uncertainty, latency/RAM, adaptive attacks | Meets as proposed evaluation |
| Submission: GitHub repository containing one document covering all tasks and pipeline code | Public repository; root `SUBMISSION.md` and `poc/src/edge_guard` | Meets |

## Defect found and corrected

TextDetox's tokenizer discards some nonblank control/zero-width inputs. Previously the adapter returned no windows, causing the pipeline to assign score 0.0, complete coverage, and ALLOW when toxicity alone was required. The adapter now raises an explicit processing error for nonblank input with no content tokens; the pipeline returns ESCALATE with no measured score. Intentionally blank input remains a documented empty-content assumption.

Three regression tests cover zero-width space, zero-width joiner, and NUL. Actual provisioned-tokenizer checks confirm all three escalate; the results are persisted in `poc/validation/real-integration.json`.

## Initial verification (historical)

- Installed the locked test-only environment into an isolated temporary virtual environment using cached dependencies. The documented demo ran successfully; tests reported 28 passed and three optional ML tests skipped.
- Added the locked ML extra to that same fresh environment. The documented `uv run` validation workflow passed all 31 tests, eight mock fixtures, six real integration cases, real multilingual offsets/tail checks, and the discarded-input checks, with networking disabled.
- Actual real integration includes both rule-triggered blocking and an ML-triggered toxicity block. These establish execution branches, not detector accuracy.
- Task 1 remains 499 words. Local submission links and Markdown tables were checked. The standalone Task 3 section matches the combined submission.

## Remaining limitations

No literal deliverable requirement remains unmet. The assignment does not require quality experiments or training. Real injection/joint efficacy, adaptive workflow security, multilingual quality, calibration, hard latency/RAM bounds, and mobile feasibility remain unverified. Broad source-specific routing, action authorization, encoded-payload decoding, and quantization are deferred features of the research scope. The POC's runtime limits are justified demonstration controls, not proven production budgets.

The separate [literature review](LITERATURE_ALIGNMENT.md) supports positioning this as a literature-informed CPU baseline. Comparative efficacy measurements are required before making a SOTA claim.

## Revision verification

- Read the original assignment PDF locally and checked the three deliverables against it.
- Ran 47 behavioral/adapter tests successfully with ML dependencies present and offline flags enabled; persisted `poc/validation/tests.txt`.
- Ran ten mock fixtures and six TextDetox-only integration cases. Preserved the original nonblank discarded-input fix and its real-tokenizer evidence.
- Provisioned the ungated DeBERTa injection candidate at an immutable revision, then ran 15 offline joint/scoped cases. An explicit override and cue-free injection trigger real ML blocking; contextual rules block without ML; cached scores do not freeze policy; Hebrew/Arabic injection coverage remains unsupported.
- Preserved observed benign quotation/repetition false positives rather than tuning the examples into an accuracy claim. A toxicity-only follow-up demonstrates pending triage to complete ALLOW; joint repeated-text scanning remains BLOCK.
- Task 1 is 434 whitespace-delimited words in the authoritative submission. Supporting Task 1/3 copies explicitly link to it. Selective routing is described as triage; deadline/RAM controls remain POC controls.

The current candidate strengthens execution evidence and layer integration. It does not resolve injection false positives, establish multilingual injection quality, prove low-latency ALLOW on long documents, or supply a full proxy/agent runtime.

The subsequent risk-label and smoke-command hardening narrows the synthetic-secret API and requires both real models for smoke success. The persisted 47-test result predates those edits and was not rerun in this update.
