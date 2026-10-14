# Inline edge guardrail POC

This CPU proof of concept combines multilingual suspicion rules with local injection/toxicity classifier adapters. It returns ALLOW, BLOCK, or ESCALATE plus detector coverage and evidence. TextDetox and ungated DeBERTa run as real local classifiers; optional Prompt Guard requires separately provisioned gated artifacts. Missing required models cause ESCALATE, with no silent mock fallback.

It implements a subset of the [canonical submission](../SUBMISSION.md), with proposed extensions distinguished in the design. It does not establish detector quality, calibrated thresholds, mobile feasibility, or a latency SLA.

## Install and run the offline demo

From this directory, with Python 3.12 and `uv` available:

```sh
uv sync --extra test
uv run edge-guard demo
uv run pytest
```

The demo explicitly uses mocks and the JSONL fixtures in `fixtures/demo.jsonl`. Reserved `[MOCK_INJECTION]` and `[MOCK_TOXICITY]` markers create deterministic simulated scores. A mock result includes a separate `simulated_decision`; mocked required coverage cannot justify operational ALLOW. The configured literal `DEMO_SECRET_DO_NOT_EXPORT` demonstrates a real rule-based outgoing synthetic-secret block. The supported rule-only risk label is `synthetic_secret`; `leakage` is rejected because general credential detection is not implemented. These examples are control-flow fixtures, not a quality benchmark.

## Provision and scan with real models

Model provisioning is the explicit online step. It downloads model artifacts and records resolved repository revisions in `.models/manifest.json`:

```sh
uv sync --extra ml --extra test
uv run edge-guard provision --model all --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run edge-guard smoke --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run edge-guard scan --backend real --models-dir .models < envelope.json
```

To reproduce the saved execution evidence after provisioning:

```sh
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run python scripts/validate_local.py
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run python scripts/validate_injection.py
```

The first script retains the original TextDetox-only checks and may include joint checks in the refreshed evidence. The second explicitly exercises both classifiers and saves `validation/real-injection.json`, including contextual rule isolation, benign quotations, and toxicity-scoped triage plus a complete follow-up. The follow-up deliberately excludes injection coverage; its ALLOW makes no injection-safety claim. Joint scanning blocks the benign quote and repeated benign questions, which are preserved as observed false positives. Run both scripts after provisioning to refresh evidence for the current source. Neither script estimates detection quality.

Create `envelope.json` with an application-supplied envelope:

```json
{
  "text": "Summarize the meeting notes in one sentence.",
  "boundary": "input",
  "source": "user",
  "sensitive_action": false,
  "required_risks": ["injection", "toxicity"]
}
```

`boundary` is `input`, `tool_call`, `tool_result`, or `output`. `source` is a free application label, not authority claimed by the scanned text. The default required risks are injection and toxicity. With only TextDetox installed, its real result is available, but missing injection coverage prevents ALLOW. Narrowing `required_risks` deliberately narrows the requested coverage; it does not establish safety against omitted risks.

Prompt Guard is gated. Obtain the necessary Hugging Face access before explicitly provisioning it; ordinary scans load only local files. The real-model smoke requires both configured classifiers, checks complete coverage and finite scores on a repeated English input, and verifies cache reuse for both. It does not validate detection accuracy or multilingual quality. The saved `real-smoke.json` predates this stricter check and records a TextDetox-only run with injection unavailable.

```sh
uv run edge-guard provision --model prompt_guard --models-dir .models
```

The contextual rule treats tool results, and inputs whose application-provided source differs from `user`, as lower trust. Before a sensitive action, a role marker followed within 256 characters by an exfiltration cue produces `BLOCK`, even without ML. The same user input has no contextual block, but still requires complete ML coverage for ALLOW. Metadata must be set by the application, not an attacker. Quoted attack instructions can trigger this narrow rule; it is not a semantic quote detector. Source-aware window prioritization and an action executor remain deferred.

The [DeBERTa model card](https://huggingface.co/deepset/deberta-v3-base-injection) lists English/German. Non-Latin letters, including Hebrew/Arabic and mixed inputs, cause injection assessment to remain unavailable. This conservative script gate is not language identification: Spanish and other Latin-script languages can pass it despite unverified model support. Multilingual rules and TextDetox do not establish multilingual injection protection. Prompt Guard remains the proposed multilingual injection research candidate; the ungated DeBERTa baseline makes the present POC runnable without gated access.

## Decisions and coverage

- A valid positive real detection, contextual injection rule, or configured outgoing synthetic-secret rule can BLOCK even if other checks are incomplete.
- Otherwise missing, mocked, timed-out, or incomplete required coverage causes ESCALATE.
- ALLOW requires complete real coverage for the requested risks below the provisional thresholds. Classifier scores are not calibrated probabilities; thresholds are unvalidated.
- Isolated injection cues do not automatically BLOCK; the contextual conjunction can block quoted content before sensitive actions. Normalized-rule offsets refer to the NFKC view; model evidence identifies flagged windows.

Full scanning is the default. The default eight-window per-detector cap is a demo control; full mode preflights excessive windows and escalates before classifier inference. Experimental selective mode is triage, reducing initial inference work while leaving a decision pending. It scans a bounded subset, reserves random exploration, and reports partial coverage unless all windows are covered. Use `--mode selective`, `--max-windows`, `--seed`, and `--deadline` to vary those controls. The toxicity-only follow-up demo raises the full-scan budget explicitly and reuses exact-input scores; it is not an automatic background worker or a latency claim. A 30-second cooperative deadline excludes startup and can overrun during one synchronous inference call.

Output includes `decision`, `reasons`, `findings`, per-risk `detectors`, coverage/window counts, mode, elapsed time, and explicit `security_validated: false` / `thresholds_validated: false`. Offline tests verify contracts and policy invariants. Real-model inference evidence is reported separately from mocked demonstrations.

See [DESIGN.md](DESIGN.md) for boundaries and limitations and [SUBMISSION.md](../SUBMISSION.md) for the research scope and evaluation plan.
