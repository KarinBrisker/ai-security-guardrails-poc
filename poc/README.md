# Inline edge guardrail POC

This CPU proof of concept combines multilingual suspicion rules with local injection/toxicity classifier adapters. It returns ALLOW, BLOCK, or ESCALATE plus detector coverage and evidence. TextDetox can run as a real accessible model; Prompt Guard requires separately provisioned gated artifacts. Missing required models cause ESCALATE, with no silent mock fallback.

It demonstrates the Task 1 architecture. It does not establish detector quality, calibrated thresholds, mobile feasibility, or a latency SLA.

## Install and run the offline demo

From this directory, with Python 3.12 and `uv` available:

```sh
uv sync --extra test
uv run edge-guard demo
uv run pytest
```

The demo explicitly uses mocks and the JSONL fixtures in `fixtures/demo.jsonl`. Reserved `[MOCK_INJECTION]` and `[MOCK_TOXICITY]` markers create deterministic simulated scores. A mock result includes a separate `simulated_decision`; mocked required coverage cannot justify operational ALLOW. The configured literal `DEMO_SECRET_DO_NOT_EXPORT` demonstrates a real rule-based outgoing leakage block. These examples are control-flow fixtures, not a quality benchmark.

## Provision and scan with real models

Model provisioning is the explicit online step. It downloads model artifacts and records resolved repository revisions in `.models/manifest.json`:

```sh
uv sync --extra ml --extra test
uv run edge-guard provision --model textdetox --models-dir .models
uv run edge-guard smoke --models-dir .models
uv run edge-guard scan --backend real --models-dir .models < envelope.json
```

To reproduce the saved execution evidence after provisioning:

```sh
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run python scripts/validate_local.py
```

This runs tests, the mock demo, and real-model integration cases in a TextDetox-only configuration, explicitly disabling optional injection inference for reproducibility. It writes results into `validation/`; it does not estimate detection quality.

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

Prompt Guard is gated. Obtain the necessary Hugging Face access before explicitly provisioning it; ordinary scans load only local files. The real-model smoke validates model loading, output shape, and finite scores. It does not validate multilingual quality or accuracy.

```sh
uv run edge-guard provision --model prompt_guard --models-dir .models
```

`source` and `sensitive_action` are carried as metadata in this POC. Source-specific trust/routing rules and an action executor are deferred; the caller must hold sensitive actions when the verdict is ESCALATE.

## Decisions and coverage

- A valid positive real detection or configured outgoing synthetic-secret rule can BLOCK even if other checks are incomplete.
- Otherwise missing, mocked, timed-out, or incomplete required coverage causes ESCALATE.
- ALLOW requires complete real coverage for the requested risks below the provisional thresholds. Classifier scores are not calibrated probabilities; thresholds are unvalidated.
- Injection cues, including quoted cues, do not automatically BLOCK. Normalized-rule offsets refer to the NFKC view; model evidence identifies flagged windows.

Full scanning is the default. The default eight-window per-detector cap is a demo control; full mode preflights excessive windows and escalates before classifier inference. Experimental selective mode scans a bounded subset, reserves random exploration, and reports partial coverage unless all windows are covered. Use `--mode selective`, `--max-windows`, `--seed`, and `--deadline` to vary those controls. A 30-second cooperative deadline excludes startup and can overrun during one synchronous inference call.

Output includes `decision`, `reasons`, `findings`, per-risk `detectors`, coverage/window counts, mode, elapsed time, and explicit `security_validated: false` / `thresholds_validated: false`. Offline tests verify contracts and policy invariants. Real-model inference evidence is reported separately from mocked demonstrations.

See [DESIGN.md](DESIGN.md) for boundaries and limitations, [DISCUSSION.md](DISCUSSION.md) for the research-team decisions, and the surrounding Task 1/Task 3 documents for the proposed quality evaluation.
