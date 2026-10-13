# AI security guardrails: home exercise

An offline CPU text-scanning POC with rule-based cues, real pretrained toxicity detection, an optional injection-model adapter, and explicit routing/coverage policy.

**[Read the complete submission covering Tasks 1, 2, and 3](SUBMISSION.md).**

- [Source, setup, and demonstrations](poc/README.md)
- [Design and trade-offs](poc/DESIGN.md)
- [Specialist discussion](poc/DISCUSSION.md)
- [Persisted execution checks](poc/validation/)

## Quick start

With Python 3.12+ and `uv` installed:

```sh
cd poc
uv sync --extra test
uv run edge-guard demo
uv run pytest
```

The demo uses explicitly labelled fixture-only mocks. To run real CPU toxicity detection:

```sh
uv sync --extra ml --extra test
uv run edge-guard provision --model textdetox --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run edge-guard smoke --models-dir .models
```

TextDetox was executed locally on CPU. Prompt Guard weights were not provisioned; missing required injection coverage escalates. Thresholds and runtime caps are demonstration controls. The saved checks establish execution and integration, not detection effectiveness or deployment readiness.
