# AI security guardrails: home exercise

An offline CPU text-scanning POC with rule-based cues, real pretrained injection and toxicity detection, a contextual injection-blocking rule, and explicit routing/coverage policy.

**[Read the complete submission covering Tasks 1, 2, and 3](SUBMISSION.md).**

- [Source, setup, and demonstrations](poc/README.md)
- [Design and trade-offs](poc/DESIGN.md)
- [Specialist discussion](poc/DISCUSSION.md)
- [Persisted execution checks](poc/validation/)
- [Correctness and completeness audit](VERIFICATION.md)
- [Best-practice and literature alignment](LITERATURE_ALIGNMENT.md)

## Quick start

With Python 3.12+ and `uv` installed:

```sh
cd poc
uv sync --extra test
uv run edge-guard demo
uv run pytest
```

The demo uses explicitly labelled fixture-only mocks. To run both real CPU classifiers:

```sh
uv sync --extra ml --extra test
uv run edge-guard provision --model all --models-dir .models
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 uv run edge-guard smoke --models-dir .models
```

TextDetox and ungated DeBERTa are the CPU inference path. Optional Prompt Guard remains unexecuted. The injection model's card lists English/German; a non-Latin-letter gate leaves other scripts unassessed but cannot identify unsupported Latin-script languages. Required missing/unassessed checks prevent ALLOW unless another check blocks. Thresholds and runtime caps are demonstration controls. Refresh the documented validation scripts after provisioning; execution checks do not establish detection effectiveness or deployment readiness.
