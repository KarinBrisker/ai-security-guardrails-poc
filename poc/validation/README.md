# Execution checks

These artifacts establish control flow and real local execution. They are not an efficacy benchmark.

- `tests.txt`: 28 behavioral/adapter tests passed. Most use test doubles; model-polarity tests require the ML extra and otherwise skip.
- `demo.jsonl`: eight explicit mock fixtures; operational decisions remain distinct from simulated decisions.
- `real-smoke.json`: real TextDetox loading, first CPU inference, and an identical cached request, with offline environment flags enabled.
- `real-integration.json`: six real integration cases on Python 3.12.13, macOS ARM64, CPU FP32. Shows rules and ML in the same request, outgoing synthetic-secret blocking, complete toxicity-only coverage, cache reuse, ML-triggered toxicity blocking, and partial selective coverage. Also checks real multilingual tokenizer offsets and tail retention.

The toxicity stimulus produced a real score of approximately 0.99765 and `BLOCK` at the provisional 0.5 threshold. This single execution example establishes the ML enforcement branch; it does not establish a calibrated probability, recall, FPR, or multilingual quality. The selective case scored two of seven windows, reported approximately 0.34094 unique-token coverage, and escalated.

The model revision is `8fe5526e9c6b69cf1a615104a2ad037fb266c670`. Prompt Guard was not downloaded or executed. The integration script explicitly disables optional injection inference to keep its TextDetox-only checks reproducible.

Single-run durations are descriptive observations, not p50/p95 estimates or a deployment SLA. Model weights, caches, and the local virtual environment are excluded from the repository. Reproduce after explicit setup using the commands in [the POC README](../README.md).
