# Execution checks

Refreshed on 14 October 2026 from code revision `dd94eba97b297ea677bf3745fe40eb8d2980678f`, including the `synthetic_secret` contract and stricter smoke checks. Dependency setup used `uv sync --locked --extra ml --extra test`; model execution used `HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1`. These artifacts establish control flow and real local execution. They are not an efficacy benchmark.

- `tests.txt`: 47 behavioral/adapter tests passed on the validated revision. Most use test doubles; model-polarity checks ran with the ML extra installed.
- `demo.jsonl`: ten explicit mock fixtures; operational decisions remain distinct from simulated decisions.
- `real-smoke.json`: both real classifiers loaded, produced complete finite scores on the first request, and reused one cached score each on the repeated request. The stricter CLI smoke checks passed.
- `real-integration.json`: six real integration cases on Python 3.12.13, macOS ARM64, CPU FP32. Shows rules and ML in the same request, outgoing synthetic-secret blocking, complete toxicity-only coverage, cache reuse, ML-triggered toxicity blocking, and partial selective coverage. Also checks real multilingual tokenizer offsets/tail retention and escalation for nonblank inputs discarded by the tokenizer.

The toxicity stimulus produced a real score of approximately 0.99765 and `BLOCK` at the provisional 0.5 threshold. This single execution example establishes the ML enforcement branch; it does not establish a calibrated probability, recall, FPR, or multilingual quality. The selective case scored two of seven windows, reported approximately 0.34094 unique-token coverage, and escalated.

The model revision is `8fe5526e9c6b69cf1a615104a2ad037fb266c670`. Prompt Guard was not downloaded or executed. The integration script explicitly disables optional injection inference to keep its TextDetox-only checks reproducible.

Single-run durations are descriptive observations, not p50/p95 estimates or a deployment SLA. Model weights, caches, and the local virtual environment are excluded from the repository. Reproduce after explicit setup using the commands in [the POC README](../README.md).

## Real injection and joint execution

`real-injection.json` adds 15 execution cases using both real classifiers on macOS ARM64, CPU FP32, Python 3.12.13. DeBERTa is pinned to `80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1`; TextDetox retains the revision above. Runtime flags disable network access. The run used an Apple M4 Pro; CPU identity, architecture, and Torch thread count are recorded.

- A clean question receives joint ALLOW with complete coverage.
- An explicit override gets an injection score approximately 0.9990 and BLOCK. A cue-free instruction gets approximately 0.9988 and BLOCK without any rule finding.
- A lower-trust role/exfiltration conjunction blocks before a sensitive action with ML deliberately unavailable. Identical user input remains ESCALATE, not safe.
- Hebrew/Arabic inputs have real toxicity results but unassessed injection coverage, so neither receives ALLOW.
- **Observed false positives:** a benign security quotation scores approximately 0.9988; repeated benign questions score approximately 0.9940 in selective scanning. Both are blocked. These examples expose the candidate's limitations; they are not an estimated population FPR.
- **Scoped follow-up:** a separate toxicity-only scan first escalates with partial coverage, then completes fuller scanning with cached scores and ALLOW. Injection is explicitly outside this demonstration's required scope. The joint result for the same repeated questions remains BLOCK.

`long-input-probes.json` preserves exploratory fixture checks for four benign repeated-text styles. Only first/last injection windows were scored, all above threshold. These probes informed the demo; they are not held-out evaluation or complete document coverage.

The joint process recorded about 1.29 GiB peak RSS in this run. This includes the interpreter, both models, and scan state; it is not a per-request memory allocation or a hard cap. These results do not establish laptop latency targets or mobile feasibility. No threshold tuning or quoted-text exemption was introduced to conceal the false positives.

A real CLI `scan` using the English question “What is the capital of France?” with both injection and toxicity required returned ALLOW, complete coverage, and the documented JSON fields. Existing benign-quotation/repetition false positives remain in the refreshed joint results.
