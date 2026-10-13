# Specialist discussion: Part 1 research scope

Three agents reviewed the proposal: an AI security researcher, a data scientist, and a research manager. The specialists reviewed independently, exchanged findings directly, and agreed on a minimal controlled experiment. The manager challenged priorities and scope. This is a synthesis of their actual messages, not a verbatim transcript or an experimental result.

## Security researcher's challenge

The ML classifiers score windows; the proposal should not imply precise attack-span localization. Also, instruction-override detection does not establish coverage of every injection mechanism. Test goal hijacking without override cues and decoy rule hits that consume the routing budget before the malicious payload.

The [Prompt Guard model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) defines its target around explicit instruction overrides. Evasion by cue-free attacks and budget flooding are hypotheses proposed for testing, not observed failures in this POC.

## Data scientist's challenge

Separately tuning full and selective scanning would mix threshold changes with routing effects. Freeze models, rules, aggregation, validation-selected thresholds, and coverage policy for the paired routing ablation. Report achieved document-level FPR and uncertainty in recall loss. Keep source documents and their translations/paraphrases in the same split.

Escalating every partially scanned document could look secure while preventing legitimate work. Measure escalation and task completion separately from detector recall and workflow attack success.

## Manager's resolution

Prioritize five changes within 500 words: honest localization, adversarial routing tests, grouped splits, controlled paired comparison, and explicit acceptance budgets. Preserve trust boundaries and the mobile-validation caveat. Remove the optional smaller-model comparison and caching ablation before cutting core requirements.

The specialists directly agreed that the minimum comparison should use identical held-out inputs, frozen detector configuration, and the same incomplete-coverage policy, including decoy flooding and cue-free attacks. Independently optimized configurations remain a possible later deployment study; they do not isolate routing effects.

They found the existing cache contract adequate: exact model inputs and component versions identify reusable scores, while current interaction context determines policy. They also rejected adding a rigid detector-placement matrix to this short scope; the four interception points and contextual policy suffice.

## Result and open decisions

All five changes are incorporated in [Part 1](TASK1_RESEARCH_SCOPE_IMPROVED.md), now 499 whitespace-delimited words. The ≤1% FPR target is provisional. Hardware, latency/RAM budgets, recall-loss tolerance, acceptable task-completion loss, and dataset sizes remain choices to fix before experiments. Classifier coverage, edge feasibility, and mobile reliability remain unproven. A laptop document-level comparison is the first experiment; workflow replay checks operational effects.
