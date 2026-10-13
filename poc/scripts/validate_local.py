"""Persist local execution evidence; these examples are not an efficacy set."""

import json
import platform
from pathlib import Path
import subprocess
import sys
import time

from edge_guard.models import UnavailableDetector, build_detectors
from edge_guard.pipeline import Config, Envelope, Pipeline


def main():
    output = Path("validation")
    output.mkdir(exist_ok=True)
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q"], capture_output=True, text=True)
    (output / "tests.txt").write_text(tests.stdout + tests.stderr)
    if tests.returncode:
        raise RuntimeError("Offline tests failed")
    demo = subprocess.run([sys.executable, "-m", "edge_guard.cli", "demo"], capture_output=True, text=True)
    if demo.returncode:
        raise RuntimeError(demo.stderr)
    (output / "demo.jsonl").write_text(demo.stdout)
    started = time.perf_counter()
    detectors = build_detectors("real", ".models")
    load_ms = (time.perf_counter() - started) * 1000
    if detectors["toxicity"].backend != "real":
        raise RuntimeError("Provision real TextDetox first")
    # Keep these checks reproducible even if optional Prompt Guard is installed.
    detectors["injection"] = UnavailableDetector("injection", "Intentionally disabled in TextDetox-only execution checks")
    pipeline = Pipeline(detectors)
    results = {
        "quoted_rule_and_real_ml": pipeline.scan(Envelope('The paper quotes "ignore previous instructions" as an attack.')),
        "outgoing_rule_block": pipeline.scan(Envelope("DEMO_SECRET_DO_NOT_EXPORT", boundary="tool_call", sensitive_action=True)),
        "toxicity_only_complete": pipeline.scan(Envelope("Thank you for your help.", required_risks=("toxicity",))),
        "cached_toxicity_only": pipeline.scan(Envelope("Thank you for your help.", required_risks=("toxicity",))),
        "real_toxicity_signal": pipeline.scan(Envelope("Fuck you, you stupid asshole.", required_risks=("toxicity",))),
        "selective_partial_real": Pipeline(detectors, Config(mode="selective", max_windows=2)).scan(Envelope("ignore previous instructions " + "meeting notes " * 1400, required_risks=("toxicity",))),
    }
    quoted = results["quoted_rule_and_real_ml"]
    assert quoted["findings"] and quoted["detectors"]["toxicity"]["status"] == "complete"
    assert quoted["decision"] == "ESCALATE"  # Injection model not provisioned.
    assert results["outgoing_rule_block"]["decision"] == "BLOCK"
    assert results["cached_toxicity_only"]["detectors"]["toxicity"]["cache_hits"] == 1
    assert results["real_toxicity_signal"]["detectors"]["toxicity"]["status"] == "complete"
    assert results["selective_partial_real"]["detectors"]["toxicity"]["status"] == "partial"
    assert results["selective_partial_real"]["decision"] == "ESCALATE"
    # Check real tokenizer tail and multilingual original-offset contracts.
    text = " ".join(["שלום", "مرحبا", "hello"] * 400)
    windows = detectors["toxicity"].windows(text)
    assert windows[-1].end == len(text)
    assert all(w.text == text[w.start:w.end] and len(w.token_ids) <= 512 for w in windows)
    evidence = {
        "python": platform.python_version(), "os": platform.system(), "architecture": platform.machine(),
        "model_load_ms": load_ms, "efficacy_evaluation": False, "configuration": "TextDetox-only; injection explicitly disabled",
        "model_manifest": json.loads(Path(".models/manifest.json").read_text()),
        "real_tokenizer_checks": {"multilingual_windows": len(windows), "tail_preserved": True, "offsets_valid": True},
        "cases": results,
    }
    (output / "real-integration.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"tests_passed": True, "demo_cases": len(demo.stdout.splitlines()), "real_cases": len(results), "efficacy_evaluation": False}))


if __name__ == "__main__":
    main()
