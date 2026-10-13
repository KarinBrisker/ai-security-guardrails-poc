"""JSON command line interface; scans never download models."""

import argparse
import json
from pathlib import Path
import sys
import time

from .models import MockDetector, build_detectors, provision_models
from .pipeline import Config, Envelope, Pipeline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--backend", choices=["real", "mock"], default="real")
    scan.add_argument("--models-dir", default=".models")
    scan.add_argument("--mode", choices=["full", "selective"], default="full")
    scan.add_argument("--max-windows", type=int, default=8)
    scan.add_argument("--seed", type=int, default=17)
    scan.add_argument("--deadline", type=float, default=30)
    demo = sub.add_parser("demo")
    demo.add_argument("--fixtures", default="fixtures/demo.jsonl")
    provision = sub.add_parser("provision")
    provision.add_argument("--model", choices=["textdetox", "prompt_guard"], default="textdetox")
    provision.add_argument("--models-dir", default=".models")
    smoke = sub.add_parser("smoke")
    smoke.add_argument("--models-dir", default=".models")
    args = parser.parse_args()
    try:
        if args.command == "provision":
            print(json.dumps(provision_models(args.models_dir, args.model == "prompt_guard"), indent=2))
        elif args.command == "demo":
            pipeline = Pipeline({r: MockDetector(r) for r in ("injection", "toxicity")})
            for line in Path(args.fixtures).read_text().splitlines():
                if not line.strip():
                    continue
                fixture = json.loads(line)
                name = fixture.pop("name")
                print(json.dumps({"name": name, **pipeline.scan(Envelope.from_dict(fixture))}, ensure_ascii=False))
        elif args.command == "smoke":
            started = time.perf_counter()
            detectors = build_detectors("real", args.models_dir)
            load_ms = (time.perf_counter() - started) * 1000
            detector = detectors["toxicity"]
            if detector.backend != "real":
                raise RuntimeError(getattr(detector, "reason", "TextDetox is not available"))
            pipeline = Pipeline(detectors)
            first = pipeline.scan(Envelope("Thank you for your help.", required_risks=("toxicity",)))
            second = pipeline.scan(Envelope("Thank you for your help.", required_risks=("toxicity",)))
            if first["detectors"]["toxicity"]["status"] != "complete":
                raise RuntimeError("Real smoke did not complete: " + json.dumps(first))
            print(json.dumps({"model_load_ms": load_ms, "first_request": first, "cached_request": second, "efficacy_evaluation": False}, indent=2))
        else:
            config = Config(mode=args.mode, max_windows=args.max_windows, seed=args.seed, deadline_seconds=args.deadline)
            # Input validation precedes expensive model loading.
            envelope = Envelope.from_dict(json.load(sys.stdin))
            detectors = build_detectors(args.backend, args.models_dir) if len(envelope.text) <= config.max_chars else {}
            print(json.dumps(Pipeline(detectors, config).scan(envelope), ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
