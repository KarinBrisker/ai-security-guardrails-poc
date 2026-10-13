"""Bounded routing and explicit per-detector scan coverage."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import math
import random
import time

from .models import DetectorUnavailable
from .policy import decide
from .rules import scan_rules


@dataclass(frozen=True)
class Envelope:
    text: str
    boundary: str = "input"
    source: str = "user"
    sensitive_action: bool = False
    required_risks: tuple[str, ...] = ("injection", "toxicity")

    def __post_init__(self):
        if not isinstance(self.text, str):
            raise ValueError("text must be a string")
        if self.boundary not in {"input", "tool_call", "tool_result", "output"}:
            raise ValueError("invalid interception boundary")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("source must be a nonempty application-provided string")
        if not isinstance(self.sensitive_action, bool):
            raise ValueError("sensitive_action must be boolean")
        if not self.required_risks or any(r not in {"injection", "toxicity", "leakage"} for r in self.required_risks):
            raise ValueError("required_risks must be nonempty and use known labels")

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ValueError("input must be a JSON object")
        keys = {"text", "boundary", "source", "sensitive_action", "required_risks"}
        if set(value) - keys:
            raise ValueError(f"unknown envelope fields: {sorted(set(value) - keys)}")
        if "text" not in value:
            raise ValueError("text is required")
        args = dict(value)
        if "required_risks" in args:
            if not isinstance(args["required_risks"], list):
                raise ValueError("required_risks must be a JSON array")
            args["required_risks"] = tuple(args["required_risks"])
        return cls(**args)


@dataclass(frozen=True)
class Config:
    mode: str = "full"
    max_chars: int = 65_536
    max_windows: int = 8
    seed: int = 17
    deadline_seconds: float = 30.0
    cache_entries: int = 128

    def __post_init__(self):
        if self.mode not in {"full", "selective"}:
            raise ValueError("mode must be full or selective")
        if min(self.max_chars, self.max_windows, self.cache_entries) < 1:
            raise ValueError("character, window and cache limits must be positive")
        if not math.isfinite(self.deadline_seconds) or self.deadline_seconds <= 0:
            raise ValueError("deadline must be a finite positive number")


def select_windows(windows, findings, budget, seed):
    """Reserve random slots so rule-silent windows remain eligible."""
    if len(windows) <= budget:
        return list(windows)
    reserved = min(2, budget)
    def hits(window):
        return sum(
            f["view"] == "raw" and f["start"] < window.end and f["end"] > window.start
            for f in findings
        )
    ranked = sorted(windows, key=lambda w: (-hits(w), w.index))
    priority = ranked[:budget - reserved]
    selected_ids = {w.index for w in priority}
    remaining = [w for w in windows if w.index not in selected_ids]
    sampled = random.Random(seed).sample(remaining, reserved)
    return sorted(priority + sampled, key=lambda w: w.index)


class Pipeline:
    def __init__(self, detectors, config=None, clock=time.perf_counter):
        self.detectors = detectors
        self.config = config or Config()
        self.clock = clock
        self.cache = OrderedDict()

    def scan(self, envelope: Envelope):
        start = self.clock()
        deadline = start + self.config.deadline_seconds
        result = {
            "decision": "ESCALATE", "reasons": [], "mode": self.config.mode,
            "boundary": envelope.boundary, "source": envelope.source,
            "sensitive_action": envelope.sensitive_action,
            "required_risks": list(envelope.required_risks),
            "thresholds_validated": False, "security_validated": False,
            "findings": [], "detectors": {}, "elapsed_ms": 0.0,
            "deadline_exceeded": False,
        }
        if len(envelope.text) > self.config.max_chars:
            result["reasons"] = ["INPUT_LIMIT"]
            result["elapsed_ms"] = (self.clock() - start) * 1000
            return result
        findings = result["findings"] = scan_rules(
            envelope.text, envelope.boundary, envelope.source, envelope.sensitive_action,
        )
        reports, plans = result["detectors"], {}
        # Rules complete only the deliberately narrow configured-secret check.
        reports["leakage"] = {
            "backend": "rules", "status": "complete", "score": 0.0,
            "scope": "configured_synthetic_secret_only", "rule_text_coverage": 1.0,
        }
        for risk, detector in self.detectors.items():
            report = reports[risk] = {
                "backend": detector.backend, "identity": detector.identity,
                "status": "unavailable", "score": None, "total_windows": None,
                "selected_windows": 0, "scored_windows": 0, "skipped_windows": None,
                "token_coverage": None, "cache_hits": 0, "flagged_windows": [],
            }
            if self.clock() >= deadline:
                report.update(status="error", error="soft_deadline_exceeded")
                continue
            try:
                windows = detector.windows(envelope.text)
            except DetectorUnavailable as exc:
                report["error"] = str(exc)
                continue
            except Exception as exc:
                report.update(status="error", error=f"{type(exc).__name__}: {exc}")
                continue
            report.update(total_windows=len(windows), skipped_windows=len(windows), token_coverage=0.0)
            plans[risk] = (detector, windows)
        overcap = self.config.mode == "full" and any(
            len(plans[r][1]) > self.config.max_windows
            for r in envelope.required_risks if r in plans
        )
        for risk, (detector, windows) in plans.items():
            report = reports[risk]
            if overcap or (self.config.mode == "full" and len(windows) > self.config.max_windows):
                report.update(status="window_limit", error="WINDOW_LIMIT")
                continue
            selected = windows if self.config.mode == "full" else select_windows(
                windows, findings, self.config.max_windows, self.config.seed,
            )
            report["selected_windows"] = len(selected)
            all_positions = {p for w in windows for p in w.token_positions}
            scored_positions = set()
            scores = []
            failure = None
            for window in selected:
                if self.clock() >= deadline:
                    failure = "soft_deadline_exceeded"
                    break
                key = (detector.identity, window.token_ids)
                try:
                    if key in self.cache:
                        score = self.cache[key]
                        self.cache.move_to_end(key)
                        report["cache_hits"] += 1
                    else:
                        score = detector.score(window)
                        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
                            raise ValueError("invalid classifier score")
                        self.cache[key] = score
                        if len(self.cache) > self.config.cache_entries:
                            self.cache.popitem(last=False)
                except Exception as exc:
                    failure = f"{type(exc).__name__}: {exc}"
                    break
                scores.append(score)
                scored_positions.update(window.token_positions)
                if score >= 0.5:
                    report["flagged_windows"].append({"index": window.index, "start": window.start, "end": window.end, "score": score})
                if self.clock() >= deadline:
                    failure = "soft_deadline_exceeded"
                    break
            count = len(scores)
            report.update(
                scored_windows=count, skipped_windows=len(windows) - count,
                score=max(scores) if scores else (0.0 if not windows else None),
                token_coverage=len(scored_positions) / len(all_positions) if all_positions else 1.0,
                status="error" if failure else ("complete" if count == len(windows) else "partial"),
            )
            if failure:
                report["error"] = failure
            if detector.backend == "mock":
                report["simulation_scan_status"] = report["status"]
                report["status"] = "mock"
        overdue = self.clock() >= deadline
        result["decision"], result["reasons"] = decide(findings, reports, envelope.required_risks, overdue)
        if overcap:
            result["reasons"].append("WINDOW_LIMIT")
        if any(r.get("backend") == "mock" for r in reports.values()):
            simulated = {risk: dict(report) for risk, report in reports.items()}
            for report in simulated.values():
                if report.get("backend") == "mock":
                    report.update(backend="simulated", status=report.get("simulation_scan_status", "error"))
            result["simulated_decision"], result["simulated_reasons"] = decide(findings, simulated, envelope.required_risks, overdue)
        result["elapsed_ms"] = (self.clock() - start) * 1000
        result["deadline_exceeded"] = overdue
        return result
