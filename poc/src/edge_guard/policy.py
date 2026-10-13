"""Conservative demonstration policy, with provisional unvalidated thresholds."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping


THRESHOLD = 0.5
_REAL_STATUSES = frozenset({"complete", "partial", "error", "window_limit"})
_ACCEPTED_BACKENDS = frozenset({"real", "rules", "simulated"})


def _valid_score(score: object) -> bool:
    return (
        isinstance(score, (int, float)) and not isinstance(score, bool)
        and math.isfinite(score) and 0 <= score <= 1
    )


def decide(
    findings: Iterable[Mapping],
    detectors: Mapping[str, Mapping],
    required_risks: Iterable[str],
    overdue: bool = False,
) -> tuple[str, list[str]]:
    """Preserve positive real evidence; incomplete checks cannot justify ALLOW.

    Scores are classifier scores, not calibrated probabilities. The fixed 0.5
    threshold exists for demonstration, not as a validated operating point.
    Mocks cannot justify either an operational BLOCK or an operational ALLOW.
    The pipeline uses the internal ``simulated`` backend only on a private copy
    for its separate, nonoperative simulated verdict. Detector backend identity
    is internal application metadata, never accepted from scanned text.
    """
    blocking = [
        f"blocking_rule:{finding.get('rule_id', 'unknown')}"
        for finding in findings if finding.get("blocking") is True
    ]
    for risk, detector in detectors.items():
        score = detector.get("score")
        if (
            detector.get("status") in _REAL_STATUSES
            and detector.get("backend") in _ACCEPTED_BACKENDS
            and _valid_score(score) and score >= THRESHOLD
        ):
            blocking.append(f"detector_threshold:{risk}")
    if blocking:
        return "BLOCK", list(dict.fromkeys(blocking))

    reasons = ["soft_deadline_exceeded"] if overdue else []
    for risk in dict.fromkeys(required_risks):
        detector = detectors.get(risk)
        if detector is None:
            reasons.append(f"detector_missing:{risk}")
            continue
        status = detector.get("status", "unavailable")
        if detector.get("backend") not in _ACCEPTED_BACKENDS:
            reasons.append(f"detector_invalid_backend:{risk}")
        elif status != "complete":
            reasons.append(f"detector_incomplete:{risk}:{status}")
        elif not _valid_score(detector.get("score")):
            reasons.append(f"detector_invalid_score:{risk}")
    if reasons:
        return "ESCALATE", reasons
    return "ALLOW", []
