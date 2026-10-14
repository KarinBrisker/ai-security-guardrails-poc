"""Bounded text cues; these rules do not establish general attack detection."""

from __future__ import annotations

from bisect import bisect_left
import re
import unicodedata


DEMO_SECRET = "DEMO_SECRET_DO_NOT_EXPORT"
_OUTGOING = frozenset({"tool_call", "output"})

# Fixed, bounded expressions avoid nested quantifiers and unbounded wildcards.
# A cue is evidence only: legitimate quotations can match these expressions.
_CUES = (
    ("override_en", re.compile(
        r"\b(?:ignore|disregard|forget)\s{1,16}(?:(?:all|the|your)\s{1,16})?"
        r"(?:previous|prior|above)\s{1,16}(?:instructions|rules|prompts)\b", re.I)),
    ("override_he", re.compile(
        r"(?:התעלם|התעלמי|התעלמו)\s{1,16}(?:מכל\s{1,16})?"
        r"(?:ההוראות|מההוראות|הוראות)\s{1,16}(?:הקודמות|קודמות)")),
    ("override_ar", re.compile(
        r"(?:تجاهل|تجاهلي|تجاهلوا)\s{1,16}(?:كل\s{1,16})?"
        r"(?:التعليمات|تعليمات)\s{1,16}(?:السابقة|سابقة)")),
    ("role_spoof", re.compile(
        r"(?:<\|(?:system|developer|assistant)\|>|"
        r"\[(?:system|developer)\]|\b(?:system|developer)\s{0,8}:)", re.I)),
    ("exfiltration_cue", re.compile(
        r"\b(?:exfiltrate|steal|leak)\s{1,16}(?:(?:the|all)\s{1,16})?"
        r"(?:secrets?|credentials?|passwords?|api[ _-]?keys?)\b", re.I)),
)


def scan_rules(text: str, boundary: str, source: str = "user", sensitive_action: bool = False) -> list[dict]:
    """Return cues with offsets relative to the explicitly named text view.

    Input size is bounded by the pipeline before invoking this function.
    A narrow contextual conjunction blocks lower-trust authority/exfiltration
    cues ahead of sensitive actions; isolated injection cues remain evidence.
    Normalized offsets are never presented as offsets into the original text.
    """
    findings: list[dict] = []
    normalized = unicodedata.normalize("NFKC", text)
    views = [("raw", text)]
    if normalized != text:
        views.append(("nfkc", normalized))

    for view, content in views:
        for rule_id, pattern in _CUES:
            for match in pattern.finditer(content):
                findings.append({
                    "risk": "injection", "rule_id": rule_id, "view": view,
                    "start": match.start(), "end": match.end(),
                    "blocking": False,
                })
        lower_trust = boundary == "tool_result" or (boundary == "input" and source != "user")
        if lower_trust and sensitive_action:
            roles = [f for f in findings if f["view"] == view and f["rule_id"] == "role_spoof"]
            exports = [f for f in findings if f["view"] == view and f["rule_id"] == "exfiltration_cue"]
            export_starts = [f["start"] for f in exports]
            # Bounded proximity avoids linking unrelated cues across a document.
            for role in roles:
                index = bisect_left(export_starts, role["end"])
                if index < len(exports) and exports[index]["start"] <= role["end"] + 256:
                    export = exports[index]
                    findings.append({
                        "risk": "injection", "rule_id": "untrusted_role_exfiltration",
                        "view": view, "start": role["start"], "end": export["end"],
                        "blocking": True,
                        "context": {"boundary": boundary, "source": source, "sensitive_action": True},
                    })
        # Exact synthetic value makes this configured-secret demonstration deterministic;
        # it is not a detector for arbitrary real credentials.
        for match in re.finditer(re.escape(DEMO_SECRET), content):
            findings.append({
                "risk": "synthetic_secret", "rule_id": "synthetic_secret", "view": view,
                "start": match.start(), "end": match.end(),
                "blocking": boundary in _OUTGOING,
            })
    return findings
