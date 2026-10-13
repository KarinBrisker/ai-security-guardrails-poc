"""Local CPU classifiers and explicit fixture-only simulation adapters."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import unicodedata


MODEL_IDS = {
    "toxicity": "textdetox/bert-multilingual-toxicity-classifier",
    "injection": "deepset/deberta-v3-base-injection",
}
PROMPT_GUARD_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
MODEL_DIRS = {"toxicity": "textdetox", "injection": "deepset_injection"}


@dataclass(frozen=True)
class Window:
    index: int
    text: str
    start: int
    end: int
    token_ids: tuple[int, ...]
    token_positions: tuple[int, ...]


class DetectorUnavailable(RuntimeError):
    """A required local classifier could not be loaded."""


class UnavailableDetector:
    backend = "unavailable"

    def __init__(self, risk: str, reason: str):
        self.risk = risk
        self.reason = reason
        self.identity = f"unavailable:{risk}"

    def windows(self, text: str) -> list[Window]:
        raise DetectorUnavailable(self.reason)

    def score(self, window: Window) -> float:
        raise DetectorUnavailable(self.reason)


class MockDetector:
    """Deterministic reserved-marker fixture scores, never real detection."""

    backend = "mock"

    def __init__(self, risk: str):
        if risk not in MODEL_IDS:
            raise ValueError(f"Unknown risk: {risk}")
        self.risk = risk
        self.identity = f"mock:{risk}:whitespace-v1:510:64"

    def windows(self, text: str) -> list[Window]:
        matches = list(re.finditer(r"\S+", text))
        if not matches:
            return []
        result = []
        for base in range(0, len(matches), 446):
            content = matches[base:base + 510]
            start, end = content[0].start(), content[-1].end()
            # Stable fixture IDs: Python's randomized hash is unsuitable here.
            ids = tuple(int.from_bytes(hashlib.sha256(m.group().encode()).digest()[:4], "big") for m in content)
            result.append(Window(len(result), text[start:end], start, end, ids, tuple(range(base, base + len(content)))))
            if base + len(content) == len(matches):
                break
        return result

    def score(self, window: Window) -> float:
        marker = "[MOCK_INJECTION]" if self.risk == "injection" else "[MOCK_TOXICITY]"
        return 0.95 if marker in window.text else 0.05


class HFDetector:
    backend = "real"

    def __init__(self, risk: str, directory: Path, revision: str = "local-unpinned", model_id: str | None = None):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.risk = risk
        self.model_id = model_id or MODEL_IDS[risk]
        self._torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(directory), use_fast=True, local_files_only=True, trust_remote_code=False,
        )
        if not self.tokenizer.is_fast:
            raise ValueError("A fast tokenizer is required for original offsets")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            str(directory), local_files_only=True, trust_remote_code=False,
            use_safetensors=True,
        ).to(device="cpu", dtype=torch.float32).eval()
        if self.model.config.num_labels != 2:
            raise ValueError("Expected binary sequence classifier")
        if getattr(self.model.config, "max_position_embeddings", 0) < 512:
            raise ValueError("Classifier must support 512-token windows")
        if risk == "toxicity":
            if self.model.config.model_type != "bert":
                raise ValueError("TextDetox adapter requires its BERT classifier")
            # Explicit model-card contract: class 0 neutral, class 1 toxic.
            self.positive_id = 1
        elif risk == "injection":
            mapping = {int(k): str(v).upper() for k, v in self.model.config.id2label.items()}
            positive_label = "MALICIOUS" if self.model_id == PROMPT_GUARD_ID else "INJECTION"
            negative_label = "BENIGN" if self.model_id == PROMPT_GUARD_ID else "LEGIT"
            positive = [k for k, v in mapping.items() if v == positive_label]
            if len(positive) != 1 or positive[0] not in (0, 1):
                raise ValueError(f"Injection configuration must identify {positive_label} polarity")
            if mapping.get(1 - positive[0]) != negative_label:
                raise ValueError(f"Injection configuration must identify {negative_label} polarity")
            self.positive_id = positive[0]
        else:
            raise ValueError(f"Unknown risk: {risk}")
        config_digest = hashlib.sha256(json.dumps(self.model.config.to_dict(), sort_keys=True).encode()).hexdigest()
        tokenizer_digest = hashlib.sha256(self.tokenizer.backend_tokenizer.to_str().encode()).hexdigest()
        self.identity = f"{self.model_id}:{revision}:fp32:raw-v1:512:64:{config_digest}:{tokenizer_digest}"

    def windows(self, text: str) -> list[Window]:
        if self.risk == "injection" and self.model_id == MODEL_IDS["injection"]:
            # Conservative script gate, not language identification. The model
            # card lists English/German; non-Latin inputs cannot justify ALLOW.
            if any(c.isalpha() and "LATIN" not in unicodedata.name(c, "") for c in text):
                raise DetectorUnavailable("unsupported_script: deepset injection candidate covers English/German only")
        if not text.strip():
            return []
        encoded = self.tokenizer(
            text, truncation=True, max_length=512, stride=64,
            return_overflowing_tokens=True, return_offsets_mapping=True,
            return_special_tokens_mask=True, padding=False,
        )
        result = []
        base = 0
        for ids, offsets, specials in zip(encoded["input_ids"], encoded["offset_mapping"], encoded["special_tokens_mask"]):
            raw_offsets = [pair for pair, special in zip(offsets, specials) if not special]
            count = len(raw_offsets)
            if not count:
                continue
            start, end = min(pair[0] for pair in raw_offsets), max(pair[1] for pair in raw_offsets)
            result.append(Window(len(result), text[start:end], start, end, tuple(ids), tuple(range(base, base + count))))
            base += count - 64
        if not result:
            raise ValueError("Nonblank input produced no content tokens; detection is unassessed")
        return result

    def score(self, window: Window) -> float:
        if not window.token_ids or len(window.token_ids) > 512:
            raise ValueError("Invalid classifier window length")
        ids = self._torch.tensor([window.token_ids], dtype=self._torch.long, device="cpu")
        with self._torch.inference_mode():
            output = self.model(input_ids=ids, attention_mask=self._torch.ones_like(ids))
            if tuple(output.logits.shape) != (1, 2):
                raise ValueError("Expected one binary classification result")
            value = self._torch.softmax(output.logits, dim=-1)[0, self.positive_id].item()
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("Classifier returned an invalid score")
        return float(value)


def build_detectors(backend: str, model_root: str | Path) -> dict:
    if backend == "mock":
        return {risk: MockDetector(risk) for risk in MODEL_IDS}
    if backend != "real":
        raise ValueError("backend must be real or mock")
    root = Path(model_root)
    manifest = {}
    if (root / "manifest.json").exists():
        try:
            manifest = json.loads((root / "manifest.json").read_text())
        except (OSError, ValueError):
            manifest = {}
    result = {}
    for risk, subdir in MODEL_DIRS.items():
        entry = manifest.get(risk, {})
        model_id = entry.get("repo_id", MODEL_IDS[risk])
        if risk == "injection" and model_id == PROMPT_GUARD_ID:
            subdir = "prompt_guard"
        elif model_id != MODEL_IDS[risk]:
            result[risk] = UnavailableDetector(risk, "Unsupported model identity in local manifest")
            continue
        directory = root / subdir
        if not directory.is_dir():
            result[risk] = UnavailableDetector(risk, f"Local {subdir} model is absent; run explicit model setup")
            continue
        try:
            revision = entry.get("revision", "local-unpinned")
            result[risk] = HFDetector(risk, directory, revision, model_id)
        except Exception as exc:
            result[risk] = UnavailableDetector(risk, f"Local classifier load failed: {type(exc).__name__}: {exc}")
    return result


def provision_models(model_root: str | Path, include_prompt_guard: bool = False, include_injection: bool = False) -> dict:
    """Explicit online setup; resolve immutable commits before downloading."""
    from huggingface_hub import HfApi, snapshot_download

    root = Path(model_root)
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    risks = ["toxicity", "injection"] if include_prompt_guard or include_injection else ["toxicity"]
    for risk in risks:
        repo_id = PROMPT_GUARD_ID if risk == "injection" and include_prompt_guard else MODEL_IDS[risk]
        subdir = "prompt_guard" if repo_id == PROMPT_GUARD_ID else MODEL_DIRS[risk]
        revision = HfApi().model_info(repo_id, revision="main").sha
        if not revision:
            raise RuntimeError(f"No resolved revision for {repo_id}")
        snapshot_download(
            repo_id=repo_id, revision=revision, local_dir=str(root / subdir),
            allow_patterns=["*.json", "*.safetensors", "*.model", "*.txt"],
        )
        manifest[risk] = {"repo_id": repo_id, "revision": revision, "directory": subdir}
        temporary = root / "manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2) + "\n")
        temporary.replace(manifest_path)
    return manifest
