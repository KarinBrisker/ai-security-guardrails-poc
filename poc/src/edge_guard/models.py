"""Local CPU classifiers and explicit fixture-only simulation adapters."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re


MODEL_IDS = {
    "toxicity": "textdetox/bert-multilingual-toxicity-classifier",
    "injection": "meta-llama/Llama-Prompt-Guard-2-86M",
}
MODEL_DIRS = {"toxicity": "textdetox", "injection": "prompt_guard"}


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

    def __init__(self, risk: str, directory: Path, revision: str = "local-unpinned"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.risk = risk
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
            positive = [k for k, v in mapping.items() if v == "MALICIOUS"]
            if len(positive) != 1 or positive[0] not in (0, 1):
                raise ValueError("Prompt Guard configuration must identify MALICIOUS polarity")
            self.positive_id = positive[0]
        else:
            raise ValueError(f"Unknown risk: {risk}")
        config_digest = hashlib.sha256(json.dumps(self.model.config.to_dict(), sort_keys=True).encode()).hexdigest()
        tokenizer_digest = hashlib.sha256(self.tokenizer.backend_tokenizer.to_str().encode()).hexdigest()
        self.identity = f"{MODEL_IDS[risk]}:{revision}:fp32:raw-v1:512:64:{config_digest}:{tokenizer_digest}"

    def windows(self, text: str) -> list[Window]:
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
        directory = root / subdir
        if not directory.is_dir():
            result[risk] = UnavailableDetector(risk, f"Local {subdir} model is absent; run explicit model setup")
            continue
        try:
            revision = manifest.get(risk, {}).get("revision", "local-unpinned")
            result[risk] = HFDetector(risk, directory, revision)
        except Exception as exc:
            result[risk] = UnavailableDetector(risk, f"Local classifier load failed: {type(exc).__name__}: {exc}")
    return result


def provision_models(model_root: str | Path, include_prompt_guard: bool = False) -> dict:
    """Explicit online setup; resolve immutable commits before downloading."""
    from huggingface_hub import HfApi, snapshot_download

    root = Path(model_root)
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    risks = ["toxicity", "injection"] if include_prompt_guard else ["toxicity"]
    for risk in risks:
        repo_id = MODEL_IDS[risk]
        revision = HfApi().model_info(repo_id, revision="main").sha
        if not revision:
            raise RuntimeError(f"No resolved revision for {repo_id}")
        snapshot_download(
            repo_id=repo_id, revision=revision, local_dir=str(root / MODEL_DIRS[risk]),
            allow_patterns=["*.json", "*.safetensors", "*.model", "*.txt"],
        )
        manifest[risk] = {"repo_id": repo_id, "revision": revision, "directory": MODEL_DIRS[risk]}
        temporary = root / "manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2) + "\n")
        temporary.replace(manifest_path)
    return manifest
