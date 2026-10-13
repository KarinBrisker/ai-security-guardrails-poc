"""Check adapter contracts without downloading pretrained weights."""

from types import SimpleNamespace
import pytest

from edge_guard.models import HFDetector, build_detectors


def test_real_backend_without_local_models_is_explicitly_unavailable(tmp_path):
    detectors = build_detectors("real", tmp_path)
    assert all(d.backend == "unavailable" for d in detectors.values())
    assert not any(d.backend == "mock" for d in detectors.values())


@pytest.mark.parametrize("mapping,expected", [({0: "BENIGN", 1: "MALICIOUS"}, 1), ({0: "MALICIOUS", 1: "BENIGN"}, 0), ({0: "LABEL_0", 1: "LABEL_1"}, None)])
def test_injection_polarity_is_loaded_from_named_labels(monkeypatch, tmp_path, mapping, expected):
    pytest.importorskip("torch")
    transformers = pytest.importorskip("transformers")
    config = SimpleNamespace(num_labels=2, max_position_embeddings=512, id2label=mapping, to_dict=lambda: {"id2label": mapping})
    class FakeModel:
        def __init__(self):
            self.config = config
        def to(self, **kwargs):
            return self
        def eval(self):
            return self
    tokenizer = SimpleNamespace(is_fast=True, backend_tokenizer=SimpleNamespace(to_str=lambda: "test-tokenizer"))
    monkeypatch.setattr(transformers.AutoTokenizer, "from_pretrained", lambda *a, **k: tokenizer)
    monkeypatch.setattr(transformers.AutoModelForSequenceClassification, "from_pretrained", lambda *a, **k: FakeModel())
    if expected is None:
        with pytest.raises(ValueError, match="MALICIOUS polarity"):
            HFDetector("injection", tmp_path)
    else:
        assert HFDetector("injection", tmp_path).positive_id == expected
