"""Character trigram head for text the word classifier still cannot read.

Trained only on the classifier training split. Obfuscated copies of those
rows are extra positive examples. The held-out test split is never used.
"""

from __future__ import annotations

import hashlib
import json
import random
from functools import lru_cache
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parent
_MODEL = _ROOT / "obfuscation_model.json"
DIM = 2048
EPOCHS = 5
LR = 0.35
L2 = 1e-4


def char_features(text: str, dim: int = DIM) -> dict[int, int]:
    raw = str(text or "").lower()
    counts: dict[int, int] = {}
    if len(raw) < 3:
        return counts
    for index in range(len(raw) - 2):
        gram = raw[index : index + 3]
        bucket = int(hashlib.md5(gram.encode("utf-8", errors="replace")).hexdigest()[:8], 16) % dim
        counts[bucket] = min(3, counts.get(bucket, 0) + 1)
    return counts


def augment_positive(text: str) -> list[str]:
    raw = str(text or "")
    if len(raw) < 8 or len(raw) > 400:
        return [raw]
    chars = list(raw)
    return [
        raw,
        raw.swapcase(),
        " ".join(chars),
        "\u200b".join(chars),
        ".".join(chars),
    ]


def _sigmoid(value: float) -> float:
    if value >= 20:
        return 1.0
    if value <= -20:
        return 0.0
    return 1.0 / (1.0 + pow(2.718281828, -value))


def train_obfuscation(rows: list[tuple[str, dict[str, float]]]) -> dict[str, Any]:
    examples: list[tuple[str, float]] = []
    positives = 0
    for text, labels in rows:
        target = 1.0 if labels.get("prompt_injection", 0.0) >= 1.0 else 0.0
        if target == 1.0:
            positives += 1
            if positives <= 900:
                for variant in augment_positive(text):
                    examples.append((variant, 1.0))
            else:
                examples.append((text, 1.0))
        else:
            examples.append((text, 0.0))
    bias = 0.0
    weights: dict[str, float] = {}
    rng = random.Random(7)
    for _epoch in range(EPOCHS):
        rng.shuffle(examples)
        for text, target in examples:
            features = char_features(text, DIM)
            total = bias
            for index, value in features.items():
                total += weights.get(str(index), 0.0) * value
            error = _sigmoid(total) - target
            if target == 1.0:
                error *= 3.0
            bias -= LR * error
            for index, value in features.items():
                key = str(index)
                updated = weights.get(key, 0.0) * (1.0 - LR * L2) - LR * error * value
                if abs(updated) < 1e-6:
                    weights.pop(key, None)
                else:
                    weights[key] = round(updated, 6)
    model = {
        "version": 1,
        "dim": DIM,
        "bias": round(bias, 6),
        "weights": weights,
        "threshold": 0.8,
        "feature": "char_trigram",
        "train_rows": len(examples),
        "trained": "obfuscation_head_only",
    }
    _MODEL.write_text(json.dumps(model), encoding="utf-8")
    clear_obfuscation()
    return model


@lru_cache(maxsize=1)
def load_obfuscation() -> dict[str, Any]:
    if not _MODEL.is_file():
        return {}
    try:
        model = json.loads(_MODEL.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if "weights" not in model:
        return {}
    return model


def clear_obfuscation() -> None:
    load_obfuscation.cache_clear()


def score_obfuscation(text: str) -> float:
    model = load_obfuscation()
    if not model:
        return 0.0
    dim = int(model.get("dim", DIM))
    total = float(model.get("bias", 0.0))
    weights = model.get("weights", {})
    for index, value in char_features(text, dim).items():
        total += float(weights.get(str(index), 0.0)) * value
    return round(_sigmoid(total), 4)


def obfuscation_threshold() -> float:
    model = load_obfuscation()
    return float(model.get("threshold", 0.8)) if model else 1.0
