"""Local trajectory judge trained on agent traces.

Scores a proposed tool against the user request and tool observations.
Cross-step features record when the action repeats content that appeared
only in an observation. The word-level prompt heads do not make this call.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parent
_MODEL = _ROOT / "trajectory_model.json"
_TOKEN = re.compile(r"[a-z0-9]{3,}|[\u4e00-\u9fff]")
_CUE = re.compile(
    r"\b(please|next|instead|before you|you should|make sure to|do not forget)\b|请|接下来|改为",
    re.I,
)
DIM = 1024


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(str(text or "").lower()))


def _grams(text: str, prefix: str, shift: int) -> dict[int, int]:
    words = _TOKEN.findall(str(text or "").lower())
    counts: dict[int, int] = {}
    pieces = [f"{prefix}:{word}" for word in words]
    pieces.extend(f"{prefix}:{left}:{right}" for left, right in zip(words, words[1:]))
    for piece in pieces:
        bucket = shift + int(hashlib.md5(piece.encode("utf-8")).hexdigest()[:8], 16) % DIM
        counts[bucket] = min(3, counts.get(bucket, 0) + 1)
    return counts


def featurize(user: str, observation: str, name: str, args: dict[str, Any]) -> dict[int, int]:
    action = name + " " + json.dumps(args, ensure_ascii=False)
    features: dict[int, int] = {}
    for source in (
        _grams(user, "u", 0),
        _grams(observation, "o", DIM),
        _grams(action, "a", DIM * 2),
    ):
        features.update(source)
    user_tokens = _tokens(user)
    observation_tokens = _tokens(observation)
    action_tokens = _tokens(action)
    introduced = observation_tokens - user_tokens
    followed = action_tokens & introduced
    aligned = action_tokens & user_tokens
    for token in list(followed)[:12]:
        bucket = DIM * 3 + int(hashlib.md5(f"f:{token}".encode("utf-8")).hexdigest()[:8], 16) % DIM
        features[bucket] = features.get(bucket, 0) + 1
    mutating = name in {"bash", "write", "edit", "run_command", "write_file", "str_replace"}
    features[DIM * 4] = min(5, len(followed)) * 3
    features[DIM * 4 + 1] = min(5, len(aligned))
    features[DIM * 4 + 2] = 3 if _CUE.search(observation or "") and followed else 0
    features[DIM * 4 + 3] = 1 if mutating and followed else 0
    return features


def _sigmoid(value: float) -> float:
    if value >= 20:
        return 1.0
    if value <= -20:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))


def train_trajectory(rows: list[tuple[str, str, str, dict[str, Any], float]]) -> dict[str, Any]:
    bias = 0.0
    weights: dict[str, float] = {}
    learning_rate = 0.35
    for _epoch in range(8):
        for user, observation, name, args, target in rows:
            features = featurize(user, observation, name, args)
            total = bias
            for index, value in features.items():
                total += weights.get(str(index), 0.0) * value
            error = _sigmoid(total) - target
            if target == 1.0:
                error *= 2.0
            bias -= learning_rate * error
            for index, value in features.items():
                key = str(index)
                updated = weights.get(key, 0.0) * (1.0 - learning_rate * 1e-4) - learning_rate * error * value
                if abs(updated) < 1e-6:
                    weights.pop(key, None)
                else:
                    weights[key] = round(updated, 6)
    model = {
        "version": 1,
        "dim": DIM,
        "bias": round(bias, 6),
        "weights": weights,
        "threshold": 0.6,
        "feature": "trajectory_cross_step",
        "train_rows": len(rows),
        "trained": "agent_trajectory_only",
    }
    _MODEL.write_text(json.dumps(model), encoding="utf-8")
    clear_trajectory()
    return model


@lru_cache(maxsize=1)
def load_trajectory() -> dict[str, Any]:
    if not _MODEL.is_file():
        return {}
    try:
        model = json.loads(_MODEL.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if "weights" not in model:
        return {}
    return model


def clear_trajectory() -> None:
    load_trajectory.cache_clear()


def score_trajectory(user: str, observation: str, name: str, args: dict[str, Any]) -> float:
    model = load_trajectory()
    if not model:
        return 0.0
    total = float(model.get("bias", 0.0))
    weights = model.get("weights", {})
    for index, value in featurize(user, observation, name, args).items():
        total += float(weights.get(str(index), 0.0)) * value
    return round(_sigmoid(total), 4)


def trajectory_threshold() -> float:
    model = load_trajectory()
    return float(model.get("threshold", 0.6)) if model else 1.0


def judge_trajectory(steps: list[dict[str, Any]], name: str, args: dict[str, Any]) -> bool:
    user = " ".join(str(step.get("text") or "") for step in steps if step.get("kind") == "user")
    observation = " ".join(str(step.get("text") or "") for step in steps if step.get("kind") == "observation")
    if not observation:
        return False
    return score_trajectory(user, observation, name, args) >= trajectory_threshold()
