"""Local multi-head safety classifier.

Cheap hashed n-gram logistic model. Rules stay the fast first pass; this
model scores the remainder. If the model file is missing or scoring exceeds
the latency budget, callers fail closed on input and on high-risk tools.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parent
_WORD = re.compile(r"[a-z0-9_]+|[\u4e00-\u9fff]")
HEADS = (
    "prompt_injection",
    "malicious_code",
    "sensitive_info",
    "danger_ops",
    "resource_abuse",
)


class ClassifierUnavailable(RuntimeError):
    pass


@dataclass
class Assessment:
    blocked: bool
    risk_score: float
    labels: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    reason: str = ""
    degraded: bool = False
    elapsed_ms: float = 0.0
    policy_version: str = ""


def tokenize(text: str) -> list[str]:
    words = _WORD.findall(str(text).lower())
    tokens = [f"w:{word}" for word in words]
    tokens.extend(f"b:{left}|{right}" for left, right in zip(words, words[1:]))
    return tokens[:512]


def feature_index(token: str, dim: int) -> int:
    digest = hashlib.md5(token.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % dim


def featurize(text: str, dim: int) -> dict[int, float]:
    counts: dict[int, float] = {}
    for token in tokenize(text):
        index = feature_index(token, dim)
        counts[index] = min(3.0, counts.get(index, 0.0) + 1.0)
    return counts


def _sigmoid(value: float) -> float:
    if value >= 20:
        return 1.0
    if value <= -20:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))


@lru_cache(maxsize=1)
def load_policy() -> dict[str, Any]:
    path = _ROOT / "policy.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_model() -> dict[str, Any]:
    policy = load_policy()
    relative = policy.get("classifier", {}).get("model", "classifier_model.json")
    path = _ROOT / relative
    if not path.is_file():
        raise ClassifierUnavailable(f"classifier model missing: {path.name}")
    model = json.loads(path.read_text(encoding="utf-8"))
    if "heads" not in model or "weights" not in model:
        raise ClassifierUnavailable("classifier model is invalid")
    return model


def reload_classifier() -> None:
    load_policy.cache_clear()
    load_model.cache_clear()
    from security.obfuscation import clear_obfuscation
    from security.patterns import clear_patterns

    clear_obfuscation()
    clear_patterns()


def score_text(text: str) -> dict[str, float]:
    started = time.perf_counter()
    model = load_model()
    policy = load_policy()
    budget_ms = float(policy.get("classifier", {}).get("timeout_ms", 30))
    dim = int(model.get("dim", 2048))
    features = featurize(text, dim)
    scores: dict[str, float] = {}
    bias = model.get("bias", {})
    weights = model.get("weights", {})
    for head in model.get("heads", HEADS):
        total = float(bias.get(head, 0.0))
        head_weights = weights.get(head, {})
        for index, value in features.items():
            total += float(head_weights.get(str(index), 0.0)) * value
        scores[head] = round(_sigmoid(total), 4)
        if (time.perf_counter() - started) * 1000 > budget_ms:
            raise ClassifierUnavailable("classifier exceeded latency budget")
    return scores


def assess(text: str, rail: str, tool: str = "") -> Assessment:
    policy = load_policy()
    version = str(policy.get("version", ""))
    from security.normalize import hidden_payloads, looks_obfuscated, recover
    from security.obfuscation import obfuscation_threshold, score_obfuscation

    started = time.perf_counter()
    try:
        scores = score_text(recover(text))
        for extra in hidden_payloads(text)[:2]:
            for head, value in score_text(recover(extra)).items():
                scores[head] = max(scores.get(head, 0.0), value)
    except ClassifierUnavailable as exc:
        fail_open = tool in set(policy.get("classifier", {}).get("fail_open_tools", []))
        elapsed = (time.perf_counter() - started) * 1000
        if rail == "pre_tool" and fail_open:
            return Assessment(
                blocked=False,
                risk_score=0.0,
                reason="classifier_unavailable_low_risk",
                degraded=True,
                elapsed_ms=elapsed,
                policy_version=version,
            )
        return Assessment(
            blocked=True,
            risk_score=1.0,
            labels=["classifier_unavailable"],
            reason=f"classifier_unavailable:{exc}",
            degraded=True,
            elapsed_ms=elapsed,
            policy_version=version,
        )

    thresholds = policy.get("classifier", {}).get("rails", {}).get(rail, {})
    labels = [head for head, threshold in thresholds.items() if scores.get(head, 0.0) >= float(threshold)]
    if "prompt_injection" not in labels and looks_obfuscated(text):
        obfuscated = score_obfuscation(text)
        scores["obfuscation"] = obfuscated
        if obfuscated >= obfuscation_threshold():
            labels.append("prompt_injection")
    risk = max((value for key, value in scores.items() if key != "obfuscation"), default=0.0)
    if scores.get("obfuscation", 0.0) > risk and "prompt_injection" in labels:
        risk = scores["obfuscation"]
    elapsed = (time.perf_counter() - started) * 1000
    if labels:
        return Assessment(
            blocked=True,
            risk_score=round(risk, 4),
            labels=labels,
            scores=scores,
            reason="classifier:" + ",".join(labels),
            elapsed_ms=elapsed,
            policy_version=version,
        )
    return Assessment(
        blocked=False,
        risk_score=round(risk, 4),
        scores=scores,
        elapsed_ms=elapsed,
        policy_version=version,
    )
